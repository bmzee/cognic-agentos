# A2A Conformance Matrix

**Status:** Authoritative reference for which A2A 1.0 features Cognic AgentOS supports, restricts, or defers per wave.

This document complements [`docs/adrs/ADR-003-a2a-inter-agent.md`](adrs/ADR-003-a2a-inter-agent.md). Pinned spec version: **A2A 1.0** (released April 2026).

## Spec compliance posture

AgentOS Wave 1 implements the A2A 1.0 wire format **as published by the spec**, not a Cognic-bespoke shape. CI test `test_a2a_schema_drift.py` (Sprint 6) fails the build if AgentOS's pinned schema falls behind upstream.

## Feature conformance matrix

| Feature | Wave 1 | Wave 2 | Deferred |
|---|---|---|---|
| **Agent Cards** — published descriptors at `/.well-known/agent-card.json` | ✅ Required (every agent pack ships one) | — | — |
| **Tasks** — request/response unit with declared inputs/outputs | ✅ Required | — | — |
| **Streaming messages** — SSE-style server → caller updates during a task | ✅ Required | — | — |
| **Artifacts** — output blobs (PDFs, evidence packs, large JSON) returned via reference | ✅ Required | — | — |
| **Push notification config** — caller subscribes for completion via webhook | ⚠️ Optional in Wave 1 (callers may poll instead) | Required | — |
| **Multi-modal payloads** — audio / video / image as first-class | ❌ | ✅ | — |
| **Long-running task resumption** — caller reconnects to an in-flight task | ⚠️ Optional in Wave 1 (callers tolerate restart) | Required | — |
| **Federated A2A across organisations** — cross-bank agent calls with verifiable credentials | ❌ | ❌ | Wave 3 (depends on AGNTCY identity adoption) |
| **Anonymous / unauthenticated A2A** | ❌ | ❌ | Forbidden — every A2A call requires per-tenant token (Wave 1) or VC (Wave 3) |
| **Capability negotiation** — caller probes which capabilities the agent supports | ✅ Required | — | — |
| **Cancellation** — caller aborts an in-flight task | ✅ Required | — | — |
| **Error taxonomy** — full A2A error code coverage | ✅ Required | — | — |

## Authorization

| Wave 1 | Wave 2 | Wave 3 |
|---|---|---|
| Per-tenant pinned tokens (rotated via Vault); `Authorization: Bearer ...` on every A2A request | mTLS for cross-pod / cross-pack auth within a single tenant | Verifiable Credentials (VC) for cross-organisation federated A2A |

## Agent Cards

Every agent pack must publish an A2A AgentCard. The card is **also discoverable through the plugin registry** (per ADR-002 manifest declaration `agent_card_url`).

### Card shape — upstream A2A 1.0 schema + AgentOS bank-grade profile

AgentOS validates the published `/.well-known/agent-card.json` document in **two passes**, with **enforcement split between two gates** — the runtime verifier in `protocol/a2a_agent_cards.py` (Sprint 6) and the build-time `agentos validate` CLI (Sprint 7A).

1. **Upstream validation (runtime + build-time)** — the card MUST parse cleanly against the official A2A 1.0 `AgentCard` protobuf message class via `google.protobuf.json_format.Parse` (the spec source-of-truth is `specification/a2a.proto`; the SDK ships protobuf-generated classes via `MessageMeta`). This is the spec-conformance gate; failure here means the card isn't A2A 1.0 at all. Both runtime and build-time gates enforce this pass identically. T7 R5 P2 reviewer correction: a top-level `url` field (forbidden by spec) is detected via raw-JSON inspection BEFORE protobuf parse so the dedicated `agent_card_profile_top_level_url_forbidden` reason stays reachable rather than collapsing into the generic schema-invalid bucket.

2. **AgentOS profile validation** — on top of the upstream schema, AgentOS imposes a **stricter profile** suited to bank-grade deployments. Fields the spec marks "optional" but AgentOS requires populated. **Profile enforcement is split** based on threat-model role:

   #### 2a. Runtime-critical profile subset (enforced by Sprint 6 runtime verifier)

   The fields below gate registration AND outbound-dispatch in production. These are the security-critical fields the runtime verifier in `protocol/a2a_agent_cards.py` enforces against every card it sees — both inbound (pack registration) AND outbound (remote agent's published card before we dispatch to it). The runtime verifier's closed-enum reasons fire one-per-field so authors get specific diagnostics:

   - `provider.organization` — spec-optional, **AgentOS profile mandatory** so reviewers can audit who owns the agent. Refused with `agent_card_profile_provider_missing` if absent or empty.
   - `securitySchemes` — spec-optional, **AgentOS profile mandatory** (no anonymous A2A; matches the per-tenant token requirement in this matrix). Refused with `agent_card_profile_security_schemes_missing` if empty.
   - `securityRequirements` — spec-optional, **AgentOS profile mandatory**. Refused with `agent_card_profile_security_requirements_missing` if empty.
   - `signatures` — JWS over the card content. Spec-optional, **AgentOS profile mandatory** (see "Card signatures (JWS)" section below). Refused with `agent_card_profile_signatures_missing` if empty.
   - `supportedInterfaces` — array of wire-interface entries; **each entry carries its own `url`** (and protocol/transport metadata). AgentOS profile requires at least one entry. **A2A endpoint URLs live here, NOT at the AgentCard top level.** Refused with `agent_card_profile_supported_interfaces_empty` if empty; refused with `agent_card_profile_top_level_url_forbidden` if a top-level `url` is present.

   Why this subset: each of the five gates above is a vector an attacker could exploit at registration or dispatch time. Anonymous A2A would bypass the per-tenant token gate; an unsigned card would let anyone re-write the service descriptor; an empty interface list means there's nowhere to dispatch; a top-level `url` field is a spec-violation that a malicious pack could use to redirect callers.

   #### 2b. Build-time governance metadata (enforced by Sprint 7A `agentos validate`)

   The fields below are bank-grade governance metadata — they identify, describe, and document the agent for compliance + reviewer + operator surfaces. They are **NOT** enforced by the Sprint 6 runtime verifier; instead, Sprint 7A `agentos validate` enforces them at pack-build CI time, before the pack ever ships:

   - `name`, `description`, `version` — agent identity + versioning. Build-time required so pack authors can't publish an unidentified or unversioned agent.
   - `provider.url` — provider's homepage / contact URL. Build-time required so reviewers + operators can reach the agent owner.
   - `capabilities` — declared `AgentCapabilities` flags per the spec object: `streaming`, `pushNotifications`, `extensions`, `extendedAgentCard`. Build-time required so capability-mismatch issues surface during authoring rather than at first invocation.
   - `defaultInputModes` / `defaultOutputModes` — array of MIME types. Build-time required.
   - `skills` — array of skill definitions (id, name, description, tags, examples, inputModes, outputModes). Build-time required.

   Why split: the runtime gate's job is to keep the registration / dispatch surface security-critical and the closed-enum refusal vocabulary narrow. Build-time CI catches missing governance metadata for AgentOS-built packs (the cognic + bank-overlay packs). Splitting keeps the runtime closed-enum count small (10 reasons total across all 3 passes), keeps the registry-side `RefusalReason` mapping 1:1, and keeps the pack-author developer experience focused (`agentos validate` reports all governance-metadata violations at once during local CI).

   #### 2c. Outbound remote agent cards (runtime verification only)

   When AgentOS calls a remote agent (cross-pod / cross-pack / future cross-organisation), the remote pack's card is fetched from the target's `/.well-known/agent-card.json` and verified by the runtime verifier. Remote packs are NOT built through our pipeline, so Sprint 7A `agentos validate` never runs on them. **Remote cards are gated only by the runtime-critical profile subset (§2a above).** This is the correct posture: the runtime verifier's job is to refuse outbound dispatch to any card whose security-critical profile is incomplete; missing governance metadata on a remote card is a UX + auditability concern (the operator may want to refuse based on missing `description`, but that's a per-tenant policy decision, not a wire-protocol-public refusal). Operators who require comprehensive metadata on remote cards can extend the verifier with a per-tenant policy hook in a Sprint-N amendment.

A spec-valid card without (e.g.) `signatures` or `securitySchemes` populated is a legitimate A2A 1.0 card — it just fails the AgentOS profile gate, and that's by design. The error returned to the pack author distinguishes **"not spec-valid"** (upstream error code) from **"spec-valid but does not meet AgentOS profile requirements"** (`agentos_profile_violation` with the specific mandatory field listed) so authors can diagnose without confusing the two layers.

**No top-level `url` on the AgentCard.** Endpoint URLs live inside `supportedInterfaces[].url` per the spec; a card may advertise multiple interfaces (e.g. JSON-RPC over HTTP plus gRPC) each with their own URL.

**Well-known path is `/.well-known/agent-card.json` (singular, no per-id suffix).** The spec well-known path serves the card for the agent that the host represents at that origin. AgentOS hosts one card per agent at the spec path on the agent's own origin (one origin per agent pack in Wave 1). For **multi-agent discovery across an AgentOS deployment**, the plugin registry exposes a Cognic-specific catalog endpoint `GET /api/v1/system/agent-cards` — that is registry/catalog metadata, not the spec well-known path.

**Cognic-specific identity fields do NOT live in the AgentCard.** The URN-form `agent_id`, AGNTCY/OASF `oasf_capability_set`, `verifiable_credentials_path`, and other Cognic identity metadata stay in the **pack manifest** (`[tool.cognic.identity]` block per ADR-002 amendment). Keeping the card free of Cognic-only fields means any A2A 1.0 caller can consume it without Cognic-specific knowledge; the AgentOS profile only **requires more** of the spec's existing optional fields, it never adds non-spec fields. The pack manifest carries the Cognic governance metadata that the trust gate + reviewer evidence panels consume internally.

Sprint 6 schema-drift CI gate diffs the upstream A2A 1.0 protobuf source against a pinned digest captured at T6 commit time and fails on upstream drift; profile rules are version-controlled separately. JSON-schema parity is **deferred** until upstream publishes a canonical JSON-schema bundle (the spec authors currently publish only the protobuf source at `specification/a2a.proto`; the `specification/json/` directory is README-only). See §"Versioning" below for the full drift-gate contract.

### Card signatures (JWS) — mandatory for AgentOS

A2A 1.0 supports JWS-signed Agent Cards. **AgentOS makes them mandatory** for bank deployments:

| Direction | Behaviour |
|---|---|
| **Inbound (pack registration)** | Pack manifest declares `agent_card_jws_path` (detached JWS over the card JSON). Trust gate (Sprint 4) verifies the JWS against the per-tenant trust root — the **same authority that signs the wheel signs the card**. Unsigned card or signer not on the trust root → registration refused. |
| **Outbound (calling a remote agent)** | AgentOS fetches the target's `/.well-known/agent-card.json` (the spec well-known path on the target's origin), fetches the detached JWS, verifies against the trust root. Verification failure → call refused with `agent_card_signature_invalid`. Cards signed by allow-listed signers only. The endpoint URL the call is dispatched to comes from the verified card's `supportedInterfaces[].url` — never a URL the caller supplied directly. |
| **Card mutations** | Cards do NOT live-swap. Changing card content requires re-registering the pack (lifecycle event auditable per ADR-012). The card's content hash is chain-linked into `decision_history` at registration so examiners can prove which card version was in force when. |

Reasoning: in a bank deployment, an unsigned Agent Card is an unauthenticated service descriptor that anyone on the network could rewrite. The same supply-chain discipline that ADR-016 demands for code applies to the identity descriptors that route requests between agents.

## Audit linkage

Every A2A call (inbound or outbound) creates a hash-chained `decision_history` event:
- Inbound: `a2a.task_received` with caller identity + task name + parent_trace_id
- Outbound (sub-agent spawn per ADR-005): `a2a.task_dispatched` with target agent + child_trace_id linked to parent

The chain verifier walks A2A traffic across agent boundaries to prove no message was injected, dropped, or re-ordered.

## What Wave 1 deliberately omits (deferral rationale)

- **Federated cross-org A2A**: requires Verifiable Credentials infrastructure (W3C VC + AGNTCY identity) that doesn't exist yet. Wave 3 ambition.
- **Multi-modal payloads**: bank use cases in Wave 1 are text-heavy (PolicyQA, RegIntel, AML reasoning). Multi-modal lands when document-extraction agents go cross-pack.
- **Form-mode elicitation parallels**: same concern as MCP elicitation — if A2A adds an interactive-elicitation feature for sensitive data, AgentOS treats it like the MCP form-mode case (Wave 2 + dedicated review).

## Versioning

Pinned A2A spec version: **1.0** (April 2026 release).

**Canonical data model:** A2A 1.0 publishes its schemas as **Protocol Buffers** (.proto files). AgentOS treats the protobuf source as the wire-format truth; the SDK's protobuf-generated message classes (re-exported under stable names by `protocol/a2a_schema.py` per Sprint-6 T6) are the in-process types AgentOS dispatches against.

`test_a2a_schema_drift.py` runs in CI on the dedicated `a2a-spec-drift` lane (env-gated via `COGNIC_RUN_A2A_UPSTREAM=1` per Sprint-6 Doctrine Decision C):
- Pulls the upstream A2A 1.0 protobuf source from the canonical `v1.0.0` git tag URL (`raw.githubusercontent.com/a2aproject/A2A/v1.0.0/specification/a2a.proto`).
- SHA-256s the bytes against `_PINNED_PROTOBUF_DIGEST` in `protocol/a2a_schema.py` (a digest captured at T6 commit time alongside the SDK pin).
- Fails the build on mismatch — forces a deliberate review against the Wave-1/2/3 matrix in this document + a version bump per Sprint-6 Decision Lock #1 (silent upgrades forbidden).

**JSON-schema parity check is deferred (T6 R0 capture-time discovery):** the planning-stage draft of the drift gate envisioned a parallel JSON-schema digest pin + parity check between the protobuf source and a spec-published JSON-schema binding. Reality at T6 capture: the spec authors publish only the protobuf source at a canonical URL; the `specification/json/` directory in the upstream repo is a README-only directory pointing back at the protobuf source. The JSON-schema digest pin + parity test arm + the `protocol/a2a_schema_parity.py` helper module land together when (or if) the spec authors publish a canonical JSON-schema bundle. Documented inline in `protocol/a2a_schema.py`'s docstring + `tests/unit/protocol/test_a2a_schema_drift.py`'s docstring + Sprint-6 plan-of-record §Doctrine Decision C.

When upstream A2A releases 1.1+, AgentOS evaluates feature additions, decides Wave 1/2/3 placement per the matrix above, and bumps the pinned version with explicit changelog.

### Version negotiation (`A2A-Version` header)

Per A2A 1.0 spec, every HTTP request carries an `A2A-Version` header. AgentOS handles all six cases via the closed-enum :class:`A2AVersionOutcome` matrix the spec mandates (T8's `protocol/a2a_version.py` is the runtime gate; the matrix below is the operator-facing summary):

| Inbound header | Behaviour |
|---|---|
| `A2A-Version: 1.0` | Accepted (matches pinned version) |
| Header absent | **Per A2A 1.0 spec, an absent header is interpreted as version `0.3`.** AgentOS does not implement 0.3, so the request is **rejected** with `VersionNotSupportedError` + `Supported-A2A-Versions: 1.0` response header. A warning is logged so operators can spot non-conforming callers. We do **not** silently upgrade absent-header to `1.x`. |
| `A2A-Version: 0.x` (legacy spec versions) | Rejected with `VersionNotSupportedError` + `Supported-A2A-Versions: 1.0` |
| `A2A-Version: 1.<higher minor>` | Processed; if call uses a feature only in the higher minor, feature-degradation warning emitted |
| `A2A-Version: 2.x` (or any other unsupported version) | **Rejected** with spec-defined `VersionNotSupportedError`; response includes `Supported-A2A-Versions` header |
| Header malformed | Rejected with spec-defined parse error |

Outbound calls AgentOS makes always include `A2A-Version: 1.0`. Bumping the pinned version is a deliberate reviewed change tied to the schema-drift CI gate.

## What pack authors must declare

Every agent pack must declare in its manifest:

```toml
[tool.cognic.a2a]
spec_version = "1.0"
agent_card_url = "https://packs.cognic.ai/agent_cards/policy_qa.json"
agent_card_jws_path = "agent_cards/policy_qa.jws"  # MANDATORY — detached JWS over the card; trust gate (Sprint 4) verifies
capabilities_supported = ["regulatory_qa", "citation_grounded"]
streaming = true
push_notification_config = false  # opt-in for Wave 2
artifacts_supported = true
auth_scheme = "bearer"  # or "mtls" in Wave 2
```

**`agent_card_jws_path` is mandatory** for any pack publishing an A2A AgentCard (per "Card signatures (JWS)" section above). Trust gate refuses registration if the field is missing or the JWS does not verify against the per-tenant trust root.

`agentos validate` (Sprint 7A) verifies the declarations against the conformance matrix.

## References

- [A2A 1.0 specification](https://a2a-protocol.org/dev/specification/)
- [`docs/adrs/ADR-003-a2a-inter-agent.md`](adrs/ADR-003-a2a-inter-agent.md)
- [`docs/adrs/ADR-005-subagent-primitive.md`](adrs/ADR-005-subagent-primitive.md) — sub-agent spawning rides A2A
- [AGNTCY (Cisco / Linux Foundation)](https://docs.agntcy.org/) — Wave 3 identity substrate
