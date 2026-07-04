# Proof M6 — Governed Agent Skill (deployed 3-bar proof)

This proof stands up a `kind` cluster and proves the **ADR-025 governed agent
skill** live against a deployed AgentOS kernel: the open `SKILL.md` package
standard is **hosted** (validated, trust-registered, surfaced) while the
skill's **signed executable action runs fully sandboxed** and reaches MCP
tools **only** through the kernel-side skill broker, which enforces the
skill's `declared_tools` per call and routes to `MCPHost.call_tool`.

Three **RELEASED, signed packs** are consumed (released assets only — none is
built from source here; every pinned asset is sha256-verified fail-closed by
`stage-packs.sh` before staging):

* **`cognic-skill-schema-summary@v0.1.0`** — the M6 governed skill pack: the
  agentskills.io-standard `SKILL.md` (frontmatter `name: schema-summary`) +
  the deterministic, no-LLM executable action (`cognic.skills` entry point)
  declaring `declared_tools = [cognic-tool-oracle-schema/list_tables,
  cognic-tool-oracle-schema/describe_table]`.
* **`cognic-tool-oracle-schema@v0.2.0`** — the M5 DLP-governed tool release,
  reused unchanged. Operator-installed via the M4 flow; the skill's declared
  tools resolve to this deployed MCP server.
* **`cognic-hook-schema-guard@v0.1.0`** — the M5 hook pack, reused unchanged.
  Required because the oracle `v0.2.0` manifest binds its `dlp_pre` hooks —
  without the hook pack every governed tool call would fail-close at the DLP
  gate and BAR 1 could never pass.

It **extends** the proven Proof M4/M5 harness (multi-actor proof app + the
governed operator-install flow + in-cluster Oracle XE + RS256/JWKS AS + the
single effective MCP URL `10.96.0.51:8765/mcp`). The **delta is the governed
skill runtime**: the M6 kernel branch adds the `SkillExecutor` (the action
runs in an immutable, cosign-verified sandbox runtime image under the
DockerSibling backend — `--network none`-equivalent isolation, no ambient
credentials) + the per-invocation `SkillBroker` (a `0700` Unix-socket trust
boundary) + `SKILL.md` hosting/ingestion + `POST /api/v1/skills/{id}/invoke`.

## The skill-vs-tool split (what is hosted vs what runs)

* The **`SKILL.md` package is hosted, read-only**: at boot the skill pack is
  discovered (`cognic.skills`), cosign-verified against its per-pack trust
  root, admitted per the tenant allow-list, its `SKILL.md` frontmatter
  validated, and the skill surfaced on `/api/v1/system/plugins`
  (`hosted_skills`). The instructions body is the layer an M8 agent will
  read; in M6 it is validated + hosted + audited, **never executed**.
* The **signed executable action** is the ONLY thing that runs — and it runs
  **fully sandboxed** (the C1 skill-runtime image; `requires_credentials=()`;
  no general egress), reaching MCP tools exclusively through the kernel-side
  broker socket. "Signed ≠ safe" is handled by **isolation + per-call broker
  enforcement**, not trust.

## The three bars (spec §8) — argument is the only variable

All three bars POST the SAME deployed skill
(`/api/v1/skills/schema-summary/invoke`, `skill.invoke` scope); the request
argument is the only variable:

* **BAR 1 — governed composition works (prints `PROOF M6 (BAR 1) PASS`).**
  `{"arguments":{"owner":"COGNIC"}}` → the executor runs the action
  sandboxed; the broker mediates the declared `list_tables` +
  `describe_table` calls through `MCPHost.call_tool` (OAuth + DLP + audit all
  apply downstream, unchanged); a fixed-shape summary returns → **200
  `completed`** with the seeded schema (`DEPARTMENTS` + `EMPLOYEES`, incl.
  `FULL_NAME`, `"table_count": 2`). Evidence is **dual-layer**:
  execution-layer `audit.tool_invocation` rows for BOTH declared tools
  (emitted by the MCP host, never duplicated) **and** one instruction-layer
  `skill.invoked` decision row (digest-only: `arguments_sha256` +
  `stdout_sha256`, never raw bytes).
* **BAR 2 — undeclared tool refused (load-bearing; prints `PROOF M6 (BAR 2)
  PASS`).** `{"arguments":{"owner":"COGNIC","mode":"forbidden"}}` (`mode=forbidden`) → the action
  requests `cognic-tool-oracle-schema/get_constraints` — a REAL tool on the
  deployed pack, deliberately **outside** `declared_tools` → the **broker
  refuses** (`skill_tool_not_declared`, **403**) BEFORE `MCPHost.call_tool`
  is reached: no token minted, no tool touched, ZERO evidence rows for
  `get_constraints` of any event type, `audit.tool_invocation` count
  unchanged. Proves runtime broker enforcement, not just admission-time
  declaration.
* **BAR 3 — isolation holds (MANDATORY, never weakened; prints `PROOF M6
  (BAR 3) PASS`).** `{"arguments":{"owner":"COGNIC","mode":"exfil"}}` (`mode=exfil`) → the
  action attempts one DIRECT outbound HTTP request (bypassing the broker) →
  blocked by the sandbox (`--network none` posture: `egress_allow_list=()`,
  internal-bridge-only, proxy allows nothing) → the failure propagates
  fail-closed → **502 `skill_runtime_error`** (`failed`), no tool rows, and
  the probe's success marker (`unexpectedly_succeeded`) appears NOWHERE — not
  in the response, not in any evidence row. The action holds **no ambient
  credential** (`requires_credentials=()`), so signed-but-hostile code is
  contained. Isolation is a required part of M6, not optional hardening.

On any BAR failure the runner captures pod logs + HTTP status + the refusal
reason + the `skill.invoked` / `audit.tool_invocation%` evidence tails to
`docs/VALIDATION-RESULTS.md` and exits non-zero — the proof is **never
redefined downward**. On all-pass it prints `PROOF M6 (ALL BARS) PASS`.

## Three-key trust staging (read before touching `stage-packs.sh`)

The three releases are signed with **three different cosign keys**. The
staging tree carries all three under the one `COGNIC_TRUST_ROOT_PREFIX`:

| Staged path | Key | Consumed by |
|---|---|---|
| `trust-roots/_default/cosign.pub` | oracle `v0.2.0` key | The kernel's **LOCKED** boot convention (`harness/registry_boot.py` verifies discovered packs against `<prefix>/_default/cosign.pub`) AND the approve 5-gate's signature root (`ProofStagedTrustRootResolver`). |
| `trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub` | hook pack key | The hook pack's boot trust registration (M5 layout, unchanged). |
| `trust-roots/skill-packs/cognic-skill-schema-summary/cosign.pub` | skill pack key | The skill pack's boot trust registration. `skill-packs/` is the kernel's LOCKED per-pack subdir for `skills`-kind packs (`registry_boot._SKILL_PACK_TRUST_ROOT_SUBDIR`, M6 Task A8) — exactly the hook-pack layout with the skills subdir. NOT a tenant directory. |

`stage-packs.sh` downloads the three releases with `gh release download` and
**sha256-verifies every pinned asset digest fail-closed** (three wheels +
three `cosign.pub`s) before arranging the tree — a digest mismatch means the
release moved and the stage aborts; the pins are never silently re-pointed.

## Sandbox-image trust — the REAL admission gate, no bypass

The sandbox admission pipeline (`sandbox/admission.py` + `sandbox/catalog.py`)
cosign-verifies the runtime image against the **canonical trust root** before
any session is created. The proof runs that gate REAL by enacting the
documented bank **re-home** flow (`core/config.py`: "Bank deployments re-home
to their own registry + re-sign under their canonical trust root") with a
dev-grade proof canonical key:

1. the runner builds the **skill-runtime image** (`Dockerfile.skill-runtime`:
   the branch kernel SDK overlay + the released skill wheel on the same
   default-adapters base as the kernel — wire-protocol parity between the
   kernel-side broker and the in-sandbox runner);
2. mints a **proof canonical cosign keypair** + a local **TLS registry** on
   the kind docker network (self-signed CA; the kernel image carries the CA
   in its `SSL_CERT_FILE` bundle and the canonical public key at
   `COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH`);
3. pushes + **cosign-signs BOTH** re-homed canonical images (the
   skill-runtime workload image AND the `sandbox-egress-proxy` sidecar,
   re-tagged from the published ghcr digest) under the proof canonical key;
4. injects the **digest-pinned** refs at install time
   (`helm install --set sandbox.canonicalRuntimeImage=... --set
   sandbox.canonicalEgressProxyImage=...`) — the static overlay carries no
   personal-registry ref (deploy-safety guard G7) and no placeholder.

No fixture flags, no verification skip: catalog membership + cosign verify +
the sandbox Rego bundle all run exactly as in production.

## How to run (operator-only, env-gated)

```bash
COGNIC_RUN_PROOF_M6=1 bash infra/proof-m6/run-proof-m6.sh
```

The runner is **env-gated**: with `COGNIC_RUN_PROOF_M6` unset it prints a
skip notice and exits `0` (inert in any non-operator context, including CI —
NO default-on CI job). It needs `docker`, `kind`, `kubectl`, `helm`, `uv`,
`cosign`, `syft`, `grype`, `curl`, `python3`, `gh`, and `openssl` on `PATH`,
and deletes the `kind` cluster (and the proof registry container) on exit.

## ⚠ Proof-only wiring — production needs a real overlay

The deployed image runs a **proof-only** `create_proof_app()` factory
(vendored as `proof_m6/`, which lives INSIDE this directory — unlike the
M4/M5 apps under `tests/integration/` — so it is already in the build
context). The M4/M5 caveats carry forward unchanged, plus three M6-specific
notes:

1. **The multi-actor binder is header-driven** (`X-Proof-Role`). Test-header
   trust is **unacceptable in production** — a real bank-overlay `ActorBinder`
   resolves each authenticated request from a real auth primitive (OIDC /
   mTLS), never a client header.
2. **The eager-injection wiring builds a second engine** (two engines on one
   Postgres). Acceptable for a proof-only factory; **production would inject
   ONE engine via a real single-engine eager deploy.**
3. **Per-pack trust roots are proof-staged** (three-key table above); a
   production deployment provisions pack trust roots through its real
   trust-root management (per-tenant Vault-backed per ADR-012), not
   image-baked files.
4. **Single-uid broker↔sandbox alignment.** The kernel pod runs as uid/gid
   `65534` (`proof-m6-values.yaml podSecurityContext`) — the SAME identity
   the backend forces on the workload container — so the broker's `0700`
   socket dir + `0600` socket stay connectable by the intended client and
   nothing else. A cross-uid broker↔workload contract is a forward kernel
   item, not proof scope.
5. **`TMPDIR` + host docker socket patch** (`agentos-sandbox-patch.yaml`).
   The broker's per-invocation socket dirs must exist at the SAME absolute
   path in the pod and on the docker host (the sibling bind-mount), so
   `TMPDIR` is redirected to a VM-local hostPath share and the host docker
   socket is mounted into the pod. Both are proof-topology; a production
   Kubernetes deployment uses the same-Pod sidecar + `emptyDir` realization
   (spec §5.5), never a host socket.
6. **The proof canonical key is dev-grade.** Production canonical-image
   signing-key custody is a Human-only decision (`infra/sandbox/
   build-and-sign.md`); the proof key is minted per run and never reused.

These are proof-only and must NOT be shipped as kernel behavior.

## Topology / invariants (inherited from Proof M4/M5 / 1b-2c)

* **Single effective MCP URL** `http://10.96.0.51:8765/mcp` — byte-identical
  across the **materialized** `mcp_server_url_override` row, the pack's
  `COGNIC_MCP_SERVER_URL` / `COGNIC_OAUDIENCE`-equivalent, the RFC-8707
  `resource`, and the AS-echoed token `aud`. The skill's broker-mediated tool
  calls ride this SAME governed carve-out — the broker adds enforcement, it
  removes none.
* **AS issuer** `http://192.88.99.9:9000` — RFC7526 genuine-global,
  kube-proxy-intercepted (no real egress).
* **DLP posture unchanged** — the oracle `v0.2.0` `dlp_pre` hooks fire on
  every governed call (BAR 1's permitted args pass them); M6 adds no hook
  bar, it INHERITS the M5 gate.
* **Scheduler control plane** — `cache.enabled=true` + in-cluster Redis: the
  skill executor exists only when the lifespan constructs the sandbox
  runtime, which requires the (cache-conditional) scheduler.

## Files

| File | Purpose |
|---|---|
| `stage-packs.sh` | Downloads + **sha256-pins** + arranges the THREE released packs into `proof-m6-staging/` (wheels, per-pack attestations, the three-key trust roots, the three-pack allow-list, `alembic.ini`). |
| `Dockerfile.skill-runtime` | **C1** — the immutable sandbox runtime image: branch SDK overlay + the released skill wheel; exec entrypoint `python -m cognic_agentos.sdk.skill_runner`; USER 65534; keep-alive CMD. Pushed + proof-canonical-signed by the runner. |
| `Dockerfile.agentos-proof` | Bakes the multi-actor `create_proof_app` + ALL THREE released packs' trust staging + `aiodocker` + the proof canonical-image trust material onto the default-adapters base. |
| `Dockerfile.oracle-pack` | The released oracle-schema `v0.2.0` MCP tool Service image (built from the downloaded wheel). |
| `Dockerfile.as` | The emulated-external RS256 AS image. |
| `proof_m6/` | The PROOF-ONLY multi-actor app factory (vendored in-context; `skill.invoke` on the `mcp` role). |
| `kind-config.yaml` | kind topology: host docker socket + broker-share extraMounts (the DockerSibling sibling pattern). |
| `agentos-sandbox-patch.yaml` | Post-install Deployment patch: docker-sock + broker-share hostPaths + `TMPDIR` + the broker-share perms initContainer. |
| `manifests/redis.yaml` | The scheduler control plane (cache.enabled=true). |
| `manifests/oracle-xe.yaml` | In-cluster Oracle XE Deployment + Service (seeded via the `oracle-xe-seed` ConfigMap). |
| `manifests/oracle-pack.yaml` | Oracle-pack Deployment + Service (`clusterIP: 10.96.0.51`; real RS256/JWKS verifier). |
| `manifests/auth-server.yaml` | AS Deployment + Service (`externalIPs: [192.88.99.9]`, RS256 mode). |
| `oracle-seed/seed_schema.sql` | First-boot schema seed (single source of truth for the `oracle-xe-seed` ConfigMap). |
| `seed-db.sh` | **No-op guard** — the override + allow-list rows are **materialized by `install`**; neither the hook nor the skill pack needs DB state. |
| `seed-vault.sh` | Provisions the OAuth + AS-allow-list secrets **by reference** (D5); the sandboxed action itself holds NO credentials. |
| `run-proof-m6.sh` | The operator-run end-to-end 3-bar runner (**C3**; env-gated `COGNIC_RUN_PROOF_M6=1`). |
