# Hook pack failure-policy operator runbook

**Audience.** AgentOS operators on-call. Pairs with the alert
catalogue + the audit-event taxonomy.

**ADR.** ADR-017 (data-governance contracts) §"DLP hook failure
policy" amendment (Sprint-7A2). Pack-author counterpart at
`docs/HOW-TO-WRITE-A-PACK.md` §8 + `docs/PACK-MANIFEST-SPEC.md` §8.

**Wave-1: fail-closed only.** When a DLP-aware tool / skill / agent
invocation triggers a hook chain (per `[data_governance]`
declarations), every hook in the chain runs through the dispatcher
at `packs/hooks/dispatcher.py`. The dispatcher reports a closed-enum
`HookFailureMode` per failed hook; the calling pack's invocation
is **refused** by default if any hook fails. Wave-1 accepts only
`fail_policy = "fail_closed"` on every `[hooks].declarations[]`
entry; the build-time validator (`cli/validators/hooks.py`) refuses
every `fail_open` declaration with closed-enum
`hook_fail_policy_invalid` (failure_mode
`fail_open_without_exception`).

The runtime registry's `HookDeclaration.fail_open_exception` field
+ the dispatcher's `fail_open` carve-out path are wired but
unreachable in Wave-1 because the build-time validator refuses any
hook pack that would populate them. The runtime field is a single
**exception class name** the dispatcher matches against the raised
exception's class via a class-name walk through the MRO (see
`packs/hooks/dispatcher.py` §"Failure-mode routing" for the
walk-then-pass-on-match rule); the matching build-time manifest
shape that would populate it is reserved for a follow-up sprint.
Until that lands, every hook failure routes to a fail-closed
refusal regardless of the dispatcher's runtime carve-out code path.

---

## The 5 closed-enum dispatcher failure modes

The `HookFailureMode` literal at `packs/hooks/dispatcher.py:102` is
the wire-format taxonomy. Every per-hook outcome the audit chain
records carries exactly one of these values.

### 1. `hook_timeout`

**What happened.** `Hook._invoke()` exceeded its declared
`timeout_seconds` ceiling (per the `[hooks].declarations[].timeout_seconds`
field; manifest validator caps this at `Settings.hook_max_timeout_s`,
default 30.0). The dispatcher's `asyncio.wait_for` raised
`TimeoutError`; the dispatcher caught it and emitted the
`hook_timeout` audit row.

**On-call response.**

1. Pull the audit row by `failed_hook_id` from the event-stream
   (`tool_call.hook_failed` or its phase-specific variant). The row
   carries the calling pack's `pack_id` + the failing hook pack's
   distribution name.
2. Check the failing hook's recent timeout-rate against the kill-switch
   dashboard. A sudden timeout-rate spike for a single hook_id
   typically signals either (a) an upstream dependency outage on the
   hook's side (e.g., the hook calls a regulator API that is
   degraded), or (b) a payload-shape regression that pushes the
   regex / parser past the timeout ceiling.
3. **Mitigation if pack code is the regression.** Activate the
   per-pack kill-switch on the failing hook pack via the emergency
   API (`KillSwitchPack`). Propagation P99 ≤ 30s. Inflight invocations
   already past admission continue; new invocations route around the
   killed hook pack.
4. **Mitigation if the regression is in the calling pack.** Review the
   pack's `[data_governance].dlp_pre_hooks` / `dlp_post_hooks` list
   — a misordered declaration can push more payload than expected
   through a single hook. The dispatcher's per-pack budget gate
   (`hook_payload_unscannable`) catches gross overflow but a
   subtle change might land below the budget yet above the timeout.
5. **Postmortem.** Open an RCA per ADR-006 §"Critical-controls
   failure". Hook timeouts are critical-controls events; ISO 42001
   evidence-pack export must capture the audit chain.

**Do NOT.** Increase `timeout_seconds` past the
`Settings.hook_max_timeout_s` ceiling without an ADR amendment +
human gate-keeper sign-off — the ceiling is a deterministic
fail-closed posture.

### 2. `hook_exception`

**What happened.** The hook's `_invoke()` raised an exception that
is NOT in the `HookError` hierarchy (i.e., NOT
`HookContractError` / `HookContextError` / `HookPayloadError` /
`HookResultShapeError`). The dispatcher caught it at the single
try/except boundary and routed it to `hook_exception`.

**On-call response.**

1. Pull the audit row's `exception_type` field. Common patterns:
   `httpx.ConnectError` (the hook's outbound call failed), `KeyError`
   (the hook's input parser hit an unexpected payload shape),
   `RuntimeError` (catch-all from poorly-typed pack code).
2. **If the exception_type is a network-layer error** (httpx /
   asyncio / TimeoutError-not-asyncio): the hook depends on an
   external service. Confirm the external service status + activate
   the per-pack kill-switch if the regression is on the external
   side (the hook will refuse-by-default until the dependency
   returns).
3. **If the exception_type is a parser / shape error**: payload
   regression on the calling pack's side OR pack-author bug in the
   hook's parser. Cross-correlate the audit row's `failed_hook_id`
   with recent pack deployments — a calling pack that deployed
   recently is the more likely regressor.
4. **Postmortem.** The hook pack's author owns the bug; route via
   the bank-pack lifecycle issue tracker (`hook_pack_quarantined`
   audit emission).

**Do NOT.** Patch around `hook_exception` audit rows by setting
`fail_policy = "fail_open"` — Wave-1 refuses every `fail_open`
declaration at the build-time validator (`cli/validators/hooks.py`).
The exception-declaration shape that would carve out a per-pack
`fail_open` path is reserved for a follow-up sprint; until then,
every `fail_open` attempt is fail-closed at the validator boundary.
A regression that needs `fail_open` semantics today is an ADR-017
escalation, not a config patch.

### 3. `hook_malformed_result`

**What happened.** `Hook._invoke()` returned a value that violates
the `HookResult` decision-↔-fields invariant. The SDK's
`_validate_hook_result()` (see SDK-REFERENCE.md §8.5) raises
`HookResultShapeError`; the dispatcher catches it and routes to
`hook_malformed_result`.

Sub-cases (carried via `HookResultShapeError` message + audit-row
`exception_message`):

- `_invoke` returned a non-`HookResult` (e.g., a dict, None, a
  wrong dataclass).
- `decision="pass"` or `"refuse"` with `redacted_payload` not None.
- `decision="redact"` or `"mask"` with `redacted_payload` None or
  non-bytes.
- `decision="refuse"` with `policy_reason` None / empty / whitespace.
- `decision` in {`pass`, `redact`, `mask`} with `policy_reason` not
  None.

**On-call response.**

1. This is **always** a pack-author bug in the failing hook pack.
   The SDK's contract validation catches it before the dispatcher
   trusts the result.
2. Pull the audit row's `exception_message` to identify the exact
   sub-case. Cross-reference with the hook pack's last release
   notes; recent pack version = recent regression.
3. **Quarantine the hook pack** if the malformed-result rate is
   non-trivial (>0.1% of invocations over 5 minutes) via the
   per-pack kill-switch. The dispatcher's fail-closed default keeps
   the calling invocation refused; quarantine prevents further
   audit-row spam + lets pack-author ship a fix.
4. **Postmortem.** Route to the failing hook pack's author with the
   `HookResultShapeError` message + the sub-case identifier.

**Do NOT.** Try to "patch" malformed results by editing the audit
chain — the chain is hash-chain-canonical (see ADR-006); any edit
breaks `core/canonical.py` evidence-pack export. The right answer
is the pack-author fix.

### 4. `hook_policy_refused`

**What happened.** The hook returned `HookResult(decision="refuse",
policy_reason=...)`. This is a **legitimate policy refusal** — the
hook intentionally rejected the calling invocation per its
declared policy (e.g., a PAN was detected and the calling pack does
not declare a redaction allowance).

**On-call response.**

1. Pull the audit row's `policy_reason` value. The policy_reason is
   a closed-enum from the calling pack's policy vocabulary; pair it
   with the calling pack's `[data_governance]` declaration to
   understand the refusal context.
2. **This is NOT an alert.** A `hook_policy_refused` audit row is
   the success case for governance — the dispatcher caught a
   policy violation and refused the invocation. The audit chain
   carries the evidence; the calling pack's user surface returns the
   refusal envelope.
3. **If the rate is anomalously high.** A sudden spike of
   `hook_policy_refused` for a single calling pack typically signals
   a regression in that pack's input validation upstream (e.g., the
   pack started accepting customer input it previously sanitised).
   Investigate the calling pack's recent deployments + audit-row
   correlation; the regression is upstream of the hook.

**Do NOT.** Treat `hook_policy_refused` as a hook-pack bug — the
hook did its job. The audit row is the evidence of the governance
working as designed.

### 5. `hook_payload_unscannable`

**What happened.** The payload exceeded the per-pack scannable
budget BEFORE the hook ran. The dispatcher's budget check fires at
dispatch entry (BEFORE registry lookup, per the T8 R1 P2-2
delegate-first precedence fix); a payload above the budget is
refused without invoking any hook. The dispatcher emits
`hook_payload_unscannable` for every hook in the would-have-been
chain.

**On-call response.**

1. Pull the audit row's `payload_size_bytes` field. Cross-reference
   with the calling pack's `[data_governance]` declaration —
   payload-size budgets are tier-derived; the closed-enum
   `[risk_tier].tier` + the data-class set determines the ceiling.
2. **If the calling pack is sending oversized payloads.** Pack-
   author bug: the pack accepted an input it should have refused
   upstream. The hook chain refusal protects governance enforcement
   from being silently bypassed by oversized inputs.
3. **If the budget itself is regressing.** Wave-1 budgets are
   pinned to `Settings.hook_payload_max_bytes` (default ceiling
   small enough that DLP scanning runs in deterministic time). Any
   change to the budget is a critical-controls change requiring an
   ADR amendment + human sign-off; treat unexpected budget regression
   as a config drift incident.
4. **Mitigation.** Activate the calling pack's kill-switch if the
   oversized-payload rate is >1% over 5 minutes. The pack-author
   fix is to add upstream input-size validation.

**Do NOT.** Increase `hook_payload_max_bytes` at the runtime config
layer to "let the hook scan" — the budget ceiling is a
deterministic fail-closed posture; raising it changes the
governance-enforcement timing model.

---

## Audit-trail contract

Every dispatcher invocation emits one audit row per hook in the
chain (regardless of outcome). The row carries:

- `pack_id` — calling pack's `[pack].pack_id`.
- `failed_hook_id` — the hook_id that produced the failure outcome
  (None for `outcome="passed"`).
- `failed_pack_distribution_name` — the failing hook pack's
  distribution name (None for `outcome="passed"`).
- `outcome` — closed-enum: `passed` / `refused` (legitimate policy
  refusal) / `failed` (timeout / exception / malformed result /
  unscannable budget).
- `failure_mode` — closed-enum `HookFailureMode` (one of the 5
  values above; None for `outcome="passed"`).
- `policy_input_digest` — SHA-256 hex digest of the **original**
  payload (NEVER the transformed payload). Computed once at dispatch
  entry; propagated to every audit row + the dispatch result envelope.

Audit rows are hash-chain-canonical per ADR-006; the
evidence-pack export at `core/canonical.py` re-verifies the chain
on every regulator export. **Do not edit audit rows out-of-band**;
treat any "unexpected" row as evidence-of-governance, not as
something to clean up.

---

## Cross-references

- **ADR-017** — data-governance contracts (§"DLP hook failure
  policy" amendment Sprint-7A2 lists this runbook as the operator
  surface).
- **ADR-018** — emergency controls (kill-switch propagation P99 ≤ 30s).
- **ADR-006** — ISO 42001 evidence-pack format (audit-row hash
  chain).
- **`packs/hooks/dispatcher.py`** — closed-enum
  `HookFailureMode` literal + the dispatcher state machine.
- **`packs/hooks/dlp_integration.py`** — DLPGuard adapter; closed-
  enum 3-value `DLPRefusalReason` for the integration boundary
  (`dlp_hook_id_unresolved` / `dlp_dispatcher_failed` /
  `dlp_dispatcher_refused`).
- **`docs/HOW-TO-WRITE-A-PACK.md` §8** — pack-author counterpart
  (manifest shape + `Hook` subclass + scaffolding).
- **`docs/PACK-MANIFEST-SPEC.md` §8** — `[hooks]` block schema.
- **`docs/SDK-REFERENCE.md` §8** — `Hook` API reference.
