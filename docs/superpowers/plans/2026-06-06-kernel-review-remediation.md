# Kernel Review Remediation — Checklist (2026-06-06)

**Source:** `docs/reviews/2026-06-06-multiagent-code-review.md` (17-agent fan-out + Opus-skeptic verification of every high/critical).
**Branch:** `fix/kernel-review-remediation` (from `main` @ `9be577b`).
**Mode:** direct TDD per fix — defects are concrete, file-scoped, review-verified; no design spec. **Halt-before-commit on EVERY fix**; **full suite** on CC/shared-surface commits; **explicit-path staging**; keep `docs/reviews/2026-06-06-multiagent-code-review.md` + `docs/superpowers/specs/2026-05-26-…gap-analysis.md` untracked. Each fix is its own commit. `/critical-module-mode` + `core-controls-engineer` (all five touch CC stop-rule modules).

## Fixes (in order)

- [x] **1. MCP SSRF** — high §4.1 — `protocol/mcp_authz.py:413` (`discover_resource_metadata`) + `:960` (`_fetch_prm`'s `WWW-Authenticate` URL) + harden `protocol/mcp_capabilities.py:452` shape gate. **Guard:** require scheme ∈ {http,https}; reject empty/non-netloc; in the strict/prod profile resolve the host and refuse private/loopback/link-local/reserved ranges (RFC1918, 127/8, 169.254/16, ::1, fc00::/7). Mirror the existing `protocol/a2a_agent_cards.py:479` origin guard. Add negative SSRF tests (`tests/unit/protocol/test_mcp_authz.py` has **zero** scheme/SSRF coverage today). The one genuine exploitable high — fix first. CC stop-rule.
- [ ] **2. `sampling.rego` v0 syntax** — med / shipped-broken §5 (core-approval-policy-emergency) — `policies/_default/sampling.rego:38`. Port to OPA-1.x (`default allow := false` + `allow if {`). Add the missing **real-OPA parity test** (env-gated skip-if-absent): all-four-true → allow; each single-false → deny. Wire-protocol-public stop-rule (refusal-vocab/decision-point contract).
- [ ] **3. Scheduler tenant-blind counters** — high §4.2 — `core/scheduler/engine.py:248-249` (reads `:488-489`, decrement `:1000-1003`). Key `_pack_counts`/`_actor_counts` as `dict[tuple[str,str],int]` with `(tenant_id, pack_id)` / `(tenant_id, actor_subject)` (the `_TaskAttribution.tenant_id` at `:109` already carries the tenant on the decrement path). Cross-tenant regression (`test_per_pack_cap_is_scoped_per_tenant` + `_per_actor_`). CC stop-rule.
- [ ] **4. Memory agent-kind erasure** — high §4.3 — `core/memory/storage.py:581` (guard `:600`). Add `subject_kind: Literal["human","agent"]` to `RegulatorErasureCommand` (`core/memory/_context.py`) + `ErasureCommandBody` (portal DTO); derive `expected_subject_ref = f"{subject_kind}:{subject_id}"`; thread `subject_kind` from the forget route (already on `ForgetRequest`). Agent-kind success-path + cross-kind-mismatch tests (`test_storage_erasure.py` covers only human today). CC stop-rule.
- [ ] **5. Pack override-audit invisibility** — high §4.4 — `packs/storage.py:1313` (`load_lifecycle_history` filter `event_type LIKE 'pack.lifecycle.%'`). Broaden to surface `pack.approval_override` (`:1090`) — either `LIKE 'pack.%'` / `event_type IN (...)`, or add `load_override_events(pack_id)` + `GET /{pack_id}/overrides`. CC-ADJ to on-gate `packs/storage.py`; standard halt-before-commit. (Per ADR-012 §107 the override row is the examiner's force-approve authorisation fact.)

## Out of scope (this sprint)
The 16 medium / 24 low / 8 info findings (timeouts on `sign`, tar `--strip-components`, `-> NoReturn`, WARNING→INFO lifecycle logs, the `packs/sdk → cli` arrow, etc.) — tracked in the review, swept separately. The 3 unbuilt AGENTS.md CC modules are a known tracked item.

## Done criteria
All 5 boxes checked, full suite + CC gate green → `superpowers:finishing-a-development-branch` (push + PR are **separate explicit tokens**; `--squash --delete-branch`; never `gh pr merge --auto`).
