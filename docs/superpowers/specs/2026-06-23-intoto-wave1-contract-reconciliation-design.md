# in-toto Wave-1 Layout Contract Reconciliation — Design Spec

**Date:** 2026-06-23
**Status:** Design — approved (option (b), 2026-06-23)
**Slice type:** Tight critical-controls fix (ADR-016 supply-chain trust gate). Two CC modules, author↔runtime wire-adjacent.
**Surfaced by:** Proof 1a Task 7 (the in-process full-loop harness) — the first exercise of the **real** `agentos sign` in-toto output against the **real** runtime registration trust gate. Every real signed pack is refused at registration with `intoto_tampered`.

---

## 1. Problem — the author↔runtime in-toto contract disagrees

Both halves are labelled "Wave-1" and contradict each other:

- **Author** — `cli/sign.py:_build_intoto_layout_dict` (`:1665`) emits a **Wave-1 simplified** in-toto layout that declares `_type = "in-toto-layout/v1-wave1-simplified"` and **deliberately omits `steps` and `expires`** (it lists `step-graph` + `expiration-date` under `out_of_scope`). Its docstring: *"captures enough metadata for the runtime trust gate's manifest-shape check at admission time."*
- **Runtime** — `protocol/supply_chain.py:_verify_intoto` (`:604`) **hard-requires** `steps` (non-empty list; every entry a dict with a non-blank `name`) **and** `expires` (non-blank string) → raises `IntotoTampered("missing or empty 'steps'")`.

The in-toto layout is *optional* at the resolver (`pack_attestation_resolver._INTOTO_LAYOUT_BASENAME`), but `agentos sign` **always** writes it, so for any real signed pack it is present → hard-verified → refused. The startup-discovery unit tests (PR #92) passed only because they used **hand-built** attestations carrying a full `steps`+`expires` layout the real signer never emits — exactly the authoring↔runtime seam that had never run end-to-end.

This is **not** an honest tamper signal: the runtime is rejecting a *correctly-formed* Wave-1 simplified layout because it expects a *full* in-toto layout the author intentionally does not produce in Wave-1.

## 2. Decision — option (b): the runtime verifies the declared Wave-1 simplified contract

The signer already declares `_type = in-toto-layout/v1-wave1-simplified`. The runtime should **verify that declared contract** (structurally validate the fields the Wave-1 simplified layout actually carries) instead of pretending it is a full in-toto layout with `steps`/`expires`.

**Rejected:**
- **(a)** make the author emit synthetic `steps`/`expires` — ceremonial security theatre (a fake step-graph to satisfy a shape check), and re-introduces the complexity Wave-1 deferred.
- **(c)** stop hard-verifying the optional layout at admission — removes a useful present-structural tamper-binding surface entirely.

## 3. The fix (option (b)) — minimal, structural, preserves existing behaviour

### 3.1 Single-source the contract type constant
The runtime is the party that *accepts* the contract, so it owns the constant. Add to `protocol/supply_chain.py` (public, in `__all__`):
```python
AGENTOS_INTOTO_LAYOUT_TYPE: Final[str] = "in-toto-layout/v1-wave1-simplified"
```
`cli/sign.py` imports it and **deletes its private `_AGENTOS_INTOTO_LAYOUT_TYPE`** (the author emits exactly what the runtime declares it accepts — one source of truth, no drift). The architectural direction `cli → protocol` is already established (`cli/verify.py` consumes `protocol/trust_gate`).

### 3.2 `_verify_intoto` branches on the declared `_type`
After the existing predicateType handling resolves `layout` (the bare layout, or the Statement `predicate`), insert the simplified-contract branch **before** the `steps`/`expires` checks:

- **If `layout.get("_type") == AGENTOS_INTOTO_LAYOUT_TYPE`** → validate the **Wave-1 simplified shape** structurally and return:
  - `pack_id` — non-blank string.
  - `pack_version` — non-blank string.
  - `pack_kind` — non-blank string **and** a member of the canonical kind set `{"tool","skill","agent","hook"}` (a small local tuple in `supply_chain.py`; do **not** import `packs.lifecycle` — keep the layering arrow clean; a drift-pin test asserts the tuple equals `typing.get_args(PackKind)`).
  - `signing_identity` — non-blank string.
  - `artifact_paths` — non-empty list, **every** entry a non-blank string.
  - Any missing / wrong-type / blank / empty → `IntotoTampered` (the same hard-refusal class; one clear message per field).
- **Else (no simplified `_type`)** → the **existing** `steps`+`expires` validation, **unchanged**.

Same structural-only posture as `_verify_slsa` (which checks `buildType` / `builder.id` non-blank, no manifest comparison). Cross-layer pack_kind-flip comparison against the manifest is **out of scope** — neither `_verify_slsa` nor `_verify_intoto` does it today (the kind is bound into the attestation but not compared at this layer), so this slice does not regress it; it is a separate, larger trust-model concern.

### 3.3 What this does NOT change
- The `steps`+`expires` branch (non-simplified layouts) — byte-for-byte preserved (the hand-built-attestation admission tests + `test_supply_chain.py` in-toto cases stay green).
- The predicateType bare-vs-Statement handling.
- The optional-ness of the layout at the resolver, and the `verify()` orchestrator's grace-period semantics (present-but-malformed = hard refuse; absent = partial).
- `cli/sign.py`'s emitted layout shape (the author already emits the correct simplified contract — only its constant *moves*).

## 4. Test pins (the proof of the fix)

- **Cross-contract round-trip (REQUIRED, no hand-built fixture):** call the real `cli/sign.py:_build_intoto_layout_dict(pack_id=…, pack_version=…, pack_kind="tool", signing_identity=…, artifact_paths=[…])`, write its JSON to a temp file, pass that file to `protocol/supply_chain.py:_verify_intoto(path)` → it returns (no raise). This is the contract pin — the author's real output is accepted by the runtime.
- **Tamper negatives (on the simplified layout):** starting from the real `_build_intoto_layout_dict` output, mutate one field each and assert `IntotoTampered`:
  - `pack_kind` → a non-kind value (e.g. `"malware"`) and `pack_kind` → `""`.
  - `signing_identity` → missing, and → `"  "` (blank).
  - `artifact_paths` → `[]` (empty), and → `["ok", ""]` (a blank entry), and → not-a-list.
  - `pack_id` / `pack_version` → blank/missing.
- **Preserve (regression):** the existing `_verify_intoto` steps+expires tests still pass (a full layout with `steps`+`expires` and no simplified `_type` validates via the unchanged branch); a full layout that is malformed still raises.
- **Drift pin:** the local kind tuple in `supply_chain.py` equals `set(typing.get_args(packs.lifecycle.PackKind))` (test-only import; no runtime cross-module dependency).
- **Constant single-source pin:** `cli.sign` references `supply_chain.AGENTOS_INTOTO_LAYOUT_TYPE` (no private duplicate remains); a test asserts the imported value is `"in-toto-layout/v1-wave1-simplified"`.

## 5. Gates

- Targeted: `tests/unit/protocol/test_supply_chain.py` + `tests/unit/cli/test_cli_sign.py` + the new cross-contract test module.
- Full suite + `tools/check_critical_coverage.py` (both `cli/sign.py` + `protocol/supply_chain.py` are on the durable CC gate — coverage must stay at/above floor on fresh `--cov-branch coverage.json`).
- `ruff check` + `ruff format --check` + `uv run mypy src tests`.
- **Then resume Proof 1a Task 7:** rerun `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py` → the harness (currently honestly RED at assertion 2) turns **green**; commit Task 7 **only after** this CC fix is committed.

## 6. ADR-016 amendment

A focused amendment recording: the Wave-1 simplified in-toto layout contract (`_type = in-toto-layout/v1-wave1-simplified`), that the runtime trust gate verifies the simplified shape's security fields (`pack_id`/`pack_version`/`pack_kind`/`signing_identity`/`artifact_paths`) rather than a full `steps`/`expires` layout in Wave-1, and that the full in-toto layout (steps/inspections/key-thresholds) remains the Wave-2 cleanup. The constant is single-sourced in `protocol/supply_chain.py`.

## 7. Housekeeping (separate, trivial)

`examples/cognic-tool-search/attestations/` is generated by the real `agentos sign` in `_authoring.build_sign_verify` and is left untracked + not gitignored (its sibling `dist/` already is). Add `examples/cognic-tool-search/attestations/` to `.gitignore` — a tiny separate line in this slice (so generated attestations can never get near a commit). Not bundled into a CC code commit.

## 8. Scope / honesty boundary

In scope: the `_verify_intoto` simplified-contract branch + the single-sourced constant + the test pins + the ADR-016 amendment + the `.gitignore` line. **Out of scope:** any change to the author's emitted shape; cross-layer manifest pack_kind-flip comparison; the full Wave-2 in-toto layout; cryptographic in-toto signature verification (already deferred per the existing docstring). The fix makes the runtime honestly accept the contract the author honestly declares — nothing more.
