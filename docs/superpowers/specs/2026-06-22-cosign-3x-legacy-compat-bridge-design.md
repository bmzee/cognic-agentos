# cosign 3.x Legacy-Compat Bridge — Design Spec

**Date:** 2026-06-22
**Status:** Design — Fork A (legacy-compat bridge) approved with the `--tlog-upload=false` correction (2026-06-22)
**Type:** Critical-controls supply-chain slice (`core-controls-engineer` + `/critical-module-mode`)
**Relates to:** ADR-016 (supply-chain controls); ADR-002 (plugin trust gate). Surfaced by Proof 1a Task 6.
**Branch:** off `main` (separate, because it touches ADR-016 supply-chain trust contracts).

---

## 1. Problem (verified)

The kernel's pack/CLI signing path is hard-wired to **cosign 2.x's detached-signature contract** and breaks on **cosign 3.x** (verified against installed `cosign v3.0.6`):

- `cli/sign.py` (`_exec_cosign_sign_blob`, `:583-597`) runs `cosign sign-blob --output-signature <cosign.sig> --bundle <bundle.sigstore> <wheel>` relying on cosign's **default** mode.
- cosign 3.x defaults to `--new-bundle-format=true`, **deprecates + ignores `--output-signature`**, and writes only the bundle — so `cosign.sig` is never produced.
- `cli/sign.py`'s post-exec check then correctly refuses with `sign_subprocess_failed` / `payload.failure_mode=cosign_sig_output_missing` (`:1930,1948`). **The pack cannot be signed.**
- The verify side also needs additive flags (not a contract change): with the legacy sign flags the artifact IS detached-signed again, but (a) `trust_gate.py` (`:558-566`) passes `--signature` **only** (no `--bundle`), which the 3.x verify path needs, and (b) neither verify site (`cli/verify.py` `:783-793`, `trust_gate.py`) passes `--insecure-ignore-tlog` — so against an **offline-signed** artifact (no Rekor tlog entry, because sign now uses `--tlog-upload=false`) the verify searches the public transparency log and fails to find an entry. The fix is the offline + bundle flags below, verified on cosign 3.0.6; this spec does NOT claim detached-signature verification is inherently invalid on 3.x.

**The codebase already contains a PARTIAL fix pattern.** `compliance/iso42001/signing.py` (`:150-158`) signs with the legacy-output compat flags (`--use-signing-config=false --new-bundle-format=false`), so it still produces `cosign.sig` on cosign 3.x — but it **lacks `--tlog-upload=false`**, so it is NOT offline: it uploads evidence-pack signatures to public Rekor and would fail in an air-gapped deployment. So `signing.py` is a *legacy-output* precedent, not an *offline* one — the pack path needs one more flag than `signing.py` has, and `signing.py` itself carries the same offline gap (folded in narrowly — §4.6). This is a *missing-flags* bug, not a wrong design.

## 2. Decision: Fork A (legacy-compat bridge), not Fork B (bundle-only modernization)

**Fork A** — make the pack/CLI path keep emitting + verifying the legacy `cosign.sig` + `bundle.sigstore` pair on cosign 3.x via the proven compat flags. **No attestation-contract change.** Smallest blast radius, lowest wire-protocol risk, air-gapped-correct, converges the CLI/pack path onto the repo's own working `signing.py` precedent.

**Fork B** (deferred) — true bundle-only: drop `cosign.sig`, verify against `--bundle` only, converge on `models/trust.py`. Future-proof but touches ~14 wire-public sites (the `SignatureRedReason` ADR-012 §110 gate vocab, `PackAttestations`, the resolver required-set, ADR-016 filenames, all 5 manifest templates) **and** must separately solve the air-gapped-sign story. Out of scope here; tracked as the long-term cleanup for when cosign removes the deprecated flags entirely.

**Why Fork A now:** the break is "missing flags," and Fork A fixes it with five argv-site changes + one method-signature/caller adjustment, no contract churn — exactly the conservative shape a critical-controls slice wants. Fork B's value (riding the non-deprecated bundle format) does not justify a 14-site wire change plus an unsolved Rekor-offline problem to fix *this* break.

## 3. The verified flag set (cosign 3.0.6)

**Sign** (`cli/sign.py`):
```
cosign sign-blob --yes \
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false \
  --key <priv> --output-signature <cosign.sig> --bundle <bundle.sigstore> <wheel>
```
→ writes BOTH `cosign.sig` (non-empty) + `bundle.sigstore`; the bundle carries **no `tlogEntries`** (offline / no public-Rekor upload). Verified.

**Verify** (`cli/verify.py`, `trust_gate.py`):
```
cosign verify-blob --key <pub> \
  --signature <cosign.sig> --bundle <bundle.sigstore> \
  --insecure-ignore-tlog --new-bundle-format=false <wheel>
```
→ `Verified OK`. Verified.

**Correctness notes (load-bearing):**
- **`--tlog-upload=false` is what disables the public-Rekor upload** — NOT `--use-signing-config=false`. Without `--tlog-upload=false`, cosign 3.x still uploads to public Rekor. (`--use-signing-config=false` removes the conflict that `--tlog-upload=false` otherwise has with the `--use-signing-config=true` default.)
- `--insecure-ignore-tlog` on verify is REQUIRED: since sign no longer uploads a tlog entry, a verify that searches Rekor would fail.
- `--new-bundle-format=false` is explicit legacy-bundle posture on both sign + verify (optional in the local probe, included for explicitness + to pin the legacy format).
- `--tlog-upload` and `--output-signature` are **deprecated-but-functional** on 3.0.6 (both emit deprecation warnings). This is the bridge's known debt — see §8.

## 4. Module changes (pack + model + evidence-pack signing — 5 argv sites + 1 caller)

All touched modules are critical-controls / supply-chain — `cli/sign.py`, `cli/verify.py`, `protocol/trust_gate.py`, `protocol/plugin_registry.py`, `models/trust.py`, `compliance/iso42001/signing.py` → `core-controls-engineer` + `/critical-module-mode`, 95% line / 90% branch, negative-path tests required.

**4.1 `cli/sign.py`** — `_exec_cosign_sign_blob` (`:583-597`): add `--tlog-upload=false --use-signing-config=false --new-bundle-format=false` to the sign-blob argv. The post-exec checks (`cosign_sig_output_missing/_empty`, `cosign_bundle_output_missing/_empty`) are UNCHANGED and now pass (both files produced). The `{**os.environ, "COSIGN_PASSWORD": ""}` env is unchanged.

**4.2 `cli/verify.py`** — `_exec_cosign_verify_blob` (`:783-793`): the argv already passes `--key --signature <sig> --bundle <bundle>`; add `--insecure-ignore-tlog --new-bundle-format=false`. The Step-3 required-file table + Step-5/Step-8 artifact reads are UNCHANGED (both files still exist).

**4.3 `protocol/trust_gate.py`** — `verify_pack_signature` (`:472-566`): the only non-trivial change. It currently passes `--key --signature <sig> <blob>` with **no `--bundle`**. Change:
- Add a `bundle_path: Path` parameter to `verify_pack_signature(...)` (after `signature_path`).
- Add `--bundle <bundle_path>` + `--insecure-ignore-tlog --new-bundle-format=false` to the argv.
- The `signature_digest = _hash_file(sig_canonical)` (`:636`) is UNCHANGED — it stays the SHA-256 of `cosign.sig` (the wire-public audit identity is preserved). The bundle is verified-against but the digest contract does not move.
- The `require_cosign=False` synthetic-skip path (`:519-532`, `"cosign-skipped:require_cosign=false"`) is UNCHANGED (version-agnostic).

**4.4 `protocol/plugin_registry.py`** — the single `verify_pack_signature(...)` caller (`:1141-1142`): pass `bundle_path=artefacts.sigstore_bundle_path` (already resolved on `PackAttestations`). No other registry change.

**4.5 `models/trust.py`** (the narrow model-path fold-in, per §6) — `verify_model_signature` (`:86-94`): add **ONLY** `--insecure-ignore-tlog` to the existing bundle-only argv. Do NOT add `--signature` (the model path has no detached sig and stays bundle-only). Do NOT add `--new-bundle-format=false` unless a real test proves model bundles need it. This closes the model-path offline gap without changing its bundle-only posture.

**4.6 `compliance/iso42001/signing.py`** (the evidence-pack signing path, folded in for offline-correctness) — the sign-blob argv (`:150-158`) already has `--use-signing-config=false --new-bundle-format=false --output-signature --bundle` but **lacks `--tlog-upload=false`**, so it uploads evidence-pack signatures to public Rekor and would fail air-gapped. Add **ONLY** `--tlog-upload=false`. **Sign-only** — there is NO cosign *verify* of evidence-pack signatures in the kernel (the signature travels in the exported evidence-pack tarball for external/examiner verification), so there is no verify counterpart to change. No contract change (it still emits `cosign.sig` + bundle + raises `EvidencePackSigningError` fail-loud).

## 5. What does NOT change (the Fork-A invariant)

Explicitly preserved — zero wire-protocol / contract churn:
- The attestation filenames `cosign.sig` + `bundle.sigstore` (ADR-016 §23/§28).
- `protocol/pack_attestation_resolver.py` required-set (`cosign.sig` stays required+non-empty).
- `protocol/plugin_registry.py` `PackAttestations.cosign_signature_path` field (non-Optional, unchanged).
- `trust_gate.py` `CosignVerificationResult.signature_digest` semantics (SHA-256 of `cosign.sig`).
- The wire-public `SignatureRedReason` 5-gate vocabulary (`packs/approval_gates.py`, ADR-012 §110) + `packs/_signature_path_resolver.py`.
- The `AttestationKind` evidence-panel vocab (`packs/evidence/supply_chain.py`).
- All 5 pack-manifest templates' `attestation_paths` (`attestations/cosign.sig`, …).
- The evidence-pack signature *contract* (`compliance/iso42001/signing.py` still emits `cosign.sig` + bundle into the exported tarball) — only the offline `--tlog-upload=false` flag is added per §4.6; no output/contract change. (This module is NOT "left as-is" — it gains one flag.)

## 6. Model-path offline fix — folded in, NARROWLY

`models/trust.py::verify_model_signature` (`:86-94`) is **bundle-only** (`--key --bundle`, no `--signature`) — the same offline gap, one module over: it omits `--insecure-ignore-tlog`, so a model signed offline (no Rekor) would fail verification. Its proof (`test_real_cosign_proof.py`) passes only because the fixture signs WITH a public-Rekor upload. In an air-gapped bank deployment, an offline-signed model would fail `verify_model_signature`.

**Decision (locked): fold the model-path fix into this slice, but NARROWLY — add ONLY `--insecure-ignore-tlog`.** Keep the model path bundle-only:
- Do **NOT** add `--signature` — the model path has no detached sig; it stays bundle-only (closer to the future Fork-B shape).
- Do **NOT** add `--new-bundle-format=false` unless a real test proves model bundles need it — the model path uses the default/new bundle format; the legacy `--new-bundle-format=false` is a pack-contract concern only.

Rationale: the pack path preserves the legacy `cosign.sig + bundle.sigstore` ADR-016 contract; the model path is already bundle-only and must NOT inherit the pack's legacy shape. The model bug is purely offline-Rekor behaviour, not detached-signature compatibility — so the model fix is exactly one flag. The same critical-controls review is already engaged, so folding it in keeps the whole trust path offline-correct in one slice.

## 7. Tests

- **Env-gated real-cosign proof for the CLI/pack path** (new), mirroring `tests/integration/models/test_real_cosign_proof.py`, gated on the existing `COGNIC_RUN_COSIGN_INTEGRATION=1`: real `agentos sign` → real `agentos verify` → the runtime `trust_gate.verify_pack_signature` round-trip, all green on cosign 3.x, **and an offline assertion** (the produced bundle carries no `tlogEntries`). This is also what unblocks Proof 1a Task 6.
- **Negative-path unit tests** (no cosign needed) per critical-controls: the pack-path argv builders emit the exact flag set (drift-pin the flags); `trust_gate` fails closed when `bundle_path` is missing/empty; the `require_cosign=False` skip path unchanged.
- **Model-path argv unit test** (no cosign needed): assert `verify_model_signature` passes `--insecure-ignore-tlog`, AND assert it stays **bundle-only** — `--signature` is NOT in the argv, and `--new-bundle-format=false` is NOT present (the narrow §6 fix). Only claim a real offline-model proof if this slice actually creates one; if the env-gated proof does not add an offline model round-trip, do not claim it.
- **Evidence-pack signing argv unit test** (no cosign needed): assert `signing.py`'s sign-blob argv now includes `--tlog-upload=false` (drift-pin); the `cosign.sig` + bundle outputs + the `EvidencePackSigningError` fail-loud behaviour are unchanged. (No offline evidence-pack round-trip is claimed unless the slice creates one.)
- **Keep `test_real_cosign_proof.py` green** — the model path gains only `--insecure-ignore-tlog`; confirm the test stays green (the bundle still verifies; the tlog is now ignored rather than required). Add an offline model assertion only if the slice creates a genuinely offline-signed model fixture.

## 8. ADR-016 amendment

A focused amendment recording: (a) the cosign-3.x compat-flag requirement on the sign + verify argv; (b) the offline/no-Rekor posture via `--tlog-upload=false` + `--insecure-ignore-tlog`; (c) the explicit caveat that this is a **legacy-compat bridge riding cosign's deprecated `--tlog-upload` + `--output-signature` flags**, with **Fork B (bundle-only) as the tracked long-term cleanup** for when cosign removes them. No filename/contract change.

## 9. Caveats / out of scope

- **The pack/CLI path is a legacy-compat bridge, not the bundle-only modernization.** It intentionally relies on deprecated cosign 3.x flags (`--tlog-upload`, `--output-signature`) that work on 3.0.6 but are on cosign's removal path. When they're removed, Fork B becomes mandatory for the pack path. (The narrow model-path fix — `--insecure-ignore-tlog` — is a *current*, non-deprecated flag; it does not carry this debt.)
- **Out of scope:** Fork B (true bundle-only); the cosign `--signing-config`-file approach to offline signing (the "blessed" 3.x path, heavier); any change to the attestation contract / filenames / wire vocab.

## 10. Reproduction reference (Proof 1a Task 6)

The break was surfaced by the Proof 1a Task 6 authoring-provision harness (stashed as `pack-loop-proof-task6-cosign3-repro`). After this bridge lands, that harness reruns green on cosign 3.x and Proof 1a resumes at Task 6.
