# cosign 3.x Legacy-Compat Bridge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the kernel's cosign signing + verification paths work + stay offline on cosign 3.x by adding the verified legacy-compat flags, with zero attestation-contract change.

**Architecture:** Fork A (legacy-compat bridge) per the design spec — keep emitting + verifying the legacy `cosign.sig` + `bundle.sigstore` pair on cosign 3.x via the proven compat flags, instead of the bundle-only Fork B modernization. Five `cosign` argv sites gain offline/bundle flags (`cli/sign.py`, `cli/verify.py`, `protocol/trust_gate.py`, `models/trust.py`, `compliance/iso42001/signing.py`); `trust_gate.verify_pack_signature` additionally gains a required `bundle_path: Path` parameter that its production callers thread through. No filenames, no wire vocab, no `signature_digest` semantics move.

**Tech Stack:** Python 3.12, uv, pytest, cosign 3.x (legacy-compat flags), critical-controls (core-controls-engineer + /critical-module-mode, 95% line / 90% branch).

---

## Operating context (read before Task 1)

- **All eight touched modules are critical-controls / supply-chain.** Use `core-controls-engineer` + `/critical-module-mode`. Negative-path tests required; keep each module at/above the 95% line / 90% branch durable-gate floor. This slice modifies modules already on the gate AND **promotes `packs/_signature_path_resolver.py` to the durable per-file coverage gate** (it gains the approval-gate bundle projection per Task 3) — so the critical-controls count goes **134 → 135** (Task 3 adds it to `tools/check_critical_coverage.py::_CRITICAL_FILES` + bumps `_EXPECTED_ENTRY_COUNT`, with a fresh `coverage.json` in the same commit, per the repo's tightening-edit-B discipline).
- **Stop-rule modules (human-review-on-EVERY-edit per AGENTS.md):** `protocol/trust_gate.py` + `protocol/plugin_registry.py` (plugin trust gate / signature verification). The other six touched critical-controls modules — `cli/sign.py`, `cli/verify.py`, `portal/api/packs/review_routes.py` (already on the gate), `packs/_signature_path_resolver.py` (promoted to the gate here), `models/trust.py`, `compliance/iso42001/signing.py` — get `core-controls-engineer` + the coverage gate but are not the every-edit stop-rule set. The plan keeps each edit minimal + argv-shaped.
- **The byte-exact flag strings — use verbatim everywhere (drift-pin them):**
  - `--tlog-upload=false`
  - `--use-signing-config=false`
  - `--new-bundle-format=false`
  - `--insecure-ignore-tlog`
- **Verified flag placement (cosign 3.0.6, spec §3):**
  - **Sign** argv block (after `--yes`, before `--key`): `--tlog-upload=false --use-signing-config=false --new-bundle-format=false`.
  - **Verify** argv block (after `--bundle <bundle>`, before the positional `<blob>`): `--insecure-ignore-tlog --new-bundle-format=false`.
  - `--tlog-upload=false` is what disables the public-Rekor upload (NOT `--use-signing-config=false`); `--insecure-ignore-tlog` on verify is REQUIRED because sign no longer uploads a tlog entry.
- **The standing gate (run at the end of EVERY task, whole-project):**
  ```
  uv run pytest <touched test files for this task> -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: pytest `passed` (0 failed), ruff `All checks passed!`, ruff-format `… files already formatted`, mypy `Success: no issues found`.
- **Commit discipline:** Each task's final step is the **controller's** commit, executed only on the human's per-task token (full-word yes/go/commit). The step still shows the exact `git add <paths>` + the conventional message so the controller can run it verbatim. Never `git add -A`; never stage `docs/handoffs/`, `docs/reviews/`, or the 2026-05-26 gap-analysis spec (all untracked, out of scope). Every commit message ends with the `Co-Authored-By` trailer.
- **Branch:** `fix/cosign-3x-legacy-compat-bridge` (already checked out).

---

## Decision: `bundle_path` is REQUIRED, and BOTH production callers are updated atomically in Task 3 (option (a))

The spec types the new parameter as `bundle_path: Path` (non-Optional). The ORIGINAL spec draft named **one** caller (`plugin_registry.py:1141`); grounding against the real code during planning surfaced a **second production caller**: `portal/api/packs/review_routes.py:461` (the Sprint-7B.3 5-gate approval **signature gate**), which calls `verify_pack_signature(...)` with the same `--signature`-only / no-`--bundle` shape and the **identical latent cosign-3.x break**. The spec was then AMENDED (§4.4) to list **both** callers + the resolver-basename bundle derivation; this plan implements that amended spec.

Because the parameter is **required**, every production caller MUST pass it in the **same commit** as the signature change — otherwise production raises `TypeError` at runtime (the existing review-path tests mock `verify_pack_signature` with `AsyncMock`, so they would **not** catch the missing kwarg; the bug would be latent). A required param + all its callers therefore belong in **one atomic change** → **Task 3** covers `trust_gate.py` + `plugin_registry.py` + the extended `packs/_signature_path_resolver.py` (the approval-gate bundle-path projector) + `review_routes.py` + the 13 real `test_trust_gate.py` call sites + the test helper + the new resolver unit tests, together. No red commit; no follow-on.

- `plugin_registry.py:1141` → `bundle_path=artefacts.sigstore_bundle_path` (already resolved on `PackAttestations`, spec §4.4).
- `review_routes.py:461` → `bundle_path=resolution.bundle_path` — the bundle is now derived by the **extended `packs/_signature_path_resolver.py`**, which matches `bundle.sigstore` by **POSIX basename** against `[supply_chain].attestation_paths` (the manifest source of truth — custom-dir-safe, e.g. `custom/dir/bundle.sigstore`), mirroring exactly how `cosign.sig` is already resolved. **NOT a `cosign.sig` sibling:** a sibling-only derivation would silently reject a valid custom-dir manifest that the supply-chain evidence projector (`packs/evidence/supply_chain.py`) already recognises by the same basename match. The existing `.exists()` probe is extended to also require the resolved bundle; every bundle-path failure (absent / multiple-ambiguous / absolute / traversal) maps to the **existing** `signature_bundle_path_unreachable` red-reason. `SignaturePathResolution` GAINS a `bundle_path: Path | None` field (same nullable shape as `signature_path` / `blob_path`), but **NO new `SignatureRedReason` value** — the wire vocab in spec §5 stays frozen. **`packs/_signature_path_resolver.py` is now a touched critical-controls module** (the closed `SignatureRedReason` enum is unchanged; the resolver simply emits the already-existing `signature_bundle_path_unreachable` on every bundle-path failure).

Considered + rejected: an **optional** `bundle_path: Path | None = None` on `verify_pack_signature` to avoid touching `review_routes.py`. Rejected because (1) the spec types the method parameter non-Optional, (2) the prompt directs option (a), and (3) leaving the 5-gate signature gate without `--bundle` would leave it broken on cosign 3.x — the same bug this slice exists to fix. (The new `SignaturePathResolution.bundle_path` dataclass field IS nullable — `None` on every failure path, mirroring `signature_path` / `blob_path` — but the `verify_pack_signature` method parameter it feeds stays a required non-Optional `Path`.)

---

## Task 1: `cli/sign.py` — sign-blob legacy-compat flags (+3) + drift-pin test

**Files:**
- Modify: `src/cognic_agentos/cli/sign.py` (`_exec_cosign_sign_blob`, argv literal at `:583-597`). Post-exec checks `_verify_post_exec_artifacts` (`:1910-2012`, the `cosign_sig_output_missing/_empty` + `cosign_bundle_output_missing/_empty` reasons) stay UNCHANGED; the `cosign_env = {**os.environ, "COSIGN_PASSWORD": ""}` stays UNCHANGED.
- Test: `tests/unit/cli/test_cli_sign.py` (mirror `test_sign_blob_happy_path_invokes_cosign_with_correct_argv` at `:189-222`; the `_make_cosign_shim` / `_read_shim_recording` recording-JSON pattern at `:100-157`). No cosign binary needed.

- [ ] **Step 1: Write the failing drift-pin test.** Add `test_sign_blob_argv_carries_cosign3_legacy_compat_flags` next to the existing happy-path test. Reuse `_make_cosign_shim(tmp_path)`, `_set_cosign_settings(...)`, `_read_shim_recording(shim)`. Stage a wheel, run `CliRunner().invoke(app, ["sign-blob", str(wheel)])`, assert `result.exit_code == 0`, then assert against `recording["argv"]`:
  ```python
  argv = _read_shim_recording(shim)["argv"]
  assert "--tlog-upload=false" in argv
  assert "--use-signing-config=false" in argv
  assert "--new-bundle-format=false" in argv
  # The three compat flags ride the block between "--yes" and "--key".
  yes_idx, key_idx = argv.index("--yes"), argv.index("--key")
  for flag in ("--tlog-upload=false", "--use-signing-config=false", "--new-bundle-format=false"):
      assert yes_idx < argv.index(flag) < key_idx
  # Unchanged contract: the wheel is still signed + both outputs land.
  assert str(wheel) in argv
  assert (wheel.parent / "cosign.sig").is_file()
  assert (wheel.parent / "bundle.sigstore").is_file()
  ```
- [ ] **Step 2: Run it — expect FAIL.**
  ```
  uv run pytest tests/unit/cli/test_cli_sign.py::test_sign_blob_argv_carries_cosign3_legacy_compat_flags -q
  ```
  Expected: `FAILED` — `assert '--tlog-upload=false' in argv` (the flags are not in the argv yet).
- [ ] **Step 3: Make the minimal argv edit.** In `_exec_cosign_sign_blob`, insert the three flags after `"--yes",` and before `"--key",`.

  Before (`:583-597`):
  ```python
  proc = await asyncio.create_subprocess_exec(
      cosign_bin,
      "sign-blob",
      "--yes",  # skip "are you sure" prompt; required for non-interactive
      "--key",
      signing_key_path,
      "--output-signature",
      str(sig_output_path),
      "--bundle",
      str(bundle_output_path),
      str(wheel_path),
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
      env=cosign_env,
  )
  ```
  After:
  ```python
  proc = await asyncio.create_subprocess_exec(
      cosign_bin,
      "sign-blob",
      "--yes",  # skip "are you sure" prompt; required for non-interactive
      # cosign 3.x legacy-compat bridge (ADR-016): keep emitting the
      # detached cosign.sig + offline bundle. --tlog-upload=false is what
      # disables the public-Rekor upload (air-gapped-correct);
      # --use-signing-config=false removes its conflict with the
      # --use-signing-config=true default; --new-bundle-format=false pins
      # the legacy bundle format the runtime trust gate verifies.
      "--tlog-upload=false",
      "--use-signing-config=false",
      "--new-bundle-format=false",
      "--key",
      signing_key_path,
      "--output-signature",
      str(sig_output_path),
      "--bundle",
      str(bundle_output_path),
      str(wheel_path),
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
      env=cosign_env,
  )
  ```
- [ ] **Step 4: Run the new test + the existing sign argv test — expect PASS.**
  ```
  uv run pytest tests/unit/cli/test_cli_sign.py::test_sign_blob_argv_carries_cosign3_legacy_compat_flags tests/unit/cli/test_cli_sign.py::test_sign_blob_happy_path_invokes_cosign_with_correct_argv -q
  ```
  Expected: `2 passed`.
- [ ] **Step 5: Run the full standing gate.**
  ```
  uv run pytest tests/unit/cli/test_cli_sign.py -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: pytest `… passed`; ruff `All checks passed!`; ruff-format `already formatted`; mypy `Success: no issues found`.
- [ ] **Step 6 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/cli/sign.py tests/unit/cli/test_cli_sign.py
  git commit
  ```
  Message:
  ```
  fix(supply-chain): cosign 3.x sign-blob legacy-compat flags in cli/sign.py

  Add --tlog-upload=false --use-signing-config=false --new-bundle-format=false
  to _exec_cosign_sign_blob so the pack author path keeps emitting the detached
  cosign.sig + offline bundle on cosign 3.x (verified 3.0.6). Post-exec artifact
  probes unchanged + now pass. Per ADR-016 cosign-3.x compat amendment.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 2: `cli/verify.py` — verify-blob offline flags (+2) + drift-pin test

**Files:**
- Modify: `src/cognic_agentos/cli/verify.py` (`_exec_cosign_verify_blob`, argv literal at `:783-793` — already carries `--key --signature <sig> --bundle <bundle>`). The minimal-env (`PATH`+`HOME` only), timeout, SIGKILL-on-timeout, and exit-code-only verdict stay UNCHANGED.
- Test: `tests/unit/cli/test_cli_verify.py` (extend `test_verify_invokes_cosign_with_verify_blob_argv_shape` at `:489-521`; `_stage_signed_pack` / `_wire_verify_settings` / `_make_cosign_shim` / `_read_shim_recording` patterns). No cosign binary needed.

- [ ] **Step 1: Extend the failing drift-pin test.** In `test_verify_invokes_cosign_with_verify_blob_argv_shape`, after the existing `--bundle` assertions (`:517-519`) and before the trailing wheel assertion (`:521`), add:
  ```python
  assert "--insecure-ignore-tlog" in argv
  assert "--new-bundle-format=false" in argv
  # Both offline flags ride the block between --bundle <bundle> and the
  # positional wheel (so verification of an offline-signed artifact does
  # not search the public transparency log).
  bundle_val_idx = argv.index("--bundle") + 1
  wheel_idx = max(i for i, a in enumerate(argv) if a.endswith(".whl"))
  for flag in ("--insecure-ignore-tlog", "--new-bundle-format=false"):
      assert bundle_val_idx < argv.index(flag) < wheel_idx
  ```
- [ ] **Step 2: Run it — expect FAIL.**
  ```
  uv run pytest tests/unit/cli/test_cli_verify.py::test_verify_invokes_cosign_with_verify_blob_argv_shape -q
  ```
  Expected: `FAILED` — `assert '--insecure-ignore-tlog' in argv`.
- [ ] **Step 3: Make the minimal argv edit.** In `_exec_cosign_verify_blob`, insert the two flags after `str(bundle_path),` and before `str(wheel_path),`.

  Before (`:783-793`):
  ```python
  argv = [
      cosign_bin,
      "verify-blob",
      "--key",
      trust_root_path,
      "--signature",
      str(sig_path),
      "--bundle",
      str(bundle_path),
      str(wheel_path),
  ]
  ```
  After:
  ```python
  argv = [
      cosign_bin,
      "verify-blob",
      "--key",
      trust_root_path,
      "--signature",
      str(sig_path),
      "--bundle",
      str(bundle_path),
      # cosign 3.x offline verify (ADR-016): the sign side no longer
      # uploads a Rekor tlog entry (--tlog-upload=false), so verify MUST
      # ignore the tlog instead of failing to find one; --new-bundle-format
      # =false pins the legacy bundle posture.
      "--insecure-ignore-tlog",
      "--new-bundle-format=false",
      str(wheel_path),
  ]
  ```
- [ ] **Step 4: Run the extended test — expect PASS.**
  ```
  uv run pytest tests/unit/cli/test_cli_verify.py::test_verify_invokes_cosign_with_verify_blob_argv_shape -q
  ```
  Expected: `1 passed`.
- [ ] **Step 5: Run the full standing gate.**
  ```
  uv run pytest tests/unit/cli/test_cli_verify.py -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: all green.
- [ ] **Step 6 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/cli/verify.py tests/unit/cli/test_cli_verify.py
  git commit
  ```
  Message:
  ```
  fix(supply-chain): cosign 3.x verify-blob offline flags in cli/verify.py

  Add --insecure-ignore-tlog --new-bundle-format=false to _exec_cosign_verify_blob
  so `agentos verify` accepts the offline-signed (no public Rekor) pack on cosign
  3.x. Argv already passed --key --signature --bundle. Per ADR-016 cosign-3.x
  compat amendment.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 3: `protocol/trust_gate.py` + BOTH callers + 13 test call sites — `bundle_path` param + `--bundle` + offline flags (ATOMIC)

This is the one signature change and the one atomic, multi-file commit (see the decision block above). It MUST keep the whole suite green at its single commit.

**Files:**
- Modify: `src/cognic_agentos/protocol/trust_gate.py` — `verify_pack_signature` signature (`:472-482`), canonicalisation block (`:509-512`), argv literal (`:558-566`). The `require_cosign=False` skip path (`:519-532`) and `signature_digest = _hash_file(sig_canonical)` (`:636`) stay UNCHANGED.
- Modify: `src/cognic_agentos/protocol/plugin_registry.py` — the `verify_pack_signature(...)` call (`:1138-1146`); `artefacts.sigstore_bundle_path` is field `:483` on `PackAttestations`.
- Modify: `src/cognic_agentos/packs/_signature_path_resolver.py` — add the `bundle.sigstore` POSIX-basename projector `_resolve_bundle_relative(...)` (mirroring `_resolve_signature_relative` at `:125-155`), the `_bundle_failed()` helper, the `bundle_path: Path | None` field on `SignaturePathResolution` (`:91-93`), and the `_resolve_bundle_relative` threading inside `resolve_signature_paths` (`:203-226`). Every bundle-path failure maps to the **existing** `signature_bundle_path_unreachable` `SignatureRedReason` — **no new reason value**. Critical-controls / supply-chain module.
- Modify: `src/cognic_agentos/portal/api/packs/review_routes.py` — read the resolver-provided `resolution.bundle_path` (`:445-446`), extend the `None`-guard (`:447-452`) + the `.exists()` probe (`:453-458`) to also require the bundle, and thread `bundle_path=` into the `verify_pack_signature(...)` call (`:461-469`). Reuses the existing `signature_bundle_path_unreachable` red-reason; **no new vocab** (the bundle path now comes from the extended resolver, **not** a `cosign.sig` sibling).
- Test: `tests/unit/protocol/test_trust_gate.py` — extend `_make_attestation_files` (`:210-226`); add `_bundle_for` helper (the trust-gate-test fixture helper — its sibling layout is fine because trust-gate tests pass `bundle_path` explicitly, NOT via the manifest resolver); thread `bundle_path=` into the **13** real call sites (`:393, 439, 480, 518, 554, 614, 654, 685, 736, 769, 802, 825, 847`); extend `TestSubprocessShape::test_argv_is_list_form_with_explicit_flags` (`:380-417`); add a fail-closed bundle-path-traversal test; add a `signature_digest`-unchanged test if absent.
- Test: `tests/unit/packs/test_signature_path_resolver.py` — add bundle-path resolution tests mirroring the existing `cosign.sig` cases (`TestSprint7B3T9SliceBHappyPath` / `…SignatureFailureModes`): a basename happy path, a **non-sibling `custom/dir/bundle.sigstore`** case, and absent / multiple-ambiguous / absolute / traversal failures each asserting `signature_bundle_path_unreachable` with NO new `SignatureRedReason` value.
- Verify-only (no edit — signature-agnostic mocks; confirm green): `tests/unit/protocol/test_registry_integration.py`, `tests/unit/protocol/test_fixture_pack_admission.py`, `tests/unit/protocol/test_mcp_fixture_pack_admission.py`, `tests/unit/protocol/test_mcp_registration_auth_probe.py`, `tests/unit/portal/api/packs/_approve_test_support.py`, `tests/unit/harness/test_registry_boot.py`, `tests/conformance/startup_discovery/test_headline_join.py` (these use `AsyncMock` / `monkeypatch.setattr`, which accept any kwargs).

- [ ] **Step 1: Update the test helper + add `_bundle_for`.** Extend `_make_attestation_files` to ALSO write a `bundle.sigstore` file in the same `pack_dir` (additive side effect; return type stays `(sig_path, blob_path)` so the 13 unpack sites do not change arity). Add a sibling-deriving helper. **Scope note:** `_bundle_for` is a **trust-gate-test fixture** helper only — the trust-gate unit tests pass `bundle_path` explicitly to `verify_pack_signature`, which resolves via `PackAttestations.sigstore_bundle_path`, NOT the manifest resolver, so a sibling layout in the fixture is fine. It does NOT model the **approval-gate** bundle resolution, which goes through the manifest `[supply_chain].attestation_paths` basename match in the extended resolver (Steps 5 + 11).

  Before (`:210-226`):
  ```python
  def _make_attestation_files(
      attestation_root: Path,
      pack_id: str,
      version: str,
      *,
      sig_bytes: bytes = b"fake-signature-bytes",
      blob_bytes: bytes = b"fake-blob-bytes",
  ) -> tuple[Path, Path]:
      """Lay out attestation files at the conventional path. Returns
      (sig_path, blob_path)."""
      pack_dir = attestation_root / pack_id / version
      pack_dir.mkdir(parents=True)
      sig_path = pack_dir / "cosign.sig"
      blob_path = pack_dir / f"{pack_id}-{version}.whl"
      sig_path.write_bytes(sig_bytes)
      blob_path.write_bytes(blob_bytes)
      return sig_path, blob_path
  ```
  After (adds the bundle write + the `_bundle_for` helper; same return shape):
  ```python
  def _make_attestation_files(
      attestation_root: Path,
      pack_id: str,
      version: str,
      *,
      sig_bytes: bytes = b"fake-signature-bytes",
      blob_bytes: bytes = b"fake-blob-bytes",
      bundle_bytes: bytes = b"fake-bundle-bytes",
  ) -> tuple[Path, Path]:
      """Lay out attestation files at the conventional path. Returns
      (sig_path, blob_path). Also writes the sibling bundle.sigstore that
      verify_pack_signature now canonicalises + passes via --bundle; use
      _bundle_for(sig_path) to obtain it."""
      pack_dir = attestation_root / pack_id / version
      pack_dir.mkdir(parents=True)
      sig_path = pack_dir / "cosign.sig"
      blob_path = pack_dir / f"{pack_id}-{version}.whl"
      bundle_path = pack_dir / "bundle.sigstore"
      sig_path.write_bytes(sig_bytes)
      blob_path.write_bytes(blob_bytes)
      bundle_path.write_bytes(bundle_bytes)
      return sig_path, blob_path


  def _bundle_for(attestation_sibling: Path) -> Path:
      """The bundle.sigstore written next to the sig + blob in the same
      pack_dir. Accepts either the sig_path or the blob_path."""
      return attestation_sibling.parent / "bundle.sigstore"
  ```
- [ ] **Step 2: Thread `bundle_path=` into all 13 real call sites.** At each `await gate.verify_pack_signature(...)`, add `bundle_path=_bundle_for(sig),` next to the existing `signature_path=sig,`. The 13 sites: `:393, 439, 480, 518, 554, 614, 654, 685, 736, 769, 802, 825, 847`. **One exception:** the boundary test that unpacks `_, blob = _make_attestation_files(...)` (call at `:802`) discards `sig` — use `bundle_path=_bundle_for(blob),` there. Example shape:
  ```python
  await gate.verify_pack_signature(
      pack_id="demo_pack",
      version="1.0.0",
      signature_path=sig,
      bundle_path=_bundle_for(sig),
      blob_path=blob,
      trust_root=trust_root,
  )
  ```
- [ ] **Step 3: Add the new drift-pin assertions to `test_argv_is_list_form_with_explicit_flags`.** After the existing `assert "--signature" in argv` (`:415`) and before `assert argv[-1].endswith(".whl")` (`:417`), add:
  ```python
  assert "--bundle" in argv
  assert argv[argv.index("--bundle") + 1].endswith("bundle.sigstore")
  assert "--insecure-ignore-tlog" in argv
  assert "--new-bundle-format=false" in argv
  ```
  (`argv[-1]` is still the `.whl` blob — flags precede the positional — so the existing assert stays valid.)
- [ ] **Step 4: Add the fail-closed + invariant tests.** Add to `TestSubprocessShape` (mirror the path-traversal style at `:335`):
  ```python
  async def test_bundle_path_required_keyword(self) -> None:
      """bundle_path is a required keyword-only parameter (Fork-A)."""
      import inspect
      params = inspect.signature(TrustGate.verify_pack_signature).parameters
      assert "bundle_path" in params
      assert params["bundle_path"].kind is inspect.Parameter.KEYWORD_ONLY
      assert params["bundle_path"].default is inspect.Parameter.empty

  async def test_bundle_path_traversal_rejected(
      self, tmp_path, settings_factory, audit_store, attestation_root, trust_root_prefix
  ) -> None:
      """A bundle_path escaping signature_root_path fails closed."""
      shim = _make_cosign_shim(tmp_path)
      settings = settings_factory(cosign_path=str(shim))
      gate = TrustGate(settings=settings, audit_store=audit_store)
      sig, blob = _make_attestation_files(attestation_root, "esc_pack", "1.0.0")
      trust_root = _make_trust_root(trust_root_prefix)
      with pytest.raises(PathTraversalError):
          await gate.verify_pack_signature(
              pack_id="esc_pack",
              version="1.0.0",
              signature_path=sig,
              bundle_path=attestation_root / ".." / "escape.sigstore",
              blob_path=blob,
              trust_root=trust_root,
          )

  async def test_signature_digest_is_sha256_of_cosign_sig_unchanged(
      self, tmp_path, settings_factory, audit_store, attestation_root, trust_root_prefix
  ) -> None:
      """signature_digest stays the SHA-256 of cosign.sig (not the bundle)."""
      import hashlib
      shim = _make_cosign_shim(tmp_path)
      settings = settings_factory(cosign_path=str(shim))
      gate = TrustGate(settings=settings, audit_store=audit_store)
      sig, blob = _make_attestation_files(
          attestation_root, "dig_pack", "1.0.0", sig_bytes=b"known-sig-bytes"
      )
      trust_root = _make_trust_root(trust_root_prefix)
      result = await gate.verify_pack_signature(
          pack_id="dig_pack",
          version="1.0.0",
          signature_path=sig,
          bundle_path=_bundle_for(sig),
          blob_path=blob,
          trust_root=trust_root,
      )
      assert result.signature_digest == hashlib.sha256(b"known-sig-bytes").hexdigest()
  ```
  (Ensure `PathTraversalError` is imported in the test module; the existing `test_relative_traversal_rejected` at `:335` already uses it.)
- [ ] **Step 4b: Add the approval-gate bundle-path resolver tests.** In `tests/unit/packs/test_signature_path_resolver.py`, add a new test class mirroring the existing `cosign.sig` cases (`TestSprint7B3T9SliceBHappyPath` / `…SignatureFailureModes`). It pins the **basename-from-`attestation_paths`** contract — INCLUDING a non-sibling `custom/dir/bundle.sigstore` case so the slice cannot regress into a `cosign.sig`-sibling assumption — and that every bundle-path failure maps to the EXISTING `signature_bundle_path_unreachable` with NO new `SignatureRedReason` value. Reuse the existing `_manifest(...)` factory + the module-level `import typing` / `SignatureRedReason` import (both already at the file head, `:29` / `:39`); the default `_manifest()` `attestation_paths=("cosign.sig", "bundle.sigstore")` already carries a bundle, so every existing "resolved" test stays green.
  ```python
  class TestSprint7B3T9BundlePathResolution:
      """cosign 3.x bundle-path projection — basename match from
      [supply_chain].attestation_paths (NOT a cosign.sig sibling). Every
      failure maps to the EXISTING signature_bundle_path_unreachable."""

      def test_resolves_bundle_by_basename(self) -> None:
          # _manifest()'s default attestation_paths already carries
          # "bundle.sigstore".
          resolution = resolve_signature_paths(_manifest(), signed_artefact_root=_ROOT)
          assert resolution.outcome == "resolved"
          assert resolution.bundle_path == _ROOT / "bundle.sigstore"

      def test_resolves_bundle_in_custom_dir_by_basename(self) -> None:
          # The NON-SIBLING case: the bundle lives in custom/dir/, not next
          # to cosign.sig. The basename match still resolves it — a
          # sibling-only derivation would wrongly reject this recognised
          # manifest shape (the supply-chain evidence projector accepts it).
          manifest = _manifest(attestation_paths=("cosign.sig", "custom/dir/bundle.sigstore"))
          resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
          assert resolution.outcome == "resolved"
          assert resolution.bundle_path == _ROOT / "custom/dir/bundle.sigstore"

      def test_bundle_absent_maps_to_unreachable(self) -> None:
          manifest = _manifest(attestation_paths=("cosign.sig",))
          resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
          assert resolution.outcome == "bundle_missing"
          assert resolution.red_reason == "signature_bundle_path_unreachable"
          assert resolution.bundle_path is None

      def test_multiple_bundle_entries_ambiguous_maps_to_unreachable(self) -> None:
          manifest = _manifest(
              attestation_paths=("cosign.sig", "bundle.sigstore", "x/bundle.sigstore")
          )
          resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
          assert resolution.outcome == "bundle_missing"
          assert resolution.red_reason == "signature_bundle_path_unreachable"
          assert resolution.bundle_path is None

      def test_absolute_bundle_path_maps_to_unreachable(self) -> None:
          manifest = _manifest(attestation_paths=("cosign.sig", "/abs/bundle.sigstore"))
          resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
          assert resolution.red_reason == "signature_bundle_path_unreachable"
          assert resolution.bundle_path is None

      def test_bundle_path_traversal_maps_to_unreachable(self) -> None:
          manifest = _manifest(attestation_paths=("cosign.sig", "../escape/bundle.sigstore"))
          resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
          assert resolution.red_reason == "signature_bundle_path_unreachable"
          assert resolution.bundle_path is None

      def test_bundle_reason_introduces_no_new_signature_red_reason_value(self) -> None:
          # signature_bundle_path_unreachable is one of the 5 ORIGINAL
          # gate-1 reasons — already in the Literal; the resolver adds NO
          # new value (the closed SignatureRedReason enum stays frozen).
          assert "signature_bundle_path_unreachable" in set(typing.get_args(SignatureRedReason))
  ```
- [ ] **Step 5: Run the new/changed tests — expect FAIL.**
  ```
  uv run pytest tests/unit/protocol/test_trust_gate.py tests/unit/packs/test_signature_path_resolver.py -q
  ```
  Expected: `FAILED` — `TypeError: verify_pack_signature() got an unexpected keyword argument 'bundle_path'` (the real method has no such param yet) plus the new trust-gate asserts fail; the resolver suite fails on the missing `SignaturePathResolution.bundle_path` field + the `bundle_missing` outcome (the resolver does not project the bundle yet).
- [ ] **Step 6: Edit `trust_gate.py` — add the param.** Insert `bundle_path: Path,` after `signature_path: Path,` in the keyword-only signature.

  Before (`:472-482`):
  ```python
  async def verify_pack_signature(
      self,
      *,
      pack_id: str,
      version: str,
      signature_path: Path,
      blob_path: Path,
      trust_root: Path,
      tenant_id: str | None = None,
      request_id: str = "system",
  ) -> CosignVerificationResult:
  ```
  After:
  ```python
  async def verify_pack_signature(
      self,
      *,
      pack_id: str,
      version: str,
      signature_path: Path,
      bundle_path: Path,
      blob_path: Path,
      trust_root: Path,
      tenant_id: str | None = None,
      request_id: str = "system",
  ) -> CosignVerificationResult:
  ```
- [ ] **Step 7: Edit `trust_gate.py` — canonicalise the bundle.** Add the bundle canonicalisation after `blob_canonical` (`:510`) and before `trust_canonical` (`:512`), so a bundle escaping the root trips `PathTraversalError` (after sig/blob, preserving the existing sig-escape/blob-escape test semantics).

  Before (`:509-512`):
  ```python
  sig_canonical = _canonicalise_under_root(signature_path, self._settings.signature_root_path)
  blob_canonical = _canonicalise_under_root(blob_path, self._settings.signature_root_path)
  # §2 invariant 4: trust root canonicalised under its own prefix.
  trust_canonical = _canonicalise_under_root(trust_root, self._settings.trust_root_prefix)
  ```
  After:
  ```python
  sig_canonical = _canonicalise_under_root(signature_path, self._settings.signature_root_path)
  blob_canonical = _canonicalise_under_root(blob_path, self._settings.signature_root_path)
  # cosign 3.x verify (ADR-016): the bundle is canonicalised under the
  # same signature_root_path as the sig + blob (path-traversal invariant).
  bundle_canonical = _canonicalise_under_root(bundle_path, self._settings.signature_root_path)
  # §2 invariant 4: trust root canonicalised under its own prefix.
  trust_canonical = _canonicalise_under_root(trust_root, self._settings.trust_root_prefix)
  ```
- [ ] **Step 8: Edit `trust_gate.py` — argv.** Add `--bundle <bundle_canonical>` + the two offline flags.

  Before (`:558-566`):
  ```python
  argv = [
      self._cosign_bin,
      "verify-blob",
      "--key",
      str(trust_canonical),
      "--signature",
      str(sig_canonical),
      str(blob_canonical),
  ]
  ```
  After:
  ```python
  argv = [
      self._cosign_bin,
      "verify-blob",
      "--key",
      str(trust_canonical),
      "--signature",
      str(sig_canonical),
      "--bundle",
      str(bundle_canonical),
      # cosign 3.x offline verify (ADR-016): sign no longer uploads a
      # Rekor tlog entry, so verify ignores the tlog; --new-bundle-format
      # =false pins the legacy bundle posture.
      "--insecure-ignore-tlog",
      "--new-bundle-format=false",
      str(blob_canonical),
  ]
  ```
- [ ] **Step 9: Edit `plugin_registry.py` — thread the bundle (caller 1).**

  Before (`:1138-1146`):
  ```python
  cosign_result = await trust_gate.verify_pack_signature(
      pack_id=record.distribution_name,
      version=record.distribution_version,
      signature_path=artefacts.cosign_signature_path,
      blob_path=artefacts.cosign_blob_path,
      trust_root=artefacts.cosign_trust_root,
      tenant_id=tenant_id,
      request_id=request_id,
  )
  ```
  After (add the one line):
  ```python
  cosign_result = await trust_gate.verify_pack_signature(
      pack_id=record.distribution_name,
      version=record.distribution_version,
      signature_path=artefacts.cosign_signature_path,
      bundle_path=artefacts.sigstore_bundle_path,
      blob_path=artefacts.cosign_blob_path,
      trust_root=artefacts.cosign_trust_root,
      tenant_id=tenant_id,
      request_id=request_id,
  )
  ```
- [ ] **Step 9b: Edit `_signature_path_resolver.py` — add the bundle-path projector (caller-2 dependency).** Mirror `_resolve_signature_relative` for `bundle.sigstore` (POSIX-basename match against `[supply_chain].attestation_paths`), add the `bundle_path` field, and thread it through `resolve_signature_paths`. Every bundle-path failure maps to the EXISTING `signature_bundle_path_unreachable` — **no new `SignatureRedReason` value.**

  (i) Add the filename constant after `_COSIGN_SIG_FILENAME` (`:64`):
  ```python
  _COSIGN_SIG_FILENAME: str = "cosign.sig"


  #: The literal Sigstore-bundle filename produced by ``agentos sign``
  #: (``cli/sign.py``). Matched on the path basename, mirroring
  #: ``_COSIGN_SIG_FILENAME`` — a custom-dir entry such as
  #: ``custom/dir/bundle.sigstore`` still matches.
  _BUNDLE_SIGSTORE_FILENAME: str = "bundle.sigstore"
  ```

  (ii) Add the `bundle_missing` outcome + the `bundle_path` field on `SignaturePathResolution` (`:84-93`). Before → After:
  ```python
  # Before
      outcome: Literal[
          "resolved",
          "ambiguous",
          "signature_missing",
          "blob_missing",
          "root_missing",
      ]
      signature_path: Path | None
      blob_path: Path | None
      red_reason: SignatureRedReason | None
  # After
      outcome: Literal[
          "resolved",
          "ambiguous",
          "signature_missing",
          "blob_missing",
          "bundle_missing",
          "root_missing",
      ]
      signature_path: Path | None
      blob_path: Path | None
      bundle_path: Path | None
      red_reason: SignatureRedReason | None
  ```
  (`outcome` is the module-private internal classification Literal, NOT the wire-public `SignatureRedReason`; adding `bundle_missing` is an internal-classification change, not a wire-vocab change.)

  (iii) Thread `bundle_path=None` into the existing failure helpers (`:107-122`) and add `_bundle_failed`:
  ```python
  def _signature_failed(
      outcome: Literal["ambiguous", "signature_missing"],
      red_reason: SignatureRedReason,
  ) -> SignaturePathResolution:
      return SignaturePathResolution(
          outcome=outcome,
          signature_path=None,
          blob_path=None,
          bundle_path=None,
          red_reason=red_reason,
      )


  def _blob_failed(red_reason: SignatureRedReason) -> SignaturePathResolution:
      return SignaturePathResolution(
          outcome="blob_missing",
          signature_path=None,
          blob_path=None,
          bundle_path=None,
          red_reason=red_reason,
      )


  def _bundle_failed() -> SignaturePathResolution:
      """Every bundle-path failure mode (absent / multiple-ambiguous /
      absolute / ``..``-traversal) maps to the EXISTING
      ``signature_bundle_path_unreachable`` — the resolver introduces NO
      new ``SignatureRedReason`` value (the closed enum stays frozen)."""
      return SignaturePathResolution(
          outcome="bundle_missing",
          signature_path=None,
          blob_path=None,
          bundle_path=None,
          red_reason="signature_bundle_path_unreachable",
      )
  ```

  (iv) Add `_resolve_bundle_relative` after `_resolve_blob_relative` (`:174`), mirroring `_resolve_signature_relative` (`:125-155`) — but collapsing all four failure modes into the single `signature_bundle_path_unreachable`:
  ```python
  def _resolve_bundle_relative(
      manifest: dict[str, Any],
  ) -> str | SignaturePathResolution:
      """Project the manifest-relative ``bundle.sigstore`` path.

      Mirrors :func:`_resolve_signature_relative`: matches the unique
      ``[supply_chain].attestation_paths`` entry whose POSIX basename is
      exactly ``bundle.sigstore`` (custom-dir-safe — a
      ``custom/dir/bundle.sigstore`` entry still matches, consistent with
      the supply-chain evidence projector). Returns the relative-path
      ``str`` on success, or a fully-formed failure
      :class:`SignaturePathResolution` (every failure mode →
      ``signature_bundle_path_unreachable``).
      """
      supply_chain = manifest.get("supply_chain")
      attestation_paths = (
          supply_chain.get("attestation_paths") if isinstance(supply_chain, dict) else None
      )
      entries = attestation_paths if isinstance(attestation_paths, list) else []
      matches = [
          entry
          for entry in entries
          if isinstance(entry, str) and Path(entry).name == _BUNDLE_SIGSTORE_FILENAME
      ]
      # 0 matches (absent) OR >1 (ambiguous) → unreachable.
      if len(matches) != 1:
          return _bundle_failed()
      candidate = matches[0]
      if candidate.startswith("/"):
          return _bundle_failed()
      if _has_traversal(candidate):
          return _bundle_failed()
      return candidate
  ```

  (v) Thread `_resolve_bundle_relative` into `resolve_signature_paths` (`:203-226`) — AFTER blob, BEFORE the root check (precedence: signature → blob → bundle → root, so the existing precedence tests stay valid). Before → After:
  ```python
  # Before
      blob_relative = _resolve_blob_relative(manifest)
      if isinstance(blob_relative, SignaturePathResolution):
          return blob_relative

      if signed_artefact_root is None:
          return SignaturePathResolution(
              outcome="root_missing",
              signature_path=None,
              blob_path=None,
              red_reason="signature_signed_artefact_root_not_declared_at_submit",
          )

      # Both helpers returned ``str`` relatives — the isinstance guards
      # above are the only way out of the failure paths.
      return SignaturePathResolution(
          outcome="resolved",
          signature_path=signed_artefact_root / signature_relative,
          blob_path=signed_artefact_root / blob_relative,
          red_reason=None,
      )
  # After
      blob_relative = _resolve_blob_relative(manifest)
      if isinstance(blob_relative, SignaturePathResolution):
          return blob_relative

      bundle_relative = _resolve_bundle_relative(manifest)
      if isinstance(bundle_relative, SignaturePathResolution):
          return bundle_relative

      if signed_artefact_root is None:
          return SignaturePathResolution(
              outcome="root_missing",
              signature_path=None,
              blob_path=None,
              bundle_path=None,
              red_reason="signature_signed_artefact_root_not_declared_at_submit",
          )

      # All three helpers returned ``str`` relatives — the isinstance
      # guards above are the only way out of the failure paths.
      return SignaturePathResolution(
          outcome="resolved",
          signature_path=signed_artefact_root / signature_relative,
          blob_path=signed_artefact_root / blob_relative,
          bundle_path=signed_artefact_root / bundle_relative,
          red_reason=None,
      )
  ```

  (vi) Update the module docstring (`:32-35`) + the `resolve_signature_paths` docstring precedence list (`:189-202`) from "signature → blob → root" to "signature → blob → **bundle** → root", adding the bundle bullet (matched from `[supply_chain].attestation_paths` by basename; absent / ambiguous / absolute / traversal → `signature_bundle_path_unreachable`). Keep the "pure-functional — no filesystem I/O" contract (the `.exists()` probe stays in the handler).
- [ ] **Step 10: Edit `review_routes.py` — thread the resolver-provided bundle (caller 2).** Read `resolution.bundle_path` (the extended resolver derives it by basename from `attestation_paths`, NOT a `cosign.sig` sibling), extend BOTH the `None`-guard and the `.exists()` probe to also require it, and thread `bundle_path=` into the call.

  Before (`:445-469`):
  ```python
  signature_path = resolution.signature_path
  blob_path = resolution.blob_path
  if signature_path is None or blob_path is None:  # pragma: no cover - resolved ⇒ non-None
      return SignatureGateInput(
          outcome="red",
          red_reason="signature_bundle_path_unreachable",
          signature_digest=None,
      )
  if not signature_path.exists() or not blob_path.exists():
      return SignatureGateInput(
          outcome="red",
          red_reason="signature_bundle_path_unreachable",
          signature_digest=None,
      )

  try:
      result = await trust_gate.verify_pack_signature(
          pack_id=record.pack_id,
          version=version,
          signature_path=signature_path,
          blob_path=blob_path,
          trust_root=trust_root,
          tenant_id=tenant_id,
          request_id=request_id,
      )
  ```
  After:
  ```python
  signature_path = resolution.signature_path
  blob_path = resolution.blob_path
  # cosign 3.x verify (ADR-016): the runtime trust gate now requires the
  # Sigstore bundle. The resolver derives it by POSIX basename from
  # [supply_chain].attestation_paths (the manifest source of truth —
  # custom-dir-safe), NOT as a cosign.sig sibling. A missing/unresolved
  # bundle is the same author-preload failure class as a missing sig
  # (reuse the existing signature_bundle_path_unreachable reason).
  bundle_path = resolution.bundle_path
  if signature_path is None or blob_path is None or bundle_path is None:  # pragma: no cover - resolved ⇒ non-None
      return SignatureGateInput(
          outcome="red",
          red_reason="signature_bundle_path_unreachable",
          signature_digest=None,
      )
  if not signature_path.exists() or not blob_path.exists() or not bundle_path.exists():
      return SignatureGateInput(
          outcome="red",
          red_reason="signature_bundle_path_unreachable",
          signature_digest=None,
      )

  try:
      result = await trust_gate.verify_pack_signature(
          pack_id=record.pack_id,
          version=version,
          signature_path=signature_path,
          bundle_path=bundle_path,
          blob_path=blob_path,
          trust_root=trust_root,
          tenant_id=tenant_id,
          request_id=request_id,
      )
  ```
- [ ] **Step 11: Run the touched tests — expect PASS.**
  ```
  uv run pytest tests/unit/protocol/test_trust_gate.py tests/unit/protocol/test_plugin_registry.py tests/unit/protocol/test_registry_integration.py tests/unit/portal/api/packs/ -q
  ```
  Expected: all `passed`. The `AsyncMock`/`monkeypatch` callers stay green (signature-agnostic); the review-path tests stay green (mocked trust gate).
- [ ] **Step 11b: Promote `packs/_signature_path_resolver.py` to the durable CC coverage gate.** It gains the approval-gate bundle projection (Step 9b), so it joins the per-file gate (it was NOT on the gate before — verified `0` refs in `tools/check_critical_coverage.py`). Add it to `tools/check_critical_coverage.py::_CRITICAL_FILES` (`:711`), grouped with the neighbouring `packs/` entries, with the standard floor:
  ```python
  ("src/cognic_agentos/packs/_signature_path_resolver.py", 0.95, 0.90),
  ```
  Bump the count guard in `tests/unit/tools/test_check_critical_coverage.py` (`:110`):
  ```python
  _EXPECTED_ENTRY_COUNT = 135  # was 134 — + packs/_signature_path_resolver.py (cosign-3.x bridge approval bundle projector)
  ```
  Per the repo's tightening-edit-B discipline, this promotion MUST land with a FRESH full-suite `coverage.json` in THIS commit proving the module is AT/ABOVE 95/90 (not merely the count bump) — Step 12 generates + checks it.
- [ ] **Step 12: Run the full standing gate + the critical-controls coverage check** (this commit touches stop-rule + on-gate modules AND promotes `_signature_path_resolver.py` per Step 11b).
  ```
  uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  uv run python tools/check_critical_coverage.py
  ```
  Expected: pytest green; ruff/format/mypy green; the coverage tool reports `trust_gate.py` / `plugin_registry.py` / `review_routes.py` / `_signature_path_resolver.py` at/above the 95% line / 90% branch floor on the FRESH `coverage.json` (the full-suite `--cov-branch` run above exercises the resolver's tests from Step 4b + its other consumers, so the newly-promoted module reports at floor). The count guard test (`test_check_critical_coverage.py`) passes with `_EXPECTED_ENTRY_COUNT = 135`.
- [ ] **Step 13 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/protocol/trust_gate.py src/cognic_agentos/protocol/plugin_registry.py src/cognic_agentos/portal/api/packs/review_routes.py src/cognic_agentos/packs/_signature_path_resolver.py tools/check_critical_coverage.py tests/unit/protocol/test_trust_gate.py tests/unit/packs/test_signature_path_resolver.py tests/unit/tools/test_check_critical_coverage.py
  git commit
  ```
  Message:
  ```
  fix(supply-chain): trust_gate verify-blob bundle + offline flags; thread both callers

  verify_pack_signature gains a required bundle_path: Path param + canonicalises it
  under signature_root_path; argv adds --bundle <bundle> --insecure-ignore-tlog
  --new-bundle-format=false so the runtime trust gate verifies the offline-signed
  pack on cosign 3.x. signature_digest stays SHA-256 of cosign.sig; require_cosign
  =False skip unchanged. BOTH production callers updated atomically: plugin_registry
  (artefacts.sigstore_bundle_path) + the 5-gate signature gate in review_routes
  (cosign.sig sibling + existence guard onto the existing
  signature_bundle_path_unreachable reason). Per ADR-016/ADR-002 cosign-3.x amendment.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 4: `models/trust.py` — model-path offline flag (+1, narrow) + update the full-list-pin test

Per spec §4.5 / §6: add **ONLY** `--insecure-ignore-tlog`. Keep the model path **bundle-only** — do NOT add `--signature`, do NOT add `--new-bundle-format=false`.

**Files:**
- Modify: `src/cognic_agentos/models/trust.py` — `verify_model_signature` argv literal (`:86-94`).
- Test: `tests/unit/models/test_trust.py` — **update** the existing full-list-pin `test_argv_excludes_signature_flag_and_pins_bundle_only_shape` (`:67-95`), which asserts the exact argv list and WILL break.

- [ ] **Step 1: Update the failing full-list-pin test.** The existing test asserts `recorded == [...]`. Add `--insecure-ignore-tlog` (after `--bundle <bundle>`, before the positional artefact) to the expected list and add the two narrowness asserts.

  Before (`:86-95`):
  ```python
  recorded = log_file.read_text().strip().splitlines()
  assert recorded == [
      "verify-blob",
      "--key",
      str(tmp_path / "trust.pub"),
      "--bundle",
      str(tmp_path / "bundle.sigstore"),
      str(tmp_path / "model.bin"),
  ]
  assert "--signature" not in recorded
  ```
  After:
  ```python
  recorded = log_file.read_text().strip().splitlines()
  assert recorded == [
      "verify-blob",
      "--key",
      str(tmp_path / "trust.pub"),
      "--bundle",
      str(tmp_path / "bundle.sigstore"),
      "--insecure-ignore-tlog",
      str(tmp_path / "model.bin"),
  ]
  # Narrow §6 fix: model path stays bundle-only — NO detached sig, and
  # NO legacy-bundle flag (the pack-contract concern, not the model path).
  assert "--signature" not in recorded
  assert "--new-bundle-format=false" not in recorded
  ```
- [ ] **Step 2: Run it — expect FAIL.**
  ```
  uv run pytest tests/unit/models/test_trust.py::test_argv_excludes_signature_flag_and_pins_bundle_only_shape -q
  ```
  Expected: `FAILED` — the recorded list lacks `--insecure-ignore-tlog`.
- [ ] **Step 3: Make the minimal argv edit.** Insert `--insecure-ignore-tlog` after `str(sigstore_bundle_path),` and before `str(signed_artifact_path),`.

  Before (`:86-94`):
  ```python
  argv = [
      self._cosign_bin,
      "verify-blob",
      "--key",
      str(tenant_trust_root),
      "--bundle",
      str(sigstore_bundle_path),
      str(signed_artifact_path),
  ]
  ```
  After:
  ```python
  argv = [
      self._cosign_bin,
      "verify-blob",
      "--key",
      str(tenant_trust_root),
      "--bundle",
      str(sigstore_bundle_path),
      # cosign 3.x offline verify (ADR-013/ADR-016 §6): an offline-signed
      # model has no Rekor tlog entry; ignore the tlog. Bundle-only stays —
      # NO --signature, NO --new-bundle-format=false.
      "--insecure-ignore-tlog",
      str(signed_artifact_path),
  ]
  ```
- [ ] **Step 4: Run the model-trust tests — expect PASS.**
  ```
  uv run pytest tests/unit/models/test_trust.py -q
  ```
  Expected: all `passed`.
- [ ] **Step 5: Run the full standing gate.**
  ```
  uv run pytest tests/unit/models/test_trust.py -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: all green. (Optional, env-gated, NOT required to be green by default: `COGNIC_RUN_COSIGN_INTEGRATION=1 uv run pytest tests/integration/models/test_real_cosign_proof.py -q` — confirms the existing model proof stays green now that the tlog is ignored rather than required. The default run skips it.)
- [ ] **Step 6 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/models/trust.py tests/unit/models/test_trust.py
  git commit
  ```
  Message:
  ```
  fix(supply-chain): models/trust verify-blob offline flag (--insecure-ignore-tlog)

  Narrow §6 fold-in: add ONLY --insecure-ignore-tlog so an offline-signed (no
  Rekor) model verifies on cosign 3.x. Model path stays bundle-only — no
  --signature, no --new-bundle-format=false. Per ADR-013/ADR-016 §6.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 5: `compliance/iso42001/signing.py` — evidence-pack sign offline flag (+1, narrow) + new drift-pin test

Per spec §4.6: add **ONLY** `--tlog-upload=false` (the module already has `--use-signing-config=false --new-bundle-format=false --output-signature --bundle`). Sign-only — there is no cosign *verify* of evidence-pack signatures in the kernel, so no verify counterpart. Outputs + the `EvidencePackSigningError` fail-loud contract are unchanged.

**Files:**
- Modify: `src/cognic_agentos/compliance/iso42001/signing.py` — the `cosign_sign_blob` argv literal (`:148-163`).
- Test: `tests/unit/compliance/iso42001/test_signing.py` — ADD a new argv drift-pin test (no existing argv test to break). `cosign_sign_blob` resolves cosign via `signing.shutil.which("cosign")` (NOT `settings.cosign_path`); capture argv by monkeypatching `shutil.which` to a recording shim, mirroring the `test_cosign_sign_blob_fails_loud_when_cosign_absent` monkeypatch at `:63-68`.

- [ ] **Step 1: Write the failing drift-pin test.** Append to `test_signing.py`:
  ```python
  async def test_sign_blob_argv_includes_tlog_upload_false(
      tmp_path: Path,
      monkeypatch: pytest.MonkeyPatch,
  ) -> None:
      """Evidence-pack sign-blob is offline on cosign 3.x: --tlog-upload=false
      is present alongside the existing legacy-output compat flags."""
      log_file = tmp_path / "argv.log"
      shim = tmp_path / "cosign"
      shim.write_text(
          "#!/bin/sh\n"
          f'printf "%s\\n" "$@" > "{log_file}"\n'
          # Honour --output-signature / --bundle so cosign_sign_blob's
          # both-outputs-produced guard passes.
          'while [ "$#" -gt 0 ]; do\n'
          '  case "$1" in\n'
          '    --output-signature) printf sig > "$2"; shift 2 ;;\n'
          '    --bundle) printf bundle > "$2"; shift 2 ;;\n'
          '    *) shift ;;\n'
          '  esac\n'
          "done\n"
          "exit 0\n"
      )
      shim.chmod(0o755)
      monkeypatch.setattr(
          "cognic_agentos.compliance.iso42001.signing.shutil.which",
          lambda _: str(shim),
      )
      await cosign_sign_blob(b"{}", SigningIdentity(identity="x", pem=b"-----BEGIN KEY-----\n"))
      recorded = log_file.read_text().strip().splitlines()
      assert "--tlog-upload=false" in recorded
      # Existing compat flags unchanged.
      assert "--use-signing-config=false" in recorded
      assert "--new-bundle-format=false" in recorded
  ```
- [ ] **Step 2: Run it — expect FAIL.**
  ```
  uv run pytest tests/unit/compliance/iso42001/test_signing.py::test_sign_blob_argv_includes_tlog_upload_false -q
  ```
  Expected: `FAILED` — `assert '--tlog-upload=false' in recorded`.
- [ ] **Step 3: Make the minimal argv edit.** Insert `--tlog-upload=false` after `"--yes",` and before `"--use-signing-config=false",` (matching the `cli/sign.py` compat-flag block order).

  Before (`:148-163`):
  ```python
  proc = await asyncio.create_subprocess_exec(
      cosign,
      "sign-blob",
      "--yes",
      "--use-signing-config=false",
      "--new-bundle-format=false",
      "--key",
      str(key_file),
      "--output-signature",
      str(sig_file),
      "--bundle",
      str(bundle_file),
      str(blob_file),
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
  )
  ```
  After:
  ```python
  proc = await asyncio.create_subprocess_exec(
      cosign,
      "sign-blob",
      "--yes",
      # cosign 3.x offline sign (ADR-016 §4.6): --tlog-upload=false stops
      # the public-Rekor upload so air-gapped evidence-pack signing works.
      "--tlog-upload=false",
      "--use-signing-config=false",
      "--new-bundle-format=false",
      "--key",
      str(key_file),
      "--output-signature",
      str(sig_file),
      "--bundle",
      str(bundle_file),
      str(blob_file),
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
  )
  ```
  Also update the module/function docstring argv example (`:130-131`) to include `--tlog-upload=false` so the inline doc stays truthful.
- [ ] **Step 4: Run the signing tests — expect PASS.**
  ```
  uv run pytest tests/unit/compliance/iso42001/test_signing.py tests/unit/compliance/iso42001/test_signing_coverage.py -q
  ```
  Expected: all `passed`.
- [ ] **Step 5: Run the full standing gate.**
  ```
  uv run pytest tests/unit/compliance/iso42001/ -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: all green.
- [ ] **Step 6 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/compliance/iso42001/signing.py tests/unit/compliance/iso42001/test_signing.py
  git commit
  ```
  Message:
  ```
  fix(supply-chain): evidence-pack sign-blob offline flag (--tlog-upload=false)

  Add ONLY --tlog-upload=false to compliance/iso42001/signing.py so evidence-pack
  signing does not upload to public Rekor and works air-gapped on cosign 3.x. The
  module already carried --use-signing-config=false --new-bundle-format=false.
  Sign-only (no kernel verify counterpart); outputs + EvidencePackSigningError
  unchanged. Per ADR-016 §4.6 / ADR-006.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 6: Env-gated real-cosign 3.x CLI/pack proof (new) — sign → verify round-trip + offline assertion

Mirror `tests/integration/models/test_real_cosign_proof.py`: module-level `pytest.mark.skipif` on `COGNIC_RUN_COSIGN_INTEGRATION=1`; a fail-loud fixture (AssertionError → pytest ERROR, never SKIP) when opted in but cosign is missing; real keypair via `cosign generate-key-pair`. The proof exercises the ACTUAL fixed argv sites on real cosign — `cli/sign.py` (via `agentos sign-blob`), `cli/verify.py` (`_exec_cosign_verify_blob`), and `protocol/trust_gate.py` (`verify_pack_signature`) — and asserts the produced bundle is offline (no tlog).

**Decision (faithful interpretation of spec §7):** the proof uses `agentos sign-blob` + the two real verify helpers directly rather than the full `agentos sign --bundle` + `agentos verify` orchestrator, because the full orchestrator additionally requires `syft` / `grype` / `pip-licenses` / `joserfc` on PATH — out of scope for a cosign-specific offline proof, and fragile. The two argv sites being fixed for verification (`cli/verify.py`, `trust_gate.py`) are both exercised on real cosign. The model path's offline behaviour is covered by the existing `test_real_cosign_proof.py` (kept green in Task 4); the evidence-pack path is sign-only (no kernel verify) and gets no real round-trip per spec §7.

**Files:**
- Create: `tests/integration/cli/__init__.py` (empty — integration subdirs carry `__init__.py`, e.g. `tests/integration/models/__init__.py`).
- Create: `tests/integration/cli/test_real_cosign_sign_verify_proof.py`.

- [ ] **Step 1: Create the `__init__.py`.**
  ```
  : > tests/integration/cli/__init__.py   # (create the empty package marker)
  ```
- [ ] **Step 2: Write the proof.** `tests/integration/cli/test_real_cosign_sign_verify_proof.py`:
  ```python
  """Real-cosign 3.x proof of the CLI/pack legacy-compat bridge (ADR-016).

  Env-gated on COGNIC_RUN_COSIGN_INTEGRATION=1. Default pytest runs skip
  the module. When opted in, the fixture FAILS LOUD if cosign is missing
  from PATH (AssertionError -> pytest ERROR, never SKIP) — the opt-in env
  var is the "I have cosign" contract.

  Proves: real `agentos sign-blob` produces an OFFLINE cosign.sig + bundle
  on cosign 3.x (no Rekor tlog entry), and both the cli/verify.py and the
  runtime trust_gate verify-blob argv shapes verify it. This unblocks
  Proof 1a Task 6.
  """

  from __future__ import annotations

  import json
  import os
  import subprocess
  from pathlib import Path

  import pytest
  from typer.testing import CliRunner

  from cognic_agentos.cli import app
  from cognic_agentos.cli.verify import _exec_cosign_verify_blob
  from cognic_agentos.core.audit import AuditStore
  from cognic_agentos.core.config import Settings
  from cognic_agentos.protocol.trust_gate import TrustGate

  pytestmark = pytest.mark.skipif(
      os.environ.get("COGNIC_RUN_COSIGN_INTEGRATION") != "1",
      reason=(
          "real-cosign CLI/pack proof; opt in via COGNIC_RUN_COSIGN_INTEGRATION=1 "
          "(requires cosign on PATH at the target version — fails loud if missing)"
      ),
  )


  @pytest.fixture
  def real_cosign(tmp_path: Path) -> dict[str, object]:
      import shutil

      cosign = shutil.which("cosign")
      assert cosign is not None, (
          "cosign binary not found on PATH; opt-in env "
          "COGNIC_RUN_COSIGN_INTEGRATION=1 implies cosign is available — this "
          "fixture fails LOUD rather than silently skipping the proof."
      )
      env = {"COSIGN_PASSWORD": "", "PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)}
      keys = tmp_path / "keys"
      keys.mkdir()
      subprocess.run([cosign, "generate-key-pair"], cwd=keys, env=env, check=True, capture_output=True)
      return {"cosign": cosign, "private": keys / "cosign.key", "public": keys / "cosign.pub", "env": env}


  async def test_cli_sign_then_verify_offline_roundtrip_on_real_cosign(
      real_cosign: dict[str, object], tmp_path: Path
  ) -> None:
      # Layout: signature_root_path holds the wheel + produced cosign.sig +
      # bundle.sigstore; trust_root_prefix/_default holds cosign.pub.
      sig_root = tmp_path / "sig_root"
      sig_root.mkdir()
      trust_prefix = tmp_path / "trust_prefix"
      (trust_prefix / "_default").mkdir(parents=True)
      trust_root = trust_prefix / "_default" / "cosign.pub"
      trust_root.write_bytes(Path(real_cosign["public"]).read_bytes())  # type: ignore[arg-type]

      wheel = sig_root / "demo_pack-1.0.0-py3-none-any.whl"
      wheel.write_bytes(b"real-cosign-3x-proof-wheel-bytes")

      # 1) Real `agentos sign-blob` — Task 1's fixed argv produces the
      #    detached cosign.sig + the OFFLINE bundle on cosign 3.x.
      env = {
          "COGNIC_COSIGN_PATH": str(real_cosign["cosign"]),
          "COGNIC_SIGNING_KEY_PATH": str(real_cosign["private"]),
          "COSIGN_PASSWORD": "",
      }
      for key, value in env.items():
          os.environ[key] = value
      try:
          result = CliRunner().invoke(app, ["sign-blob", str(wheel)])
      finally:
          for key in env:
              os.environ.pop(key, None)
      assert result.exit_code == 0, f"agentos sign-blob failed: {result.stdout}\n{result.stderr}"

      sig = wheel.parent / "cosign.sig"
      bundle = wheel.parent / "bundle.sigstore"
      assert sig.is_file() and sig.stat().st_size > 0
      assert bundle.is_file() and bundle.stat().st_size > 0

      # 2) OFFLINE assertion: the legacy bundle carries no transparency-log
      #    proof under either the legacy (rekorBundle) or new (tlogEntries)
      #    key — --tlog-upload=false meant nothing was uploaded.
      bundle_json = json.loads(bundle.read_text())
      assert not bundle_json.get("tlogEntries"), "bundle has tlogEntries — not offline"
      assert not bundle_json.get("rekorBundle"), "bundle has rekorBundle — not offline"

      # 3) cli/verify.py argv shape verifies on real cosign (Task 2 flags).
      verify_finding = await _exec_cosign_verify_blob(
          str(real_cosign["cosign"]),
          wheel,
          sig_path=sig,
          bundle_path=bundle,
          trust_root_path=str(trust_root),
          timeout_s=30.0,
      )
      assert verify_finding is None, f"cli/verify.py verify-blob rejected the offline pack: {verify_finding}"

      # 4) Runtime trust_gate.verify_pack_signature round-trip (Task 3
      #    bundle + offline flags) verifies the same artifacts on real cosign.
      settings = Settings(
          cosign_path=str(real_cosign["cosign"]),
          signature_root_path=sig_root,
          trust_root_prefix=trust_prefix,
          require_cosign=True,
      )
      gate = TrustGate(settings=settings, audit_store=AuditStore(None))  # see note below
      verified = await gate.verify_pack_signature(
          pack_id="demo_pack",
          version="1.0.0",
          signature_path=sig,
          bundle_path=bundle,
          blob_path=wheel,
          trust_root=trust_root,
      )
      assert verified.verified is True
      assert verified.signature_digest != "cosign-skipped:require_cosign=false"
  ```
  **Implementer note for Step 2:** construct `TrustGate` + `Settings` exactly as the existing `test_trust_gate.py` fixtures do — read its `settings_factory` (`:121-145`) and the `audit_store` fixture to match the real `AuditStore` constructor and any required `Settings` fields (`signature_root_path`, `trust_root_prefix`, `cosign_verify_timeout_s`). The pseudo-`AuditStore(None)` above is a placeholder for "however the test suite builds an AuditStore"; use the suite's real construction. The trust-gate round-trip needs no audit emission on the green path (the audit store is only touched on the timeout path), so a minimal in-memory store suffices.
- [ ] **Step 3: Confirm default-run skip + opted-in behaviour.**
  ```
  uv run pytest tests/integration/cli/test_real_cosign_sign_verify_proof.py -q
  ```
  Expected (default, no env): `1 skipped` (or `s`), zero failures.
  ```
  COGNIC_RUN_COSIGN_INTEGRATION=1 uv run pytest tests/integration/cli/test_real_cosign_sign_verify_proof.py -q
  ```
  Expected when cosign 3.x is installed: `1 passed`. When opted in but cosign absent: pytest `ERROR` from the fail-loud fixture assertion (NOT skip).
- [ ] **Step 4: Run the full standing gate (default skip keeps it green).**
  ```
  uv run pytest tests/integration/cli/test_real_cosign_sign_verify_proof.py -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: pytest `1 skipped`; ruff/format/mypy green (the new file type-checks even though it is skipped at runtime).
- [ ] **Step 5 (controller commits on the human's per-task token):**
  ```
  git add tests/integration/cli/__init__.py tests/integration/cli/test_real_cosign_sign_verify_proof.py
  git commit
  ```
  Message:
  ```
  test(supply-chain): env-gated real-cosign 3.x CLI/pack sign+verify offline proof

  New COGNIC_RUN_COSIGN_INTEGRATION=1 proof: real `agentos sign-blob` produces an
  offline cosign.sig + bundle on cosign 3.x; both cli/verify.py and the runtime
  trust_gate verify-blob shapes verify it; asserts the bundle carries no tlog
  entry. Fail-loud when opted in but cosign missing. Unblocks Proof 1a Task 6.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 7: ADR-016 amendment — record the cosign-3.x legacy-compat bridge

Per spec §8: a focused amendment to `docs/adrs/ADR-016-supply-chain-controls.md` recording (a) the compat-flag requirement on the sign + verify argv; (b) the offline/no-Rekor posture via `--tlog-upload=false` + `--insecure-ignore-tlog`; (c) the caveat that this is a legacy-compat bridge riding cosign's deprecated `--tlog-upload` + `--output-signature` flags, with **Fork B (bundle-only) as the tracked long-term cleanup**. No filename/contract change.

**Files:**
- Modify: `docs/adrs/ADR-016-supply-chain-controls.md` (confirmed present).

- [ ] **Step 1: Read the ADR + locate the amendment site.**
  ```
  ls docs/adrs/ADR-016*
  ```
  Then read the file and find the trailing "Amendments" / status section (mirror the prose style of the existing amendments referenced from CLAUDE.md, e.g. the way ADR-002 "Sprint 13.8 amendment" entries read).
- [ ] **Step 2: Append the amendment** (no edits to the original decision body; additive amendment block). Suggested content:
  ```markdown
  ## Amendment (2026-06-22) — cosign 3.x legacy-compat bridge (Fork A)

  cosign 3.x changed the `sign-blob` defaults: it defaults to
  `--new-bundle-format=true`, deprecates + ignores `--output-signature`, and
  uploads to public Rekor by default. The kernel's pack/CLI signing path was
  hard-wired to cosign 2.x's detached-signature contract and broke (the
  `cosign.sig` artifact was never produced). This amendment adopts **Fork A —
  a legacy-compat bridge** that keeps the existing `cosign.sig` + `bundle.sigstore`
  attestation contract (filenames, `PackAttestations`, the resolver required-set,
  the `SignatureRedReason` 5-gate vocab, and all manifest templates UNCHANGED) by
  adding the verified compat flags. Verified on cosign 3.0.6.

  **Sign argv** (`cli/sign.py`, `compliance/iso42001/signing.py`): add
  `--tlog-upload=false --use-signing-config=false --new-bundle-format=false`.
  `--tlog-upload=false` is what disables the public-Rekor upload (air-gapped-
  correct); the evidence-pack signing path (`compliance/iso42001/signing.py`) adds
  only `--tlog-upload=false` (it already carried the other two).

  **Verify argv** (`cli/verify.py`, `protocol/trust_gate.py`): add
  `--insecure-ignore-tlog --new-bundle-format=false` (the offline-signed artifact
  has no Rekor entry, so verify must not search the public log). `trust_gate.
  verify_pack_signature` additionally gains a required `bundle_path: Path`
  parameter + passes `--bundle`; `signature_digest` stays the SHA-256 of
  `cosign.sig`. The model path (`models/trust.py`) is bundle-only and adds only
  `--insecure-ignore-tlog` (no `--signature`, no `--new-bundle-format=false`).

  **Posture:** signing is now offline / no public Rekor upload by default.

  **Known debt + long-term cleanup (Fork B):** this bridge deliberately rides
  cosign's **deprecated-but-functional** `--tlog-upload` + `--output-signature`
  flags (both emit deprecation warnings on 3.0.6 and are on cosign's removal path).
  When cosign removes them, **Fork B — true bundle-only verification (drop
  `cosign.sig`, verify against `--bundle` only, converge on the `models/trust.py`
  shape)** becomes mandatory for the pack path; it is tracked as the long-term
  cleanup (it touches the wire-public attestation vocab + must separately solve
  air-gapped signing, so it is out of scope for this bridge). The narrow model-path
  `--insecure-ignore-tlog` is a current, non-deprecated flag and does not carry
  this debt.
  ```
- [ ] **Step 3: Run the full standing gate** (docs-only; confirm nothing regressed + the markdown is clean).
  ```
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  ```
  Expected: all green (no code touched). Optionally run a fast subset of the touched suites to confirm the branch is still green end-to-end:
  ```
  uv run pytest tests/unit/cli/ tests/unit/protocol/test_trust_gate.py tests/unit/models/test_trust.py tests/unit/compliance/iso42001/ -q
  ```
  Expected: `… passed`.
- [ ] **Step 4 (controller commits on the human's per-task token):**
  ```
  git add docs/adrs/ADR-016-supply-chain-controls.md
  git commit
  ```
  Message:
  ```
  docs(adr-016): cosign 3.x legacy-compat bridge amendment

  Record the cosign-3.x compat-flag requirement on the sign + verify argv, the
  offline/no-Rekor posture (--tlog-upload=false + --insecure-ignore-tlog), and the
  legacy-bridge caveat (deprecated --tlog-upload/--output-signature) with Fork B
  (bundle-only) as the tracked long-term cleanup. No filename/contract change.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Self-review (inline)

- **Every spec §4 module change → a task.** §4.1 `cli/sign.py` → Task 1. §4.2 `cli/verify.py` → Task 2. §4.3 `trust_gate.py` → Task 3. §4.4 BOTH callers (`plugin_registry.py` + `review_routes.py`) + the `_signature_path_resolver.py` bundle projector → Task 3 (atomic). §4.5 `models/trust.py` → Task 4. §4.6 `compliance/iso42001/signing.py` → Task 5. ✅ (`_signature_path_resolver.py` is also promoted to the CC gate in Task 3 — count 134 → 135.)
- **§7 tests → tasks 1–6.** Pack-path argv drift-pins (Tasks 1, 2, 3); `trust_gate` fail-closed on bundle path + `require_cosign=False` skip unchanged + `signature_digest` unchanged (Task 3); model-path argv stays bundle-only (Task 4); evidence-pack argv `--tlog-upload=false` (Task 5); env-gated real-cosign offline proof + keep `test_real_cosign_proof.py` green (Task 6 + Task 4 Step 5). ✅
- **§8 ADR → Task 7.** ✅ records compat flags + offline posture + deprecated-flag caveat + Fork B cleanup; no contract change.
- **No placeholders.** Every argv step shows the real before→after list literal; every command shows expected output. The only deliberate "use the suite's real constructor" note is the `AuditStore`/`Settings` construction in Task 6 Step 2, flagged with the exact fixture to read (`test_trust_gate.py` `settings_factory` `:121-145`).
- **Flag strings byte-consistent across tasks:** `--tlog-upload=false` (Tasks 1, 5), `--use-signing-config=false` (Tasks 1, 5), `--new-bundle-format=false` (Tasks 1, 2, 3; deliberately ABSENT from Tasks 4 model + present in Task 5 evidence), `--insecure-ignore-tlog` (Tasks 2, 3, 4). ✅ Verified verbatim.
- **Real names match the code read:** param `bundle_path` (spec §4.3); `PackAttestations.sigstore_bundle_path` (`plugin_registry.py:483`); `review_routes.py` reuses `signature_bundle_path_unreachable`; the model full-list-pin test `test_argv_excludes_signature_flag_and_pins_bundle_only_shape` is the one that MUST be updated. ✅
- **No red commit:** Tasks 1/2/4/5 are single-module edits green at their own commit; Task 3 is atomic (required param + both callers + 13 test sites + helper in one commit); Task 6 is env-gated (default skip); Task 7 is docs. ✅
