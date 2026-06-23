# in-toto Wave-1 Layout Contract Reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the runtime trust gate (`protocol/supply_chain.py:_verify_intoto`) verify the AgentOS **Wave-1 simplified** in-toto layout the signer actually emits (option (b)), so real `agentos sign` packs are no longer refused at registration with `intoto_tampered` — while preserving the existing full-layout (`steps`+`expires`) branch unchanged.

**Architecture:** `_verify_intoto` branches on the layout's declared `_type`. The contract-type constant is single-sourced in the runtime (`protocol/supply_chain.py`) and imported by the signer (`cli/sign.py`). `pack_kind` is validated structurally only (membership in the canonical kind set); no manifest comparison.

**Tech Stack:** Python 3.12, uv, pytest. Two critical-controls modules under ADR-016 — `core-controls-engineer` + `/critical-module-mode`, 95% line / 90% branch.

**Source spec:** `docs/superpowers/specs/2026-06-23-intoto-wave1-contract-reconciliation-design.md`.

---

## Task 1: `_verify_intoto` Wave-1 simplified branch + single-sourced constant (ATOMIC CC)

The one atomic, multi-file commit: the constant moves `cli/sign.py → protocol/supply_chain.py` and the signer imports it, so both must land together (else `cli/sign.py` has a dangling reference). Both modules are critical controls.

**Files:**
- Modify: `src/cognic_agentos/protocol/supply_chain.py` — add the public `AGENTOS_INTOTO_LAYOUT_TYPE` constant + `_INTOTO_PACK_KINDS` tuple + the `_verify_intoto` `_type` branch + the `_verify_intoto_wave1_simplified` helper; extend `__all__`.
- Modify: `src/cognic_agentos/cli/sign.py` — delete the private `_AGENTOS_INTOTO_LAYOUT_TYPE` (`:182`), import the public constant from `protocol.supply_chain`, update the `_type` reference (`:1683`).
- Modify: `src/cognic_agentos/cli/verify.py` — **(plan-sync, found at implementation: a THIRD consumer the original plan missed)** `cli/verify.py` imports `_AGENTOS_INTOTO_LAYOUT_TYPE` from `cli/sign.py` for its `agentos verify` in-toto-layout check (`_check_intoto_layout_validity`). Deleting the private constant forces this: drop it from the `cli.sign` import, add `from cognic_agentos.protocol.supply_chain import AGENTOS_INTOTO_LAYOUT_TYPE`, and update its usages (3 references in `_check_intoto_layout_validity`). Part of the atomic single-source move (`cli/verify.py` is also a CC module).
- Test: `tests/unit/protocol/test_intoto_wave1_contract.py` (NEW) — the cross-contract round-trip + tamper negatives + the drift / single-source pins.
- Verify-only (no edit; confirm still green — they use the preserved full-layout branch): `tests/unit/protocol/test_supply_chain.py`, `tests/unit/cli/test_cli_sign.py`, and the hand-built-attestation admission tests (`test_fixture_pack_admission.py`, `test_registry_integration.py`, `test_mcp_fixture_pack_admission.py`).

- [ ] **Step 1: Write the failing cross-contract test (no hand-built fixture).** Create `tests/unit/protocol/test_intoto_wave1_contract.py`:
  ```python
  """ADR-016 in-toto Wave-1 contract: the signer's real
  _build_intoto_layout_dict output is accepted by the runtime
  _verify_intoto, and tampering it is refused. Cross-contract — imports
  from BOTH cli/sign.py (author) and protocol/supply_chain.py (runtime);
  no hand-built layout fixture.
  """

  from __future__ import annotations

  import json
  import typing
  from pathlib import Path

  import pytest

  from cognic_agentos.cli.sign import _build_intoto_layout_dict
  from cognic_agentos.packs.lifecycle import PackKind
  from cognic_agentos.protocol.supply_chain import (
      AGENTOS_INTOTO_LAYOUT_TYPE,
      IntotoTampered,
      SupplyChainPipeline,
      _INTOTO_PACK_KINDS,
  )


  def _real_layout() -> dict:
      return _build_intoto_layout_dict(
          pack_id="cognic-tool-search",
          pack_version="0.1.0",
          pack_kind="tool",
          signing_identity="cosign:proof@example.com",
          artifact_paths=["cognic_tool_search-0.1.0-py3-none-any.whl"],
      )


  def _write(tmp_path: Path, layout: dict) -> Path:
      p = tmp_path / "intoto-layout.json"
      p.write_text(json.dumps(layout), encoding="utf-8")
      return p


  def test_real_signer_output_is_accepted_by_runtime(tmp_path: Path) -> None:
      # The contract pin: real author output -> runtime verify, no raise.
      SupplyChainPipeline._verify_intoto(_write(tmp_path, _real_layout()))


  def test_signer_declares_the_single_sourced_runtime_constant() -> None:
      # cli/sign.py emits exactly the _type the runtime accepts.
      assert _real_layout()["_type"] == AGENTOS_INTOTO_LAYOUT_TYPE
      assert AGENTOS_INTOTO_LAYOUT_TYPE == "in-toto-layout/v1-wave1-simplified"


  def test_kind_tuple_matches_canonical_packkind() -> None:
      assert set(_INTOTO_PACK_KINDS) == set(typing.get_args(PackKind))


  @pytest.mark.parametrize(
      "mutate",
      [
          lambda d: d.update(pack_kind="malware"),
          lambda d: d.update(pack_kind=""),
          lambda d: d.update(pack_kind="  "),
          lambda d: d.pop("signing_identity"),
          lambda d: d.update(signing_identity="  "),
          lambda d: d.update(artifact_paths=[]),
          lambda d: d.update(artifact_paths=["ok", ""]),
          lambda d: d.update(artifact_paths="not-a-list"),
          lambda d: d.pop("pack_id"),
          lambda d: d.update(pack_version="   "),
      ],
  )
  def test_tampered_wave1_layout_is_refused(tmp_path: Path, mutate) -> None:
      layout = _real_layout()
      mutate(layout)
      with pytest.raises(IntotoTampered):
          SupplyChainPipeline._verify_intoto(_write(tmp_path, layout))


  def test_full_layout_branch_preserved(tmp_path: Path) -> None:
      # A non-simplified layout (no AgentOS _type) still goes through the
      # steps+expires branch: valid passes, malformed raises.
      good = {"steps": [{"name": "build"}], "expires": "2030-01-01T00:00:00Z"}
      SupplyChainPipeline._verify_intoto(_write(tmp_path, good))
      bad = {"steps": [], "expires": "2030-01-01T00:00:00Z"}
      with pytest.raises(IntotoTampered):
          SupplyChainPipeline._verify_intoto(_write(tmp_path, bad))
  ```
  **Implementer note:** confirm `_verify_intoto` is a `@staticmethod` on `SupplyChainPipeline` (call shape `SupplyChainPipeline._verify_intoto(path)` — it is, at `supply_chain.py:603-604`). Confirm `IntotoTampered` + `SupplyChainPipeline` are importable from `protocol.supply_chain` (they are; in `__all__`). If `_build_intoto_layout_dict`'s real signature differs from the kwargs above, use the REAL one + report.
- [ ] **Step 2: Run it — expect FAIL.**
  ```
  uv run pytest tests/unit/protocol/test_intoto_wave1_contract.py -q
  ```
  Expected: `test_real_signer_output_is_accepted_by_runtime` FAILS with `IntotoTampered: ... missing or empty 'steps'` (the bug); the single-source + import tests fail with `ImportError`/`AttributeError` (`AGENTOS_INTOTO_LAYOUT_TYPE` / `_INTOTO_PACK_KINDS` don't exist yet); the tamper tests may pass trivially (everything raises pre-fix).
- [ ] **Step 3: Add the runtime constant + kind tuple + `__all__` entry.** In `protocol/supply_chain.py`, near `INTOTO_PREDICATE_TYPE_PREFIX` (`:78`):
  ```python
  #: ADR-016 Wave-1 simplified AgentOS in-toto layout type. The signer
  #: (cli/sign.py:_build_intoto_layout_dict) declares this _type; the
  #: runtime verifies the simplified contract (no full step-graph in
  #: Wave-1). Single source of truth — cli/sign.py imports it.
  AGENTOS_INTOTO_LAYOUT_TYPE: Final[str] = "in-toto-layout/v1-wave1-simplified"
  #: Canonical pack kinds for the Wave-1 layout's pack_kind structural
  #: check. Drift-pinned == PackKind in test_intoto_wave1_contract.py
  #: (no runtime import of packs.lifecycle — keep the layering arrow).
  _INTOTO_PACK_KINDS: Final[tuple[str, ...]] = ("tool", "skill", "agent", "hook")
  ```
  Add `"AGENTOS_INTOTO_LAYOUT_TYPE",` to `__all__` (`:1055` block). (Confirm `Final` is imported in `supply_chain.py`; if not, add `from typing import Final`.)
- [ ] **Step 4: Add the `_type` branch + the simplified-validator helper.** In `_verify_intoto`, after `if not isinstance(layout, dict): raise IntotoTampered(... predicate not a JSON object)` (`:648-649`) and BEFORE the `steps = layout.get("steps")` line (`:660`), insert:
  ```python
          # ADR-016 Wave-1 simplified AgentOS layout: the signer declares
          # _type=AGENTOS_INTOTO_LAYOUT_TYPE and intentionally omits the
          # full step-graph + expiration (Wave-2). Verify the simplified
          # contract's security fields — same present-structural
          # hard-refusal class — instead of demanding steps/expires the
          # signer never emits.
          if layout.get("_type") == AGENTOS_INTOTO_LAYOUT_TYPE:
              SupplyChainPipeline._verify_intoto_wave1_simplified(layout, layout_path)
              return
  ```
  Then add the helper as a `@staticmethod` on `SupplyChainPipeline` immediately AFTER `_verify_intoto`:
  ```python
      @staticmethod
      def _verify_intoto_wave1_simplified(layout: dict[str, Any], layout_path: Path) -> None:
          """Structurally validate the ADR-016 Wave-1 simplified in-toto
          layout. Required: pack_id / pack_version / signing_identity
          (non-blank strings); pack_kind (non-blank, a member of
          _INTOTO_PACK_KINDS); artifact_paths (non-empty list of non-blank
          strings). Any missing / blank / wrong-type → IntotoTampered
          (present-structural hard-refusal, same class as the full-layout
          branch). pack_kind is validated structurally only — cross-layer
          manifest kind-flip comparison is out of scope (matches the
          structural-only posture of _verify_slsa)."""
          for field in ("pack_id", "pack_version", "signing_identity"):
              value = layout.get(field)
              if not isinstance(value, str) or not value.strip():
                  raise IntotoTampered(
                      f"in-toto Wave-1 layout at {layout_path!s} missing or blank {field!r}"
                  )
          pack_kind = layout.get("pack_kind")
          if not isinstance(pack_kind, str) or pack_kind.strip() not in _INTOTO_PACK_KINDS:
              raise IntotoTampered(
                  f"in-toto Wave-1 layout at {layout_path!s} has missing or unknown "
                  f"pack_kind={pack_kind!r} (expected one of {_INTOTO_PACK_KINDS})"
              )
          artifact_paths = layout.get("artifact_paths")
          if not isinstance(artifact_paths, list) or len(artifact_paths) == 0:
              raise IntotoTampered(
                  f"in-toto Wave-1 layout at {layout_path!s} missing or empty 'artifact_paths'"
              )
          for index, entry in enumerate(artifact_paths):
              if not isinstance(entry, str) or not entry.strip():
                  raise IntotoTampered(
                      f"in-toto Wave-1 layout at {layout_path!s} artifact_paths[{index}] "
                      f"is not a non-blank string"
                  )
  ```
  (Confirm `Any` is imported in `supply_chain.py` — it is, used throughout. The full-layout `steps`+`expires` block below stays UNCHANGED.)
- [ ] **Step 5: Single-source the constant in `cli/sign.py`.** Delete the private definition `_AGENTOS_INTOTO_LAYOUT_TYPE: Final[str] = "in-toto-layout/v1-wave1-simplified"` (`:182`); add `from cognic_agentos.protocol.supply_chain import AGENTOS_INTOTO_LAYOUT_TYPE` to the imports (confirm NO circular import — `protocol/supply_chain.py` does not import `cli`; if mypy/runtime flags a cycle, STOP + report); update the reference at `:1683` from `"_type": _AGENTOS_INTOTO_LAYOUT_TYPE,` to `"_type": AGENTOS_INTOTO_LAYOUT_TYPE,`. Update the existing `test_cli_sign.py` assertion that references the old private constant name (if any) to the imported public name.
- [ ] **Step 6: Run the new + touched tests — expect PASS.**
  ```
  uv run pytest tests/unit/protocol/test_intoto_wave1_contract.py tests/unit/protocol/test_supply_chain.py tests/unit/cli/test_cli_sign.py -q
  ```
  Expected: all `passed` (cross-contract green, tamper negatives meaningful, full-layout preserved, the cli-sign suite green with the imported constant).
- [ ] **Step 7: Full gate + critical-controls coverage** (both modules are on the durable CC gate).
  ```
  uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
  uv run ruff check
  uv run ruff format --check
  uv run mypy src tests
  uv run python tools/check_critical_coverage.py
  ```
  Expected: full suite green; `check_critical_coverage` reports `cli/sign.py` + `protocol/supply_chain.py` at/above the 95/90 floor on the FRESH `coverage.json`; ruff/format/mypy clean.
- [ ] **Step 8 (controller commits on the human's per-task token):**
  ```
  git add src/cognic_agentos/protocol/supply_chain.py src/cognic_agentos/cli/sign.py src/cognic_agentos/cli/verify.py tests/unit/protocol/test_intoto_wave1_contract.py docs/superpowers/plans/2026-06-23-intoto-wave1-contract-reconciliation.md
  git commit
  ```
  (`cli/verify.py` = the third-consumer plan-sync; the plan file = the file-list correction, folded into this commit per the cosign discipline. Plus `tests/unit/cli/test_cli_sign.py` ONLY if Step 5 had to update a constant-name reference there.) Message:
  ```
  fix(supply-chain): runtime verifies the Wave-1 simplified in-toto contract (ADR-016)

  _verify_intoto now branches on the declared _type: a layout declaring
  AGENTOS_INTOTO_LAYOUT_TYPE is validated structurally (pack_id / pack_version /
  pack_kind∈{tool,skill,agent,hook} / signing_identity / artifact_paths) instead of
  demanding the full steps+expires layout the Wave-1 signer never emits — so real
  `agentos sign` packs are no longer refused at registration with intoto_tampered.
  The full-layout branch is preserved. The contract type is single-sourced in
  protocol/supply_chain.py + imported by cli/sign.py. pack_kind is structural-only
  (no manifest kind-flip comparison — separate concern). Surfaced by Proof 1a Task 7.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
  ```

---

## Task 2: ADR-016 amendment

**Files:** Modify `docs/adrs/ADR-016-supply-chain-controls.md`.

- [ ] **Step 1: Append a focused amendment** before `## References` (mirror the 2026-06-22 cosign amendment placement):
  ```markdown
  ## Amendment (2026-06-23) — in-toto Wave-1 simplified layout contract

  `agentos sign` emits a **Wave-1 simplified** in-toto layout declaring
  `_type = "in-toto-layout/v1-wave1-simplified"` that intentionally omits the full
  in-toto step-graph + expiration (deferred to Wave-2). The runtime trust gate
  (`protocol/supply_chain.py:_verify_intoto`) verifies this declared contract by
  branching on `_type`: a simplified layout is validated on its security fields —
  `pack_id`, `pack_version`, `pack_kind` (∈ `{tool, skill, agent, hook}`),
  `signing_identity`, `artifact_paths` (non-empty list of non-blank strings) — all
  present-structural hard-refusals (`IntotoTampered`). A layout without that `_type`
  still goes through the full `steps`+`expires` branch (unchanged). The contract type
  is single-sourced as `AGENTOS_INTOTO_LAYOUT_TYPE` in `protocol/supply_chain.py` and
  imported by `cli/sign.py`. `pack_kind` is validated structurally only; the full
  in-toto layout (steps / inspections / key-thresholds) and a cross-layer manifest
  pack_kind-flip comparison remain Wave-2. Surfaced + proven by Proof 1a Task 7 (the
  first real `agentos sign` → runtime registration exercise).
  ```
- [ ] **Step 2: Gate (docs-only).**
  ```
  uv run ruff check
  uv run ruff format --check
  ```
  Expected: clean (no code touched).
- [ ] **Step 3 (controller commits on the human's per-task token):**
  ```
  git add docs/adrs/ADR-016-supply-chain-controls.md
  git commit
  ```
  Message:
  ```
  docs(adr-016): in-toto Wave-1 simplified layout contract amendment

  Record that the runtime trust gate verifies the declared
  in-toto-layout/v1-wave1-simplified contract (security-field structural checks)
  rather than a full steps+expires layout, single-sourced constant, structural-only
  pack_kind. Per the Proof 1a Task 7 finding.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
  ```

---

## Task 3: housekeeping — gitignore generated attestations (separate, trivial)

> **Branch note:** Task 3 lands on the **`feat/pack-loop-proof-1a`** branch (post-merge of the fix branch), NOT on `fix/intoto-wave1-contract` — `examples/cognic-tool-search/` does not exist on `main`, so the ignore is only meaningful where the generated directory lives (the Proof-1a workflow). The `fix/intoto-wave1-contract` branch carries Tasks 1–2 only.

**Files:** Modify `.gitignore`.

- [ ] **Step 1: Add the generated-attestations line.** Append under the existing `examples/cognic-tool-search/dist/` (or equivalent) ignore (confirm the existing `dist/` ignore + mirror its placement):
  ```
  examples/cognic-tool-search/attestations/
  ```
  (Generated by the real `agentos sign` in `_authoring.build_sign_verify`; like its `dist/` sibling it must never reach a commit.)
- [ ] **Step 2: Confirm the directory is now ignored.**
  ```
  git status --short examples/cognic-tool-search/
  git check-ignore examples/cognic-tool-search/attestations/
  ```
  Expected: `git status` no longer lists `attestations/`; `check-ignore` echoes the path.
- [ ] **Step 3 (controller commits on the human's per-task token):**
  ```
  git add .gitignore
  git commit
  ```
  Message:
  ```
  chore: gitignore generated cognic-tool-search attestations

  The real `agentos sign` run in the Proof-1a authoring helper writes
  examples/cognic-tool-search/attestations/; ignore it like its dist/ sibling so
  generated attestations never reach a commit.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
  ```

---

## After the slice — resume Proof 1a Task 7

Not part of this slice's commits. Once Task 1 is committed: rerun
`COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py -v` — the harness (currently honestly RED at assertion 2 with `intoto_tampered`) should turn **green** (assertions 2–5). Then the Proof 1a Task 7 harness becomes committable on its own per-task token (the integration proof).

## Self-review (inline)

- **Spec §3 → tasks.** §3.1 single-sourced constant → Task 1 Steps 3+5. §3.2 `_type` branch + simplified validator → Task 1 Step 4. §3.3 preserve full-layout → Task 1 Step 4 (insert before `steps`, leave the block) + `test_full_layout_branch_preserved`. §4 test pins → Task 1 Step 1. §5 gates → Task 1 Step 7. §6 ADR → Task 2. §7 gitignore → Task 3. ✅
- **No placeholders.** Every code step shows the real before-anchor + the inserted code; the test module is complete.
- **Atomicity.** The constant move + the import land in ONE commit (Task 1) — no dangling reference. The `.gitignore` + ADR are separate commits per the spec ("not bundled into a CC code commit").
- **Names match the code read:** `_verify_intoto` is a `@staticmethod` at `:604`; `IntotoTampered` + `SupplyChainPipeline` in `__all__`; the insert point is between `:649` and `:660`; `PackKind` at `packs/lifecycle.py:111`; the cli `_type` reference at `:1683`; the private constant at `:182`. ✅
