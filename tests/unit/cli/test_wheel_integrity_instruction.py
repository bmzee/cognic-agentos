"""M8 finding #3 (maintainer-verified, 2026-07-06) — instruction-wheel
sign/verify integrity arm regressions.

M8 instruction-only skill packs (``[pack] kind="skill"`` +
``[skill] mode="instruction"``) are CONTENT packs: SKILL.md + the signed
``cognic-pack-manifest.toml`` as package data inside one stub package, NO
entry points of any kind (by design — the A7 validator refuses a
``cognic.skills`` entry point; the B2-pre manifest-walk discovery arm
discovers them at boot). Pre-fix, the sign/verify wheel-integrity path was
entry-point-anchored:

  - ``cli/_wheel_integrity.py`` hard-failed a wheel without
    ``entry_points.txt`` (``wheel_missing_entry_points_file``).
  - ``cli/verify.py`` Step 11 fail-closed with
    ``load_probe_no_validated_entry_points`` on an empty validated
    entry-point tuple.

The fix adds a NARROW instruction arm mirroring the B2-pre discovery arm at
the wheel layer: absent ``entry_points.txt`` may pass ONLY when the wheel
ships exactly one package-local ``cognic-pack-manifest.toml`` declaring
``kind="skill"`` + ``[skill].mode="instruction"`` (dual-path); Step 11 then
runs a REAL isolated module-import probe (``importlib.import_module`` on the
validated stub package — never a faked EntryPoint). Every other
zero-entry-point wheel fails exactly as before.

Test sections:

  (a) Integrity happy path — instruction wheel passes with derived kind
      "skill", EMPTY validated entry-points, and the validated instruction
      package name threaded through the (extended) return.
  (b) Integrity refusals — zero-manifest byte-pin (EXACT pre-fix failure);
      ambiguity (two manifests); kind/mode strict-filter TM-revert pins;
      malformed/oversized manifest; package-layout (anti-decoy) refusals;
      METADATA anchoring still applies to instruction wheels.
  (c) Entry-point wheels — behavior-pin: unchanged values + ``None`` in
      the additive instruction-package slot.
  (d) Module-import probe — real built wheels driven through the isolated
      subprocess probe (clean import / raising ``__init__`` / missing
      import / stdout garbage / timeout / missing package / subprocess
      error).
  (e) Lockstep drift detector — the ``_wheel_integrity``-local dual-path
      manifest readers agree with the ``protocol/plugin_registry`` copies
      (test-only imports; NO runtime cross-import per
      feedback_drift_detector_test_only_no_runtime_import).

Per the maintainer dispatch: real built-wheel fixtures (PEP-427-complete
zips: ``<pkg>/__init__.py`` + ``<pkg>/cognic-pack-manifest.toml`` +
``<pkg>/SKILL.md`` + ``dist-info/{METADATA,WHEEL,RECORD}``, NO
entry_points.txt), not only source-tree tests.
"""

from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli._load_probe import (
    LoadProbeFailure,
    probe_module_importability,
)
from cognic_agentos.cli._wheel_integrity import (
    WheelIntegrityFailure,
    read_signed_wheel_dist_info_metadata,
)

# ---------------------------------------------------------------------------
# Fixture builder — real PEP-427-complete instruction wheels
# ---------------------------------------------------------------------------

_DEFAULT_PACKAGE = "cognic_skill_customer_data"
_DEFAULT_PROJECT = "cognic-skill-customer-data"
_DEFAULT_VERSION = "0.1.0"

#: Canonical instruction-skill manifest (the M8 A7 shape) written into the
#: wheel's package-data slot.
_INSTRUCTION_MANIFEST = (
    "[pack]\n"
    f'pack_id = "{_DEFAULT_PROJECT}"\n'
    "schema_version = 1\n"
    'kind = "skill"\n'
    "\n"
    "[skill]\n"
    'mode = "instruction"\n'
)

#: Legacy dual-path spelling of the same manifest (the R23 doctrine —
#: ``[tool.cognic.pack]`` + ``[tool.cognic.skill]``).
_INSTRUCTION_MANIFEST_LEGACY = (
    "[tool.cognic.pack]\n"
    f'pack_id = "{_DEFAULT_PROJECT}"\n'
    "schema_version = 1\n"
    'kind = "skill"\n'
    "\n"
    "[tool.cognic.skill]\n"
    'mode = "instruction"\n'
)

_SKILL_MD = (
    "---\n"
    "name: customer-data\n"
    "description: Teaches governed retail views for customer questions.\n"
    "---\n"
    "\n"
    "# Instructions\n"
    "\n"
    "Author SQL over the governed views only.\n"
)


def _build_instruction_wheel(
    dest_dir: Path,
    *,
    project_snake: str = _DEFAULT_PACKAGE,
    version: str = _DEFAULT_VERSION,
    packages: tuple[str, ...] = (_DEFAULT_PACKAGE,),
    manifest_texts: dict[str, str | bytes] | None = None,
    default_manifest: str | bytes | None = _INSTRUCTION_MANIFEST,
    include_init: bool = True,
    include_skill_md: bool = True,
    init_source: str = "",
    metadata_name: str | None = None,
    metadata_version: str | None = None,
    extra_members: dict[str, str | bytes] | None = None,
) -> Path:
    """Build a REAL PEP-427-complete instruction wheel in ``dest_dir``.

    Members per package: ``<pkg>/__init__.py`` (unless ``include_init``
    is False), ``<pkg>/cognic-pack-manifest.toml`` (from
    ``manifest_texts[pkg]`` falling back to ``default_manifest``; ``None``
    omits it), ``<pkg>/SKILL.md``. Plus
    ``<dist>-<ver>.dist-info/{METADATA,WHEEL,RECORD}`` and — by design —
    NO ``entry_points.txt`` (instruction packs are zero-entry-point
    content packs).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    wheel = dest_dir / f"{project_snake}-{version}-py3-none-any.whl"
    dist_info = f"{project_snake}-{version}.dist-info"
    members: dict[str, str | bytes] = {}
    for pkg in packages:
        if include_init:
            members[f"{pkg}/__init__.py"] = init_source
        manifest: str | bytes | None
        if manifest_texts is not None and pkg in manifest_texts:
            manifest = manifest_texts[pkg]
        else:
            manifest = default_manifest
        if manifest is not None:
            members[f"{pkg}/cognic-pack-manifest.toml"] = manifest
        if include_skill_md:
            members[f"{pkg}/SKILL.md"] = _SKILL_MD
    members[f"{dist_info}/METADATA"] = (
        "Metadata-Version: 2.1\n"
        f"Name: {metadata_name if metadata_name is not None else project_snake}\n"
        f"Version: {metadata_version if metadata_version is not None else version}\n"
    )
    members[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: agentos-test-fixture\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )
    if extra_members:
        members.update(extra_members)
    # PEP-427 RECORD listing every member (fixture-grade ``path,,`` rows —
    # RECORD itself carries no hash per the wheel spec).
    record_lines = [f"{name},," for name in [*sorted(members), f"{dist_info}/RECORD"]]
    members[f"{dist_info}/RECORD"] = "\n".join(record_lines) + "\n"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)
    return wheel


def _read(
    wheel: Path,
) -> tuple[
    tuple[str, str, str, tuple[tuple[str, str], ...], str | None] | None,
    WheelIntegrityFailure | None,
]:
    return read_signed_wheel_dist_info_metadata(
        wheel,
        expected_project_name=_DEFAULT_PROJECT,
        expected_version=_DEFAULT_VERSION,
    )


# ---------------------------------------------------------------------------
# (a) Integrity happy path
# ---------------------------------------------------------------------------


class TestInstructionWheelIntegrityHappyPath:
    def test_instruction_wheel_passes_with_skill_kind_and_package_name(
        self, tmp_path: Path
    ) -> None:
        """The core happy path: exactly-one package-local manifest with
        kind="skill" + mode="instruction" → integrity PASSES with derived
        kind "skill", EMPTY validated entry-points, and the validated
        instruction package name threaded through the additive 5th slot
        (verify Step 11 probes exactly this source — no re-discovery)."""
        wheel = _build_instruction_wheel(tmp_path / "dist")
        result, failure = _read(wheel)
        assert failure is None, f"instruction wheel refused: {failure!r}"
        assert result is not None
        name, version, kind, entry_points, instruction_package = result
        assert name == _DEFAULT_PROJECT
        assert version == _DEFAULT_VERSION
        assert kind == "skill"
        assert entry_points == ()
        assert instruction_package == _DEFAULT_PACKAGE

    def test_legacy_dual_path_manifest_accepted(self, tmp_path: Path) -> None:
        """The R23 dual-path doctrine: ``[tool.cognic.pack]`` +
        ``[tool.cognic.skill]`` legacy spellings classify identically."""
        wheel = _build_instruction_wheel(
            tmp_path / "dist", default_manifest=_INSTRUCTION_MANIFEST_LEGACY
        )
        result, failure = _read(wheel)
        assert failure is None, f"legacy-shaped instruction wheel refused: {failure!r}"
        assert result is not None
        assert result[2] == "skill"
        assert result[3] == ()
        assert result[4] == _DEFAULT_PACKAGE

    def test_metadata_anchoring_still_applies_to_instruction_wheels(self, tmp_path: Path) -> None:
        """METADATA Name/Version integrity anchoring is SHARED with the
        entry-point path — an instruction wheel whose METADATA Version
        disagrees with the wheel filename still refuses."""
        wheel = _build_instruction_wheel(tmp_path / "dist", metadata_version="0.2.0")
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_metadata_version_mismatch"

    def test_missing_metadata_file_still_refuses_instruction_wheel(self, tmp_path: Path) -> None:
        """An instruction wheel without dist-info METADATA fails the
        SAME ``wheel_missing_metadata_file`` arm as entry-point wheels —
        the instruction fallback never bypasses name+version anchoring."""
        wheel_dir = tmp_path / "dist"
        wheel = _build_instruction_wheel(wheel_dir)
        # Rebuild without METADATA.
        with zipfile.ZipFile(wheel) as zf:
            members = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/METADATA")}
        wheel.unlink()
        with zipfile.ZipFile(wheel, "w") as zf:
            for name, payload in members.items():
                zf.writestr(name, payload)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_missing_metadata_file"


# ---------------------------------------------------------------------------
# (b) Integrity refusals — closed-taxonomy + TM-revert pins
# ---------------------------------------------------------------------------


class TestInstructionWheelIntegrityRefusals:
    def test_zero_entry_point_wheel_without_manifest_fails_exactly_as_today(
        self, tmp_path: Path
    ) -> None:
        """BYTE-PIN of the pre-fix contract: a zero-entry-point wheel with
        NO package-local manifest fails with the EXACT existing
        ``wheel_missing_entry_points_file`` failure — same failure_mode,
        same message, same payload keys/values as before the instruction
        arm landed. Any other zero-entry-point wheel still fails exactly
        as today (maintainer constraint)."""
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=None)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_missing_entry_points_file"
        matched_dist_info = f"{_DEFAULT_PACKAGE}-{_DEFAULT_VERSION}.dist-info"
        assert failure.message == (
            f"wheel {wheel} dist-info {matched_dist_info!r} "
            "has no entry_points.txt; cannot derive an "
            "integrity-anchored pack kind."
        )
        assert failure.payload == {
            "wheel_path": str(wheel),
            "matched_dist_info": matched_dist_info,
        }

    def test_two_packages_each_with_manifest_refused_ambiguous(self, tmp_path: Path) -> None:
        """TM-revert pin (allow-multiple-manifests): a wheel shipping TWO
        package-local manifests is ambiguous and MUST fail closed — the
        SAME exactly-one rule as the B2-pre discovery arm applied at the
        wheel layer."""
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            packages=(_DEFAULT_PACKAGE, "cognic_skill_decoy"),
        )
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_multiple_instruction_manifests"
        assert sorted(failure.payload["manifest_members"]) == [
            f"{_DEFAULT_PACKAGE}/cognic-pack-manifest.toml",
            "cognic_skill_decoy/cognic-pack-manifest.toml",
        ]

    def test_manifest_kind_tool_refused(self, tmp_path: Path) -> None:
        """TM-revert pin (kind loosened): a zero-entry-point wheel whose
        manifest declares kind="tool" is NOT an instruction skill and MUST
        fail — a zero-entry-point executable pack is broken."""
        manifest = _INSTRUCTION_MANIFEST.replace('kind = "skill"', 'kind = "tool"')
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_kind_not_skill"
        assert failure.payload["declared_kind"] == "tool"

    def test_manifest_kind_absent_refused(self, tmp_path: Path) -> None:
        manifest = '[skill]\nmode = "instruction"\n'
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_kind_not_skill"

    def test_manifest_mode_executable_refused(self, tmp_path: Path) -> None:
        """TM-revert pin (mode loosened): kind="skill" + mode="executable"
        on a zero-entry-point wheel is a BROKEN executable pack, never an
        instruction pack — MUST fail."""
        manifest = _INSTRUCTION_MANIFEST.replace('mode = "instruction"', 'mode = "executable"')
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_mode_not_instruction"
        assert failure.payload["declared_mode"] == "executable"

    def test_manifest_mode_absent_refused(self, tmp_path: Path) -> None:
        """[skill].mode ABSENT defaults to "executable" (the A7/runtime
        classification) — a zero-entry-point kind="skill" wheel without
        instruction mode MUST fail."""
        manifest = '[pack]\nkind = "skill"\n\n[skill]\n'
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_mode_not_instruction"

    def test_manifest_skill_block_absent_refused(self, tmp_path: Path) -> None:
        manifest = '[pack]\nkind = "skill"\n'
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_mode_not_instruction"

    def test_manifest_mode_out_of_vocabulary_refused(self, tmp_path: Path) -> None:
        manifest = _INSTRUCTION_MANIFEST.replace('mode = "instruction"', 'mode = "banana"')
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=manifest)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_manifest_mode_not_instruction"

    def test_manifest_malformed_toml_refused(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(
            tmp_path / "dist", default_manifest="[pack\nkind = skill oops"
        )
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_unparseable_instruction_manifest"

    def test_manifest_non_utf8_refused(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=b"\xff\xfe[pack]\x00")
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_unparseable_instruction_manifest"

    def test_manifest_oversized_refused(self, tmp_path: Path) -> None:
        """The bounded-read contract: a manifest member larger than the
        1 MiB cap refuses BEFORE any TOML parse."""
        oversized = _INSTRUCTION_MANIFEST + "# pad\n" + ("x" * (1_048_577))
        wheel = _build_instruction_wheel(tmp_path / "dist", default_manifest=oversized)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_unparseable_instruction_manifest"
        assert "1048576" in failure.message or "1 MiB" in failure.message

    def test_package_missing_init_refused(self, tmp_path: Path) -> None:
        """Anti-decoy package-layout consistency: the manifest package must
        be an importable package in the wheel (``<pkg>/__init__.py``
        present — zipimport does not support namespace packages), so the
        Step-11 module-import probe operates on exactly the validated
        source."""
        wheel = _build_instruction_wheel(tmp_path / "dist", include_init=False)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_package_not_importable"
        assert failure.payload["package_name"] == _DEFAULT_PACKAGE

    def test_dist_info_planted_manifest_refused_not_importable(self, tmp_path: Path) -> None:
        """A manifest planted at ``<dist-info>/cognic-pack-manifest.toml``
        (2-part member, matches the scan rule — mirroring the discovery
        arm's raw dist.files walk) is NOT an importable package name and
        MUST fail the package-layout check."""
        wheel_dir = tmp_path / "dist"
        wheel_dir.mkdir(parents=True)
        wheel = wheel_dir / f"{_DEFAULT_PACKAGE}-{_DEFAULT_VERSION}-py3-none-any.whl"
        dist_info = f"{_DEFAULT_PACKAGE}-{_DEFAULT_VERSION}.dist-info"
        with zipfile.ZipFile(wheel, "w") as zf:
            zf.writestr(
                f"{dist_info}/METADATA",
                (f"Metadata-Version: 2.1\nName: {_DEFAULT_PACKAGE}\nVersion: {_DEFAULT_VERSION}\n"),
            )
            zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\n")
            zf.writestr(f"{dist_info}/cognic-pack-manifest.toml", _INSTRUCTION_MANIFEST)
        result, failure = _read(wheel)
        assert result is None
        assert failure is not None
        assert failure.failure_mode == "wheel_instruction_package_not_importable"


# ---------------------------------------------------------------------------
# (c) Entry-point wheels — behavior pin
# ---------------------------------------------------------------------------


class TestEntryPointWheelBehaviorUnchanged:
    def test_entry_point_wheel_returns_none_in_instruction_slot(self, tmp_path: Path) -> None:
        """Entry-point wheels are byte/behavior unchanged: same first four
        values as before the instruction arm; the additive 5th slot is
        ``None`` (the caller's instruction discriminator)."""
        wheel_path = tmp_path / "cognic_skill_exec-0.1.0-py3-none-any.whl"
        dist_info = "cognic_skill_exec-0.1.0.dist-info"
        with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                f"{dist_info}/entry_points.txt",
                "[cognic.skills]\nexec_skill = cognic_skill_exec.skill:ExecSkill\n",
            )
            zf.writestr(
                f"{dist_info}/METADATA",
                "Metadata-Version: 2.1\nName: cognic_skill_exec\nVersion: 0.1.0\n",
            )
            zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\n")
            zf.writestr("cognic_skill_exec/__init__.py", "")
            zf.writestr("cognic_skill_exec/skill.py", "class ExecSkill:\n    pass\n")
            # An entry-point wheel that ALSO carries a package-local
            # instruction manifest still rides the entry-point path — the
            # instruction fallback only fires when entry_points.txt is
            # ABSENT (mirrors the discovery arm's manifest-only rule).
            zf.writestr("cognic_skill_exec/cognic-pack-manifest.toml", _INSTRUCTION_MANIFEST)
        result, failure = read_signed_wheel_dist_info_metadata(
            wheel_path,
            expected_project_name="cognic-skill-exec",
            expected_version="0.1.0",
        )
        assert failure is None
        assert result is not None
        name, version, kind, entry_points, instruction_package = result
        assert name == "cognic-skill-exec"
        assert version == "0.1.0"
        assert kind == "skill"
        assert entry_points == (("cognic_skill_exec.skill", "ExecSkill"),)
        assert instruction_package is None


# ---------------------------------------------------------------------------
# (d) Module-import probe — real isolated-subprocess runs
# ---------------------------------------------------------------------------


def _probe(
    wheel: Path,
    *,
    package: str = _DEFAULT_PACKAGE,
    timeout_s: float = 30.0,
    python_executable: str | None = None,
) -> LoadProbeFailure | None:
    return asyncio.run(
        probe_module_importability(
            wheel,
            module_path=package,
            timeout_s=timeout_s,
            python_executable=python_executable,
        )
    )


class TestModuleImportProbe:
    def test_clean_instruction_package_probes_none(self, tmp_path: Path) -> None:
        """A well-formed instruction stub package imports cleanly in the
        isolated child; the per-invocation success token round-trips."""
        wheel = _build_instruction_wheel(tmp_path / "dist")
        assert _probe(wheel) is None

    def test_init_raising_fails_closed_module_runtime(self, tmp_path: Path) -> None:
        """TM-adjacent pin: the probe is REAL — a stub package whose
        ``__init__`` raises fails closed with the closed-enum
        ``load_probe_module_runtime_error``."""
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            init_source="raise RuntimeError('instruction stub must be inert')\n",
        )
        failure = _probe(wheel)
        assert failure is not None
        assert failure.failure_mode == "load_probe_module_runtime_error"
        assert failure.payload["probe_mode"] == "module_import"

    def test_init_missing_import_fails_module_import(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            init_source="import no_such_pkg_for_instruction_probe_test\n",
        )
        failure = _probe(wheel)
        assert failure is not None
        assert failure.failure_mode == "load_probe_module_import_failed"

    def test_package_absent_from_wheel_fails_module_import(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(tmp_path / "dist")
        failure = _probe(wheel, package="not_in_this_wheel")
        assert failure is not None
        assert failure.failure_mode == "load_probe_module_import_failed"

    def test_stdout_garbage_still_probes_clean(self, tmp_path: Path) -> None:
        """The devnull-discard hardening is shared with the entry-point
        probe: a package that floods stdout/stderr (including raw
        ``os.write``) still probes clean — the fd result channel is
        unaffected."""
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            init_source=(
                "import os, sys\n"
                "print('garbage' * 1000)\n"
                "sys.stderr.write('noise' * 1000)\n"
                "os.write(1, b'raw-noise')\n"
                "os.write(2, b'raw-err')\n"
            ),
        )
        assert _probe(wheel) is None

    def test_timeout_arm_sigkills_and_reports(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            init_source="import time\ntime.sleep(30)\n",
        )
        failure = _probe(wheel, timeout_s=0.5)
        assert failure is not None
        assert failure.failure_mode == "load_probe_timeout"

    def test_subprocess_error_arm(self, tmp_path: Path) -> None:
        wheel = _build_instruction_wheel(tmp_path / "dist")
        failure = _probe(wheel, python_executable=str(tmp_path / "no_such_python_interpreter"))
        assert failure is not None
        assert failure.failure_mode == "load_probe_subprocess_error"

    def test_probe_failure_messages_never_claim_entry_point_semantics(self, tmp_path: Path) -> None:
        """Maintainer constraint: the module-import probe must not pretend
        the pack has executable entry-point semantics — failure messages
        name ``importlib.import_module``, never ``EntryPoint.load``."""
        wheel = _build_instruction_wheel(
            tmp_path / "dist",
            init_source="raise RuntimeError('boom')\n",
        )
        failure = _probe(wheel)
        assert failure is not None
        assert "EntryPoint.load" not in failure.message
        assert "importlib.import_module" in failure.message


# ---------------------------------------------------------------------------
# (e) Lockstep drift detector vs protocol/plugin_registry (test-only imports;
#     NO runtime cross-import — per
#     feedback_drift_detector_test_only_no_runtime_import)
# ---------------------------------------------------------------------------


_LOCKSTEP_MANIFESTS: list[dict[str, Any]] = [
    {"pack": {"kind": "skill"}, "skill": {"mode": "instruction"}},
    {"pack": {"kind": "skill"}, "skill": {"mode": "executable"}},
    {"pack": {"kind": "skill"}, "skill": {}},
    {"pack": {"kind": "tool"}, "skill": {"mode": "instruction"}},
    {"skill": {"mode": "banana"}},
    {"skill": {"mode": 7}},
    {"tool": {"cognic": {"pack": {"kind": "skill"}, "skill": {"mode": "instruction"}}}},
    {"tool": {"cognic": {"skill": {"mode": "executable"}}}},
    {"tool": {"cognic": {"skill": {}}}},
    # Top-level non-dict falls back to the legacy path (mirror-exact shape).
    {"skill": "bad", "tool": {"cognic": {"skill": {"mode": "instruction"}}}},
    {"pack": "bad", "tool": {"cognic": {"pack": {"kind": "skill"}}}},
    {"skill": "bad"},
    {"tool": "bad"},
    {"tool": {"cognic": "bad"}},
    {"tool": {"cognic": {"skill": "bad"}}},
    {},
    {"pack": {"kind": "skill"}},
]


class TestManifestReaderLockstepWithPluginRegistry:
    """The ``_wheel_integrity``-local dual-path manifest readers MUST agree
    with the ``protocol/plugin_registry`` copies (the B2-pre discovery arm's
    classification) — cli must not import protocol's registry at runtime
    from this stdlib-shaped module, so the lockstep is pinned here test-only
    over a parametrized manifest matrix."""

    @pytest.mark.parametrize("manifest", _LOCKSTEP_MANIFESTS)
    def test_block_and_mode_classification_agree(self, manifest: dict[str, Any]) -> None:
        from cognic_agentos.cli import _wheel_integrity
        from cognic_agentos.protocol import plugin_registry

        assert _wheel_integrity._manifest_pack_block(
            manifest
        ) == plugin_registry._manifest_pack_block(manifest)

        cli_block = _wheel_integrity._manifest_skill_block(manifest)
        registry_block = plugin_registry._manifest_skill_block(manifest)
        assert cli_block == registry_block

        cli_mode = (
            _wheel_integrity._manifest_skill_mode(cli_block) if cli_block is not None else None
        )
        registry_mode = (
            plugin_registry._manifest_skill_mode(registry_block)
            if registry_block is not None
            else None
        )
        assert cli_mode == registry_mode

    def test_manifest_basename_agrees_with_discovery_arm(self) -> None:
        from cognic_agentos.cli import _wheel_integrity
        from cognic_agentos.protocol import plugin_registry

        assert _wheel_integrity._INSTRUCTION_MANIFEST_BASENAME == plugin_registry._MANIFEST_BASENAME
