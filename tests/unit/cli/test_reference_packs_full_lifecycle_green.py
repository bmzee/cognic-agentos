"""Sprint-7A T15 — full-lifecycle CI gate for the three ``examples/``
reference packs.

Per Doctrine D + the T15 step-list (plan §1375), each reference pack
must clear the per-kind Wave-1 author lifecycle:

  scaffold-on-disk → wheel-build → sign → validate → harness → verify

Step order doctrine note: the original plan listed ``validate`` as
Step 2 (before sign). That ordering only works when committed packs
ship pre-generated attestations on disk — but the
**static-only-committed-state** refinement explicitly excludes
attestations from ``examples/`` (`agentos sign --bundle` writes them
under ``tmp_path`` during this lifecycle test, never on disk in
``examples/``). The supply-chain validator's
``supply_chain.attestation_paths`` field requires non-empty + every
declared file present, so validate cannot pass on the committed
shape until sign has populated the attestation set. The lifecycle
test therefore runs sign FIRST, then validate (which proves the
artifact set sign produced satisfies every validator gate). This
matches the realistic author flow: scaffold → fill manifest → build
wheel → sign → validate → harness → publish.

The harness step is per-kind (T13/R31 narrows
``_HARNESS_SUPPORTED_KINDS = frozenset({"tool"})``):

  - tool pack — harness runs + PASSES.
  - skill pack — harness REFUSES with closed-enum
    ``harness_unsupported_pack_kind``.
  - agent pack — harness REFUSES with closed-enum
    ``harness_unsupported_pack_kind``.

Sign + verify are kind-agnostic; all three packs ship full
attestation declarations + (agent) JWS-signed AgentCard, and all
three clear sign --bundle + verify end-to-end.

R8 P2 #2 reviewer correction (plan §1474): the lifecycle test reuses
T14's shim infrastructure (cosign / syft / grype / license-auditor)
so the test stays in the **unit lane** without requiring live
binaries on the test machine. Real-binary verification is a separate
env-gated integration concern.

Refinement (this commit): committed reference packs stay STATIC —
manifest, pyproject, inert source, README, agent-card.json seed, and
the explicitly-documented test-only agent keypair only. All
sign/verify outputs (cosign.sig, bundle.sigstore, sbom.cdx.json,
vuln-scan.json, license-audit.json, slsa-provenance.intoto.json,
intoto-layout.json, agent-card.jws) are generated under ``tmp_path``
during this lifecycle test and never reach disk in ``examples/``.
"""

from __future__ import annotations

import json
import shutil
import tomllib
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app

# Re-use T14's shim infrastructure verbatim — it's the canonical
# unit-lane wiring for sign/verify against signed bundles.
from tests.unit.cli.test_cli_verify import (
    _make_cosign_shim,
    _stage_full_shim_set,
    _wire_verify_settings,
)

# Reference packs root.
_EXAMPLES_ROOT = Path(__file__).resolve().parents[3] / "examples"
_TOOL_PACK = _EXAMPLES_ROOT / "cognic-tool-example-minimal"
_SKILL_PACK = _EXAMPLES_ROOT / "cognic-skill-example-minimal"
_AGENT_PACK = _EXAMPLES_ROOT / "cognic-agent-example-minimal"

# Test-only keypair shipped with the agent reference pack (matched
# halves committed via the .gitignore exception lines).
_AGENT_TEST_PRIVATE_PEM = (
    _AGENT_PACK / "attestations" / "test-signing" / "test_signing_key.private.pem"
)
_AGENT_TEST_PUBLIC_PEM = (
    _AGENT_PACK / "attestations" / "test-signing" / "test_signing_key.public.pem"
)


def _stage_reference_pack_clone(source_pack: Path, tmp_path: Path) -> Path:
    """Copy a committed reference pack into tmp_path so sign --bundle
    can write generated attestations + a built wheel without polluting
    the working tree. Returns the staged-clone path."""
    target = tmp_path / source_pack.name
    shutil.copytree(source_pack, target)
    return target


def _synthesize_wheel_from_pack_source(pack: Path) -> Path:
    """Synthesize a Wave-1 wheel under ``<pack>/dist/`` from the
    pack's on-disk pyproject.toml + ``src/<package>/`` contents.

    Mirrors the pattern from T14's
    ``test_cli_verify._stage_signed_pack`` (R5 P2 #1 — REAL ZIP-shaped
    wheel containing a cognic.* entry-point group + dist-info METADATA
    + WHEEL + the entry-point's source files). Exists here because
    real ``python -m build`` would install the package and slow the
    unit lane; this helper produces a deterministic wheel that sign +
    verify (incl. R15 step-11 load probe) accept end-to-end.

    Reads pyproject.toml to get:

      - [project].name + .version
      - [project.entry-points."cognic.{group}"] (single entry)
      - [tool.hatch.build.targets.wheel].packages[0]

    Walks the ``src/<package>/`` tree to copy every ``.py`` file into
    the wheel under the package's dotted path (zipimport requires
    explicit ``__init__.py`` at every package level — handled by the
    on-disk source already shipping ``__init__.py`` files).

    Returns the path to the synthesized wheel.
    """
    pyproject = tomllib.loads((pack / "pyproject.toml").read_text())
    name = pyproject["project"]["name"]
    version = pyproject["project"]["version"]
    canonical_name = name.replace("-", "_")  # PEP-503 canonical wheel form

    # Entry-point group + (single) entry-target pair. The reference
    # packs each declare exactly one entry under one cognic.* group.
    entry_groups = pyproject["project"]["entry-points"]
    cognic_group = next(
        (g for g in entry_groups if g.startswith("cognic.")),
        None,
    )
    assert cognic_group is not None, f"no cognic.* entry-point group in {pack}/pyproject.toml"
    entries = entry_groups[cognic_group]
    assert len(entries) == 1, f"expected exactly one entry under [{cognic_group}], got {entries!r}"
    entry_key, entry_value = next(iter(entries.items()))

    # src/<package>/ → wheel <package>/ — Hatch wheel target.
    package_root = pack / "src" / canonical_name
    assert package_root.is_dir(), f"missing source package at {package_root}"

    dist_dir = pack / "dist"
    dist_dir.mkdir(exist_ok=True)
    wheel_path = dist_dir / f"{canonical_name}-{version}-py3-none-any.whl"
    dist_info = f"{canonical_name}-{version}.dist-info"

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # dist-info metadata
        zf.writestr(
            f"{dist_info}/entry_points.txt",
            f"[{cognic_group}]\n{entry_key} = {entry_value}\n",
        )
        zf.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        zf.writestr(
            f"{dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: agentos-test-fixture-t15\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )

        # Walk the on-disk package source and write every .py file
        # into the wheel under <canonical_name>/<relative-path>.py.
        # Source already ships __init__.py at every level — zipimport
        # requires this (PEP 420 namespace packages NOT supported).
        for source_file in package_root.rglob("*.py"):
            relative = source_file.relative_to(package_root)
            zf.writestr(f"{canonical_name}/{relative}", source_file.read_bytes())

    return wheel_path


def _wire_sign_settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    shims: dict[str, Path],
) -> None:
    """Set the env vars sign --bundle reads to wire the four shim
    binaries + the test-only signing key shipped with the agent
    reference pack. The signing-key path is set unconditionally;
    tool + skill packs do not consume it (no AgentCard JWS) but
    sign --bundle's environment hydration is the same regardless."""
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(shims["cosign"]))
    monkeypatch.setenv("COGNIC_SYFT_PATH", str(shims["syft"]))
    monkeypatch.setenv("COGNIC_GRYPE_PATH", str(shims["grype"]))
    monkeypatch.setenv("COGNIC_LICENSE_AUDITOR_PATH", str(shims["license_auditor"]))
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_AGENT_TEST_PRIVATE_PEM))


# Required attestation set produced by sign --bundle. Verify reads
# the same list at runtime (cli/verify.py:_REQUIRED_ATTESTATION_FILES).
_REQUIRED_ATTESTATION_FILENAMES: tuple[str, ...] = (
    "cosign.sig",
    "bundle.sigstore",
    "sbom.cdx.json",
    "vuln-scan.json",
    "license-audit.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
)


def _assert_full_attestation_set_exists(pack: Path) -> None:
    """Every Wave-1 attestation file must exist + be non-empty after
    sign --bundle returns 0."""
    attestations_dir = pack / "attestations"
    for filename in _REQUIRED_ATTESTATION_FILENAMES:
        path = attestations_dir / filename
        assert path.is_file(), f"missing attestation: {path}"
        assert path.stat().st_size > 0, f"empty attestation: {path}"


def _run_full_lifecycle(
    source_pack: Path,
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_kind: str,
) -> None:
    """End-to-end Wave-1 author lifecycle against a single reference
    pack: stage clone → synthesize wheel → sign --bundle → validate
    → harness → verify.

    ``expected_kind`` selects the per-kind harness expectation:

      - ``"tool"`` — harness PASSES (exit 0).
      - ``"skill"`` / ``"agent"`` — harness REFUSES with
        ``harness_unsupported_pack_kind`` (exit 1).
    """
    pack = _stage_reference_pack_clone(source_pack, tmp_path)
    _synthesize_wheel_from_pack_source(pack)
    runner = CliRunner()

    # ---- sign --bundle ----
    shims = _stage_full_shim_set(tmp_path)
    _wire_sign_settings(monkeypatch, shims=shims)
    sign_result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert sign_result.exit_code == 0, (
        f"sign --bundle refused {pack.name}: exit={sign_result.exit_code} "
        f"stdout={sign_result.stdout!r} stderr={sign_result.stderr!r}"
    )
    _assert_full_attestation_set_exists(pack)
    if expected_kind == "agent":
        # AgentCard JWS regenerated alongside the attestation set.
        jws_path = pack / "agent_cards" / "agent-card.jws"
        assert jws_path.is_file(), f"missing AgentCard JWS: {jws_path}"
        assert jws_path.stat().st_size > 0

    # ---- validate (post-sign — attestation files now exist) ----
    # ``validate --json`` writes one JSON object per finding to
    # STDERR (per the CLI convention pinned in
    # test_cli_validate.py::test_validate_json_emits_findings_one_object_per_line);
    # on a clean validate stderr is empty. Stdout carries the human
    # "PASS" / "FAIL" summary line.
    validate_result = runner.invoke(app, ["validate", "--json", str(pack)])
    assert validate_result.exit_code == 0, (
        f"validate refused {pack.name} after sign: "
        f"stdout={validate_result.stdout!r} stderr={validate_result.stderr!r}"
    )
    stderr_lines = [line for line in validate_result.stderr.splitlines() if line.strip()]
    findings = [json.loads(line) for line in stderr_lines]
    refusals = [f for f in findings if f.get("severity") == "refusal"]
    assert refusals == [], f"validate refusals on {pack.name}: {refusals!r}"

    # ---- harness — per-kind expectation matrix ----
    harness_result = runner.invoke(app, ["test-harness", "--json", str(pack)])
    if expected_kind == "tool":
        assert harness_result.exit_code == 0, (
            f"test-harness refused tool pack {pack.name}: "
            f"exit={harness_result.exit_code} stdout={harness_result.stdout!r} "
            f"stderr={harness_result.stderr!r}"
        )
        harness_payload = json.loads(harness_result.stdout)
        assert harness_payload["overall_status"] == "pass", harness_payload
    else:
        assert harness_result.exit_code == 1, (
            f"test-harness should refuse {expected_kind} pack {pack.name} at the "
            f"kind-narrow gate; got exit={harness_result.exit_code}, "
            f"stdout={harness_result.stdout!r}, stderr={harness_result.stderr!r}"
        )
        harness_payload = json.loads(harness_result.stdout)
        refusal = next(
            (
                f
                for f in harness_payload["findings"]
                if f.get("reason") == "harness_unsupported_pack_kind"
            ),
            None,
        )
        assert refusal is not None, (
            f"expected harness_unsupported_pack_kind refusal in {expected_kind} "
            f"harness output; findings={harness_payload['findings']!r}"
        )
        assert refusal["payload"]["pack_kind"] == expected_kind, refusal["payload"]

    # ---- verify ----
    # Verify Step 1 (trust-root resolution) gates regardless of
    # pack kind — agent packs consume it for AgentCard JWS
    # verification at step 9; tool + skill packs require the path
    # to be set even though step 9 is skipped (the resolution gate
    # is uniform across kinds for forward-compatibility with future
    # non-agent JWS surfaces). Wire the test-only public PEM for
    # all three kinds.
    verify_shim = _make_cosign_shim(tmp_path, exit_code=0)
    _wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=_AGENT_TEST_PUBLIC_PEM,
    )
    verify_result = runner.invoke(app, ["verify", "--json", str(pack)])
    assert verify_result.exit_code == 0, (
        f"verify refused {pack.name}: exit={verify_result.exit_code} "
        f"stdout={verify_result.stdout!r} stderr={verify_result.stderr!r}"
    )
    verify_payload = json.loads(verify_result.stdout)
    assert verify_payload["overall_status"] == "pass", verify_payload
    verify_refusals = [f for f in verify_payload["findings"] if f.get("severity") == "refusal"]
    assert verify_refusals == [], f"verify refusals on {pack.name}: {verify_refusals!r}"


def test_reference_tool_pack_full_lifecycle_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tool pack — full Wave-1 lifecycle clears every gate. Harness
    runs to completion + reports PASS (per-kind dispatch table in
    cli/test_harness.py supports ``kind="tool"``)."""
    _run_full_lifecycle(
        _TOOL_PACK,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        expected_kind="tool",
    )


def test_reference_skill_pack_full_lifecycle_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Skill pack — full Wave-1 lifecycle clears every gate EXCEPT
    the harness's per-kind narrowing (T13/R31). The harness MUST
    refuse with closed-enum ``harness_unsupported_pack_kind``;
    sign + verify still pass — they are kind-agnostic."""
    _run_full_lifecycle(
        _SKILL_PACK,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        expected_kind="skill",
    )


def test_reference_agent_pack_full_lifecycle_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent pack — full Wave-1 lifecycle, including the AgentCard
    JWS regen via the test-only signing keypair shipped under
    ``attestations/test-signing/``. Same harness narrowing as the
    skill pack: refuses with ``harness_unsupported_pack_kind``."""
    _run_full_lifecycle(
        _AGENT_PACK,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        expected_kind="agent",
    )
