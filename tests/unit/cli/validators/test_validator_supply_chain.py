"""Sprint-7A T12 — ADR-016 supply-chain attestation-path validator regressions.

The supply-chain validator's primary job is to confirm every declared
attestation path resolves to an actual file inside the pack root, with
explicit refusal on path-traversal pre-check failures (absolute paths,
``..`` escapes, symlinks pointing outside the pack). This is the
critical-controls feed into the runtime trust gate (Sprint 4): if a
pack ships a manifest pointing at ``/etc/passwd`` or ``../../../foo``
the validator MUST refuse rather than letting the path reach the
sign / verify orchestrators.

Validator scope (Wave-1):

  - Canonical T5 shape: ``[supply_chain].attestation_paths`` (required):
    list of strings — pack-relative paths to attestation files. Each
    entry is checked for ``AUTHOR-FILL`` placeholder (treated as
    missing), shape (must be a non-empty stripped string), then path
    resolution.
  - Legacy/docs shape: ``[tool.cognic.supply_chain].attestation_paths``
    (per pre-T6 fixture packs at
    ``tests/fixtures/cognic_test_{mcp,agent}_pack/``). Validated
    identically to the canonical path when present.
  - Path resolution: each declared path MUST resolve to an existing
    regular file located inside the pack root. Absolute paths and
    paths that escape the pack root via ``..`` are refused before any
    filesystem touch.

Closed-enum reasons T12 owns:

  - ``supply_chain_attestation_path_missing`` — used for "field/entry
    shape problems" (field absent, list shape wrong, AUTHOR-FILL
    placeholder, etc.). ``payload.failure_mode`` distinguishes
    (``field_absent`` / ``field_not_list`` / ``list_empty`` /
    ``path_entry_not_string`` / ``path_entry_empty`` /
    ``path_entry_author_fill``).
  - ``supply_chain_attestation_path_unresolvable`` — used for "shape OK
    but path doesn't reach a real file inside the pack root".
    ``payload.failure_mode`` distinguishes (``path_absolute`` /
    ``path_escapes_pack_root`` / ``path_does_not_exist`` /
    ``path_not_a_file``).

Dual-path lookup mirrors T8/T9/T10/T11 doctrine: each declared path
validates independently when both are declared, with payload's
``block_path`` distinguishing the source (``supply_chain`` /
``tool.cognic.supply_chain``).

The freshly-scaffolded pack iteration loop: T5 ships concrete paths
(``attestations/cosign.sig`` / ``attestations/sbom.cdx.json``) that
don't exist on disk until ``agentos sign --bundle`` populates them.
The lifecycle pinner test in section (f) drives the real scaffolder
+ asserts ``path_does_not_exist`` fires for those templated paths so
future scaffold ↔ validator field-name drift trips at CI time.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import supply_chain

_USE_DEFAULT_PATHS: Any = object()


def _manifest(
    *,
    paths: Any = _USE_DEFAULT_PATHS,
    drop_field: bool = False,
    drop_supply_chain: bool = False,
) -> dict[str, Any]:
    """Build a manifest with a populated ``[supply_chain]`` block.

    Omitting ``paths`` defaults to a single non-existent placeholder
    path so the caller can override in dedicated path-resolution
    arms; passing ``paths=None`` (or any other concrete value
    including non-list types) writes that value verbatim — necessary
    for the field-shape failure-mode arms (``field_not_list``,
    ``list_empty``, etc.). ``drop_field=True`` removes the
    ``attestation_paths`` field entirely. ``drop_supply_chain=True``
    drops the entire block.
    """
    manifest: dict[str, Any] = {"pack": {"pack_id": "cognic-tool-demo", "kind": "tool"}}
    if drop_supply_chain:
        return manifest
    block: dict[str, Any] = {}
    if not drop_field:
        block["attestation_paths"] = (
            ["attestations/x.sig"] if paths is _USE_DEFAULT_PATHS else paths
        )
    manifest["supply_chain"] = block
    return manifest


def _write_attestation_file(pack_root: Path, relative: str) -> Path:
    """Create the file at ``pack_root/relative`` with parent dirs +
    one byte of placeholder content. Returns the absolute path."""
    target = pack_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b".")
    return target


# ---------------------------------------------------------------------------
# (a) Block presence
# ---------------------------------------------------------------------------


def test_supply_chain_block_absent_no_findings(tmp_path: Path) -> None:
    """Per the T6 shape gate: an absent block trips the orchestrator's
    ``manifest_missing_required_block``. T12 itself is never called for
    that case; direct unit-test entry no-ops."""
    findings = supply_chain.validate(_manifest(drop_supply_chain=True), tmp_path)
    assert findings == []


def test_supply_chain_block_not_a_dict_no_findings(tmp_path: Path) -> None:
    """Defensive: malformed block (e.g., ``supply_chain = "x"``) falls
    through cleanly so the orchestrator's ``block_not_table`` shape
    refusal is the only signal authors see."""
    findings = supply_chain.validate(
        {"pack": {"pack_id": "x", "kind": "tool"}, "supply_chain": "not-a-table"},
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (b) attestation_paths field shape
# ---------------------------------------------------------------------------


def test_attestation_paths_field_absent_refuses(tmp_path: Path) -> None:
    """``[supply_chain]`` declared but the ``attestation_paths`` field
    is missing → ``supply_chain_attestation_path_missing`` with
    ``failure_mode='field_absent'``."""
    findings = supply_chain.validate(_manifest(drop_field=True), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "field_absent"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].payload["block_path"] == "supply_chain"


@pytest.mark.parametrize(
    "bad_value",
    [
        "attestations/cosign.sig",  # str instead of list
        {"path": "attestations/cosign.sig"},  # dict
        42,
        None,
        True,
    ],
)
def test_attestation_paths_not_a_list_refuses(tmp_path: Path, bad_value: Any) -> None:
    """``attestation_paths`` declared as a non-list type → refuse with
    ``failure_mode='field_not_list'``. Strings get special attention
    because TOML pack-author docs sometimes nudge authors toward a
    single-string shorthand which the validator rejects (the field is
    declared as a list-of-paths to support multiple attestations)."""
    findings = supply_chain.validate(_manifest(paths=bad_value), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "field_not_list"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"


def test_attestation_paths_empty_list_refuses(tmp_path: Path) -> None:
    """``attestation_paths = []`` → refuse with
    ``failure_mode='list_empty'``. An empty bundle defeats the
    purpose of the supply-chain block; the runtime trust gate has
    nothing to verify."""
    findings = supply_chain.validate(_manifest(paths=[]), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "list_empty"
    ]
    assert len(matching) == 1


@pytest.mark.parametrize("bad_entry", [42, None, True, ["nested"], {"k": "v"}])
def test_attestation_paths_non_string_entry_refuses(tmp_path: Path, bad_entry: Any) -> None:
    """A non-string entry in the list trips ``path_entry_not_string``."""
    findings = supply_chain.validate(_manifest(paths=[bad_entry]), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "path_entry_not_string"
    ]
    assert len(matching) == 1


@pytest.mark.parametrize("empty_entry", ["", "   ", "\t\n"])
def test_attestation_paths_empty_string_entry_refuses(tmp_path: Path, empty_entry: str) -> None:
    """Empty / whitespace-only entries → ``path_entry_empty``."""
    findings = supply_chain.validate(_manifest(paths=[empty_entry]), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "path_entry_empty"
    ]
    assert len(matching) == 1


def test_attestation_paths_author_fill_entry_refuses(tmp_path: Path) -> None:
    """An ``AUTHOR-FILL: ...``-prefixed entry is treated as a
    placeholder author has not yet replaced — refuse with
    ``failure_mode='path_entry_author_fill'``. Mirrors T7/T10/T11
    AUTHOR-FILL doctrine (T5 templates ship AUTHOR-FILL strings at
    every author-customizable site; validators treat them as missing)."""
    findings = supply_chain.validate(
        _manifest(paths=["AUTHOR-FILL: attestations/cosign.sig"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "path_entry_author_fill"
    ]
    assert len(matching) == 1


def test_multiple_shape_failures_emit_per_entry_findings(tmp_path: Path) -> None:
    """A list with mixed shape failures emits one finding per offending
    entry so authors get per-entry remediation. Index of the offending
    entry is in the payload."""
    findings = supply_chain.validate(
        _manifest(paths=["", 42, "AUTHOR-FILL: x"]),
        tmp_path,
    )
    refusal_modes = [
        f.payload.get("failure_mode")
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
    ]
    # one each of empty / non_string / author_fill
    assert sorted(refusal_modes) == [
        "path_entry_author_fill",
        "path_entry_empty",
        "path_entry_not_string",
    ]


# ---------------------------------------------------------------------------
# (c) Path resolution — the path-traversal pre-check + existence checks
# ---------------------------------------------------------------------------


def test_absolute_path_refuses_path_absolute(tmp_path: Path) -> None:
    """Absolute paths cannot be inside the pack — declaration is a
    bug or a path-traversal attempt → refuse with
    ``failure_mode='path_absolute'``. The check runs BEFORE any
    filesystem touch so a malicious manifest cannot probe for
    file existence on the host."""
    findings = supply_chain.validate(
        _manifest(paths=["/etc/passwd"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_absolute"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"


def test_path_escapes_pack_root_refuses(tmp_path: Path) -> None:
    """``..`` traversal that lifts the path outside the pack root →
    refuse with ``failure_mode='path_escapes_pack_root'``. Pre-check
    against path traversal attacks per ADR-016."""
    findings = supply_chain.validate(
        _manifest(paths=["../../../etc/passwd"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_escapes_pack_root"
    ]
    assert len(matching) == 1


def test_path_does_not_exist_refuses(tmp_path: Path) -> None:
    """Path resolves cleanly inside the pack root but the file isn't
    present → ``path_does_not_exist``. Canonical 'fresh scaffold'
    refusal — pack authors run ``agentos sign --bundle`` to populate
    the attestations/ directory."""
    findings = supply_chain.validate(
        _manifest(paths=["attestations/cosign.sig"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_does_not_exist"
    ]
    assert len(matching) == 1
    assert matching[0].payload["declared_path"] == "attestations/cosign.sig"


def test_path_resolves_to_directory_refuses(tmp_path: Path) -> None:
    """Path exists but is a directory (not a file) → ``path_not_a_file``.
    Defends against an author accidentally pointing at the parent
    ``attestations/`` directory instead of the cosign file inside it."""
    (tmp_path / "attestations").mkdir()
    findings = supply_chain.validate(
        _manifest(paths=["attestations"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_not_a_file"
    ]
    assert len(matching) == 1


def test_symlink_pointing_outside_pack_refuses(tmp_path: Path) -> None:
    """A symlink inside the pack pointing OUTSIDE the pack root resolves
    to outside the pack root via ``Path.resolve()`` → refuse with
    ``path_escapes_pack_root``. Defends against symlink-based
    path-traversal attacks."""
    outside = tmp_path.parent / "outside_pack_target.bin"
    outside.write_bytes(b".")
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    (pack_root / "attestations").mkdir()
    (pack_root / "attestations" / "evil.sig").symlink_to(outside)

    findings = supply_chain.validate(
        _manifest(paths=["attestations/evil.sig"]),
        pack_root,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_escapes_pack_root"
    ]
    assert len(matching) == 1


def test_path_resolution_oserror_returns_finding_not_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``Path.resolve()`` can raise ``OSError`` (e.g., symlink loops:
    ``OSError [Errno 62] Too many levels of symbolic links``) or
    ``RuntimeError`` (older Python versions) during path resolution.
    The validator MUST surface those as a deterministic refusal —
    ``supply_chain_attestation_path_unresolvable`` with
    ``failure_mode='path_resolution_error'`` — not propagate the
    traceback up through the orchestrator. Critical-controls seam:
    a malformed pack must never crash ``agentos validate``.

    Forces the failure deterministically via ``monkeypatch`` so the
    regression doesn't depend on platform-specific symlink-loop
    behaviour (macOS Python 3.13's ``Path.resolve(strict=False)``
    returns the path as-is rather than raising; Linux + Windows +
    older Python may raise)."""
    _write_attestation_file(tmp_path, "attestations/loop.sig")
    real_resolve = Path.resolve

    def _raise_on_attestation_resolve(self: Path, strict: bool = False) -> Path:
        if "attestations" in self.parts and self.name == "loop.sig":
            raise OSError(62, "Too many levels of symbolic links", str(self))
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_on_attestation_resolve)

    findings = supply_chain.validate(
        _manifest(paths=["attestations/loop.sig"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_resolution_error"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].payload["declared_path"] == "attestations/loop.sig"
    # The error type is recorded so CI parsers can render different
    # remediation copy for symlink loops vs other resolution errors.
    assert matching[0].payload["error_type"] == "OSError"


def test_path_resolution_runtime_error_also_handled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Older Python / non-POSIX platforms can raise ``RuntimeError``
    (rather than ``OSError``) on symlink loops during ``resolve()``.
    Both exception types collapse to the same closed-enum refusal."""
    _write_attestation_file(tmp_path, "attestations/loop.sig")
    real_resolve = Path.resolve

    def _raise_runtime_on_attestation_resolve(self: Path, strict: bool = False) -> Path:
        if "attestations" in self.parts and self.name == "loop.sig":
            raise RuntimeError("Symlink loop")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_runtime_on_attestation_resolve)

    findings = supply_chain.validate(
        _manifest(paths=["attestations/loop.sig"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
        and f.payload.get("failure_mode") == "path_resolution_error"
    ]
    assert len(matching) == 1
    assert matching[0].payload["error_type"] == "RuntimeError"


def test_resolvable_existing_file_no_unresolvable_finding(tmp_path: Path) -> None:
    """File exists at the declared relative path inside the pack root
    + isn't traversed outside → no path-resolution refusal."""
    _write_attestation_file(tmp_path, "attestations/cosign.sig")
    findings = supply_chain.validate(
        _manifest(paths=["attestations/cosign.sig"]),
        tmp_path,
    )
    assert not any(f.reason == "supply_chain_attestation_path_unresolvable" for f in findings)


def test_multiple_path_failures_emit_per_entry_findings(tmp_path: Path) -> None:
    """Several declared paths each fail differently → one finding per
    offending path with that path in the payload."""
    _write_attestation_file(tmp_path, "attestations/ok.sig")
    findings = supply_chain.validate(
        _manifest(
            paths=[
                "attestations/ok.sig",  # passes
                "/etc/passwd",  # path_absolute
                "../escaped",  # path_escapes_pack_root
                "attestations/missing.sig",  # path_does_not_exist
            ]
        ),
        tmp_path,
    )
    by_mode: dict[str, list[ValidatorFinding]] = {}
    for f in findings:
        if f.reason == "supply_chain_attestation_path_unresolvable":
            by_mode.setdefault(f.payload["failure_mode"], []).append(f)
    assert sorted(by_mode) == [
        "path_absolute",
        "path_does_not_exist",
        "path_escapes_pack_root",
    ]


# ---------------------------------------------------------------------------
# (d) Dual-path lookup
# ---------------------------------------------------------------------------


def test_legacy_supply_chain_path_validated(tmp_path: Path) -> None:
    """Manifests using the legacy ``[tool.cognic.supply_chain]`` shape
    (the docs / fixture-aligned layout) still get validated — declared
    paths are checked + ``block_path`` payload distinguishes the
    source."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {"cognic": {"supply_chain": {"attestation_paths": ["attestations/missing.sig"]}}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "path_does_not_exist"]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.supply_chain"


def test_legacy_supply_chain_path_field_absent_refuses(tmp_path: Path) -> None:
    """Legacy block declared without ``attestation_paths`` →
    ``field_absent`` refusal with the legacy block_path."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {"cognic": {"supply_chain": {}}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "supply_chain_attestation_path_missing"
        and f.payload.get("failure_mode") == "field_absent"
    ]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.supply_chain"


def test_both_paths_validated_independently(tmp_path: Path) -> None:
    """Both shapes declare the block; each validates independently. A
    bad path under one and a good path under the other surface
    distinct findings."""
    _write_attestation_file(tmp_path, "attestations/legacy_ok.sig")
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "supply_chain": {"attestation_paths": ["attestations/missing.sig"]},
        "tool": {"cognic": {"supply_chain": {"attestation_paths": ["attestations/legacy_ok.sig"]}}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    bad_findings = [f for f in findings if f.reason == "supply_chain_attestation_path_unresolvable"]
    assert len(bad_findings) == 1
    assert bad_findings[0].payload["block_path"] == "supply_chain"


def test_split_path_smuggle_attempt_caught_via_union(tmp_path: Path) -> None:
    """Split-location bypass: canonical declares a real file but the
    legacy path declares ``/etc/passwd``. Both paths are validated
    independently so the absolute-path refusal still surfaces with
    its own block_path."""
    _write_attestation_file(tmp_path, "attestations/canonical.sig")
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "supply_chain": {"attestation_paths": ["attestations/canonical.sig"]},
        "tool": {"cognic": {"supply_chain": {"attestation_paths": ["/etc/passwd"]}}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "path_absolute"]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.supply_chain"


def test_legacy_partial_path_no_crash(tmp_path: Path) -> None:
    """``[tool]`` without ``[tool.cognic.supply_chain]`` falls
    through cleanly (no canonical block + no legacy block →
    orchestrator's shape gate handles it; T12 no-ops)."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {"cognic": {"some_other_block": {}}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    assert findings == []


def test_legacy_non_dict_no_crash(tmp_path: Path) -> None:
    """``[tool.cognic.supply_chain]`` declared as a scalar (defensive
    guard) falls through cleanly."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {"cognic": {"supply_chain": "not-a-table"}},
    }
    findings = supply_chain.validate(manifest, tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (e) Type-shape pin + happy path
# ---------------------------------------------------------------------------


def test_supply_chain_findings_are_validator_finding_instances(tmp_path: Path) -> None:
    findings = supply_chain.validate(_manifest(paths=["/etc/passwd"]), tmp_path)
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


def test_supply_chain_full_pass_returns_empty(tmp_path: Path) -> None:
    """Every declared path resolves to a real file inside the pack
    root → no findings."""
    _write_attestation_file(tmp_path, "attestations/cosign.sig")
    _write_attestation_file(tmp_path, "attestations/sbom.cdx.json")
    findings = supply_chain.validate(
        _manifest(paths=["attestations/cosign.sig", "attestations/sbom.cdx.json"]),
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (f) Lifecycle pinner — drive the real T5 scaffolder
# ---------------------------------------------------------------------------


def test_t5_scaffolder_supply_chain_block_validates_with_path_does_not_exist(
    tmp_path: Path,
) -> None:
    """Drive the real T5 scaffolder to produce a fresh tool pack;
    parse its manifest; assert the supply-chain validator refuses
    with ``path_does_not_exist`` for the templated attestation paths
    (which only exist after ``agentos sign --bundle`` runs).

    Catches future scaffold ↔ validator field-name drift before it
    ships (per the lifecycle pinner doctrine — every conformance
    validator owns a regression that drives the real scaffolder)."""
    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="tool", pack_name="t12_pinner", parent_dir=tmp_path)
    manifest_path = pack_root / "cognic-pack-manifest.toml"
    data = tomllib.loads(manifest_path.read_text("utf-8"))

    findings = supply_chain.validate(data, pack_root)
    refusal_modes = {
        f.payload.get("failure_mode")
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
    }
    assert refusal_modes == {"path_does_not_exist"}
    declared_paths = {
        f.payload.get("declared_path")
        for f in findings
        if f.reason == "supply_chain_attestation_path_unresolvable"
    }
    # Templates ship two concrete paths under attestations/; both
    # surface as 'does not exist' until agentos sign --bundle runs.
    assert "attestations/cosign.sig" in declared_paths
    assert "attestations/sbom.cdx.json" in declared_paths


def test_t5_scaffolded_pack_with_attestations_populated_validates_clean(
    tmp_path: Path,
) -> None:
    """After the author runs ``agentos sign --bundle .`` (simulated
    here by creating the placeholder files), the supply-chain
    validator returns clean."""
    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="tool", pack_name="t12_pinner", parent_dir=tmp_path)
    _write_attestation_file(pack_root, "attestations/cosign.sig")
    _write_attestation_file(pack_root, "attestations/sbom.cdx.json")

    manifest_path = pack_root / "cognic-pack-manifest.toml"
    data = tomllib.loads(manifest_path.read_text("utf-8"))

    findings = supply_chain.validate(data, pack_root)
    assert findings == []


# ---------------------------------------------------------------------------
# (g) Closed-enum reason ownership pin
# ---------------------------------------------------------------------------


def test_supply_chain_reasons_owned_by_supply_chain_validator() -> None:
    """The two T12 reasons map to ``validators/supply_chain.py`` in the
    ownership table. Drift detector — adding a new reason without
    updating the ownership map trips this regression."""
    from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP

    assert (
        _VALIDATOR_REASON_OWNERSHIP["supply_chain_attestation_path_missing"]
        == "validators/supply_chain.py"
    )
    assert (
        _VALIDATOR_REASON_OWNERSHIP["supply_chain_attestation_path_unresolvable"]
        == "validators/supply_chain.py"
    )
