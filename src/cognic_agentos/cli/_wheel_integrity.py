"""Sprint-7A T14.C — shared wheel-content integrity helper.

Both ``cli.sign`` (T14.B) + ``cli.verify`` (T14.C) need to assert that
the cosign-signed wheel's INTERNAL ``dist-info/`` matches the wheel
filename's name + version (R6 + R7 reviewer rounds). Pre-R7 the check
lived only in verify; sign would happily emit SLSA + in-toto provenance
for a wheel whose internal METADATA disagreed with the (mutable) wheel
filename + pyproject version, producing a bundle the new verifier
would refuse immediately.

R7 P2 #1 reviewer correction: extract the helper to a shared site so
sign + verify run the same integrity check at the same point in their
respective pipelines (BEFORE provenance rendering on sign; BEFORE the
SLSA / in-toto comparisons on verify).

R7 P2 #2 reviewer correction: an EMPTY ``[cognic.agents]`` section
(no entry-point keys under the header) was previously sufficient to
make ``has_section`` return True + the kind derivation appended
``"agent"``. importlib.metadata would discover no actual entry point
from that wheel; the runtime trust gate would bless an unloadable
agent pack. Fix: require at least one well-formed ``module:object``
entry under the selected cognic.* section.

Sprint-7A2 T9: the kind-derivation table grew the 4th first-class
kind — ``cognic.hooks → "hook"`` — so hook packs flow through the
same wheel-integrity gate as tool / skill / agent packs. Hook packs
ship the same attestation set as tool / skill packs (no AgentCard
JWS); sign + verify gate JWS on ``pack_kind == "agent"`` so the
new kind wires through unchanged downstream. The
``wheel_multiple_cognic_groups`` spoof-first defense (R6 P2 #1)
extends to hook+anything spoofing automatically because the same
``len(cognic_groups) > 1`` check fires for the new group too.

R15 reviewer pivot: the static-AST loadability walk that R13/R14/R15
tried to harden incrementally (top-level Raise → unresolved bases →
decorators / defaults / annotations → strict allowlist → trusted-
import allowlist → recursive relative-member validation) has been
**removed**. Each round closed named cases while adjacent Python
import-time constructs slipped through; the reviewer's instruction
was to stop the whack-a-mole and replace the static analyzer with a
real isolated-subprocess ``EntryPoint.load()`` probe. That probe
lives in ``cli/_load_probe.py`` and is invoked by ``cli/verify.py``
after cosign verify-blob succeeds.

This module's narrowed scope, post-pivot:
  - wheel identity (zip → exactly one ``*.dist-info/`` matching
    ``{canonical_name}-{version}``)
  - METADATA Name + Version textual agreement with wheel filename +
    pyproject (R6 + R9 P2 #3)
  - kind derivation from the selected cognic.* entry-point group
  - entry-point syntax (regex shape, no duplicates, single-segment
    Object)
  - basic module + object declaration (target module exists in the
    wheel ZIP; named object is declared as a top-level ClassDef /
    FunctionDef / Assign / AnnAssign in that module)

Anything beyond that — order-aware bound-name resolution, trusted
imports, decorators, top-level Raise, import-time NameError — is the
load probe's job.

M8 finding #3 (2026-07-06) — instruction-wheel arm: M8 instruction-only
skill packs (``[pack] kind="skill"`` + ``[skill] mode="instruction"``
per ADR-027) are CONTENT packs — SKILL.md + the signed
``cognic-pack-manifest.toml`` as package data inside one stub package,
NO entry points of any kind (the A7 validator refuses a
``cognic.skills`` entry point; the B2-pre manifest-walk discovery arm
discovers them at boot). When the matched dist-info has NO
``entry_points.txt``, the helper now runs a NARROW fallback mirroring
the discovery arm (``protocol/plugin_registry.py::
_discover_manifest_only_instruction_skills``) at the wheel layer:

  1. Scan wheel members for exactly-one 2-part
     ``<package>/cognic-pack-manifest.toml`` (zero matches → the EXACT
     pre-existing ``wheel_missing_entry_points_file`` failure; more
     than one → ``wheel_multiple_instruction_manifests``).
  2. Bounded read (1 MiB cap) + TOML parse of that member
     (``wheel_unparseable_instruction_manifest`` on failure).
  3. STRICT filter: ``[pack].kind == "skill"`` AND ``[skill].mode ==
     "instruction"`` — dual-path block reading (canonical top-level +
     legacy ``[tool.cognic.*]``) via LOCAL mirrors of the registry
     readers (test-only lockstep drift test; no runtime protocol
     import from this stdlib-shaped module). Any mismatch refuses —
     a ``kind="skill"`` zero-entry-point wheel WITHOUT instruction
     mode is a broken executable pack, never an instruction pack.
  4. Package-layout consistency (anti-decoy): the manifest package
     must be a valid importable package in the wheel
     (identifier-shaped name + ``<pkg>/__init__.py`` member) —
     ``wheel_instruction_package_not_importable`` otherwise. The
     validated package name is THREADED THROUGH the return value so
     verify's Step 11 module-import probe operates on exactly the
     source this helper validated (no re-discovery).

Entry-point wheels are byte/behavior unchanged — the fallback fires
ONLY when ``entry_points.txt`` is absent from the matched dist-info,
and every other zero-entry-point wheel still fails exactly as before.

Contract:

  :func:`read_signed_wheel_dist_info_metadata` — returns
    ``((canonical_name, version, kind, entry_points,
    instruction_package), None)`` on success or ``(None,
    WheelIntegrityFailure)`` on refusal. The 4th tuple element is the
    tuple of validated ``(module_path, object_path)`` pairs from the
    **selected dist-info**'s entry_points.txt (added at R15 follow-up
    round 1 P2 #1 — verify step 11 consumes this directly so callers
    never re-discover entry points by suffix-matching wheel members).
    The 5th element (additive, M8 finding #3) is the validated
    instruction stub-package name for instruction wheels and ``None``
    for entry-point wheels — instruction wheels carry derived kind
    ``"skill"`` + an EMPTY entry-point tuple + a non-None package
    name. Callers wrap the failure into their own ``VerifyFinding`` /
    ``SignFinding`` shape.

Closed-enum failure modes (via ``failure_mode``; sign + verify wrap
each with their own top-level reason):
  - ``wheel_not_a_zip`` — invalid ZIP / wheel format.
  - ``wheel_multiple_dist_info_dirs`` — > 1 dist-info dir (R6 P2 #1
    spoof-first defense).
  - ``wheel_dist_info_mismatch`` — no dist-info matches the
    canonicalized wheel-filename name + version (R6 P2 #1).
  - ``wheel_missing_entry_points_file`` — matched dist-info has no
    entry_points.txt.
  - ``wheel_missing_metadata_file`` — matched dist-info has no
    METADATA file (R6 P2 #2).
  - ``wheel_unparseable_entry_points`` — INI parse failure.
  - ``wheel_metadata_missing_name`` / ``wheel_metadata_missing_version``
    (R6 P2 #2) — METADATA lacks Name or Version.
  - ``wheel_metadata_name_mismatch`` (R6 P2 #2) — METADATA Name
    differs from canonicalized wheel-filename name.
  - ``wheel_metadata_version_mismatch`` (R6 P2 #2 + R9 P2 #3
    textual-equality) — METADATA Version differs from wheel-filename
    version, or pyproject + METADATA disagree as text.
  - ``wheel_no_cognic_entry_point`` — no cognic.* group declared.
  - ``wheel_multiple_cognic_groups`` — > 1 cognic.* group.
  - ``wheel_empty_cognic_entry_point_group`` (R7 P2 #2) — selected
    cognic.* group has no entry-point keys.
  - ``wheel_invalid_entry_point_target`` (R7 P2 #2 + R8 P2 #2 +
    R11 P2 #1) — entry value does not match the Wave-1
    ``module[.submod]*:Object`` shape (single-segment Object; no
    dotted attribute access).
  - ``wheel_duplicate_entry_point_keys`` (R9 P2 #1) — entry_points.txt
    declares duplicate keys / sections; importlib.metadata preserves
    duplicates at runtime so we refuse here.
  - ``wheel_entry_point_module_not_found`` (R9 P2 #2) — target
    ``module.path:Object`` resolves to a module file not present in
    the wheel ZIP.
  - ``wheel_entry_point_object_not_found`` (R10 P2 #1 + R12 P2 #2)
    — the target module parses cleanly but ``Object`` is not
    declared as a top-level ClassDef / FunctionDef / Assign /
    AnnAssign target. Module bytes that fail to parse under the
    declared (PEP 263) or default UTF-8 encoding fire here too.
  - ``wheel_multiple_instruction_manifests`` (M8 finding #3) — a
    zero-entry-point wheel ships MORE THAN ONE 2-part
    ``<package>/cognic-pack-manifest.toml`` member; ambiguous —
    the exactly-one rule mirrors the B2-pre discovery arm.
  - ``wheel_unparseable_instruction_manifest`` (M8 finding #3) —
    the package-local manifest member is oversized (> 1 MiB bounded
    read), not UTF-8, or not valid TOML.
  - ``wheel_instruction_manifest_kind_not_skill`` (M8 finding #3) —
    the manifest's dual-path ``[pack].kind`` is not ``"skill"``.
  - ``wheel_instruction_manifest_mode_not_instruction`` (M8 finding
    #3) — the manifest's dual-path ``[skill].mode`` is not
    ``"instruction"`` (ABSENT defaults to ``"executable"`` per the
    A7 / runtime classification; a zero-entry-point executable skill
    is broken, not an instruction pack).
  - ``wheel_instruction_package_not_importable`` (M8 finding #3) —
    the manifest package name is not identifier-shaped OR the wheel
    lacks ``<pkg>/__init__.py`` (zipimport has no namespace-package
    support), so the Step-11 module-import probe could never operate
    on the validated source.
"""

from __future__ import annotations

import ast
import configparser
import dataclasses
import email.parser
import re
import tomllib
import zipfile
from pathlib import Path
from typing import Any, Final, Literal

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

#: Wave-1 entry-point target regex: ``module[.submod]*:Object``.
#: Each dotted segment must be a valid Python identifier; the Object
#: side is single-segment (no dotted attribute access — Wave-1
#: simplification per R11 P2 #1, since deeper attribute resolution
#: cannot be statically validated).
_IDENT_RE: Final[str] = r"[a-zA-Z_][a-zA-Z0-9_]*"
_ENTRY_POINT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"^{_IDENT_RE}(\.{_IDENT_RE})*:{_IDENT_RE}$"
)


@dataclasses.dataclass(frozen=True, slots=True)
class WheelIntegrityFailure:
    """Carrier for a wheel-integrity refusal. ``failure_mode`` is the
    closed-enum sub-case identifier; ``message`` is operator-readable;
    ``payload`` carries diagnostic context. Callers wrap in their own
    ``VerifyFinding`` / ``SignFinding`` with the appropriate top-level
    closed-enum reason.
    """

    failure_mode: str
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# M8 finding #3 — instruction-wheel fallback (zero-entry-point content packs)
# ---------------------------------------------------------------------------

#: The signed pack-manifest basename the instruction fallback scans wheel
#: members for. LOCAL mirror of ``protocol/plugin_registry._MANIFEST_BASENAME``
#: (the B2-pre discovery arm's constant) — this stdlib-shaped module must not
#: import the protocol registry at runtime; the test-only lockstep drift test
#: at ``tests/unit/cli/test_wheel_integrity_instruction.py`` pins agreement
#: per the drift-detector doctrine.
_INSTRUCTION_MANIFEST_BASENAME: Final[str] = "cognic-pack-manifest.toml"

#: Bounded-read cap for the in-wheel manifest member (1 MiB). A signed
#: instruction manifest is a small TOML file; anything larger is refused
#: BEFORE the bytes are read so a hostile wheel cannot balloon the parse.
_INSTRUCTION_MANIFEST_MAX_BYTES: Final[int] = 1_048_576


def _manifest_pack_block(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """``[pack]`` (canonical) with the legacy ``[tool.cognic.pack]`` fallback
    (dual-path doctrine); ``None`` when absent. LOCAL mirror of
    ``protocol/plugin_registry._manifest_pack_block`` — the lockstep drift
    test pins the agreement (no runtime cross-import)."""
    block = manifest.get("pack")
    if isinstance(block, dict):
        return block
    tool = manifest.get("tool")
    cognic = tool.get("cognic") if isinstance(tool, dict) else None
    legacy = cognic.get("pack") if isinstance(cognic, dict) else None
    return legacy if isinstance(legacy, dict) else None


def _manifest_skill_block(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """``[skill]`` (canonical) with the legacy ``[tool.cognic.skill]``
    fallback (dual-path doctrine); ``None`` when absent. LOCAL mirror of
    ``protocol/plugin_registry._manifest_skill_block`` — lockstep pinned
    test-only."""
    block = manifest.get("skill")
    if isinstance(block, dict):
        return block
    tool = manifest.get("tool")
    cognic = tool.get("cognic") if isinstance(tool, dict) else None
    legacy = cognic.get("skill") if isinstance(cognic, dict) else None
    return legacy if isinstance(legacy, dict) else None


def _manifest_skill_mode(
    skill_block: dict[str, Any],
) -> Literal["executable", "instruction"] | None:
    """``[skill].mode`` classification — LOCAL mirror of
    ``protocol/plugin_registry._manifest_skill_mode`` (ABSENT →
    ``"executable"``; out-of-vocabulary → ``None``). The lockstep drift
    test pins the two classifications in agreement."""
    raw = skill_block.get("mode")
    if raw is None:
        return "executable"
    if raw == "executable":
        return "executable"
    if raw == "instruction":
        return "instruction"
    return None


def _read_instruction_wheel_fallback(
    zf: zipfile.ZipFile,
    *,
    wheel_path: Path,
    matched_dist_info: str,
    all_names: list[str],
) -> tuple[str | None, WheelIntegrityFailure | None]:
    """The M8 finding #3 instruction-wheel fallback — runs ONLY when the
    matched dist-info has no ``entry_points.txt``.

    Returns ``(validated_package_name, None)`` when the wheel is a
    well-formed instruction-skill content wheel, or ``(None, failure)``
    otherwise. Zero manifest candidates reproduce the EXACT pre-existing
    ``wheel_missing_entry_points_file`` failure (message + payload
    byte-identical) so every non-instruction zero-entry-point wheel fails
    exactly as before this arm landed.
    """
    # Step 1 — exactly-one 2-part ``<package>/cognic-pack-manifest.toml``
    # member (the SAME rule the B2-pre discovery arm applies over
    # ``dist.files``, here over the wheel members).
    manifest_members = [
        name
        for name in all_names
        if len(name.split("/")) == 2 and name.split("/")[1] == _INSTRUCTION_MANIFEST_BASENAME
    ]
    if not manifest_members:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_missing_entry_points_file",
            message=(
                f"wheel {wheel_path} dist-info {matched_dist_info!r} "
                "has no entry_points.txt; cannot derive an "
                "integrity-anchored pack kind."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "matched_dist_info": matched_dist_info,
            },
        )
    if len(manifest_members) > 1:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_multiple_instruction_manifests",
            message=(
                f"wheel {wheel_path} has no entry_points.txt and ships "
                f"{len(manifest_members)} package-local "
                f"{_INSTRUCTION_MANIFEST_BASENAME} members: "
                f"{sorted(manifest_members)}. Refusing: an instruction-"
                "skill wheel MUST ship exactly one "
                f"<package>/{_INSTRUCTION_MANIFEST_BASENAME} (the same "
                "exactly-one rule as the M8 manifest-walk discovery arm); "
                "multiple is ambiguous (M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_members": sorted(manifest_members),
            },
        )
    manifest_member = manifest_members[0]

    # Step 2 — bounded read + TOML parse.
    try:
        manifest_size = zf.getinfo(manifest_member).file_size
    except KeyError:
        # Directory-entry-only listings can't reach here (the 2-part scan
        # matched a real member name), but a hostile/degenerate zip could;
        # fail closed through the unparseable arm.
        manifest_size = _INSTRUCTION_MANIFEST_MAX_BYTES + 1
    if manifest_size > _INSTRUCTION_MANIFEST_MAX_BYTES:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_unparseable_instruction_manifest",
            message=(
                f"wheel {wheel_path} member {manifest_member!r} is "
                f"{manifest_size} bytes — larger than the "
                f"{_INSTRUCTION_MANIFEST_MAX_BYTES}-byte (1 MiB) bounded-"
                "read cap for a signed instruction manifest. Refusing "
                "before reading the member (M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_member": manifest_member,
                "manifest_size": manifest_size,
                "max_bytes": _INSTRUCTION_MANIFEST_MAX_BYTES,
            },
        )
    try:
        manifest_bytes = zf.read(manifest_member)
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, zipfile.BadZipFile, OSError) as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_unparseable_instruction_manifest",
            message=(
                f"wheel {wheel_path} member {manifest_member!r} did not "
                f"read + parse as UTF-8 TOML: {type(exc).__name__}: {exc}. "
                "Cannot classify the zero-entry-point wheel as an "
                "instruction-skill content pack (M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_member": manifest_member,
                "error_type": type(exc).__name__,
            },
        )

    # Step 3 — STRICT filter: [pack].kind == "skill" AND [skill].mode ==
    # "instruction" (dual-path). Any mismatch refuses — a zero-entry-point
    # wheel of any OTHER kind/mode is a broken executable pack.
    pack_block = _manifest_pack_block(manifest)
    declared_kind = pack_block.get("kind") if pack_block is not None else None
    if declared_kind != "skill":
        return None, WheelIntegrityFailure(
            failure_mode="wheel_instruction_manifest_kind_not_skill",
            message=(
                f"wheel {wheel_path} has no entry_points.txt and its "
                f"package-local manifest {manifest_member!r} declares "
                f"[pack].kind={declared_kind!r}; only kind='skill' + "
                "[skill].mode='instruction' content packs may omit entry "
                "points. Every other zero-entry-point wheel is refused "
                "(M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_member": manifest_member,
                "declared_kind": declared_kind,
            },
        )
    skill_block = _manifest_skill_block(manifest)
    mode = _manifest_skill_mode(skill_block) if skill_block is not None else None
    if mode != "instruction":
        return None, WheelIntegrityFailure(
            failure_mode="wheel_instruction_manifest_mode_not_instruction",
            message=(
                f"wheel {wheel_path} has no entry_points.txt and its "
                f"package-local manifest {manifest_member!r} declares "
                "[pack].kind='skill' but [skill].mode is not "
                f"'instruction' (classified mode={mode!r}, declared "
                f"{(skill_block or {}).get('mode')!r}); a zero-entry-"
                "point executable-mode skill is a broken pack, not an "
                "instruction content pack (M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_member": manifest_member,
                "declared_mode": (skill_block or {}).get("mode"),
            },
        )

    # Step 4 — package-layout consistency (anti-decoy): the manifest
    # package must be an importable package inside THIS wheel so verify's
    # Step-11 module-import probe operates on exactly the validated
    # source (identifier-shaped name + ``<pkg>/__init__.py``; zipimport
    # has no namespace-package support).
    package_name = manifest_member.split("/")[0]
    candidate_init = f"{package_name}/__init__.py"
    if not package_name.isidentifier() or candidate_init not in all_names:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_instruction_package_not_importable",
            message=(
                f"wheel {wheel_path} instruction manifest at "
                f"{manifest_member!r} names package {package_name!r}, "
                "which is not an importable package in this wheel "
                f"(identifier-shaped name + {candidate_init!r} member "
                "required; zipimport does not support namespace "
                "packages). The Step-11 module-import probe could never "
                "operate on the validated source (M8 finding #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "manifest_member": manifest_member,
                "package_name": package_name,
                "candidate_init": candidate_init,
            },
        )
    return package_name, None


def read_signed_wheel_dist_info_metadata(
    wheel_path: Path,
    *,
    expected_project_name: str,
    expected_version: str,
) -> tuple[
    tuple[str, str, str, tuple[tuple[str, str], ...], str | None] | None,
    WheelIntegrityFailure | None,
]:
    """Read the cosign-signed wheel's dist-info entries (entry_points.txt
    + METADATA) integrity-anchored to the wheel filename's name+version.

    Returns ``((metadata_canonical_name, metadata_version, kind,
    entry_points, instruction_package), None)`` on success or
    ``(None, failure)`` on refusal.

    ``entry_points`` is the tuple of ``(module_path, object_path)`` pairs
    parsed + validated from the **selected dist-info's** entry_points.txt
    (same source the helper validates against). Threading this out of
    the helper avoids the R15 P2 #1 anti-pattern of having callers
    re-discover the entry-point file by an "ends with /entry_points.txt"
    suffix scan, which can match a non-dist-info member that happens to
    sort earlier in the ZIP and result in load-probing a benign decoy
    while the real dist-info entry stays unloadable. Callers MUST use
    this returned tuple directly.

    ``instruction_package`` (additive 5th slot, M8 finding #3) is the
    validated instruction stub-package name when the wheel is a
    zero-entry-point instruction-skill content wheel (derived kind
    ``"skill"``, EMPTY ``entry_points``) and ``None`` for every
    entry-point wheel. Verify's Step-11 module-import probe MUST use
    this returned name directly (same anti-decoy doctrine as the
    entry-point tuple — no re-discovery).
    """
    expected_canonical = canonicalize_name(expected_project_name)
    try:
        expected_v = Version(expected_version)
    except InvalidVersion as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_version_mismatch",
            message=(
                f"pyproject [project].version={expected_version!r} is "
                f"not a valid PEP 440 version: {type(exc).__name__}: {exc}."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "expected_version": expected_version,
            },
        )

    try:
        zf_ctx = zipfile.ZipFile(wheel_path)
    except zipfile.BadZipFile as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_not_a_zip",
            message=(
                f"wheel {wheel_path} is not a valid zip / wheel: {type(exc).__name__}: {exc}."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "error_type": type(exc).__name__,
            },
        )
    except OSError as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_not_a_zip",
            message=(f"could not open wheel {wheel_path} as a zip: {type(exc).__name__}: {exc}."),
            payload={
                "wheel_path": str(wheel_path),
                "error_type": type(exc).__name__,
            },
        )

    with zf_ctx as zf:
        all_names = zf.namelist()
        # R6 P2 #1: enumerate dist-info directories; > 1 = refuse
        # (spoof-first attack signal).
        dist_info_dirs: set[str] = set()
        for name in all_names:
            if ".dist-info/" in name:
                idx = name.find(".dist-info/")
                dist_info_dirs.add(name[: idx + len(".dist-info")])
        if len(dist_info_dirs) > 1:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_multiple_dist_info_dirs",
                message=(
                    f"wheel {wheel_path} contains {len(dist_info_dirs)} "
                    f"*.dist-info directories: {sorted(dist_info_dirs)}. "
                    "Refusing: a wheel MUST ship exactly one dist-info; "
                    "multiple is a spoof-first attack signal (R6 P2 #1)."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "dist_info_dirs": sorted(dist_info_dirs),
                },
            )

        # R6 P2 #1: select the dist-info matching the wheel-filename
        # canonicalized name + version. PEP 491 / wheel spec uses
        # ``{name}-{version}.dist-info`` where the name is normalized
        # with ``_`` for ``-``; legacy wheels may use the canonical
        # ``-`` form too — accept either spelling.
        candidates_normalized = {
            f"{expected_canonical.replace('-', '_')}-{expected_v}.dist-info",
            f"{expected_canonical}-{expected_v}.dist-info",
        }
        matched_dist_info: str | None = None
        for d in dist_info_dirs:
            if d in candidates_normalized:
                matched_dist_info = d
                break
        if matched_dist_info is None:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_dist_info_mismatch",
                message=(
                    f"wheel {wheel_path} has dist-info "
                    f"{sorted(dist_info_dirs)}, but none matches "
                    f"expected {sorted(candidates_normalized)} "
                    "(canonicalized from wheel filename name + "
                    "version). Refusing: dist-info MUST match the "
                    "wheel."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "found_dist_info_dirs": sorted(dist_info_dirs),
                    "expected_dist_info_candidates": sorted(candidates_normalized),
                },
            )

        entry_points_member = f"{matched_dist_info}/entry_points.txt"
        metadata_member = f"{matched_dist_info}/METADATA"
        instruction_package: str | None = None
        if entry_points_member not in all_names:
            # M8 finding #3 — instruction-wheel fallback. ADR-027
            # instruction-only skill packs are zero-entry-point CONTENT
            # packs; absent entry_points.txt may pass ONLY when the wheel
            # ships exactly one package-local instruction manifest with
            # kind="skill" + mode="instruction". Zero candidates
            # reproduces the EXACT pre-existing
            # ``wheel_missing_entry_points_file`` failure; any other
            # mismatch refuses via the instruction closed-taxonomy modes.
            instruction_package, instruction_failure = _read_instruction_wheel_fallback(
                zf,
                wheel_path=wheel_path,
                matched_dist_info=matched_dist_info,
                all_names=all_names,
            )
            if instruction_failure is not None:
                return None, instruction_failure
        if metadata_member not in all_names:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_missing_metadata_file",
                message=(
                    f"wheel {wheel_path} dist-info {matched_dist_info!r} "
                    "has no METADATA file; cannot integrity-anchor name "
                    "+ version (R6 P2 #2)."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "matched_dist_info": matched_dist_info,
                },
            )
        # ``entry_points_member`` is guaranteed present when
        # ``instruction_package`` is None (the fallback either validated
        # an instruction wheel or returned the refusal above).
        ep_bytes = b"" if instruction_package is not None else zf.read(entry_points_member)
        metadata_bytes = zf.read(metadata_member)
        wheel_members: frozenset[str] = frozenset(all_names)

    # R6 P2 #2: parse METADATA (RFC822 / email-message format per the
    # wheel spec) for Name + Version + cross-check.
    metadata_msg = email.parser.Parser().parsestr(metadata_bytes.decode("utf-8", errors="replace"))
    metadata_name = metadata_msg.get("Name")
    metadata_version_field = metadata_msg.get("Version")
    if not isinstance(metadata_name, str) or not metadata_name.strip():
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_missing_name",
            message=(f"wheel {wheel_path} METADATA in {matched_dist_info!r} missing Name field."),
            payload={
                "wheel_path": str(wheel_path),
                "matched_dist_info": matched_dist_info,
            },
        )
    if not isinstance(metadata_version_field, str) or not metadata_version_field.strip():
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_missing_version",
            message=(
                f"wheel {wheel_path} METADATA in {matched_dist_info!r} missing Version field."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "matched_dist_info": matched_dist_info,
            },
        )
    metadata_name_canonical = canonicalize_name(metadata_name.strip())
    if metadata_name_canonical != expected_canonical:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_name_mismatch",
            message=(
                f"wheel {wheel_path} METADATA Name={metadata_name!r} "
                f"(canonicalized {metadata_name_canonical!r}) does not "
                f"match wheel-filename canonicalized name "
                f"{expected_canonical!r}. Refusing: a renamed wheel "
                "cannot pass verification (R6 P2 #2)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "metadata_name": metadata_name,
                "metadata_name_canonical": metadata_name_canonical,
                "expected_canonical": expected_canonical,
            },
        )
    try:
        metadata_v = Version(metadata_version_field.strip())
    except InvalidVersion as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_version_mismatch",
            message=(
                f"wheel {wheel_path} METADATA Version="
                f"{metadata_version_field!r} is not a valid PEP 440 "
                f"version: {type(exc).__name__}: {exc}."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "metadata_version": metadata_version_field,
            },
        )
    if metadata_v != expected_v:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_version_mismatch",
            message=(
                f"wheel {wheel_path} METADATA Version={metadata_v} "
                f"does not match wheel-filename version {expected_v}. "
                "Refusing: a renamed wheel cannot pass verification — "
                "signed METADATA bytes are the source of truth (R6 P2 "
                "#2)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "metadata_version": str(metadata_v),
                "expected_version": str(expected_v),
            },
        )
    # R9 P2 #3: require EXACT TEXTUAL agreement between pyproject
    # ``[project].version`` (== ``expected_version``) and the wheel
    # METADATA Version field. Pre-fix the helper used ``Version()``
    # semantic equality so ``1.0`` (pyproject + filename) and
    # ``1.0.0`` (METADATA) compared equal; sign emitted SLSA
    # ``pack_version='1.0'`` while verify rebound to ``'1.0.0'`` →
    # round-trip failure with ``slsa_pack_version_mismatch``.
    metadata_version_stripped = metadata_version_field.strip()
    if metadata_version_stripped != expected_version:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_metadata_version_mismatch",
            message=(
                f"wheel {wheel_path} METADATA Version="
                f"{metadata_version_stripped!r} differs from pyproject "
                f"+ wheel-filename version {expected_version!r} as "
                "TEXTUAL form, even though both parse to the same PEP "
                "440 Version. Refusing: pyproject, wheel filename, and "
                "wheel METADATA MUST all use the same spelling so sign "
                "+ verify operate on the same string (R9 P2 #3)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "metadata_version_text": metadata_version_stripped,
                "expected_version_text": expected_version,
            },
        )

    # M8 finding #3 — instruction wheels return here: METADATA name +
    # version anchoring above is SHARED with the entry-point path; the
    # fallback already validated the exactly-one manifest + strict
    # kind/mode filter + package layout. Derived kind is "skill", the
    # validated entry-point tuple is EMPTY (zero-executable by design —
    # no faked entry point), and the validated stub-package name rides
    # the additive 5th slot for verify's Step-11 module-import probe.
    if instruction_package is not None:
        return (
            metadata_name_canonical,
            metadata_version_stripped,
            "skill",
            (),
            instruction_package,
        ), None

    # R8 P2 #3: ``RawConfigParser`` (no interpolation). A wheel with
    # ``sign_target = pkg:%(missing)s`` would otherwise raise
    # ``InterpolationMissingOptionError`` at parser.get time —
    # OUTSIDE the configparser.Error catch. RawConfigParser returns
    # values verbatim; the regex check then catches malformed
    # targets cleanly.
    #
    # R9 P2 #1: ``strict=True`` (default) so duplicate option keys
    # raise ``DuplicateOptionError`` — importlib.metadata preserves
    # duplicates at runtime, so we refuse here with a distinct
    # closed-enum sub-case.
    parser = configparser.RawConfigParser()
    parser.optionxform = str  # type: ignore[method-assign,assignment]
    try:
        parser.read_string(ep_bytes.decode("utf-8", errors="replace"))
    except (configparser.DuplicateOptionError, configparser.DuplicateSectionError) as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_duplicate_entry_point_keys",
            message=(
                f"wheel {wheel_path} entry_points.txt declares duplicate "
                f"entry-point keys / sections: {type(exc).__name__}: "
                f"{exc}. importlib.metadata preserves all duplicates at "
                "runtime; refusing to validate the bundle when one of "
                "the duplicate values could be malformed (R9 P2 #1)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "error_type": type(exc).__name__,
            },
        )
    except configparser.Error as exc:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_unparseable_entry_points",
            message=(
                f"wheel {wheel_path} entry_points.txt did not parse as "
                f"INI: {type(exc).__name__}: {exc}."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "error_type": type(exc).__name__,
            },
        )

    cognic_groups: list[str] = []
    if parser.has_section("cognic.agents"):
        cognic_groups.append("agent")
    if parser.has_section("cognic.tools"):
        cognic_groups.append("tool")
    if parser.has_section("cognic.skills"):
        cognic_groups.append("skill")
    # Sprint-7A2 T9: hook is the 4th first-class pack kind (alongside
    # tool / skill / agent). Hook packs declare ``[cognic.hooks]`` in
    # entry_points.txt; the kind-derivation table below maps it to
    # ``"hook"``. Hook packs ship the same attestation set as tool /
    # skill packs (no AgentCard JWS); sign + verify gate JWS on
    # ``pack_kind == "agent"`` so hook packs flow through identically.
    if parser.has_section("cognic.hooks"):
        cognic_groups.append("hook")

    if not cognic_groups:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_no_cognic_entry_point",
            message=(
                f"wheel {wheel_path} declares no cognic.* entry-point "
                "group. Cognic packs MUST declare exactly one of "
                '[project.entry-points."cognic.agents" / "cognic.tools" '
                '/ "cognic.skills" / "cognic.hooks"] so verify can derive '
                "an integrity-anchored kind."
            ),
            payload={
                "wheel_path": str(wheel_path),
            },
        )
    if len(cognic_groups) > 1:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_multiple_cognic_groups",
            message=(
                f"wheel {wheel_path} declares multiple cognic.* "
                f"entry-point groups: {cognic_groups}. Refusing: a "
                "pack MUST declare exactly one cognic kind."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "cognic_groups": cognic_groups,
            },
        )
    kind = cognic_groups[0]
    selected_section = {
        "agent": "cognic.agents",
        "tool": "cognic.tools",
        "skill": "cognic.skills",
        # Sprint-7A2 T9 — hook is the 4th first-class kind.
        "hook": "cognic.hooks",
    }[kind]

    # R7 P2 #2: the selected cognic.* group MUST contain at least one
    # well-formed ``module:Object`` entry. An empty section header
    # alone would otherwise pass ``has_section`` while
    # importlib.metadata at runtime would discover no entry point.
    entries = parser.options(selected_section)
    if not entries:
        return None, WheelIntegrityFailure(
            failure_mode="wheel_empty_cognic_entry_point_group",
            message=(
                f"wheel {wheel_path} declares ``[{selected_section}]`` "
                "but the section has no entry-point keys. The pack "
                "would not load via importlib.metadata at runtime "
                "admission (R7 P2 #2)."
            ),
            payload={
                "wheel_path": str(wheel_path),
                "selected_section": selected_section,
            },
        )

    # Validate each entry's target syntax + module/object declaration.
    # Collect every validated ``(module_path, object_path)`` tuple from
    # the SAME parser pass so callers (verify step 11 — the FINAL gate
    # of the trust pipeline) can probe each without re-reading the
    # wheel — R15 follow-up round 1 P2 #1 + P2 #2 reviewer fixes.
    validated_entry_points: list[tuple[str, str]] = []
    for entry_key in entries:
        entry_value_raw = parser.get(selected_section, entry_key)
        entry_value = entry_value_raw.strip() if isinstance(entry_value_raw, str) else ""
        if not _ENTRY_POINT_TARGET_RE.match(entry_value):
            return None, WheelIntegrityFailure(
                failure_mode="wheel_invalid_entry_point_target",
                message=(
                    f"wheel {wheel_path} ``[{selected_section}]`` entry "
                    f"{entry_key!r} = {entry_value!r} does not match "
                    "the Wave-1 ``module[.submod]*:Object`` shape "
                    "(R7 P2 #2 + R8 P2 #2 + R11 P2 #1)."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "selected_section": selected_section,
                    "entry_key": entry_key,
                    "entry_value": entry_value,
                },
            )

        # R9 P2 #2: target module must exist as a wheel member.
        module_path, _separator, object_path = entry_value.partition(":")
        module_parts = module_path.split(".")
        candidate_file = "/".join(module_parts) + ".py"
        candidate_pkg = "/".join(module_parts) + "/__init__.py"
        if candidate_file in wheel_members:
            module_member = candidate_file
        elif candidate_pkg in wheel_members:
            module_member = candidate_pkg
        else:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_entry_point_module_not_found",
                message=(
                    f"wheel {wheel_path} ``[{selected_section}]`` entry "
                    f"{entry_key!r} = {entry_value!r} targets module "
                    f"{module_path!r} but neither {candidate_file!r} "
                    f"nor {candidate_pkg!r} is a member of the wheel "
                    "(R9 P2 #2)."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "selected_section": selected_section,
                    "entry_key": entry_key,
                    "entry_value": entry_value,
                    "target_module": module_path,
                    "candidate_file": candidate_file,
                    "candidate_pkg": candidate_pkg,
                },
            )

        # R10 P2 #1 + R12 P2 #2: parse module bytes via ``ast.parse``
        # (PEP 263 coding cookies honored automatically; no static
        # decode); confirm the named object is declared as a top-level
        # ClassDef / FunctionDef / Assign / AnnAssign target.
        # Loadability + import-time-failure detection moved to the
        # isolated-subprocess load probe in ``cli/_load_probe.py``
        # (R15 reviewer pivot).
        try:
            with zipfile.ZipFile(wheel_path) as _zf_object_check:
                module_source_bytes = _zf_object_check.read(module_member)
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_entry_point_object_not_found",
                message=(
                    f"wheel {wheel_path}: could not read module member "
                    f"{module_member!r} for object-existence check: "
                    f"{type(exc).__name__}: {exc}."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_member": module_member,
                    "error_type": type(exc).__name__,
                },
            )
        try:
            module_ast = ast.parse(module_source_bytes, filename=module_member)
        except (SyntaxError, ValueError) as exc:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_entry_point_object_not_found",
                message=(
                    f"wheel {wheel_path} module {module_member!r} did "
                    f"not parse as Python: {type(exc).__name__}: {exc}. "
                    "Cannot statically validate the entry-point object "
                    "is declared. (PEP 263 source encoding cookies are "
                    "honored; modules with invalid bytes under the "
                    "declared / default encoding fail here.)"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_member": module_member,
                    "error_type": type(exc).__name__,
                },
            )

        # The R11 P2 #1 regex requires single-segment Object syntax,
        # so ``object_path`` here is exactly the declared name.
        top_level_names: set[str] = set()
        for node in module_ast.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                top_level_names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        top_level_names.add(target.id)
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                top_level_names.add(elt.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                top_level_names.add(node.target.id)

        if object_path not in top_level_names:
            return None, WheelIntegrityFailure(
                failure_mode="wheel_entry_point_object_not_found",
                message=(
                    f"wheel {wheel_path} ``[{selected_section}]`` entry "
                    f"{entry_key!r} = {entry_value!r} targets object "
                    f"{object_path!r} in module {module_path!r}, but "
                    f"{object_path!r} is not declared as a top-level "
                    "ClassDef / FunctionDef / Assign / AnnAssign target. "
                    "Loadability — including imported names + executable "
                    "top-level constructs — is checked by the isolated-"
                    "subprocess load probe (R15 reviewer pivot)."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "selected_section": selected_section,
                    "entry_key": entry_key,
                    "entry_value": entry_value,
                    "target_module": module_path,
                    "target_object": object_path,
                    "module_member": module_member,
                    "top_level_names": sorted(top_level_names),
                },
            )

        # Entry validated end-to-end: shape + module-member existence +
        # parseable + object declared. Record the (module, object)
        # tuple for downstream load-probe consumption.
        validated_entry_points.append((module_path, object_path))

    return (
        metadata_name_canonical,
        metadata_version_stripped,
        kind,
        tuple(validated_entry_points),
        # M8 finding #3 — additive instruction-package slot: ALWAYS None
        # on the entry-point path (byte/behavior-unchanged contract for
        # entry-point wheels).
        None,
    ), None


__all__ = [
    "WheelIntegrityFailure",
    "read_signed_wheel_dist_info_metadata",
]
