"""protocol/mcp_manifest.py — signed-static MCP pack manifest extractor.

Critical-controls module per AGENTS.md (Plugin trust + supply chain
— manifest extraction is the registry's only read of pack-controlled
TOML at admission time, and its deferred-load invariant is what
keeps a malicious pack from getting code execution before the trust
gate has cleared it).

Per Sprint-5 R3 P1 doctrine, this module is **admission-side**: it
imports + constructs cleanly without the ``mcp`` SDK installed
(``mcp_manifest`` does not import ``mcp`` anywhere — neither at
module scope nor inside method bodies; pack-manifest extraction uses
``importlib.metadata`` + ``tomllib`` only). The kernel image therefore
runs the manifest extractor without the default-adapters image's
extra deps.

The contract per ADR-002 §"MCP STDIO threat model" gate 1:

  1. A pack ships ``cognic-pack-manifest.toml`` as **package data**
     inside its importable package directory (e.g.,
     ``cognic_test_mcp_pack/cognic-pack-manifest.toml``).
  2. The pack's cosign-verified wheel covers the manifest file's
     bytes via inclusion (the pack's ``pyproject.toml`` declares the
     file via ``[tool.hatch.build.targets.wheel.force-include]``,
     ``[tool.setuptools.package-data]``, ``[tool.poetry.include]``,
     or the equivalent build-backend mechanism — the contract is
     "ship as package data inside the importable package directory",
     NOT "use any specific build backend").
  3. ``extract_pack_manifest(distribution_name, package_name)`` reads
     this file via ``importlib.metadata.Distribution.locate_file()``
     — which returns a path WITHOUT importing the package code. The
     deferred-load invariant of Sprint-4 plugin admission applies
     here too: the registry must NOT execute pack code (not even
     ``__init__.py``) before the trust gate has verified the
     cosign signature over the wheel.

Why ``Distribution.locate_file()`` and not ``importlib.resources.files()``:

- ``locate_file()`` resolves relative paths against the dist's RECORD
  metadata WITHOUT triggering package import. Works for both editable
  (``uv pip install -e``) and wheel installs identically.
- ``importlib.resources.files()`` may execute ``__init__.py`` as a
  side effect (depends on the resource backend), even an empty init.
  The Sprint-4 invariant is specifically about not calling
  ``EntryPoint.load()`` (which loads the Plugin class), but
  ``__init__.py`` execution is in a gray zone we treat as forbidden
  for safety.

The deferred-load invariant has a load-bearing test
(``TestExtractDoesNotImportPackage`` in
``tests/unit/protocol/test_mcp_manifest.py``): the on-disk fixture
pack's ``__init__.py`` raises ``AssertionError`` on import, so any
regression that triggers package import surfaces immediately. The
test ALSO monkeypatches ``importlib.import_module`` to fail loudly
on any attempt — so a regression is caught even without the fixture
pack actually installed.

Closed exception hierarchy. The two leaves are MEANINGFULLY
DISTINCT extractor outcomes; the **registry's choice of how to
react** to each is a separate concern (Sprint-5 T6 R2 doctrine):

- :class:`PackManifestNotFoundError` — distribution / RECORD /
  on-disk file absent. **Current T6 admission contract:** the
  registry treats this as "no MCP intent" and proceeds (the pack
  is Sprint-4-style or non-MCP cognic). The closed-enum reason
  ``mcp_manifest_missing`` is RESERVED for a future explicit
  MCP-intent path (Sprint-7A's ``agentos validate``, or a future
  MCP-specific entry-point group); no current T6 admission code
  path emits it. This split — extractor exception vs registry
  refusal — is intentional: the extractor surfaces the structural
  fact "no manifest at this path"; whether that should refuse the
  pack is a policy question the registry answers.
- :class:`PackManifestMalformedError` — file present but TOML
  decode failed. **Current T6 admission contract:** the registry
  refuses with ``mcp_manifest_malformed``, regardless of whether
  the manifest would have signalled MCP intent (cosign-signed
  bytes that don't parse imply a packaging bug or corruption that
  must surface). The R2 doctrine also routes a present-but-non-
  dict ``[tool.cognic.mcp]`` block to ``mcp_manifest_malformed``
  via the registry's safe walk, even though the extractor itself
  succeeds in that case (the TOML parsed fine; the inner block
  shape is wrong).

Both leaves inherit from :class:`MCPManifestError` so a single
``except`` at the registry boundary can catch the whole extraction
surface.
"""

from __future__ import annotations

import importlib.metadata as _im
import re as _re
import tomllib
from pathlib import Path
from typing import Any


class MCPManifestError(Exception):
    """Base class for manifest-extraction failures.

    The registry catches this base in its admission pipeline
    (``register_with_full_attestation_check``) but the **per-leaf
    routing is asymmetric** — it is NOT a one-leaf-one-refusal
    mapping (R2 doctrine; see the module docstring for the
    extractor-vs-registry semantic split):

    - :class:`PackManifestMalformedError` → registry refuses with
      ``mcp_manifest_malformed`` (always, regardless of pack
      intent — cosign-signed bytes that don't parse imply a
      packaging-bug fail-closed event).
    - :class:`PackManifestNotFoundError` → registry catches and
      **proceeds** (no MCP intent — Sprint-4-style pack OR non-MCP
      cognic pack). The closed-enum ``mcp_manifest_missing``
      literal exists in the ``RefusalReason`` vocabulary but is
      RESERVED for a future explicit MCP-intent path; no current
      admission code path emits it.

    When adding a new leaf subclass, choose its registry-side
    behaviour deliberately: a fail-closed-on-bytes-corruption leaf
    behaves like ``PackManifestMalformedError`` (always refuses;
    needs a new ``RefusalReason`` literal + mapper branch); a
    structural-fact leaf behaves like ``PackManifestNotFoundError``
    (registry policy decides whether/when to refuse). The Sprint-4
    closed-enum extension contract (literal + mapper + test arm
    + audit branch) only applies to the FAIL-CLOSED leaves.
    """


class PackManifestNotFoundError(MCPManifestError):
    """Raised when ``cognic-pack-manifest.toml`` cannot be located in
    the installed pack distribution.

    Three ways this fires:

    1. Distribution itself is not installed (``importlib.metadata.
       PackageNotFoundError`` from the underlying lookup).
    2. Distribution is installed but RECORD does not list the
       manifest path (the pack's build backend was misconfigured —
       e.g., ``[tool.hatch.build.targets.wheel.force-include]``
       missing the manifest line).
    3. RECORD lists the path but the file does not exist on disk
       (corrupted install / partial wheel extraction).

    **Current T6 admission contract** (R2 doctrine): the registry
    catches this exception and proceeds — a missing manifest is
    treated as "no MCP intent" (the pack is Sprint-4-style or a
    non-MCP cognic pack). The closed-enum ``mcp_manifest_missing``
    literal exists in the registry's :data:`RefusalReason` vocabulary
    but is RESERVED for a future explicit MCP-intent path; today no
    admission code path emits it. See the module docstring for the
    extractor-vs-registry semantic split.

    The exception message names the distribution and the expected
    manifest relative path so when a future caller does decide to
    map this to a refusal — or when a pack author is debugging via
    Sprint-7A's ``agentos validate`` — the build-configuration error
    is direct.
    """


class PackManifestMalformedError(MCPManifestError):
    """Raised when the manifest file exists but is not valid TOML.

    Operators see this as ``mcp_manifest_malformed``. The original
    ``tomllib.TOMLDecodeError`` is chained via ``__cause__`` so the
    parser's line/column diagnostic is preserved for debugging.
    """


#: T15 R1 P3 #1 — pack-controlled ``package_name`` shape pin. Restricts
#: the value to a single Python identifier segment (the importable
#: package directory): ``[A-Za-z_][A-Za-z0-9_]*``. This rejects path
#: separators (``/``, ``\``), parent-directory traversal (``..``),
#: leading dots, hyphens (which Python disallows in package names but
#: a malformed pack metadata might include), and any other character
#: that could be interpolated into a path Distribution.locate_file
#: would resolve outside the intended package-data directory.
#:
#: This is a defence-in-depth gate: ``locate_file`` itself walks the
#: distribution's RECORD index and shouldn't return paths outside the
#: distribution, BUT (a) editable installs + custom backends use
#: looser path resolution; (b) some test stubs / SimplePath
#: implementations don't validate; (c) the Sprint-4 contract is that
#: pack-controlled string fields fail closed at admission, not at
#: deeper layers. Mirrors :func:`_validate_version_for_object_key` in
#: ``protocol/supply_chain.py`` (Sprint 4 R1 P2).
_PACKAGE_NAME_PATTERN: _re.Pattern[str] = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_package_name(package_name: str) -> None:
    """Reject any pack-controlled ``package_name`` that is not a
    single Python identifier segment.

    :raises PackManifestNotFoundError: when the value contains path
        separators, parent-directory traversal, leading dots, or any
        character outside ``[A-Za-z0-9_]``. Also rejects values that
        don't start with a letter or underscore (``0foo``, etc.).

    The message names the closed-enum invariant explicitly so an
    operator debugging via Sprint-7A ``agentos validate`` sees the
    contract: ``package_name`` is the importable directory segment,
    NOT a path. Path-shaped inputs get rejected here rather than
    flowing into ``Distribution.locate_file`` (which on some backends
    would resolve them outside the package-data root).
    """
    if not isinstance(package_name, str) or not _PACKAGE_NAME_PATTERN.fullmatch(package_name):
        raise PackManifestNotFoundError(
            f"package_name must be a single Python identifier segment "
            f"matching ^[A-Za-z_][A-Za-z0-9_]*$ (got "
            f"{type(package_name).__name__}). Path separators, '..' "
            f"traversal, hyphens, and leading dots are rejected: this is "
            f"defence-in-depth before Distribution.locate_file resolves "
            f"the cognic-pack-manifest.toml path. The pack's distribution "
            f"metadata declares an invalid package directory name."
        )


def extract_pack_manifest(*, distribution_name: str, package_name: str) -> dict[str, Any]:
    """Read ``<package_name>/cognic-pack-manifest.toml`` from an
    installed pack distribution WITHOUT importing pack code.

    :param distribution_name: The cosign-signed distribution identity
        (the value in pack's ``[project] name``; same value the trust
        gate verifies the cosign signature over). Looked up via
        ``importlib.metadata.distribution(distribution_name)``.
    :param package_name: The importable package directory name (the
        value in pack's ``[tool.hatch.build.targets.wheel] packages``).
        For most packs ``distribution_name`` and ``package_name``
        differ only in ``-`` vs ``_`` (PEP 503 normalisation), but
        the contract is to take both explicitly so packs that don't
        follow that convention still work. T15 R1 P3 #1: validated
        against ``_PACKAGE_NAME_PATTERN`` BEFORE any path
        interpolation.
    :returns: The parsed TOML manifest as a nested dict (output of
        ``tomllib.loads``). Empty TOML parses to ``{}``; the caller
        (the capability validator in T6.2) is responsible for
        validating semantic shape.
    :raises PackManifestNotFoundError: distribution not installed OR
        manifest path not in RECORD OR file does not exist on disk OR
        ``package_name`` violates the identifier pattern (T15 R1 P3 #1).
    :raises PackManifestMalformedError: file exists but is not valid
        TOML (chained from :class:`tomllib.TOMLDecodeError`).

    Resolution mechanism: ``Distribution.locate_file(relative_path)``.
    Returns a path WITHOUT importing the package; works for both
    editable and wheel installs. Pack code is NEVER imported by this
    function — the deferred-load invariant of Sprint-4 admission
    applies (see the module docstring + ``TestExtractDoesNotImportPackage``
    in ``tests/unit/protocol/test_mcp_manifest.py``).
    """
    # T15 R1 P3 #1: shape-check ``package_name`` before any path
    # interpolation. Catches '../', backslashes, slashes, and any
    # other separator-shaped value that could escape the intended
    # package-data resolution root.
    _validate_package_name(package_name)

    try:
        dist = _im.distribution(distribution_name)
    except _im.PackageNotFoundError as exc:
        raise PackManifestNotFoundError(
            f"Pack distribution {distribution_name!r} is not installed in the "
            f"current Python environment. The MCP manifest extractor cannot "
            f"locate ``cognic-pack-manifest.toml`` without an installed "
            f"distribution to query. Install the pack via ``uv pip install`` "
            f"(or the equivalent) and retry."
        ) from exc

    relative_path = f"{package_name}/cognic-pack-manifest.toml"
    located = dist.locate_file(relative_path)
    if located is None:
        raise PackManifestNotFoundError(
            f"Pack {distribution_name!r} does not declare "
            f"``{relative_path}`` in its RECORD / installed-files metadata. "
            f"Per ADR-002 §'MCP STDIO threat model' gate 1, the signed "
            f"static manifest must ship as package data at this path. "
            f"Check the pack's pyproject.toml: for hatchling, the file "
            f"must be listed under "
            f"``[tool.hatch.build.targets.wheel.force-include]`` (or be "
            f"matched by the package directory glob); for setuptools, "
            f"``[tool.setuptools.package-data]``; for poetry, "
            f"``[tool.poetry.include]``."
        )
    # ``Distribution.locate_file`` returns either ``Path`` (real
    # distributions) or ``SimplePath`` (test stubs / certain backends);
    # both expose ``__fspath__`` and behave path-like for our purposes.
    # Construct ``Path`` via ``str(...)`` to satisfy the typed
    # ``Path(str | PathLike[str])`` signature without losing runtime
    # compatibility with stub objects.
    manifest_path = Path(str(located))
    if not manifest_path.is_file():
        raise PackManifestNotFoundError(
            f"Pack {distribution_name!r} declares ``{relative_path}`` in its "
            f"RECORD metadata but the file does not exist on disk at "
            f"{manifest_path!s}. Likely a corrupted install or partial "
            f"wheel extraction; reinstall the pack."
        )

    try:
        raw = manifest_path.read_text(encoding="utf-8")
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PackManifestMalformedError(
            f"Pack {distribution_name!r} ships ``{relative_path}`` but the "
            f"file is not valid TOML: {exc}. The cosign signature covers "
            f"the file's bytes — re-signing a corrected manifest is the "
            f"required fix; AgentOS does not interpret partial / repaired "
            f"manifests."
        ) from exc

    return parsed


__all__ = (
    "MCPManifestError",
    "PackManifestMalformedError",
    "PackManifestNotFoundError",
    "extract_pack_manifest",
)
