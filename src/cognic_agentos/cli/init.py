"""Sprint-7A T5 + Sprint-7A2 T3 — `agentos init-{tool,skill,agent,hook}` scaffold logic.

The Typer command wrappers in :mod:`cognic_agentos.cli` delegate
into :func:`scaffold`; the scaffold function is the unit-tested seam
that walks the per-kind Jinja2 template tree under
:mod:`cognic_agentos.cli.templates` and renders each file into the
target pack directory.

Pack-author UX:

    $ agentos init-tool example
    $ ls cognic-tool-example/
    pyproject.toml  cognic-pack-manifest.toml  README.md  src/  tests/
    attestations/   .github/

Every produced ``pyproject.toml`` + manifest carries ``AUTHOR-FILL:``
placeholders at every author-customizable site so ``agentos validate``
(Sprint-7A T6) refuses the freshly-scaffolded pack with explicit
remediation messages — NOT generic "missing field" panics. Authors
replace the placeholders, re-run validate, iterate to green.

The generated SDK subclass overrides the right abstract method per
kind (R5 P2 #2):

  - Tool subclass overrides ``_invoke`` (NOT ``invoke``; the SDK's
    ``Tool.__init_subclass__`` rejects subclasses that override the
    public final method per R3 P2 #1 / R8 P2 #1).
  - Skill subclass overrides ``execute`` (NOT ``__init__``; the SDK's
    ``Skill.__init_subclass__`` rejects subclasses that define their
    own constructor per R6 P2 #1).
  - Agent subclass overrides ``handle`` (the public abstract; the
    signature matches the shipped Sprint-6 ``A2AEndpoint`` dispatch
    contract).
  - Hook subclass overrides ``_invoke(context, payload)`` (NOT
    ``invoke``; the SDK's ``Hook.__init_subclass__`` rejects
    subclasses that override the public final method, mirrors Tool
    R8 P2 #1; Sprint-7A2 T2). Pack authors declare ``hook_id`` +
    ``phase`` ClassVars; the build-time validator (Sprint-7A2 T6)
    cross-checks both against the manifest's ``[hooks].declarations``
    block.

Sprint-7A2 T3 adds ``hook`` as the 4th supported kind. The
hook-specific entry-point group is ``cognic.hooks`` (not
``cognic.hooks`` plural-like-the-others — wait, it IS plural;
``cognic.tools`` / ``cognic.skills`` / ``cognic.agents`` /
``cognic.hooks`` all follow the same plural-noun convention).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final

import jinja2

#: Root of the Jinja2 template tree shipped with the SDK. Each
#: subdirectory ``tool / skill / agent`` is a self-contained pack
#: scaffold.
_TEMPLATES_ROOT: Final[Path] = Path(__file__).parent / "templates"

#: Path placeholder substituted at write time for the pack's Python
#: module name (``cognic_{kind}_{pack_name}``). Used in the template
#: tree so files under ``src/__module__/`` land under
#: ``src/cognic_<kind>_<name>/`` in the produced pack.
_MODULE_PATH_PLACEHOLDER: Final[str] = "__module__"

#: Closed allow-list of supported scaffold kinds. Each kind has a
#: matching template subtree + an ``app.command`` registration in
#: :mod:`cognic_agentos.cli`. Sprint-7A2 T3 adds ``hook`` as the 4th
#: kind alongside the Sprint-7A T5 trio.
_SUPPORTED_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent", "hook"})

#: Pack-name validator: lowercase ASCII letters / digits / underscores;
#: must start with a letter (Python-identifier rule, restricted to
#: lowercase to keep generated module names PEP 8). Rejects empty
#: strings, paths with separators, mixed case, and shell-metacharacter
#: payloads in a single regex.
_PACK_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]*$")


class ScaffoldError(Exception):
    """Raised when scaffolding cannot proceed (invalid pack name,
    target directory exists, unsupported kind, etc.). The CLI wrapper
    catches this + renders a fail-loud message; never leaves a partial
    scaffold on disk."""


def _validate_pack_name(pack_name: str) -> None:
    if not _PACK_NAME_PATTERN.match(pack_name):
        raise ScaffoldError(
            f"invalid pack name {pack_name!r}: must be a lowercase "
            "Python-identifier fragment (letters/digits/underscores; "
            "cannot start with a digit). The pack name becomes the "
            "Python module name + the project slug, so the constraint "
            "matches PEP 8 module-name rules."
        )


def _build_context(*, kind: str, pack_name: str) -> dict[str, str]:
    """Render-time variables surfaced to every Jinja2 template.

    - ``kind`` — one of ``tool / skill / agent``.
    - ``pack_name`` — the lowercase identifier the author supplied.
    - ``module_name`` — Python module name, ``cognic_<kind>_<name>``.
    - ``pack_id`` — distribution slug, ``cognic-<kind>-<name>``.
    - ``class_name`` — Python class name on the generated subclass,
      ``<PackName><Kind>`` (e.g., ``ExampleTool``).
    - ``entry_point_group`` — the matching ``cognic.<kind>s``
      entry-point group the produced ``pyproject.toml`` registers
      under.
    """
    pack_class_part = "".join(word.capitalize() for word in pack_name.split("_"))
    return {
        "kind": kind,
        "pack_name": pack_name,
        "module_name": f"cognic_{kind}_{pack_name}",
        "pack_id": f"cognic-{kind}-{pack_name}",
        "class_name": f"{pack_class_part}{kind.capitalize()}",
        "entry_point_group": f"cognic.{kind}s",
    }


def _walk_template_files(template_dir: Path) -> list[Path]:
    """Return every template file under ``template_dir`` as absolute
    paths. Includes hidden directories (e.g., ``.github/``) and
    hidden files (e.g., ``.gitkeep``) — Jinja's
    :class:`jinja2.FileSystemLoader.list_templates` skips dot-prefixed
    paths by convention, which would silently drop the GitHub Actions
    workflow + the gitkeep markers from the produced pack."""
    files: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(template_dir):
        for filename in filenames:
            files.append(Path(dirpath) / filename)
    return sorted(files)


def scaffold(
    *,
    kind: str,
    pack_name: str,
    parent_dir: Path,
) -> Path:
    """Render the per-kind template tree into
    ``parent_dir / cognic-<kind>-<name>/`` and return the produced
    pack root.

    Raises :class:`ScaffoldError` (BEFORE any filesystem write) when:

      - ``kind`` is not in :data:`_SUPPORTED_KINDS`.
      - ``pack_name`` fails the
        :data:`_PACK_NAME_PATTERN` validation.
      - The target directory already exists (refuses to overwrite —
        pack authors who actually want to overwrite delete the
        directory first).
    """
    if kind not in _SUPPORTED_KINDS:
        raise ScaffoldError(
            f"unsupported scaffold kind {kind!r}; expected one of {sorted(_SUPPORTED_KINDS)}"
        )
    _validate_pack_name(pack_name)

    template_dir = _TEMPLATES_ROOT / kind
    if not template_dir.is_dir():
        # Bundled-templates invariant: every supported kind ships its
        # own subtree. A missing subtree is a packaging bug, not a
        # pack-author error — fail loudly so the CI gate catches it.
        raise ScaffoldError(
            f"bundled templates for kind {kind!r} are missing at "
            f"{template_dir}; this is a packaging bug — please file "
            "an issue against cognic-agentos."
        )

    context = _build_context(kind=kind, pack_name=pack_name)
    pack_root = parent_dir / context["pack_id"]
    if pack_root.exists():
        raise ScaffoldError(
            f"target directory {pack_root} already exists; refusing "
            "to overwrite. Delete it first if you intend to re-scaffold."
        )

    # Set up Jinja2 environment for content rendering. We don't use
    # FileSystemLoader for path discovery (its list_templates() skips
    # hidden files) — instead, walk the tree manually + render each
    # file's content via a raw Template object.
    # autoescape stays False — scaffold output is plain text (Python /
    # TOML / Markdown / YAML), not HTML; HTML-escaping ``{{ pack_id }}``
    # would corrupt every produced file.
    env = jinja2.Environment(
        autoescape=False,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )

    for source_path in _walk_template_files(template_dir):
        rel_path = source_path.relative_to(template_dir)
        # Substitute the path placeholder so files under
        # ``src/__module__/...`` land at ``src/cognic_<kind>_<name>/...``.
        out_rel_str = str(rel_path).replace(_MODULE_PATH_PLACEHOLDER, context["module_name"])
        out_path = pack_root / out_rel_str
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Render the file body through Jinja. ``.gitkeep`` files have
        # empty bodies; the render is a no-op.
        rendered = env.from_string(source_path.read_text()).render(**context)
        out_path.write_text(rendered)

    return pack_root


__all__ = [
    "ScaffoldError",
    "scaffold",
]
