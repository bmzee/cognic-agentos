"""Architecture-discipline test — no env-specific values in source.

Per the Phase-1 principle in ``docs/BUILD_PLAN.md`` (line ~17):

    "No environment-specific operational values in source. Ports, URLs,
    hostnames, timeouts, log levels, CORS origins, retry counts, model
    identifiers — all come from core/config.py Pydantic Settings.
    Constants are fine. Route names (/api/v1/healthz), protocol names
    (mcp, a2a), package metadata, and reasonable in-code defaults inside
    `Settings` class declarations are not 'hardcoding.' The discipline
    test targets operational-config drift only."

Concretely the test refuses, in any AgentOS source file outside
``core/config.py``:

- A string literal that looks like a fully-qualified URL (matches
  ``^https?://`` or an IPv4 address).
- An integer literal in the IANA ephemeral / well-known port range
  (1024 ≤ x ≤ 65535) that is **assigned** to a lowercase identifier
  whose name signals operational config (``port``, ``host_port``,
  ``listen_port``, ``redis_port``, ...).

It explicitly **allows**:

- Any string literal that begins with ``/`` (route names like
  ``"/api/v1/healthz"`` or well-known paths).
- Any string literal whose value is a known protocol identifier
  (``mcp``, ``a2a``, ``http``, ``https``, ``oauth``, ...).
- Any int / string literal inside a ``Settings`` subclass declaration
  (defaults are by definition not "hardcoding").
- Module-level UPPERCASE constants whose value matches a curated
  spec/standard URI prefix (``_SPEC_URI_PREFIXES``: SLSA / in-toto
  / SPDX / CycloneDX). Operational URLs assigned to UPPERCASE names
  (``PROD_API_URL = "https://bank.example"``) stay rejected — the
  exemption is intentionally narrow per the R3 reviewer-P2 audit.

The test is parametrised over every source file so a regression names
the offender directly.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"
EXEMPT_RELATIVE_PATHS: frozenset[str] = frozenset(
    {
        # core/config.py is the *home* of operational config — exempt by design.
        "core/config.py",
    }
)

# Regexes used by the smell test.
_URL_LITERAL = re.compile(r"^https?://", re.IGNORECASE)
_IPV4_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_OPERATIONAL_INT_NAMES = re.compile(
    r"^(?:[a-z_]*_)?(?:port|host_port|listen_port|bind_port|redis_port|"
    r"otel_port|metrics_port|grpc_port)$"
)
_PORT_RANGE = range(1024, 65536)

#: Spec/standard URI prefixes that are NEVER operational endpoints —
#: they identify a protocol or schema fixed by an external standards
#: body. URL literals matching one of these prefixes ARE allowed when
#: assigned to a module-level UPPERCASE constant. Anything else
#: (e.g. ``PROD_API_URL = "https://bank.example"``) stays rejected.
#: Update this list only when adding a new external standard. R3
#: reviewer-P2 narrowed exemption: previously *any* UPPERCASE module
#: constant was exempt, which let operational drift sneak through.
_SPEC_URI_PREFIXES: tuple[str, ...] = (
    "https://slsa.dev/",
    "https://in-toto.io/",
    "https://spdx.org/",
    "https://cyclonedx.org/",
    # Sprint-6 T6 — A2A 1.0 spec source-of-truth at a pinned ``v1.0.0``
    # tag URL. The drift CI gate (test_a2a_schema_drift.py) compares
    # this URL's SHA-256 against ``_PINNED_PROTOBUF_DIGEST`` per
    # Doctrine Decision C; a deliberate spec-author update to the
    # v-tag (or our own bump) trips the gate. Same shape as the
    # SPDX / CycloneDX / SLSA / in-toto exemptions: a fixed external
    # standards body identifier, not an operational endpoint.
    "https://raw.githubusercontent.com/a2aproject/A2A/",
)


#: Sprint-7A T5 carve-out: the CLI's Jinja2 scaffold-template tree
#: contains ``.py`` files with ``{{ ... }}`` placeholders + raw
#: AUTHOR-FILL string literals that the env-specific-values gate
#: cannot meaningfully scan. Pinned to the exact CLI templates root
#: rather than a ``templates`` path-segment match so future modules
#: under other ``*/templates/`` directories stay gated. R18 P3 #1.
_CLI_TEMPLATES_ROOT: Path = SRC_ROOT / "cli" / "templates"


def _iter_py_files() -> list[Path]:
    files: list[Path] = []
    for p in sorted(SRC_ROOT.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        if p.is_relative_to(_CLI_TEMPLATES_ROOT):
            continue
        rel = str(p.relative_to(SRC_ROOT))
        if rel in EXEMPT_RELATIVE_PATHS:
            continue
        files.append(p)
    return files


def _is_inside_settings_class(node: ast.AST, settings_classes: set[ast.ClassDef]) -> bool:
    # ast doesn't give us parent links; we precompute classes that subclass
    # BaseSettings (or any Settings) and walk children of those bodies.
    for cls in settings_classes:
        for child in ast.walk(cls):
            if child is node:
                return True
    return False


def _settings_subclasses(tree: ast.AST) -> set[ast.ClassDef]:
    out: set[ast.ClassDef] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                # Match ``class X(BaseSettings):`` or ``class X(Settings):``.
                if isinstance(base, ast.Name) and base.id in {"BaseSettings", "Settings"}:
                    out.add(node)
                if isinstance(base, ast.Attribute) and base.attr in {
                    "BaseSettings",
                    "Settings",
                }:
                    out.add(node)
    return out


def _module_level_uppercase_spec_constants(tree: ast.AST) -> set[int]:
    """Identify ``ast.Constant`` nodes that are the RHS of a module-
    level Assign or AnnAssign with an all-UPPERCASE ``Name`` target
    AND whose string value matches a known spec/standard URI prefix
    (``_SPEC_URI_PREFIXES``).

    Narrow exemption (R3 reviewer-P2 fix): previously any UPPERCASE
    module constant was exempt from the URL-literal guard, which
    permitted operational drift like
    ``PROD_API_URL = "https://bank.example"``. The exemption is now
    keyed off both UPPERCASE-name AND a known spec prefix; arbitrary
    operational URLs assigned to UPPERCASE names stay rejected.

    Sprint-6 T6 widened to also recognise ``AnnAssign`` (annotated
    assignments like ``_UPSTREAM_PROTOBUF_URL: str = "https://..."``)
    so the exemption logic matches URL semantics, not assignment-
    statement type. Annotated and unannotated assignments are
    semantically equivalent for this guard.
    """
    if not isinstance(tree, ast.Module):
        return set()
    out: set[int] = set()
    for node in tree.body:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is None:
            continue
        if not all(isinstance(t, ast.Name) and t.id.isupper() for t in targets):
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        if any(value.value.startswith(p) for p in _SPEC_URI_PREFIXES):
            out.add(id(value))
    return out


def _string_offenders(tree: ast.AST, settings: set[ast.ClassDef]) -> list[str]:
    spec_const_ids = _module_level_uppercase_spec_constants(tree)
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if _is_inside_settings_class(node, settings):
            continue
        if id(node) in spec_const_ids:
            # Spec/standard URI constants are exempt — they identify
            # a protocol or schema fixed by an external standards
            # body, not an operational endpoint.
            continue
        value = node.value
        if value.startswith("/"):
            continue  # route name / well-known path — allowed
        if _URL_LITERAL.match(value):
            bad.append(f"line {node.lineno}: URL literal {value!r}")
        elif _IPV4_LITERAL.match(value):
            bad.append(f"line {node.lineno}: IPv4 literal {value!r}")
    return bad


def _int_offenders(tree: ast.AST, settings: set[ast.ClassDef]) -> list[str]:
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, int):
            continue
        if _is_inside_settings_class(node, settings):
            continue
        if node.value.value not in _PORT_RANGE:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and _OPERATIONAL_INT_NAMES.match(target.id):
                bad.append(f"line {node.lineno}: operational int {target.id} = {node.value.value}")
    return bad


@pytest.mark.parametrize("path", _iter_py_files(), ids=lambda p: str(p.relative_to(SRC_ROOT)))
def test_no_env_specific_values(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    settings = _settings_subclasses(tree)
    offenders = _string_offenders(tree, settings) + _int_offenders(tree, settings)
    assert not offenders, (
        f"{path.relative_to(SRC_ROOT)} carries env-specific operational values "
        f"that belong in core/config.py: {offenders!r}"
    )


# ---------------------------------------------------------------------------
# Self-tests for the smell-test machinery itself. R3 reviewer-P2:
# the spec-prefix exemption MUST stay narrow — uppercase operational
# URLs and IPs assigned to uppercase names are still rejected.
# ---------------------------------------------------------------------------


def _offenders_for_source(source: str) -> list[str]:
    """Helper for the self-tests below — runs ``_string_offenders``
    against an in-memory module."""
    tree = ast.parse(source)
    return _string_offenders(tree, _settings_subclasses(tree))


class TestSpecPrefixExemption:
    def test_uppercase_spec_uri_is_exempt(self) -> None:
        """Module-level UPPERCASE constants whose value starts with a
        known spec prefix (SLSA / in-toto / SPDX / CycloneDX) are
        allowed — they're external-standards identifiers, not
        operational endpoints."""
        for prefix in _SPEC_URI_PREFIXES:
            source = f'SPEC_URI = "{prefix}some/path"\n'
            assert _offenders_for_source(source) == [], f"spec URI {prefix!r} should be exempt"

    def test_uppercase_operational_url_is_still_rejected(self) -> None:
        """Critical: ``PROD_API_URL = "https://bank.example"`` must
        STILL be rejected. The exemption is NOT "any uppercase
        constant" — only spec-prefix constants."""
        source = 'PROD_API_URL = "https://bank.example/v1"\n'
        offenders = _offenders_for_source(source)
        assert any("https://bank.example" in o for o in offenders), (
            f"uppercase operational URL must be rejected; got offenders={offenders!r}"
        )

    def test_uppercase_ipv4_is_still_rejected(self) -> None:
        """IPv4 literals stay caught regardless of name case."""
        source = 'PROD_DB_HOST = "10.0.0.1"\n'
        offenders = _offenders_for_source(source)
        assert any("10.0.0.1" in o for o in offenders)

    def test_lowercase_spec_uri_is_still_rejected(self) -> None:
        """The exemption requires UPPERCASE name AND spec prefix.
        Lowercase ``slsa_uri = "https://slsa.dev/..."`` is rejected
        — operational drift even with an innocuous-looking value
        could confuse readers, and the policy is conservative."""
        source = 'slsa_uri = "https://slsa.dev/provenance/v1"\n'
        offenders = _offenders_for_source(source)
        assert any("https://slsa.dev" in o for o in offenders), (
            f"lowercase-named URL even with spec prefix must be rejected; offenders={offenders!r}"
        )

    def test_inside_function_url_is_still_rejected(self) -> None:
        """Spec-prefix URLs inside function bodies (not module-level
        Assigns) are not exempted — UPPERCASE-name + module-level
        is the exemption gate."""
        source = 'def f() -> str:\n    SPEC = "https://slsa.dev/provenance/v1"\n    return SPEC\n'
        offenders = _offenders_for_source(source)
        assert any("https://slsa.dev" in o for o in offenders)

    def test_dunder_uppercase_url_is_still_rejected(self) -> None:
        """``__url__ = "https://..."`` looks like dunder metadata but
        the URL match still applies — we don't special-case dunders."""
        source = '__url__ = "https://bank.example/v1"\n'
        offenders = _offenders_for_source(source)
        # __url__ is not all-UPPERCASE per str.isupper() (underscores
        # are non-cased; lowercase letters present), so spec-prefix
        # exemption doesn't apply at all. Operational URL → rejected.
        assert any("https://bank.example" in o for o in offenders)
