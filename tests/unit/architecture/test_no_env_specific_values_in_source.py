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
- Any UPPERCASE module-level constant.

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


def _iter_py_files() -> list[Path]:
    files: list[Path] = []
    for p in sorted(SRC_ROOT.rglob("*.py")):
        if "__pycache__" in p.parts:
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


def _string_offenders(tree: ast.AST, settings: set[ast.ClassDef]) -> list[str]:
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if _is_inside_settings_class(node, settings):
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
