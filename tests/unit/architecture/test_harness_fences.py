"""Harness Injection T9 — architecture fences over the composition root.

AST + source guards pinning the B1-fenced ``harness/`` invariants (per
``feedback_security_regression_hardening``): the composition root constructs the
real kernel runtime from the adapter pool + nothing more. It must NOT import
Layer-C agents, open its own Redis client (it consumes ``adapters.cache.client``
— Redis is a first-class adapter), open a second SQLAlchemy engine (it reuses
``adapters.relational.engine``), or invent a Bucket-1 bank-overlay default
(those fail loud by design and are wired by the deploying bank).

The kill-switch-is-real-Redis behavioural pin lives in
``tests/unit/harness/test_runtime.py`` (it needs a constructed runtime) and is
TM-revert-proven load-bearing.

Path derivation mirrors ``test_memory_layer_c_no_direct_storage.py`` (absolute
``parents[3]``) so the fence is CWD-independent.
"""

from __future__ import annotations

import ast
import pathlib

_HARNESS_DIR = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "harness"


def _harness_sources() -> list[pathlib.Path]:
    return sorted(_HARNESS_DIR.glob("*.py"))


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_harness_dir_has_expected_sources() -> None:
    """Non-vacuous guard: if the glob returns nothing (rename / move) every
    fence below would pass trivially. Pins the exact B1 file set so a NEW
    harness module forces a deliberate fence review."""
    names = {p.name for p in _harness_sources()}
    assert names == {"__init__.py", "memory_policy.py", "runtime.py"}, names


def test_harness_imports_no_layer_c() -> None:
    """No ``cognic_agentos.agents.*`` import — Layer-C agents live in pack repos,
    never the OS composition root."""
    for path in _harness_sources():
        for mod in _imported_modules(path):
            assert not mod.startswith("cognic_agentos.agents"), f"{path.name}: Layer-C import {mod}"


def test_harness_has_no_redis_import_or_client() -> None:
    """No harness-local Redis client — build_runtime consumes
    ``adapters.cache.client`` (Redis is a first-class adapter), never opens its
    own. Forbids a ``redis`` import AND a ``Redis(...)`` / ``Redis.from_url``
    construction. (The construction checks are raw-source substrings; the tree is
    verified free of these tokens — note that ``RedisMemoryAdapter(`` does NOT
    contain ``Redis(``. A future COMMENT containing the tokens would need
    rewording.)"""
    for path in _harness_sources():
        src = path.read_text(encoding="utf-8")
        for mod in _imported_modules(path):
            assert not (mod == "redis" or mod.startswith("redis.")), (
                f"{path.name}: redis import {mod}"
            )
        assert "redis.asyncio" not in src, f"{path.name}: references redis.asyncio"
        assert "Redis(" not in src and "Redis.from_url" not in src, (
            f"{path.name}: constructs a Redis client"
        )


def test_harness_opens_no_second_engine() -> None:
    """build_runtime reuses ``adapters.relational.engine`` — never
    ``create_async_engine`` (a second pool would fragment connection limits +
    bypass the adapter's lifecycle)."""
    for path in _harness_sources():
        assert "create_async_engine" not in path.read_text(encoding="utf-8"), (
            f"{path.name}: opens a second engine"
        )


def test_harness_constructs_no_bucket1_default() -> None:
    """The harness invents NO bank-overlay (Bucket-1) default — those fail loud
    by design (ADR contracts) and must be wired by the deploying bank, not
    silently defaulted by the OS composition root."""
    forbidden = (
        "KernelDefaultActorBinder",
        "KernelDefaultTrustRootResolver",
        "KernelDefaultElicitationAdapter",
        "KernelDefaultCredentialAdapter",
    )
    for path in _harness_sources():
        src = path.read_text(encoding="utf-8")
        for name in forbidden:
            assert name not in src, f"{path.name}: constructs Bucket-1 default {name}"
