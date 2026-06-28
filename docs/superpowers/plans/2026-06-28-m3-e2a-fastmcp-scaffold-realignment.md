# M3-E2a — FastMCP tool-pack authoring path realignment (implementation plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Realign the `agentos init-tool` scaffold + the SDK test helper to the real FastMCP MCP-server tool-pack shape, and bump all four scaffold kernel pins to `@v0.0.2`, so the official authoring path matches the proven product-pack pattern.

**Architecture:** The scaffold is a Jinja2 template tree under `src/cognic_agentos/cli/templates/<kind>/`; `cli/init.py:scaffold()` walks + renders it generically (substituting `__module__` in paths), so swapping the tool's `tool.py` for `__init__.py` + `server.py` needs **no `init.py` code change** — only template-tree edits + test updates. The SDK test helper `sdk/testing.py:_load_entry_point_tools` is fixed to classify `cognic.tools` entries three ways instead of blindly instantiating them.

**Tech Stack:** Python 3.12, Jinja2 templates, Typer CLI, pytest, `mcp` (FastMCP) + `uvicorn` as the *generated pack's* runtime deps (not the kernel's).

**Source spec:** `docs/superpowers/specs/2026-06-28-m3-e2-oracle-schema-tool-pack-design.md` (this plan implements **Phase M3-E2a** only; M3-E2b is a separate-repo plan after `v0.0.2` is cut; M3-E2c is the deferred deploy-plan).

## Global Constraints

- **Scope is the `tool` scaffold shape only.** `skill` / `agent` / `hook` templates keep their SDK-subclass shape (they import the SDK at runtime); they receive only the `@v0.0.2` pin bump.
- **Kernel tag:** the scaffold emits `cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2`. `v0.0.2` is cut from green `main` **after** this PR merges (Task 4) — it is the first tag containing the realigned scaffold.
- **Generated FastMCP tool packs carry NO kernel runtime dep.** The kernel pin lives in `[project.optional-dependencies] dev` (author/CI), not `[project] dependencies`.
- **Fresh scaffolds do NOT `validate` clean** — they carry `AUTHOR-FILL` placeholders and `agentos validate` surfaces remediation. The "validates clean" proof is on a *filled* fixture.
- **`sdk/testing.py` is a Doctrine-E semver-stable SDK surface** — the Task 1 commit **halts before commit** (CLAUDE.md / AGENTS.md). The change must stay backward-compatible (legacy SDK-`Tool` packs still discovered).
- **`sdk/testing.py` is NOT on the critical-controls per-file coverage gate** (verify with `grep _CRITICAL_FILES tools/check_critical_coverage.py`); templates + `test_*` are data/tests. No CC-gate count change. No ADR (aligns to existing ADR-002).
- **Per-action authorization:** every commit is token-gated by the user; never push/PR/merge/tag without an explicit full-word token; `git add` exact paths only (never the protected untracked paths: `docs/handoffs/…`, `docs/reviews/`, the gap-analysis spec, `infra/proof-1b/`).
- **Local gate before any commit:** `uv run pytest <touched>` + `uv run ruff check` + `uv run ruff format --check` + `uv run mypy src tests` for touched scope; full suite at the commit token per the gate-ladder.
- Branches: this **plan + the spec** live on `docs/m3-e2-spec` (the docs PR). The **implementation** (Tasks 1–3) lands on a separate `feat/m3-e2a-fastmcp-scaffold` branch off `main`, created at execution start.

---

## File Structure

**Modified (kernel source):**
- `src/cognic_agentos/sdk/testing.py` — three-way `_load_entry_point_tools` (Task 1).

**Template tree — `tool` realignment (Task 3):**
- Create `src/cognic_agentos/cli/templates/tool/src/__module__/__init__.py` — `SERVER_DESCRIPTOR` + `cognic_pack_kind` marker.
- Create `src/cognic_agentos/cli/templates/tool/src/__module__/server.py` — FastMCP `build_server` + sample `ping` tool.
- Delete `src/cognic_agentos/cli/templates/tool/src/__module__/tool.py`.
- Modify `src/cognic_agentos/cli/templates/tool/pyproject.toml` — runtime deps `mcp`+`uvicorn`; entry-point → `:SERVER_DESCRIPTOR`; force-include manifest; kernel pin → `[project.optional-dependencies] dev`.
- Modify `src/cognic_agentos/cli/templates/tool/cognic-pack-manifest.toml` — add `[tool.cognic.mcp]` runtime block (keep `[mcp]` capabilities block).
- Modify `src/cognic_agentos/cli/templates/tool/tests/test_tool.py` — FastMCP-shaped sample tests.
- Modify `src/cognic_agentos/cli/templates/tool/README.md` — FastMCP authoring instructions.

**Template tree — pin bump only (Task 2):**
- Modify `src/cognic_agentos/cli/templates/{tool,skill,agent,hook}/pyproject.toml` — `@v0.0.1` → `@v0.0.2`.
- Modify `src/cognic_agentos/cli/templates/{tool,skill,agent,hook}/.github/workflows/sign-and-publish.yml` — `@v0.0.2`.

**Tests:**
- `tests/unit/sdk/test_testing_fixtures.py` — three-way classification regression (Task 1).
- `tests/unit/cli/test_cli_init.py` — pin constant `@v0.0.2` (Task 2); tool split out of subclass-shape + runtime-deps-pin parametrizations + new FastMCP-shape / placeholder-hygiene / filled-fixture tests (Task 3).
- `tests/unit/cli/test_cli_init_hook.py` — pin constant `@v0.0.2` (Task 2).

---

## Task 1: `sdk/testing.py` — three-way `_load_entry_point_tools` classification

**Files:**
- Modify: `src/cognic_agentos/sdk/testing.py:128-140`
- Test: `tests/unit/sdk/test_testing_fixtures.py`

**Interfaces:**
- Produces: `_load_entry_point_tools() -> dict[str, Tool]` (unchanged signature) that (1) instantiates `Tool` subclasses, (2) skips inert MCP-server descriptors with a `logging.DEBUG` trace on `logging.getLogger("cognic_agentos.sdk.testing")`, (3) raises `TypeError` on any other object.
- Recognition predicate `_is_mcp_server_descriptor(obj)`: `getattr(obj, "cognic_pack_kind", None) == "mcp_server"` OR the **exact** legacy `cognic-tool-search` shape (a frozen dataclass instance whose class is named `_ServerDescriptor` with `str` `pack_id` + `str` `tool_name`). Deliberately narrow — an unrelated dataclass entry point does NOT match and still raises. The back-compat arm recognises the already-signed example without re-signing it.

**Doctrine-E: this commit halts before commit** (semver-stable SDK surface).

- [ ] **Step 1: Write the failing test** — append to `tests/unit/sdk/test_testing_fixtures.py`:

```python
# ---------------------------------------------------------------------------
# (b2) _load_entry_point_tools — three-way classification (M3-E2a)
# ---------------------------------------------------------------------------
import dataclasses
import logging
from importlib.metadata import EntryPoint
from unittest.mock import patch

from cognic_agentos.sdk.tool import Tool


class _StubTool(Tool):
    name = "stub_tool"
    input_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    output_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}

    async def _invoke(self, **kwargs):  # type: ignore[no-untyped-def]
        return {}


@dataclasses.dataclass(frozen=True)
class _StubServerDescriptor:
    cognic_pack_kind: str = "mcp_server"
    pack_id: str = "cognic-tool-stub"


class _FakeEntry:
    def __init__(self, name: str, obj: object) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _patch_entry_points(entries: list[object]):
    return patch("importlib.metadata.entry_points", return_value=entries)


def test_load_entry_point_tools_instantiates_tool_subclass() -> None:
    from cognic_agentos.sdk.testing import _load_entry_point_tools

    with _patch_entry_points([_FakeEntry("stub_tool", _StubTool)]):
        tools = _load_entry_point_tools()
    assert "stub_tool" in tools
    assert isinstance(tools["stub_tool"], _StubTool)


def test_load_entry_point_tools_skips_descriptor_with_trace(caplog) -> None:  # type: ignore[no-untyped-def]
    from cognic_agentos.sdk.testing import _load_entry_point_tools

    with _patch_entry_points([_FakeEntry("svc", _StubServerDescriptor())]):
        with caplog.at_level(logging.DEBUG, logger="cognic_agentos.sdk.testing"):
            tools = _load_entry_point_tools()
    assert tools == {}
    assert any("svc" in rec.message for rec in caplog.records), "skip must emit a testable trace"


def test_load_entry_point_tools_raises_on_unknown_object() -> None:
    from cognic_agentos.sdk.testing import _load_entry_point_tools

    with _patch_entry_points([_FakeEntry("weird", object())]):
        with pytest.raises(TypeError, match="weird"):
            _load_entry_point_tools()


def test_load_entry_point_tools_skips_legacy_descriptor_shape(caplog) -> None:  # type: ignore[no-untyped-def]
    """The marker-less cognic-tool-search example descriptor (class named
    _ServerDescriptor with str pack_id + str tool_name) is skipped via the
    back-compat arm WITHOUT re-signing the example."""
    from cognic_agentos.sdk.testing import _load_entry_point_tools

    @dataclasses.dataclass(frozen=True)
    class _ServerDescriptor:
        pack_id: str = "cognic-tool-search"
        tool_name: str = "search_policy_docs"

    with _patch_entry_points([_FakeEntry("legacy", _ServerDescriptor())]):
        with caplog.at_level(logging.DEBUG, logger="cognic_agentos.sdk.testing"):
            tools = _load_entry_point_tools()
    assert tools == {}


def test_load_entry_point_tools_raises_on_unrelated_dataclass() -> None:
    """An unrelated dataclass instance is NOT a descriptor — it must raise,
    not be silently skipped (the predicate is exact, not 'any dataclass')."""
    from cognic_agentos.sdk.testing import _load_entry_point_tools

    @dataclasses.dataclass(frozen=True)
    class _SomeConfig:
        value: int = 1

    with _patch_entry_points([_FakeEntry("cfg", _SomeConfig())]):
        with pytest.raises(TypeError, match="cfg"):
            _load_entry_point_tools()
```

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/sdk/test_testing_fixtures.py -k "load_entry_point_tools" -v`
Expected: the skip + unknown tests FAIL (current code calls `obj()` on the descriptor → `TypeError: ... not callable` for skip; calls `object()` then `.name` → AttributeError for unknown).

- [ ] **Step 3: Implement the three-way classification** — replace `_load_entry_point_tools` (`src/cognic_agentos/sdk/testing.py:128-140`) and add the helper + module logger. Add `import dataclasses` + `import logging` to the imports, move the `Tool` import to runtime (out of `TYPE_CHECKING`), and add `logger = logging.getLogger(__name__)`:

```python
def _is_mcp_server_descriptor(obj: object) -> bool:
    """True for an inert FastMCP MCP-server descriptor (an external MCP
    server pack's entry-point target). Import-free recognition so the
    pack never has to import the kernel:

      - new scaffold packs declare ``cognic_pack_kind = "mcp_server"``;
      - the already-signed ``cognic-tool-search`` example ships a frozen
        dataclass with NO marker — recognised by its EXACT shape (class
        named ``_ServerDescriptor`` with ``str`` ``pack_id`` + ``str``
        ``tool_name``) so it is skipped WITHOUT re-signing it.

    The back-compat arm is deliberately narrow: an UNRELATED dataclass
    instance does NOT match, so it falls through to the ``raise`` in the
    caller (unknown objects must be visible, not silently skipped).
    """
    if getattr(obj, "cognic_pack_kind", None) == "mcp_server":
        return True
    return (
        dataclasses.is_dataclass(obj)
        and not isinstance(obj, type)
        and type(obj).__name__ == "_ServerDescriptor"
        and isinstance(getattr(obj, "pack_id", None), str)
        and isinstance(getattr(obj, "tool_name", None), str)
    )


def _load_entry_point_tools() -> dict[str, Tool]:
    """Resolve ``cognic.tools`` entry-points → instantiated tool map.

    Three-way classification (M3-E2a):
      1. SDK ``Tool`` subclass  -> instantiate + register.
      2. inert MCP-server descriptor -> skip with a DEBUG trace (FastMCP
         packs run behind HTTP; they contribute nothing in-process).
      3. anything else -> raise ``TypeError`` (a broken/unexpected entry
         point must be visible, not silently dropped).
    """
    tools: dict[str, Tool] = {}
    for entry in importlib.metadata.entry_points(group="cognic.tools"):
        obj = entry.load()
        if isinstance(obj, type) and issubclass(obj, Tool):
            instance = obj()
            tools[instance.name] = instance
        elif _is_mcp_server_descriptor(obj):
            logger.debug(
                "skipping cognic.tools entry %r: inert MCP-server descriptor "
                "(external FastMCP pack, runs behind HTTP)",
                entry.name,
            )
            continue
        else:
            raise TypeError(
                f"cognic.tools entry-point {entry.name!r} resolved to an "
                f"unrecognised object of type {type(obj).__name__!r}: expected "
                "an SDK Tool subclass or an inert MCP-server descriptor."
            )
    return tools
```

- [ ] **Step 4: Run the tests — verify they pass**

Run: `uv run pytest tests/unit/sdk/test_testing_fixtures.py -v`
Expected: all pass (incl. the pre-existing `test_fixture_tool_registry_lists_zero_tools_when_no_entry_points`).

- [ ] **Step 5: Security-regression evidence** (per `feedback_security_regression_hardening`): the three tests fire on known-bad shapes (descriptor → no crash; unknown → raises). Note in the commit body that reverting the classification makes the skip/unknown tests fail.

- [ ] **Step 6: Local gate + HALT before commit (Doctrine-E)**

Run: `uv run pytest tests/unit/sdk/ -q && uv run ruff check src/cognic_agentos/sdk/testing.py tests/unit/sdk/test_testing_fixtures.py && uv run ruff format --check src/cognic_agentos/sdk/testing.py && uv run mypy src/cognic_agentos/sdk/testing.py`
Then **halt** with a summary and request the commit token. Commit message: `fix(sdk): classify cognic.tools entry points three ways in test helper`.

---

## Task 2: Bump all four scaffold kernel pins `@v0.0.1` → `@v0.0.2`

**Files:**
- Modify: `src/cognic_agentos/cli/templates/{tool,skill,agent,hook}/pyproject.toml`
- Modify: `src/cognic_agentos/cli/templates/{tool,skill,agent,hook}/.github/workflows/sign-and-publish.yml`
- Test: `tests/unit/cli/test_cli_init.py:338` + `tests/unit/cli/test_cli_init_hook.py:339`

**Interfaces:**
- Produces: every scaffold emits `cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2` (pyproject + CI). At this task the **tool** pin is still in runtime `dependencies` (Task 3 moves it to `dev` extras).

- [ ] **Step 1: Update the test constants to `@v0.0.2`** — edit `tests/unit/cli/test_cli_init.py:338` and `tests/unit/cli/test_cli_init_hook.py:339`:

```python
_PINNED_KERNEL_DEP = "cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2"
```

- [ ] **Step 2: Run the pin tests — verify they fail**

Run: `uv run pytest tests/unit/cli/test_cli_init.py tests/unit/cli/test_cli_init_hook.py -k "git_pins_kernel_dep or installs_kernel_from_git" -v`
Expected: FAIL (templates still emit `@v0.0.1`).

- [ ] **Step 3: Bump the eight template files** — in each of `tool/skill/agent/hook` replace `@v0.0.1` with `@v0.0.2` in both `pyproject.toml` (the `dependencies` entry) and `.github/workflows/sign-and-publish.yml` (the `pip install "..."` step). Mechanical find/replace of the exact pin string; no other change.

- [ ] **Step 4: Run the pin tests — verify they pass**

Run: `uv run pytest tests/unit/cli/test_cli_init.py tests/unit/cli/test_cli_init_hook.py -k "git_pins_kernel_dep or installs_kernel_from_git or requires_python" -v`
Expected: PASS.

- [ ] **Step 5: Commit** (token-gated)

`git add` the eight template files + the two test files. Message: `chore(cli): bump scaffold kernel pins to @v0.0.2`.

---

## Task 3: Realign the `tool` scaffold to the FastMCP shape

**Files:**
- Create: `src/cognic_agentos/cli/templates/tool/src/__module__/__init__.py`
- Create: `src/cognic_agentos/cli/templates/tool/src/__module__/server.py`
- Delete: `src/cognic_agentos/cli/templates/tool/src/__module__/tool.py`
- Modify: `src/cognic_agentos/cli/templates/tool/pyproject.toml`
- Modify: `src/cognic_agentos/cli/templates/tool/cognic-pack-manifest.toml`
- Modify: `src/cognic_agentos/cli/templates/tool/tests/test_tool.py`
- Modify: `src/cognic_agentos/cli/templates/tool/README.md`
- Test: `tests/unit/cli/test_cli_init.py`

**Interfaces:**
- Produces: a generated tool pack with entry-point `<pack_name> = "<module>:SERVER_DESCRIPTOR"`, runtime deps `mcp`+`uvicorn` (no kernel), kernel pin in `[project.optional-dependencies] dev`, manifest `[tool.cognic.mcp]` runtime block, and a runnable FastMCP `server.py` with a sample `ping` tool.
- Consumes: the Task 1 `_is_mcp_server_descriptor` recognition (the generated `__init__.py` carries `cognic_pack_kind = "mcp_server"`).

- [ ] **Step 1: Write the failing tests** — restructure `tests/unit/cli/test_cli_init.py`. (a) Add a subclass-kinds constant and repoint the two SDK-subclass tests + add tool-divergent tree/pin tests:

```python
# tool is now a FastMCP MCP-server pack (no SDK Tool subclass); the
# subclass-shape + runtime-deps-pin assertions apply to skill/agent only.
_SUBCLASS_KINDS: tuple[str, ...] = ("skill", "agent")
```

Change `@pytest.mark.parametrize("kind", _KINDS)` → `@pytest.mark.parametrize("kind", _SUBCLASS_KINDS)` on `test_scaffolded_subclass_overrides_correct_abstract_method` (`:233`) and `test_scaffolded_subclass_imports_and_subclass_check_passes` (`:264`).

(b) Make the tree test tool-aware — replace the `module_dir / f"{kind}.py"` line in `test_scaffold_creates_canonical_tree` (`:111`) with a per-kind module-file set:

```python
    module_files = (
        [module_dir / "__init__.py", module_dir / "server.py"]
        if kind == "tool"
        else [module_dir / "__init__.py", module_dir / f"{kind}.py"]
    )
    expected_files = [
        pack_root / "pyproject.toml",
        pack_root / "cognic-pack-manifest.toml",
        pack_root / "README.md",
        *module_files,
        pack_root / "tests" / f"test_{kind}.py",
        pack_root / "tests" / "conftest.py",
        pack_root / "attestations" / ".gitkeep",
        pack_root / ".github" / "workflows" / "sign-and-publish.yml",
    ]
```

(c) Split the runtime-deps pin test so tool checks `dev` extras + kernel-absent-from-runtime, others check runtime deps. Repoint `test_scaffolded_pyproject_git_pins_kernel_dep` (`:341`) to `_SUBCLASS_KINDS` + the hook (it stays runtime-deps) and add a tool-specific test:

```python
def test_tool_scaffold_pins_kernel_in_dev_extras_not_runtime(tmp_path: Path) -> None:
    """FastMCP tool packs carry NO kernel runtime dep; the authoring
    pin lives in [project.optional-dependencies] dev."""
    pack_root = _scaffold("tool", "example", tmp_path)
    pyproject = tomllib.loads((pack_root / "pyproject.toml").read_text())
    runtime = pyproject["project"]["dependencies"]
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    assert _PINNED_KERNEL_DEP in dev
    assert not any("cognic-agentos" in d for d in runtime), (
        f"tool runtime deps must not carry the kernel; got {runtime!r}"
    )
    assert any(d.startswith("mcp") for d in runtime) and any(d.startswith("uvicorn") for d in runtime)
```

(d) Add the FastMCP-shape + runtime-mcp-block + placeholder-hygiene + filled-fixture tests:

```python
def test_tool_scaffold_entry_point_targets_server_descriptor(tmp_path: Path) -> None:
    pack_root = _scaffold("tool", "example", tmp_path)
    eps = tomllib.loads((pack_root / "pyproject.toml").read_text())["project"]["entry-points"]["cognic.tools"]
    assert eps["example"] == "cognic_tool_example:SERVER_DESCRIPTOR"


def test_tool_scaffold_descriptor_carries_marker(tmp_path: Path) -> None:
    pack_root = _scaffold("tool", "example", tmp_path)
    init_src = (pack_root / "src" / "cognic_tool_example" / "__init__.py").read_text()
    assert "SERVER_DESCRIPTOR" in init_src
    assert 'cognic_pack_kind' in init_src and '"mcp_server"' in init_src


def test_tool_scaffold_server_builds_fastmcp(tmp_path: Path) -> None:
    pack_root = _scaffold("tool", "example", tmp_path)
    server_src = (pack_root / "src" / "cognic_tool_example" / "server.py").read_text()
    assert "FastMCP" in server_src and "build_server" in server_src


def test_tool_scaffold_server_auth_fails_closed_without_dev_optin(tmp_path: Path) -> None:
    """The scaffold's sample verifier must NOT teach an unguarded permissive
    pattern: the dev verifier is reachable only via dev_insecure + COGNIC_ENV=dev,
    and the default path fails closed."""
    pack_root = _scaffold("tool", "example", tmp_path)
    server_src = (pack_root / "src" / "cognic_tool_example" / "server.py").read_text()
    assert "dev_insecure" in server_src
    assert "COGNIC_ENV" in server_src
    assert "RuntimeError" in server_src


def test_tool_scaffold_manifest_carries_tool_cognic_mcp_runtime_block(tmp_path: Path) -> None:
    pack_root = _scaffold("tool", "example", tmp_path)
    parsed = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    block = parsed["tool"]["cognic"]["mcp"]
    assert block["transport"] == "streamable-http"
    assert block["auth"] == "oauth-prm"
    assert "server_url" in block and "scopes" in block
```

For placeholder-hygiene + filled-fixture, use the SDK helper `assert_manifest_validates` (it delegates to `run_validators`). Fresh → refuses; filled → clean:

```python
def _fill_author_fields(pack_root: Path) -> None:
    """Replace AUTHOR-FILL placeholders with valid values so the manifest
    validates clean (the doctrine: fresh = remediation, filled = clean)."""
    manifest = pack_root / "cognic-pack-manifest.toml"
    text = manifest.read_text()
    text = text.replace(
        'agent_id = "AUTHOR-FILL: stable identifier (e.g., did:web:example.com:tools:example)"',
        'agent_id = "did:web:example.com:tools:example"',
    )
    # ... replace each remaining AUTHOR-FILL identity/data_governance/risk_tier
    # field with a validator-clean value (read-only + internal + operational_telemetry).
    manifest.write_text(text)


def test_fresh_tool_scaffold_validate_refuses_with_remediation(tmp_path: Path) -> None:
    from cognic_agentos.cli.validate import run_validators
    pack_root = _scaffold("tool", "example", tmp_path)
    findings = run_validators(pack_root)
    assert any(f.affects_exit_code for f in findings), "fresh scaffold must NOT validate clean"


def test_filled_tool_scaffold_validates_clean(tmp_path: Path) -> None:
    from cognic_agentos.sdk.testing import assert_manifest_validates
    pack_root = _scaffold("tool", "example", tmp_path)
    _fill_author_fields(pack_root)
    assert_manifest_validates(pack_root)  # raises AssertionError on any refusal
```

> **Implementer note:** flesh out `_fill_author_fields` against the realigned tool manifest's exact AUTHOR-FILL strings (Step 5). Mirror the proven `examples/cognic-tool-search/cognic-pack-manifest.toml` identity shape — it omits `agent_card_url` / `agent_card_jws_path` for a tool pack and validates; if `run_validators` still demands a field, the `test_filled_tool_scaffold_validates_clean` red bar tells you exactly which.

- [ ] **Step 2: Run the new tool tests — verify they fail**

Run: `uv run pytest tests/unit/cli/test_cli_init.py -k "tool" -v`
Expected: the new FastMCP-shape / dev-extras / runtime-block / filled-fixture tests FAIL (template still SDK-subclass shape).

- [ ] **Step 3: Create `src/cognic_agentos/cli/templates/tool/src/__module__/__init__.py`:**

```python
"""{{ pack_id }} — Cognic AgentOS MCP tool pack.

SERVER_DESCRIPTOR is the inert entry-point object PluginRegistry.discover()
resolves the distribution from. The runtime MCP path runs the tool behind a
real HTTP server (see server.py) and NEVER EntryPoint.load()s this object; it
exists only for discovery + the `agentos verify` load-probe. Do NOT
import-poison this module.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _ServerDescriptor:
    """Inert marker. The real server lives in {{ module_name }}.server."""

    cognic_pack_kind: str = "mcp_server"
    pack_id: str = "{{ pack_id }}"


SERVER_DESCRIPTOR = _ServerDescriptor()
```

- [ ] **Step 4: Create `src/cognic_agentos/cli/templates/tool/src/__module__/server.py`** (mirrors the proven `examples/cognic-tool-search/server.py`, generalised + AUTHOR-FILL on the verifier + a sample `ping` tool):

```python
"""Streamable-HTTP MCP server for {{ pack_id }} (FastMCP).

Resource-server OAuth mode: passing `auth` + `token_verifier` makes FastMCP
auto-publish Protected Resource Metadata and wrap /mcp with bearer auth.

AUTHOR-FILL: implement a real JWT/JWKS TokenVerifier (issuer / signature /
expiry / audience / scope) and run with COGNIC_AUTH_MODE=jwt before production.
The shipped DevTokenVerifier is dev-only and fails closed unless
COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev.
"""

from __future__ import annotations

import os

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

_HOST = os.environ.get("COGNIC_MCP_HOST", "127.0.0.1")
_PORT = int(os.environ.get("COGNIC_MCP_PORT", "8765"))
_SERVER_URL = os.environ.get("COGNIC_MCP_SERVER_URL", "http://127.0.0.1:8765/mcp")
_REQUIRED_SCOPES = ["mcp:tools"]  # AUTHOR-FILL: your pack's required scopes


class DevTokenVerifier(TokenVerifier):
    """DEV-ONLY verifier — accepts any non-empty bearer and binds it to this
    resource. Reachable ONLY via COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev
    (see _select_token_verifier). Production packs implement a real JWT/JWKS
    verifier and run with COGNIC_AUTH_MODE=jwt (see the cognic-tool-oracle-schema
    pack for a worked example)."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token,
            client_id="{{ pack_id }}",
            scopes=list(_REQUIRED_SCOPES),
            expires_at=None,
            resource=_SERVER_URL,
        )


def _select_token_verifier() -> TokenVerifier:
    """Fail-closed verifier selection. COGNIC_AUTH_MODE defaults to 'jwt'; the
    scaffold ships NO real jwt verifier, so the default path raises with
    remediation. The permissive DevTokenVerifier is reachable ONLY via
    COGNIC_AUTH_MODE=dev_insecure AND COGNIC_ENV=dev."""
    mode = os.environ.get("COGNIC_AUTH_MODE", "jwt")
    if mode == "dev_insecure":
        if os.environ.get("COGNIC_ENV") != "dev":
            raise RuntimeError(
                "COGNIC_AUTH_MODE=dev_insecure requires COGNIC_ENV=dev; refusing "
                "to start a permissive verifier outside dev."
            )
        return DevTokenVerifier()
    raise RuntimeError(
        "AUTHOR-FILL: implement a real JWT/JWKS TokenVerifier for "
        "COGNIC_AUTH_MODE=jwt (validate issuer / signature / expiry / audience / "
        "scope; see the cognic-tool-oracle-schema pack), or run locally with "
        "COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev."
    )


def build_server(*, as_issuer: str) -> FastMCP:
    mcp = FastMCP(
        "{{ pack_id }}",
        host=_HOST,
        port=_PORT,
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=False,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(as_issuer),
            resource_server_url=AnyHttpUrl(_SERVER_URL),
            required_scopes=list(_REQUIRED_SCOPES),
        ),
        token_verifier=_select_token_verifier(),
    )

    @mcp.tool(name="ping", description="AUTHOR-FILL: replace with your tool. Returns 'pong'.")
    def ping() -> str:
        return "pong"

    return mcp


if __name__ == "__main__":
    build_server(
        as_issuer=os.environ.get("COGNIC_MCP_AS_ISSUER", "http://127.0.0.1:9000")
    ).run(transport="streamable-http")
```

- [ ] **Step 5: Delete `tool.py`, rewrite `pyproject.toml` + manifest + tests + README.**

Delete `src/cognic_agentos/cli/templates/tool/src/__module__/tool.py`.

`pyproject.toml` (tool) — runtime deps `mcp`+`uvicorn`, entry-point → descriptor, force-include manifest, kernel pin in `dev` extras:

```toml
[project]
name = "{{ pack_id }}"
version = "0.1.0"
description = "AUTHOR-FILL: short description of what this {{ kind }} pack does."
readme = "README.md"
requires-python = ">=3.12,<3.13"
license = { text = "AUTHOR-FILL: e.g., Proprietary or Apache-2.0" }
authors = [
    { name = "AUTHOR-FILL: your name", email = "AUTHOR-FILL: you@example.com" },
]

dependencies = [
    "mcp==1.27.0",
    "uvicorn[standard]>=0.35",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=1",
    # AgentOS authoring/governance CLI — author/CI-time only (validate/sign/verify).
    "cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2",
]

[project.entry-points."{{ entry_point_group }}"]
{{ pack_name }} = "{{ module_name }}:SERVER_DESCRIPTOR"

[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/{{ module_name }}"]

# LOCK 2: ship the SAME manifest the CLI reads as package data inside the wheel,
# so the runtime extract_pack_manifest finds it at
# {{ module_name }}/cognic-pack-manifest.toml.
[tool.hatch.build.targets.wheel.force-include]
"cognic-pack-manifest.toml" = "{{ module_name }}/cognic-pack-manifest.toml"

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

`cognic-pack-manifest.toml` (tool) — append the runtime block after the existing `[supply_chain]` block (keep `[mcp]` capabilities + the AUTHOR-FILL identity/data_governance blocks; mirror the proven example's identity shape — see the Step-1 implementer note):

```toml
[tool.cognic.mcp]
# Runtime-consumed block (harness/mcp_host.py + protocol/mcp_capabilities.py).
# The key is `scopes`, NOT `required_scopes`.
transport = "streamable-http"
auth = "oauth-prm"
server_url = "AUTHOR-FILL: e.g., http://127.0.0.1:8765/mcp (the deployed ClusterIP at install)"
scopes = ["AUTHOR-FILL: e.g., mcp:tools"]
resources_supported = false
prompts_supported = false
sampling_supported = false
conformance_version = "1.0"
```

`tests/test_tool.py` (tool) — replace the SDK-subclass smoke test with a FastMCP-shape smoke test:

```python
"""{{ pack_id }} smoke tests."""

from __future__ import annotations

import pytest

from {{ module_name }} import SERVER_DESCRIPTOR
from {{ module_name }}.server import build_server


def test_server_descriptor_is_marked() -> None:
    assert SERVER_DESCRIPTOR.cognic_pack_kind == "mcp_server"


def test_build_server_returns_fastmcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    assert build_server(as_issuer="http://127.0.0.1:9000") is not None


def test_build_server_fails_closed_without_dev_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COGNIC_AUTH_MODE", raising=False)
    monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(RuntimeError):
        build_server(as_issuer="http://127.0.0.1:9000")
```

`README.md` (tool) — update the authoring instructions to the FastMCP flow (`uv pip install -e '.[dev]'` for the CLI; run locally with `COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev python -m {{ module_name }}.server`; `agentos validate/sign/verify`). The README must state the dev verifier is dev-only and that production requires a real JWT/JWKS verifier (`COGNIC_AUTH_MODE=jwt`).

- [ ] **Step 6: Run the tool tests — verify they pass**

Run: `uv run pytest tests/unit/cli/test_cli_init.py -v`
Expected: all pass (the realigned tool shape + the unchanged skill/agent/hook arms).

- [ ] **Step 7: Commit** (token-gated)

`git add` the tool template files (incl. the deletion) + `tests/unit/cli/test_cli_init.py`. Message: `feat(cli): realign init-tool scaffold to the FastMCP MCP-server shape`.

---

## Task 4: Full local gate, PR, and the post-merge `v0.0.2` tag

- [ ] **Step 1: Full local gate** — `uv run pytest -q && uv run ruff check && uv run ruff format --check && uv run mypy src tests`. Expected: green.
- [ ] **Step 2: Critical-coverage check** — confirm `sdk/testing.py` is NOT on the gate (`grep -n "sdk/testing" tools/check_critical_coverage.py`); if it is, run `uv run python tools/check_critical_coverage.py` against fresh `--cov-branch` data per `feedback_verify_promotion_meets_floor_at_promotion_time`.
- [ ] **Step 3: HALT** — summarise files changed, gate results, remaining risks; request the push/PR token (remote-affecting — full-word token required).
- [ ] **Step 4: PR** (on token) — open the M3-E2a PR; merge on green CI + the user's merge token.
- [ ] **Step 5: Post-merge — cut `v0.0.2`** (on token) — `git tag -a v0.0.2 <merge-sha> -m "..." && git push origin v0.0.2`. This is the forward tag the realigned scaffold pins; it must come from the green merge commit. Then M3-E2b can be generated from `v0.0.2`.

---

## Self-Review

**Spec coverage:** Task 1 = M3-E2a §4.2 (`sdk/testing.py` three-way). Task 2 = §4.1/§4-intro (all-four pin bump). Task 3 = §4.1 (FastMCP tool shape) + §4.3 (structural shape + placeholder hygiene + filled fixture). Task 4 = §4.4 (tag `v0.0.2`). M3-E2b / M3-E2c are out of scope (separate plans, per §2 ordering).

**Placeholder scan:** the only `AUTHOR-FILL` strings are inside the *generated pack templates* (by doctrine) — not plan placeholders. `_fill_author_fields` has a documented implementer flesh-out keyed to the realigned manifest (the filled-fixture red bar is the guard).

**Type/name consistency:** `cognic_pack_kind = "mcp_server"` is the marker in the scaffold `__init__.py` (Task 3 Step 3) AND the recognition predicate (Task 1 Step 3) AND the marker test (Task 3 Step 1). Entry-point `{{ module_name }}:SERVER_DESCRIPTOR` matches between the pyproject template (Step 5), the `__init__.py` (Step 3), and `test_tool_scaffold_entry_point_targets_server_descriptor` (Step 1). `_PINNED_KERNEL_DEP` `@v0.0.2` is consistent (Task 2) and the tool's pin asserted in `dev` extras (Task 3). `_SUBCLASS_KINDS=("skill","agent")` repoints exactly the two SDK-subclass tests; hook stays in its own file. The `dev_insecure`+`COGNIC_ENV=dev` auth guard is consistent across `server.py` `_select_token_verifier` (Task 3 Step 4), the template test (Step 5), and the kernel content assertion `test_tool_scaffold_server_auth_fails_closed_without_dev_optin` (Step 1).

**Risks:** (1) the realigned tool manifest's exact filled values must validate clean — the `test_filled_tool_scaffold_validates_clean` red bar surfaces any missing field (mirror the proven example). (2) `mcp==1.27.0` pin — confirm it's the version the kernel's MCP host interoperates with at execution time; bump if a newer validated `mcp` is in use.

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task + two-stage review between tasks. Note: Task 1 (`sdk/testing.py`, Doctrine-E) halts before commit regardless.
2. **Inline Execution** — execute in this session with checkpoints.

Which approach? (And confirm the feat branch name `feat/m3-e2a-fastmcp-scaffold` off `main`.)
