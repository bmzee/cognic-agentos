"""Structural gate (author-time): the Proof 1b-2 MCP tool Service image Dockerfile
pins the load-bearing invariants that ``docker build`` would otherwise only catch at
the operator-run T9 stage (the build is deferred behind ``COGNIC_RUN_PROOF_1B2=1``).

Per the Proof 1b-2 plan (Task 4), ``infra/proof-1b-2/Dockerfile.mcp-server`` builds the
in-cluster MCP tool Service from the in-tree ``cognic-tool-search`` wheel plus the
``mcp==1.27.0`` FastMCP runtime, with build context = repo root. The deployed proof
depends on four facts that a broken Dockerfile would silently regress:

1. the ``COPY`` references the repo-root-relative wheel dir + the exact wheel filename
   (so the repo-root build context resolves it);
2. the ``CMD`` invokes the T1 env-driven module ``cognic_tool_search.server`` (so the
   k8s manifest's ``COGNIC_PROOF_*`` env vars actually drive host/URL/issuer);
3. ``pip install`` pins ``mcp==1.27.0`` (the FastMCP runtime) and includes ``uvicorn``
   (the ASGI server for streamable-http).

This test reads the Dockerfile as text only — it never invokes ``docker build``.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MCP_SERVER_DOCKERFILE = _REPO_ROOT / "infra" / "proof-1b-2" / "Dockerfile.mcp-server"


def _dockerfile_text() -> str:
    return _MCP_SERVER_DOCKERFILE.read_text()


def test_mcp_server_dockerfile_exists() -> None:
    assert _MCP_SERVER_DOCKERFILE.is_file(), (
        f"Proof 1b-2 MCP server Dockerfile not found at {_MCP_SERVER_DOCKERFILE}"
    )


def test_copy_references_repo_root_relative_wheel() -> None:
    # Build context = repo root, so the COPY source path is repo-root-relative.
    text = _dockerfile_text()
    assert "examples/cognic-tool-search/dist/" in text, (
        "COPY must reference the repo-root-relative wheel dir examples/cognic-tool-search/dist/"
    )
    assert "cognic_tool_search-0.1.0-py3-none-any.whl" in text, (
        "COPY must reference the exact wheel filename cognic_tool_search-0.1.0-py3-none-any.whl"
    )


def test_cmd_runs_the_t1_env_driven_module() -> None:
    # The CMD must invoke the T1 env-driven module so the k8s manifest's COGNIC_PROOF_*
    # env vars (host / server URL / AS issuer) actually take effect at runtime.
    text = _dockerfile_text()
    assert 'CMD ["python", "-m", "cognic_tool_search.server"]' in text, (
        'CMD must be exec-form `["python", "-m", "cognic_tool_search.server"]`'
    )


def test_pip_install_pins_mcp_and_uvicorn() -> None:
    text = _dockerfile_text()
    assert "mcp==1.27.0" in text, "pip install must pin mcp==1.27.0 (the FastMCP runtime)"
    assert "uvicorn" in text, (
        "pip install must include uvicorn (the ASGI server for streamable-http)"
    )
