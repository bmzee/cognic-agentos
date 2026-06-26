"""Structural gate (author-time): the Proof 1b-2 proof image Dockerfiles
pin the load-bearing invariants that ``docker build`` would otherwise only catch at
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

Per the Proof 1b-2 plan (Task 5), ``infra/proof-1b-2/Dockerfile.as`` builds the
emulated-external OAuth Authorization Server by vendoring the single fixture file
``tests/integration/pack_loop/_local_as.py`` (it has no installable distribution),
with build context = repo root. The deployed proof depends on three more facts:

1. the ``COPY`` vendors the repo-root-relative ``tests/integration/pack_loop/_local_as.py``
   (so the repo-root build context resolves it);
2. the ``CMD`` is exec-form ``["python", "_local_as.py"]`` (the Task-2 ``__main__``
   entry path, env-driven by ``COGNIC_PROOF_AS_ISSUER`` / ``_AS_HOST`` / ``_AS_PORT``);
3. ``pip install`` includes ``uvicorn`` + ``starlette`` and ``python-multipart`` (the
   AS ``/token`` endpoint reads ``await request.form()``; Starlette form parsing requires
   it — without it Bar 2 fails at the token POST).

These tests read each Dockerfile as text only — they never invoke ``docker build``.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MCP_SERVER_DOCKERFILE = _REPO_ROOT / "infra" / "proof-1b-2" / "Dockerfile.mcp-server"
_AS_DOCKERFILE = _REPO_ROOT / "infra" / "proof-1b-2" / "Dockerfile.as"


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


# --- Task 5: emulated-external AS image (vendored _local_as.py) -----------------


def _as_dockerfile_text() -> str:
    return _AS_DOCKERFILE.read_text()


def test_as_dockerfile_exists() -> None:
    assert _AS_DOCKERFILE.is_file(), (
        f"Proof 1b-2 emulated-external AS Dockerfile not found at {_AS_DOCKERFILE}"
    )


def test_as_copy_vendors_the_local_as_file() -> None:
    # The AS fixture has no installable distribution, so the image vendors the single
    # file. Build context = repo root, so the COPY source path is repo-root-relative.
    text = _as_dockerfile_text()
    assert "COPY tests/integration/pack_loop/_local_as.py" in text, (
        "COPY must vendor the repo-root-relative fixture tests/integration/pack_loop/_local_as.py"
    )


def test_as_cmd_runs_the_t2_main_path() -> None:
    # The CMD must run the vendored file directly so the Task-2 `__main__` entry path
    # fires (env-driven by COGNIC_PROOF_AS_ISSUER / _AS_HOST / _AS_PORT).
    text = _as_dockerfile_text()
    assert 'CMD ["python", "_local_as.py"]' in text, (
        'CMD must be exec-form `["python", "_local_as.py"]` (the Task-2 __main__ path)'
    )


def test_as_pip_install_pins_multipart_uvicorn_starlette() -> None:
    text = _as_dockerfile_text()
    assert "python-multipart" in text, (
        "pip install must include python-multipart — the AS /token endpoint reads "
        "`await request.form()`, which Starlette form parsing requires (else Bar 2 "
        "fails at the token POST)"
    )
    assert "uvicorn" in text, "pip install must include uvicorn (the ASGI server)"
    assert "starlette" in text, "pip install must include starlette (the web framework)"
