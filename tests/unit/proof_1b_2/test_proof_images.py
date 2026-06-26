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

Per the Proof 1b-2 plan (Task 6), ``infra/proof-1b-2/Dockerfile.agentos-proof`` bakes the
proof-only ``create_proof_app`` factory + the Proof 1b-1 trust staging onto the
``default-adapters`` base (``ARG BASE_IMAGE=cognic-agentos:proof1b2-base``). Unlike the
MCP/AS images, its build context = ``infra/proof-1b-2/`` (the T9 runner copies
``proof1b-staging/`` and ``proof_1b_2/`` into it first), so its ``COPY`` sources are
context-relative, NOT repo-root-relative. The deployed proof depends on:

1. the trust-staging bake mirrors 1b-1 — the staged wheel is pip-installed into the base
   ``/opt/venv`` and the three trust-input trees + ``alembic.ini`` + the three
   ``COGNIC_*`` root ENVs are present (the trust gate + migrations need them);
2. the proof-only ``proof_1b_2`` module is vendored to ``/app/proof_1b_2/`` and ``/app`` is
   importable (``ENV PYTHONPATH=/app``) — the base sets no ``PYTHONPATH`` and runs uvicorn
   as a console script (``sys.path[0] = /opt/venv/bin``, not the ``/app`` WORKDIR);
3. the ``CMD`` overrides the base ``create_prod_app`` factory with the proof-only
   ``create_proof_app`` factory (which sets ``app.state.actor_binder`` to the fixed proof
   binder so the governed MCP route can be driven end-to-end).

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


# --- Task 6: proof AgentOS image (bakes create_proof_app + trust staging) --------

_AGENTOS_PROOF_DOCKERFILE = _REPO_ROOT / "infra" / "proof-1b-2" / "Dockerfile.agentos-proof"


def _agentos_proof_dockerfile_text() -> str:
    return _AGENTOS_PROOF_DOCKERFILE.read_text()


def test_agentos_proof_dockerfile_exists() -> None:
    assert _AGENTOS_PROOF_DOCKERFILE.is_file(), (
        f"Proof 1b-2 proof AgentOS Dockerfile not found at {_AGENTOS_PROOF_DOCKERFILE}"
    )


def test_agentos_proof_from_proof1b2_base() -> None:
    # The proof image FROMs the locally-built default-adapters stage retagged
    # cognic-agentos:proof1b2-base (the T9 runner builds `--target default-adapters`
    # to that tag), so the ARG default pins the contract.
    text = _agentos_proof_dockerfile_text()
    assert "ARG BASE_IMAGE=cognic-agentos:proof1b2-base" in text, (
        "ARG BASE_IMAGE must default to cognic-agentos:proof1b2-base"
    )
    assert "FROM ${BASE_IMAGE}" in text, "the image must FROM ${BASE_IMAGE}"


def test_agentos_proof_bakes_the_1b1_trust_staging() -> None:
    # Same staging bake as 1b-1: pip-install the staged wheel into the base /opt/venv +
    # COPY the three trust-input trees + alembic.ini. Build context = infra/proof-1b-2/
    # (the runner copies proof1b-staging/ in), so these COPY sources are CONTEXT-relative,
    # NOT repo-root-relative (unlike the MCP/AS images above).
    text = _agentos_proof_dockerfile_text()
    assert "COPY proof1b-staging/wheel/" in text, "must COPY the staged wheel dir"
    assert "/opt/venv/bin/python -m pip install" in text and "/tmp/wheel/*.whl" in text, (
        "must pip-install the staged wheel into the base /opt/venv"
    )
    assert "COPY proof1b-staging/pack-attestations/" in text, "must COPY pack-attestations/"
    assert "COPY proof1b-staging/trust-roots/" in text, "must COPY trust-roots/"
    assert "COPY proof1b-staging/policies/" in text, "must COPY policies/"
    assert "COPY proof1b-staging/alembic.ini" in text, "must COPY alembic.ini"


def test_agentos_proof_bakes_the_three_cognic_root_envs() -> None:
    # The three trust-root ENVs point the kernel at the baked attestation / trust-root /
    # allow-list paths (mirrors the 1b-1 bake).
    text = _agentos_proof_dockerfile_text()
    assert "COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations" in text
    assert "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots" in text
    assert "COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json" in text


def test_agentos_proof_vendors_the_proof_app_module() -> None:
    # The proof-only app factory lives in the test tree; the runner copies
    # tests/integration/proof_1b_2 into the build context as proof_1b_2/, and the image
    # vendors it to /app/proof_1b_2/ so uvicorn can import proof_1b_2.proof_app.
    text = _agentos_proof_dockerfile_text()
    assert "COPY proof_1b_2/ /app/proof_1b_2/" in text, (
        "must vendor the proof_1b_2 module to /app/proof_1b_2/"
    )


def test_agentos_proof_cmd_runs_the_proof_factory() -> None:
    # The CMD overrides the base create_prod_app factory with the proof-only
    # create_proof_app factory (which sets app.state.actor_binder to the fixed proof
    # binder). Substring assert tolerates the sh -c exec wrapper.
    text = _agentos_proof_dockerfile_text()
    assert "uvicorn proof_1b_2.proof_app:create_proof_app --factory" in text, (
        "CMD must run the proof-only create_proof_app factory (not the base create_prod_app)"
    )


def test_agentos_proof_sets_pythonpath_so_app_is_importable() -> None:
    # /app/proof_1b_2 is vendored (COPY, not pip-installed), and the default-adapters
    # base sets no PYTHONPATH + runs uvicorn as a console script (sys.path[0] =
    # /opt/venv/bin, not the /app WORKDIR). ENV PYTHONPATH=/app makes the import
    # deterministic instead of relying on uvicorn's --app-dir cwd default.
    text = _agentos_proof_dockerfile_text()
    assert "ENV PYTHONPATH=/app" in text, (
        "ENV PYTHONPATH=/app must be set so uvicorn can import the vendored "
        "proof_1b_2 module from /app"
    )
