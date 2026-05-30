"""T8 — runtime-python production Dockerfile static-pin regressions.

The runtime-python image is the WORKLOAD container the sandbox launches and
execs into. The Dockerfile is build-context content (not Python); it is read
here as text. These tests pin the invariants a future edit must not silently
break:

  * base drift off its pinned digest (immutability);
  * the **workload-GID contract** — the backend forces the runtime container to
    run as ``_NON_ROOT_USER`` (``docker_sibling.py``); credential projection
    ``chgrp``s projected files (mode 0440, group-readable) to the workload GID
    parsed from THIS image's ``USER`` directive (``_inspect_image_user_directive``
    → ``verify_docker_credential_projection_preflight``). For the running
    workload to READ those files, the image's USER GID MUST equal the forced
    runtime GID — a drift here silently breaks Z3/Z4 credential reads. Pinned by
    a test-only drift detector that imports ``_NON_ROOT_USER``
    (``[[feedback_drift_detector_test_only_no_runtime_import]]`` — the cross-check
    lives in the test, never as a production cross-module import);
  * ``/workspace`` writability under a read-only rootfs — the VOLUME declaration
    is what keeps it writable (Docker auto-creates a fresh anonymous volume,
    writable even under ``ReadonlyRootfs=True``); dropping VOLUME would break
    every workload write;
  * a missing keep-alive ``CMD`` — the backend sets no ``Cmd`` override
    (``docker_sibling.py`` runtime config), so the image CMD must keep the
    container alive for the exec-driven workload model;
  * a create-time dynamic install (pip) smuggled into the image
    (``[[feedback_immutable_runtime_images_no_dynamic_install]]``).

Mirrors ``tests/fixtures/sandbox/runtime-fixture.Dockerfile``'s proven approach,
but as a production (labelled, digest-pinned, python3-bearing) artifact.
"""

from pathlib import Path

import pytest

_DOCKERFILE = (
    Path(__file__).resolve().parents[3] / "infra" / "sandbox" / "runtime-python" / "Dockerfile"
)

# Same pinned debian:bookworm-slim multi-arch index digest as the egress-proxy
# image (captured 2026-05-29). A deliberate base bump updates BOTH Dockerfiles
# and BOTH pin constants in the same edit.
_BASE_REF = (
    "debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb"
)


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return _DOCKERFILE.read_text(encoding="utf-8")


def _instruction_values(text: str, instruction: str) -> list[str]:
    """Argument string of every logical line for ``instruction`` (continuations
    joined; comments/blanks dropped)."""
    joined = text.replace("\\\n", " ")
    values: list[str] = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, _, rest = line.partition(" ")
        if head.upper() == instruction.upper():
            values.append(rest.strip())
    return values


def test_dockerfile_exists() -> None:
    assert _DOCKERFILE.is_file(), f"missing runtime-python Dockerfile at {_DOCKERFILE}"


def test_base_pinned_to_exact_digest(dockerfile_text: str) -> None:
    froms = _instruction_values(dockerfile_text, "FROM")
    assert froms, "no FROM instruction"
    assert any(_BASE_REF in f for f in froms), (
        f"FROM is not pinned to the captured base digest; want {_BASE_REF!r}, got {froms!r}"
    )
    assert all("@sha256:" in f for f in froms), f"a FROM is not digest-pinned: {froms!r}"


def test_runs_as_non_root_numeric_user(dockerfile_text: str) -> None:
    users = _instruction_values(dockerfile_text, "USER")
    assert users, "no USER instruction — image would run as root"
    uid = users[-1].split(":", 1)[0]
    assert uid.isdigit(), f"USER is not numeric: {users[-1]!r}"
    assert uid != "0", "USER resolves to root (uid 0)"


def test_user_gid_matches_backend_forced_runtime_gid(dockerfile_text: str) -> None:
    # The workload-GID contract (see module docstring). Test-only cross-module
    # import: the value must agree with the backend constant, but neither file
    # imports the other at runtime.
    from cognic_agentos.sandbox.backends.docker_sibling import _NON_ROOT_USER

    assert ":" in _NON_ROOT_USER, f"_NON_ROOT_USER not uid:gid shaped: {_NON_ROOT_USER!r}"
    forced_gid = _NON_ROOT_USER.split(":", 1)[1]
    users = _instruction_values(dockerfile_text, "USER")
    assert users, "no USER instruction"
    final = users[-1]
    assert ":" in final, f"USER must be uid:gid shaped for the GID contract: {final!r}"
    image_gid = final.split(":", 1)[1]
    assert image_gid == forced_gid, (
        f"image USER GID {image_gid!r} must equal the backend-forced runtime GID "
        f"{forced_gid!r} (_NON_ROOT_USER={_NON_ROOT_USER!r}) — credential projection "
        f"chgrp's to the workload GID and the workload runs as the forced GID; a "
        f"mismatch silently breaks Z3/Z4 credential reads"
    )


def test_workspace_volume_keeps_it_writable_under_readonly_root(dockerfile_text: str) -> None:
    volumes = _instruction_values(dockerfile_text, "VOLUME")
    assert any("/workspace" in v for v in volumes), (
        f"VOLUME does not declare /workspace (read-only-root writability mechanism): {volumes!r}"
    )


def test_workdir_is_workspace(dockerfile_text: str) -> None:
    workdirs = _instruction_values(dockerfile_text, "WORKDIR")
    assert any("/workspace" in w for w in workdirs), f"WORKDIR is not /workspace: {workdirs!r}"


def test_installs_python3(dockerfile_text: str) -> None:
    # "runtime-python" — the workload interpreter must be present.
    assert "python3" in dockerfile_text, "python3 (the runtime interpreter) is not installed"


def test_apt_uses_no_install_recommends_and_cleans_lists(dockerfile_text: str) -> None:
    assert "--no-install-recommends" in dockerfile_text, "minimal-surface apt flag missing"
    assert "rm -rf /var/lib/apt/lists" in dockerfile_text, "apt lists not cleaned"


def test_no_create_time_dynamic_install(dockerfile_text: str) -> None:
    assert "pip install" not in dockerfile_text
    assert "pip3 install" not in dockerfile_text


def test_has_keep_alive_cmd_for_exec_model(dockerfile_text: str) -> None:
    # The backend sets no Cmd override, so the image CMD must keep the container
    # alive for the exec-driven workload model.
    cmds = _instruction_values(dockerfile_text, "CMD")
    assert len(cmds) == 1, f"expected exactly one CMD keep-alive, got {cmds!r}"
    value = cmds[0]
    assert value.startswith("["), f"CMD should be exec-form (JSON array): {value!r}"
    assert "sleep" in value and "infinity" in value, (
        f"CMD is not the proven `sleep infinity` keep-alive: {value!r}"
    )
