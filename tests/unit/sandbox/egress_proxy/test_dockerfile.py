"""T7 — egress-proxy production Dockerfile static-pin regressions.

The Dockerfile is build-context content (not Python); it is read here as text.
These tests pin the security- and supply-chain-relevant invariants of the
canonical egress-proxy image so a future edit cannot SILENTLY:

  * drift the base off its pinned digest (immutability — base is content-pinned,
    not tag-tracked);
  * unpin or bump tinyproxy (the tinyproxy-log → ProxyAccessRecord mapping in
    ``cognic_egress_shim`` is wording-coupled to tinyproxy 1.11.1 per the T1
    spike's residual risk #2 — a version bump MUST re-run the spike matrix);
  * run the proxy as root (it is an internet-facing forward proxy in the sandbox
    egress path; root is unacceptable);
  * break the PID1 signal path by switching ENTRYPOINT to shell-form (T6's
    SIGTERM/SIGINT handling requires the Python entrypoint to BE PID1, which
    requires exec-form ENTRYPOINT — shell-form makes /bin/sh PID1 and swallows
    the signals);
  * forget to ship BOTH image-content modules — the entrypoint does a same-dir
    ``from cognic_egress_shim import ...`` so both files must land in /opt/cognic;
  * smuggle a create-time dynamic install (pip) into the image
    (``[[feedback_immutable_runtime_images_no_dynamic_install]]``); the shim is
    stdlib-only by contract;
  * move ``VOLUME`` ABOVE the chown of the runtime dirs (Docker discards
    filesystem mutations to a VOLUME path made AFTER the VOLUME instruction, so
    a reorder would silently leave /var/log/cognic-proxy un-writable by the
    non-root USER at runtime).
"""

from pathlib import Path

import pytest

_DOCKERFILE = (
    Path(__file__).resolve().parents[4] / "infra" / "sandbox" / "egress-proxy" / "Dockerfile"
)

# The pinned base: ``debian:bookworm-slim`` content-addressed to the multi-arch
# index digest captured 2026-05-29. A deliberate base bump updates BOTH this
# constant and the Dockerfile in the same edit.
_BASE_REF = (
    "debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb"
)

# The version-coupled security pin (T1 spike residual risk #2).
_TINYPROXY_PIN = "tinyproxy=1.11.1-2.1+deb12u1"


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return _DOCKERFILE.read_text(encoding="utf-8")


def _instruction_values(text: str, instruction: str) -> list[str]:
    """Return the argument string of every logical line for ``instruction``.

    Backslash line-continuations are joined first so a multi-line ``RUN`` is one
    logical line; ``#`` comment lines and blanks are dropped.
    """
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
    assert _DOCKERFILE.is_file(), f"missing egress-proxy Dockerfile at {_DOCKERFILE}"


def test_base_pinned_to_exact_digest(dockerfile_text: str) -> None:
    froms = _instruction_values(dockerfile_text, "FROM")
    assert froms, "no FROM instruction"
    # Single-stage image; the (only) FROM must be the digest-pinned base.
    assert any(_BASE_REF in f for f in froms), (
        f"FROM is not pinned to the captured base digest; want {_BASE_REF!r}, got {froms!r}"
    )
    assert all("@sha256:" in f for f in froms), f"a FROM is not digest-pinned: {froms!r}"


def test_tinyproxy_version_pinned(dockerfile_text: str) -> None:
    assert _TINYPROXY_PIN in dockerfile_text, (
        f"tinyproxy is not pinned to {_TINYPROXY_PIN!r} (version-coupled to the shim mapping)"
    )
    # No UNPINNED tinyproxy install (would let an apt bump break the log mapping).
    assert "install tinyproxy " not in dockerfile_text
    assert "install tinyproxy\n" not in dockerfile_text


def test_apt_uses_no_install_recommends_and_cleans_lists(dockerfile_text: str) -> None:
    assert "--no-install-recommends" in dockerfile_text, "minimal-surface apt flag missing"
    assert "rm -rf /var/lib/apt/lists" in dockerfile_text, "apt lists not cleaned"


def test_no_create_time_dynamic_install(dockerfile_text: str) -> None:
    # The shim + entrypoint are stdlib-only; nothing pip-installed into the image.
    assert "pip install" not in dockerfile_text
    assert "pip3 install" not in dockerfile_text


def test_runs_as_non_root_numeric_user(dockerfile_text: str) -> None:
    users = _instruction_values(dockerfile_text, "USER")
    assert users, "no USER instruction — image would run as root"
    final = users[-1]
    uid = final.split(":", 1)[0]
    assert uid.isdigit(), f"USER is not numeric: {final!r}"
    assert uid != "0", "USER resolves to root (uid 0)"


def test_path_reaches_tinyproxy_binary(dockerfile_text: str) -> None:
    # The entrypoint launches bare ``tinyproxy`` via PATH; /usr/bin (its install
    # location) must be reachable.
    env_lines = _instruction_values(dockerfile_text, "ENV")
    assert any("PATH=" in e and "/usr/bin" in e for e in env_lines), (
        "ENV PATH does not explicitly include /usr/bin (bare `tinyproxy` resolution)"
    )


def test_volume_declares_proxy_log_dir(dockerfile_text: str) -> None:
    volumes = _instruction_values(dockerfile_text, "VOLUME")
    assert any("/var/log/cognic-proxy" in v for v in volumes), (
        f"VOLUME does not declare /var/log/cognic-proxy: {volumes!r}"
    )


def test_exposes_proxy_port_3128(dockerfile_text: str) -> None:
    exposes = _instruction_values(dockerfile_text, "EXPOSE")
    assert any("3128" in e for e in exposes), f"EXPOSE does not include 3128: {exposes!r}"


def test_entrypoint_is_exec_form_running_entrypoint_py(dockerfile_text: str) -> None:
    entrypoints = _instruction_values(dockerfile_text, "ENTRYPOINT")
    assert len(entrypoints) == 1, f"expected exactly one ENTRYPOINT, got {entrypoints!r}"
    value = entrypoints[0]
    # Exec-form (JSON array) is mandatory: it makes the Python entrypoint PID1 so
    # T6's SIGTERM/SIGINT handlers actually fire. Shell-form would interpose
    # /bin/sh as PID1 and swallow the signals.
    assert value.startswith("["), f"ENTRYPOINT is not exec-form (JSON array): {value!r}"
    assert "/opt/cognic/entrypoint.py" in value, f"ENTRYPOINT must run entrypoint.py: {value!r}"
    assert "python3" in value, f"ENTRYPOINT does not invoke python3: {value!r}"


def test_ships_both_image_content_modules(dockerfile_text: str) -> None:
    copies = _instruction_values(dockerfile_text, "COPY")
    blob = "\n".join(copies)
    assert "cognic_egress_shim.py" in blob, "COPY does not ship the shim module"
    assert "entrypoint.py" in blob, "COPY does not ship the entrypoint module"
    assert "/opt/cognic" in blob, "image-content modules are not placed in /opt/cognic"


def test_runtime_dirs_chowned_before_volume(dockerfile_text: str) -> None:
    # Docker discards filesystem changes to a VOLUME path made AFTER the VOLUME
    # instruction. The chown that makes /var/log/cognic-proxy writable by the
    # non-root USER MUST therefore precede VOLUME, or the runtime dir reverts to
    # root-owned and the entrypoint cannot create access.jsonl.
    joined = dockerfile_text.replace("\\\n", " ")
    chown_idx = next(
        (i for i, ln in enumerate(joined.splitlines()) if "chown" in ln and "cognic-proxy" in ln),
        None,
    )
    volume_idx = next(
        (
            i
            for i, ln in enumerate(joined.splitlines())
            if ln.strip().upper().startswith("VOLUME") and "cognic-proxy" in ln
        ),
        None,
    )
    assert chown_idx is not None, "no chown of the cognic-proxy runtime dir found"
    assert volume_idx is not None, "no VOLUME for the cognic-proxy log dir found"
    assert chown_idx < volume_idx, "chown of /var/log/cognic-proxy must precede VOLUME"
