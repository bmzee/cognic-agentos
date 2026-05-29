"""T8.6 — real-cosign proof of the canonical/​tenant IMAGE verify path.

Sprint 8A's ``CanonicalImageCatalog._run_cosign_verify`` shells out to
``cosign verify`` on an OCI image ref. Every catalog unit test mocks the
subprocess, so the actual argv was never exercised against a real cosign
binary — which is exactly how the T8.6 bug (``--key`` passed together with
``--certificate-identity-regexp``, mutually exclusive in cosign v3) stayed
hidden until T30 tried to admit a real signed image. The argv-shape regression
in ``tests/unit/sandbox/test_image_catalog.py`` pins the corrected wire-contract
in CI; THIS module codifies the live behaviour end-to-end so a future cosign
bump that changes the verify contract is caught.

**Two checks against the REAL catalog method:**
  * positive — a real key-signed local image verifies (``passed=True``) +
    ``verify_cosign_or_refuse`` does not raise;
  * negative — verifying against a DIFFERENT public key fails closed
    (``passed=False``), proving the verify actually checks the signature.

**Env-gated** on ``COGNIC_RUN_COSIGN_IMAGE_VERIFY_PROOF=1``. Default ``pytest``
invocations skip the entire module. When the env var IS set, the fixture
**fails LOUD** (``AssertionError``, NOT skip) if ``cosign`` or ``docker`` is
missing or the local registry cannot start — the opt-in env var is the "I have
cosign + docker" contract; a broken environment at that point is an error, not a
non-issue (no silent skip, no pretend-success).

**Invariants (mirroring the Sprint 9.5 Z2 proof):**
  * **Local registry only** — a throwaway ``registry:2`` on localhost; NO remote
    push. cosign auto-treats ``localhost`` as insecure, so the catalog's exact
    production argv (no ``--allow-insecure-registry``) verifies it unmodified.
  * **Scratch image** — ``FROM scratch`` + one file, so no base image is pulled.
    This avoids a base-image pull; it does NOT make the proof offline — cosign
    v3 ``sign`` uses default signing behaviour and MAY contact the configured
    transparency log / signing service. The invariant is "no remote *image
    registry* push" (the registry is local), NOT "network-free".
  * **Private key lives in ``tmp_path``, wiped after signing**; only the public
    key (the trust root) + the signed image survive into the verify surface.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import cognic_agentos.sandbox.catalog as _catalog_mod
from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

# Module-level env-gate. Default ``pytest`` skips; opting in requires the env
# var. The message names the var so "SKIPPED [N]" output is self-explanatory.
pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_COSIGN_IMAGE_VERIFY_PROOF") != "1",
    reason=(
        "real-cosign image-verify proof; opt in via "
        "COGNIC_RUN_COSIGN_IMAGE_VERIFY_PROOF=1 (requires cosign + docker on "
        "PATH and a startable local registry — fails loud if missing)"
    ),
)

# Throwaway local registry on an uncommon port to reduce collision odds.
_REGISTRY_PORT = 5051
_REGISTRY_NAME = "t30-cosign-image-verify-registry"
_IMAGE_REPO = f"localhost:{_REGISTRY_PORT}/cognic-cosign-image-verify-proof"


def _run(args: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, check=True, capture_output=True, **kw)


def _wait_for_registry(port: int, *, timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("localhost", port), timeout=1.0).close()
            return True
        except OSError:
            time.sleep(0.25)
    return False


@pytest.fixture(scope="module")
def signed_local_image() -> Iterator[dict[str, Any]]:
    """Stand up a local registry, build + push a scratch image, mint a real
    cosign keypair, sign the image (key-based), wipe the private key, and yield
    the full ref + digest + the public trust root.

    Fail-loud (AssertionError) on any missing prerequisite when opted in.
    """
    cosign = shutil.which("cosign")
    docker = shutil.which("docker")
    assert cosign is not None, (
        "cosign not on PATH; opt-in COGNIC_RUN_COSIGN_IMAGE_VERIFY_PROOF=1 "
        "implies cosign is available — failing loud rather than skipping."
    )
    assert docker is not None, (
        "docker not on PATH; opt-in COGNIC_RUN_COSIGN_IMAGE_VERIFY_PROOF=1 "
        "implies docker is available — failing loud rather than skipping."
    )

    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="t30_cosign_image_verify_"))
    cosign_env = {"COSIGN_PASSWORD": "", "PATH": os.environ.get("PATH", ""), "HOME": str(tmp)}
    started_registry = False
    tag = f"{_IMAGE_REPO}:v1"
    try:
        # 1. Local registry (best-effort remove any stale container first).
        subprocess.run([docker, "rm", "-f", _REGISTRY_NAME], capture_output=True, check=False)
        _run(
            [
                docker,
                "run",
                "-d",
                "-p",
                f"{_REGISTRY_PORT}:5000",
                "--name",
                _REGISTRY_NAME,
                "registry:2",
            ]
        )
        started_registry = True
        assert _wait_for_registry(_REGISTRY_PORT), (
            f"local registry on :{_REGISTRY_PORT} did not become reachable"
        )

        # 2. Build a scratch image (no base pull) + push.
        (tmp / "payload").write_text("t30 cosign image-verify proof\n")
        (tmp / "Dockerfile").write_text("FROM scratch\nCOPY payload /payload\n")
        _run([docker, "build", "-t", tag, str(tmp)])
        _run([docker, "push", tag])
        inspect = _run([docker, "inspect", tag, "--format", "{{index .RepoDigests 0}}"])
        full_ref = inspect.stdout.decode().strip()
        assert "@sha256:" in full_ref, f"could not resolve pushed digest: {full_ref!r}"
        digest = full_ref.rsplit("@", 1)[1]

        # 3. Real cosign keypair (correct + a second WRONG keypair for the
        #    negative case), in tmp; private keys wiped after signing.
        keys = tmp / "keys"
        keys.mkdir()
        _run([cosign, "generate-key-pair"], cwd=keys, env=cosign_env)
        wrong_keys = tmp / "wrong_keys"
        wrong_keys.mkdir()
        _run([cosign, "generate-key-pair"], cwd=wrong_keys, env=cosign_env)

        trust_root = tmp / "trust-root.pub"
        trust_root.write_bytes((keys / "cosign.pub").read_bytes())
        wrong_trust_root = tmp / "wrong-trust-root.pub"
        wrong_trust_root.write_bytes((wrong_keys / "cosign.pub").read_bytes())

        # 4. Sign the image with the CORRECT key (sign may use the insecure
        #    flag — it is the operator step, not the catalog's verify argv).
        _run(
            [
                cosign,
                "sign",
                "--key",
                str(keys / "cosign.key"),
                "--yes",
                "--allow-insecure-registry",
                full_ref,
            ],
            env=cosign_env,
        )

        # 5. Wipe private keys — only public trust roots + signed image survive.
        (keys / "cosign.key").unlink()
        (wrong_keys / "cosign.key").unlink()
        for path in tmp.rglob("*"):
            assert not path.name.endswith((".key", ".pem")), f"private key leaked: {path}"

        yield {
            "full_ref": full_ref,
            "digest": digest,
            "trust_root": trust_root,
            "wrong_trust_root": wrong_trust_root,
        }
    finally:
        if started_registry:
            subprocess.run([docker, "rm", "-f", _REGISTRY_NAME], capture_output=True, check=False)
        subprocess.run([docker, "rmi", tag], capture_output=True, check=False)
        shutil.rmtree(tmp, ignore_errors=True)


def _patch_catalog_env_for_test_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prepend this host's cosign dir to the catalog's minimal
    ``_SUBPROCESS_ENV`` PATH so the REAL ``_run_cosign_verify`` argv executes
    against the real binary.

    The catalog's production PATH is ``/usr/local/bin:/usr/bin`` — where the
    agentos image installs cosign — so a dev host with cosign elsewhere (e.g.
    Homebrew ``/opt/homebrew/bin``) cannot launch it. ONLY the PATH is adjusted;
    the verify ARGV (``cosign verify --key <root> <ref>`` — the T8.6 contract
    under proof) is unchanged. Without this, the catalog returns
    ``failed to launch cosign`` and the verify is never exercised."""
    cosign = shutil.which("cosign")
    assert cosign is not None
    cosign_dir = str(Path(cosign).parent)
    base_path = _catalog_mod._SUBPROCESS_ENV["PATH"]
    monkeypatch.setattr(
        _catalog_mod,
        "_SUBPROCESS_ENV",
        {**_catalog_mod._SUBPROCESS_ENV, "PATH": f"{cosign_dir}:{base_path}"},
    )


async def test_real_catalog_cosign_verify_passes_for_key_signed_image(
    signed_local_image: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The REAL catalog ``_run_cosign_verify`` argv
    (``cosign verify --key <trust_root> <full_ref>`` — NO keyless flags)
    verifies a real key-signed image at the pinned cosign version."""
    _patch_catalog_env_for_test_host(monkeypatch)
    catalog = CanonicalImageCatalog(
        canonical_refs=frozenset({signed_local_image["full_ref"]}),
        tenant_trust_roots={"t-proof": signed_local_image["trust_root"]},
        tenant_allow_lists={},
    )
    result = await catalog._run_cosign_verify(signed_local_image["digest"], tenant_id="t-proof")
    assert result.passed is True, f"real cosign verify failed: {result.detail!r}"
    # The public or-refuse path must NOT raise for a validly-signed image.
    await catalog.verify_cosign_or_refuse(signed_local_image["digest"], tenant_id="t-proof")


async def test_real_catalog_cosign_verify_fails_closed_against_wrong_key(
    signed_local_image: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifying against a DIFFERENT public key fails closed — proves the
    verify actually checks the signature (not merely that cosign exits 0)."""
    _patch_catalog_env_for_test_host(monkeypatch)
    catalog = CanonicalImageCatalog(
        canonical_refs=frozenset({signed_local_image["full_ref"]}),
        tenant_trust_roots={"t-wrong": signed_local_image["wrong_trust_root"]},
        tenant_allow_lists={},
    )
    result = await catalog._run_cosign_verify(signed_local_image["digest"], tenant_id="t-wrong")
    assert result.passed is False, "verify against the wrong key must fail closed"
    # Anti-false-green guard: the failure MUST be a real signature mismatch, NOT
    # a cosign-not-found launch failure (which would also yield passed=False and
    # silently vacuously "pass" this negative case).
    assert "failed to launch cosign" not in result.detail.lower(), (
        f"negative case false-greened on a launch failure, not a signature "
        f"mismatch: {result.detail!r}"
    )
