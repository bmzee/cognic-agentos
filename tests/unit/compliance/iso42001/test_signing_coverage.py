"""Sprint 9 T10 — signing.py negative-path + subprocess coverage top-up.

The T3 suite covers identity resolution + the cosign-absent fail-loud +
`validate_cosign_artifacts` directly; this file tops up the
`cosign_sign_blob` subprocess body (cosign is mocked — never invoked for
real in unit tests) and the `_resolve_pem_path` / `_resolve_vault`
negative branches, for the T10 critical-controls gate promotion.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    EvidencePackSigningError,
    SigningIdentity,
    cosign_sign_blob,
    resolve_signing_identity,
)
from tests.support.adapter_fixtures import InMemorySecretAdapter

_IDENTITY = SigningIdentity(identity="/k.pem", pem=b"-----BEGIN PRIVATE KEY-----\n")


class _FakeProc:
    """Stand-in for the cosign subprocess handle."""

    def __init__(self, returncode: int, stderr: bytes) -> None:
        self.returncode = returncode
        self._stderr = stderr
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return (b"", self._stderr)

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


def _fake_exec(
    *,
    returncode: int = 0,
    write_outputs: bool = True,
    signature: bytes = b"SIG",
    bundle: bytes = b"BUNDLE",
    stderr: bytes = b"",
) -> Callable[..., Awaitable[_FakeProc]]:
    """A fake `asyncio.create_subprocess_exec` simulating cosign: it parses
    `--output-signature` / `--bundle` from argv and (optionally) writes
    those files, mirroring what real cosign does."""

    async def _exec(*argv: str, **_kwargs: object) -> _FakeProc:
        args = list(argv)
        if write_outputs:
            Path(args[args.index("--output-signature") + 1]).write_bytes(signature)
            Path(args[args.index("--bundle") + 1]).write_bytes(bundle)
        return _FakeProc(returncode, stderr)

    return _exec


def _arm_cosign(
    monkeypatch: pytest.MonkeyPatch, exec_fn: Callable[..., Awaitable[_FakeProc]]
) -> None:
    monkeypatch.setattr(
        "cognic_agentos.compliance.iso42001.signing.shutil.which",
        lambda _: "/usr/bin/cosign",
    )
    monkeypatch.setattr(
        "cognic_agentos.compliance.iso42001.signing.asyncio.create_subprocess_exec",
        exec_fn,
    )


# --- _resolve_pem_path negative branches ---


async def test_resolve_pem_path_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(EvidencePackSigningError, match="not a readable file"):
        await resolve_signing_identity(key_path=str(tmp_path / "nope.pem"), secret_adapter=None)


async def test_resolve_pem_path_raises_on_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(EvidencePackSigningError, match="is empty"):
        await resolve_signing_identity(key_path=str(empty), secret_adapter=None)


async def test_resolve_pem_path_raises_on_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pem = tmp_path / "k.pem"
    pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")

    def _raise(_self: Path) -> bytes:
        raise OSError("simulated read failure")

    monkeypatch.setattr(Path, "read_bytes", _raise)
    with pytest.raises(EvidencePackSigningError, match="failed to read"):
        await resolve_signing_identity(key_path=str(pem), secret_adapter=None)


# --- _resolve_vault negative branches ---


async def test_resolve_vault_raises_when_adapter_read_fails() -> None:
    # InMemorySecretAdapter.read raises KeyError on a missing path; the
    # resolver collapses any adapter error to a fail-loud signing error.
    with pytest.raises(EvidencePackSigningError, match="failed to read"):
        await resolve_signing_identity(
            key_path="vault://secret/missing", secret_adapter=InMemorySecretAdapter()
        )


async def test_resolve_vault_raises_when_key_field_missing() -> None:
    adapter = InMemorySecretAdapter()
    await adapter.write("secret/x", {"not_the_key": "value"})
    with pytest.raises(EvidencePackSigningError, match="no non-empty"):
        await resolve_signing_identity(key_path="vault://secret/x", secret_adapter=adapter)


# --- cosign_sign_blob subprocess paths ---


async def test_cosign_sign_blob_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _arm_cosign(monkeypatch, _fake_exec(signature=b"real-sig", bundle=b"real-bundle"))
    artifacts = await cosign_sign_blob(b"{}", _IDENTITY)
    assert artifacts == CosignArtifacts(signature=b"real-sig", bundle=b"real-bundle")


async def test_cosign_sign_blob_pins_v3_compat_flags_for_sig_and_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    async def _exec(*argv: str, **_kwargs: object) -> _FakeProc:
        captured.extend(argv)
        Path(argv[argv.index("--output-signature") + 1]).write_bytes(b"SIG")
        Path(argv[argv.index("--bundle") + 1]).write_bytes(b"BUNDLE")
        return _FakeProc(0, b"")

    _arm_cosign(monkeypatch, _exec)
    await cosign_sign_blob(b"{}", _IDENTITY)

    assert "--use-signing-config=false" in captured
    assert "--new-bundle-format=false" in captured


async def test_cosign_sign_blob_raises_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _arm_cosign(
        monkeypatch,
        _fake_exec(returncode=1, write_outputs=False, stderr=b"cosign boom"),
    )
    with pytest.raises(EvidencePackSigningError, match="exit 1"):
        await cosign_sign_blob(b"{}", _IDENTITY)


async def test_cosign_sign_blob_raises_on_missing_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _arm_cosign(monkeypatch, _fake_exec(returncode=0, write_outputs=False))
    with pytest.raises(EvidencePackSigningError, match="did not produce both"):
        await cosign_sign_blob(b"{}", _IDENTITY)


async def test_cosign_sign_blob_raises_on_empty_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _arm_cosign(monkeypatch, _fake_exec(signature=b""))
    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        await cosign_sign_blob(b"{}", _IDENTITY)


async def test_cosign_sign_blob_raises_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _arm_cosign(monkeypatch, _fake_exec(write_outputs=False))

    async def _raise_timeout(awaitable: Any, timeout: float) -> object:
        if hasattr(awaitable, "close"):
            awaitable.close()  # tidy the unawaited communicate() coroutine
        raise TimeoutError("simulated")

    monkeypatch.setattr(
        "cognic_agentos.compliance.iso42001.signing.asyncio.wait_for", _raise_timeout
    )
    with pytest.raises(EvidencePackSigningError, match="timed out"):
        await cosign_sign_blob(b"{}", _IDENTITY)
