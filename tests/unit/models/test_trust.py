"""Sprint 9.5 A2 — model-artefact cosign trust gate."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.models.trust import (
    ModelSignatureVerificationError,
    ModelTrustGate,
    sigstore_bundle_digest,
)


def test_sigstore_bundle_digest_is_sha256_of_raw_bytes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.sigstore"
    payload = b'{"sig": "abc"}' * 100
    bundle.write_bytes(payload)
    assert sigstore_bundle_digest(bundle) == hashlib.sha256(payload).hexdigest()


async def test_verify_raises_when_cosign_binary_missing(tmp_path: Path) -> None:
    # An absolute cosign_path that does not exist -> shutil.which -> None.
    settings = Settings(cosign_path=str(tmp_path / "no-such-cosign"))
    gate = ModelTrustGate(settings)
    with pytest.raises(ModelSignatureVerificationError, match="cosign binary not found"):
        await gate.verify_model_signature(
            signed_artifact_path=tmp_path / "model.bin",
            sigstore_bundle_path=tmp_path / "bundle.sigstore",
            tenant_trust_root=tmp_path / "trust.pub",
        )


async def test_verify_returns_true_on_exit_zero(tmp_path: Path) -> None:
    # A stub "cosign" that exits 0 -> verified.
    fake = tmp_path / "cosign"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake))
    gate = ModelTrustGate(settings)
    result = await gate.verify_model_signature(
        signed_artifact_path=tmp_path / "model.bin",
        sigstore_bundle_path=tmp_path / "bundle.sigstore",
        tenant_trust_root=tmp_path / "trust.pub",
    )
    assert result is True


async def test_verify_returns_false_on_exit_nonzero(tmp_path: Path) -> None:
    fake = tmp_path / "cosign"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake))
    gate = ModelTrustGate(settings)
    result = await gate.verify_model_signature(
        signed_artifact_path=tmp_path / "model.bin",
        sigstore_bundle_path=tmp_path / "bundle.sigstore",
        tenant_trust_root=tmp_path / "trust.pub",
    )
    assert result is False


async def test_argv_excludes_signature_flag_and_pins_bundle_only_shape(
    tmp_path: Path,
) -> None:
    """Pin the exact cosign argv: --key <trust> --bundle <bundle> <artefact>;
    NO --signature (the Sigstore bundle carries it). Wire-protocol-public
    cosign invocation shape — the real-cosign proof at Task Z2 confirms
    this works in the target cosign version.
    """
    log_file = tmp_path / "argv.log"
    fake = tmp_path / "cosign"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log_file}"\nexit 0\n')
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake))
    gate = ModelTrustGate(settings)
    await gate.verify_model_signature(
        signed_artifact_path=tmp_path / "model.bin",
        sigstore_bundle_path=tmp_path / "bundle.sigstore",
        tenant_trust_root=tmp_path / "trust.pub",
    )
    recorded = log_file.read_text().strip().splitlines()
    assert recorded == [
        "verify-blob",
        "--key",
        str(tmp_path / "trust.pub"),
        "--bundle",
        str(tmp_path / "bundle.sigstore"),
        "--insecure-ignore-tlog",
        str(tmp_path / "model.bin"),
    ]
    # Narrow §6 fix: model path stays bundle-only — NO detached sig, and
    # NO legacy-bundle flag (the pack-contract concern, not the model path).
    assert "--signature" not in recorded
    assert "--new-bundle-format=false" not in recorded


async def test_verify_raises_on_timeout(tmp_path: Path) -> None:
    fake = tmp_path / "cosign"
    # NOTE: invoke /bin/sleep by absolute path. The production
    # _SUBPROCESS_ENV freezes PATH=/usr/local/bin:/usr/bin; on macOS
    # `sleep` lives at /bin/sleep (not /usr/bin/sleep), so a bare
    # `sleep 30` in the stub script can't be resolved and the
    # subprocess exits immediately with "command not found" — the
    # timeout never fires and the test flakes. Absolute path bypasses
    # PATH lookup; /bin/sleep exists on every POSIX target the model
    # registry is built for (macOS dev + Linux CI / bank prod).
    fake.write_text("#!/bin/sh\nexec /bin/sleep 30\n")
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake), cosign_verify_timeout_s=0.5)
    gate = ModelTrustGate(settings)
    with pytest.raises(ModelSignatureVerificationError, match="timed out"):
        await gate.verify_model_signature(
            signed_artifact_path=tmp_path / "model.bin",
            sigstore_bundle_path=tmp_path / "bundle.sigstore",
            tenant_trust_root=tmp_path / "trust.pub",
        )


async def test_verify_raises_typed_error_on_launch_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Force asyncio.create_subprocess_exec to raise OSError (binary was
    resolved at construction but exec failed at runtime — permission
    denied, fd exhaustion, etc.). Must surface as the typed
    ModelSignatureVerificationError carrying errno + exc class, NOT raw
    OSError. Fail-closed launch path per spec §2.3.
    """
    fake = tmp_path / "cosign"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake))
    gate = ModelTrustGate(settings)

    async def _raise_oserror(*args: object, **kwargs: object) -> object:
        # OSError(13, …) auto-promotes to PermissionError, OSError(2, …)
        # to FileNotFoundError, etc. The production except branch
        # catches ALL OSError subclasses; any concrete errno works for
        # the pin. errno=13 here exercises the EACCES path that a real
        # exec hits when the binary is non-executable.
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _raise_oserror)

    with pytest.raises(ModelSignatureVerificationError, match="failed to launch cosign") as ei:
        await gate.verify_model_signature(
            signed_artifact_path=tmp_path / "model.bin",
            sigstore_bundle_path=tmp_path / "bundle.sigstore",
            tenant_trust_root=tmp_path / "trust.pub",
        )
    # `from None` sets both __cause__ = None AND __suppress_context__
    # = True. The first is a tautology for any raise without `from X`;
    # the second is what actually pins the `from None` clause — removing
    # `from None` from production would leave __cause__ = None but flip
    # __suppress_context__ to False (the PermissionError on __context__
    # would then re-surface in traceback display). Both are pinned so
    # the test fails if the `from None` is dropped.
    assert ei.value.__cause__ is None
    assert ei.value.__suppress_context__ is True
    # Errno + class name surface in the wrapper message for diagnostics
    # (class is OSError-subclass-agnostic by construction).
    assert "errno=13" in str(ei.value)
    assert "class=" in str(ei.value)
    # Defensive: the wrapper itself is not an OSError subclass — the
    # typed wrapper escaped, not the raw OSError. (The OSError is still
    # on __context__ — Python always sets that inside an except block —
    # but `from None` suppresses traceback context display.)
    assert not isinstance(ei.value, OSError)


async def test_verify_timeout_kills_and_reaps_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Force asyncio.wait_for to raise TimeoutError and assert the
    except-branch calls proc.kill() FIRST then awaits proc.wait().
    Without proc.kill() the subprocess keeps running; without
    `await proc.wait()` it becomes a zombie. The natural-timeout test
    above proves the timeout RAISES — this one proves the side-effects
    survive (the natural test would still pass if the reap were
    removed).
    """
    fake = tmp_path / "cosign"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    settings = Settings(cosign_path=str(fake), cosign_verify_timeout_s=0.1)
    gate = ModelTrustGate(settings)

    call_order: list[str] = []

    class _FakeProc:
        def kill(self) -> None:
            call_order.append("kill")

        async def wait(self) -> int:
            call_order.append("wait")
            return -9

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b"", b"")

    fake_proc = _FakeProc()

    async def _fake_create_subprocess_exec(*args: object, **kwargs: object) -> _FakeProc:
        return fake_proc

    async def _fake_wait_for(aw: object, timeout: float) -> object:
        # Close the un-awaited coroutine to avoid RuntimeWarning, then
        # force the timeout branch.
        if hasattr(aw, "close"):
            aw.close()
        raise TimeoutError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(asyncio, "wait_for", _fake_wait_for)

    with pytest.raises(ModelSignatureVerificationError, match="timed out"):
        await gate.verify_model_signature(
            signed_artifact_path=tmp_path / "model.bin",
            sigstore_bundle_path=tmp_path / "bundle.sigstore",
            tenant_trust_root=tmp_path / "trust.pub",
        )
    # Both kill + wait must have been called, kill BEFORE wait
    # (awaiting wait() on a live process would hang).
    assert call_order == ["kill", "wait"], f"expected ['kill', 'wait'], got {call_order!r}"
