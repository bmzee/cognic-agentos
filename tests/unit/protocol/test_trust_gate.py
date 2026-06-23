"""Sprint 4 T6 — cosign trust gate tests.

The most security-sensitive surface in Sprint 4. ≥95% line / ≥90% branch
coverage per AGENTS.md critical-controls discipline.

Test classes:

  * ``TestInputValidation`` — pack_id / version / path-canonicalisation
    helpers in isolation. Pure unit tests; no subprocess. Covers all
    shell-metacharacter vectors enumerated in §2 invariant 8.
  * ``TestPathCanonicalisation`` — the ``_canonicalise_under_root``
    helper specifically: relative traversal, absolute paths, symlink
    escape, type errors.
  * ``TestSubprocessShape`` — the trust gate's actual subprocess
    invocation, against a Python ``cosign`` shim that records its
    argv / env / stdin / cwd. Validates §2 invariants 1 (list-form
    argv) and 5 (minimal env). Per the R3 reviewer-P1 fix, argv
    must NOT pass ``--output json`` (unsupported by cosign verify-
    blob); the shape test asserts its absence.
  * ``TestSubprocessFailureClasses`` — non-zero cosign exit,
    stderr/stdout privacy (no raw stream bytes leak into
    diagnostics), subprocess-launch OSError wrapped into
    ``CosignVerificationFailed``, post-verify ``_hash_file``
    OSError wrapped into the same taxonomy. Per §2 invariant 7
    (R3-revised), verification is exit-code-only — there are no
    "JSON-parse" failure classes because we never parse cosign
    stdout.
  * ``TestTimeout`` — strict timeout SIGKILLs the cosign process AND
    chains an ``audit_event(trust_gate.cosign_timeout)`` row.
  * ``TestCosignNotInstalled`` — ``shutil.which`` returns None at
    construction; first verify call raises CosignNotInstalledError.
  * ``TestRequireCosignFalse`` — dev override skips the subprocess
    entirely with a synthetic ``cosign-skipped`` digest sentinel.
  * ``TestSourceLevelInvariants`` — module source MUST NOT reference
    ``subprocess.run`` / ``subprocess.Popen`` / ``shell=True`` /
    ``os.environ`` passthrough into the subprocess call (§2
    invariants 1 + 5 enforced at the source level so a future commit
    cannot silently regress).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import inspect
import json
import os
import stat
import sys
import textwrap
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol import trust_gate as _tg_mod
from cognic_agentos.protocol.trust_gate import (
    CosignNotInstalledError,
    CosignVerificationFailed,
    CosignVerificationResult,
    PathTraversalError,
    TrustGate,
    TrustGateError,
    _canonicalise_under_root,
    _validate_pack_id,
    _validate_version,
)

# ---------------------------------------------------------------------------
# Fixtures — engine + audit store + settings layout under tmp_path.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'trust_gate_test.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def attestation_root(tmp_path: Path) -> Path:
    """Per-test ``signature_root_path``. Real attestation files (the
    .sig + the blob being verified) live under here."""
    root = tmp_path / "attestations"
    root.mkdir()
    return root


@pytest.fixture
def trust_root_prefix(tmp_path: Path) -> Path:
    """Per-test ``trust_root_prefix`` for cosign keys."""
    prefix = tmp_path / "trust-roots"
    prefix.mkdir()
    return prefix


@pytest.fixture
def settings_factory(
    tmp_path: Path,
    attestation_root: Path,
    trust_root_prefix: Path,
) -> Any:
    """Returns a callable that builds a ``Settings`` instance with
    trust-gate config pointed at per-test tmp paths."""

    def _build(
        *,
        cosign_path: str | None = None,
        require_cosign: bool = True,
        cosign_verify_timeout_s: float = 5.0,
    ) -> Any:
        return build_settings_without_env_file().model_copy(
            update={
                "cosign_path": cosign_path,
                "require_cosign": require_cosign,
                "cosign_verify_timeout_s": cosign_verify_timeout_s,
                "signature_root_path": attestation_root,
                "trust_root_prefix": trust_root_prefix,
                "local_object_store_root": tmp_path / "obj-store",
            }
        )

    return _build


# ---------------------------------------------------------------------------
# Cosign-shim helpers — produce a Python script the trust gate can
# actually exec, then assert what it received.
# ---------------------------------------------------------------------------


def _make_cosign_shim(
    tmp_path: Path,
    *,
    response_stdout: str = '{"verified": true}',
    response_stderr: str = "",
    sleep_s: float = 0.0,
    exit_code: int = 0,
    recording_path: Path | None = None,
) -> Path:
    """Write a Python script that records its argv + env + cwd to JSON
    and writes a configurable response to stdout/stderr. Returns the
    absolute path to the shim (chmod +x).

    The shim is used as ``settings.cosign_path`` so the trust gate's
    real ``asyncio.create_subprocess_exec`` runs against it. Tests
    then read the recording file to assert §2 invariants on argv /
    env / etc.
    """
    rec = recording_path or (tmp_path / f"shim_recording_{os.urandom(4).hex()}.json")
    shim = tmp_path / f"cosign_shim_{os.urandom(4).hex()}.py"
    # The shim uses the running interpreter so unit tests can run on
    # any reasonable POSIX without a system Python on PATH.
    shebang = f"#!{sys.executable}"
    body = textwrap.dedent(
        f"""
        import json, os, sys, time
        recording = {{
            "argv": sys.argv,
            "env": dict(os.environ),
            "cwd": os.getcwd(),
        }}
        with open({str(rec)!r}, "w") as f:
            json.dump(recording, f)
        if {sleep_s!r} > 0:
            time.sleep({sleep_s!r})
        sys.stdout.write({response_stdout!r})
        sys.stderr.write({response_stderr!r})
        sys.exit({exit_code!r})
        """
    ).strip()
    shim.write_text(f"{shebang}\n{body}\n")
    shim.chmod(stat.S_IRWXU)
    # Stash the recording path on the shim object so tests can find it
    # without threading another return value.
    shim_meta = tmp_path / f"{shim.name}.recording_path"
    shim_meta.write_text(str(rec))
    return shim


def _read_shim_recording(shim: Path) -> dict[str, Any]:
    rec_path = Path(shim.parent.joinpath(f"{shim.name}.recording_path").read_text())
    payload: dict[str, Any] = json.loads(rec_path.read_text())
    return payload


def _make_attestation_files(
    attestation_root: Path,
    pack_id: str,
    version: str,
    *,
    sig_bytes: bytes = b"fake-signature-bytes",
    blob_bytes: bytes = b"fake-blob-bytes",
    bundle_bytes: bytes = b"fake-bundle-bytes",
) -> tuple[Path, Path]:
    """Lay out attestation files at the conventional path. Returns
    (sig_path, blob_path). Also writes the sibling bundle.sigstore that
    verify_pack_signature now canonicalises + passes via --bundle; use
    _bundle_for(sig_path) to obtain it."""
    pack_dir = attestation_root / pack_id / version
    pack_dir.mkdir(parents=True)
    sig_path = pack_dir / "cosign.sig"
    blob_path = pack_dir / f"{pack_id}-{version}.whl"
    bundle_path = pack_dir / "bundle.sigstore"
    sig_path.write_bytes(sig_bytes)
    blob_path.write_bytes(blob_bytes)
    bundle_path.write_bytes(bundle_bytes)
    return sig_path, blob_path


def _bundle_for(attestation_sibling: Path) -> Path:
    """The bundle.sigstore written next to the sig + blob in the same
    pack_dir. Accepts either the sig_path or the blob_path."""
    return attestation_sibling.parent / "bundle.sigstore"


def _make_trust_root(trust_root_prefix: Path, name: str = "_default") -> Path:
    tenant_dir = trust_root_prefix / name
    tenant_dir.mkdir()
    key_path = tenant_dir / "cosign.pub"
    key_path.write_bytes(b"fake-cosign-public-key")
    return key_path


async def _read_audit_events(engine: AsyncEngine) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        rows = (await conn.execute(select(_audit_event).order_by(_audit_event.c.sequence))).all()
    return [dict(r._mapping) for r in rows]


# ---------------------------------------------------------------------------
# TestInputValidation — pack_id, version regexes (§2 invariant 3).
# ---------------------------------------------------------------------------


SHELL_METACHARS_PACK_ID = [
    "pack;ls",
    "pack|cat",
    "pack`whoami`",
    "pack$(id)",
    "pack&",
    "pack\nrm -rf",
    "pack\\test",
    "pack'",
    'pack"',
    "pack*",
    "pack?",
    "pack<",
    "pack>",
    "pack ",
    "pack\t",
    "pack/sub",
    "pack:tag",
    "PACK_UPPER",
    "_leading_underscore",
    "-leading-dash",
]


SHELL_METACHARS_VERSION = [
    "v1; ls",
    "1.0\nrm",
    "1.0$(whoami)",
    "1.0`id`",
    "1.0|cat",
    "1.0&",
    "1.0'",
    '1.0"',
    "1.0\\",
    "1.0 ",
    "1.0/sub",
]


class TestInputValidation:
    @pytest.mark.parametrize("bad", SHELL_METACHARS_PACK_ID)
    def test_pack_id_with_shell_metacharacter_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="invalid pack_id"):
            _validate_pack_id(bad)

    def test_pack_id_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            _validate_pack_id("a" * 129)

    def test_pack_id_at_boundary_accepted(self) -> None:
        # 128 chars exactly is the max allowed.
        _validate_pack_id("a" * 128)

    def test_pack_id_typical_accepted(self) -> None:
        _validate_pack_id("cognic-tool-search")
        _validate_pack_id("cognic_tool_search_v2")
        _validate_pack_id("a")
        _validate_pack_id("a1")

    def test_pack_id_non_string_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be str"):
            _validate_pack_id(b"bytes")  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", SHELL_METACHARS_VERSION)
    def test_version_with_invalid_chars_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="invalid version"):
            _validate_version(bad)

    def test_version_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            _validate_version("a" * 65)

    def test_version_pep440_examples_accepted(self) -> None:
        for v in ("1.0.0", "0.1.0a1", "2.0.0rc1+local.123", "2026.04.27", "1.0_dev"):
            _validate_version(v)

    def test_version_non_string_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be str"):
            _validate_version(1.0)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestPathCanonicalisation — _canonicalise_under_root (§2 invariants 3+4).
# ---------------------------------------------------------------------------


class TestPathCanonicalisation:
    def test_relative_traversal_rejected(self, attestation_root: Path) -> None:
        with pytest.raises(PathTraversalError):
            _canonicalise_under_root(attestation_root / ".." / "escape", attestation_root)

    def test_absolute_outside_root_rejected(self, attestation_root: Path) -> None:
        with pytest.raises(PathTraversalError):
            _canonicalise_under_root(Path("/etc/passwd"), attestation_root)

    def test_dot_dot_segment_in_middle_rejected(self, attestation_root: Path) -> None:
        with pytest.raises(PathTraversalError):
            _canonicalise_under_root(
                attestation_root / "valid" / ".." / ".." / "escape",
                attestation_root,
            )

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
    def test_symlink_escape_rejected(self, tmp_path: Path, attestation_root: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret").write_text("steal me")
        link = attestation_root / "evil-link"
        link.symlink_to(outside)
        with pytest.raises(PathTraversalError):
            _canonicalise_under_root(link / "secret", attestation_root)

    def test_path_directly_under_root_accepted(self, attestation_root: Path) -> None:
        target = attestation_root / "pack" / "1.0" / "blob"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"x")
        canonical = _canonicalise_under_root(target, attestation_root)
        assert canonical.is_relative_to(attestation_root.resolve())

    def test_non_path_argument_rejected(self, attestation_root: Path) -> None:
        with pytest.raises(PathTraversalError, match="must be a Path"):
            _canonicalise_under_root("string-not-path", attestation_root)  # type: ignore[arg-type]
        with pytest.raises(PathTraversalError, match="must be a Path"):
            _canonicalise_under_root(attestation_root, "string-not-path")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestSubprocessShape — argv/env/cwd via the cosign shim (§2 invariants 1+5).
# ---------------------------------------------------------------------------


class TestSubprocessShape:
    async def test_argv_is_list_form_with_explicit_flags(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "demo_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        await gate.verify_pack_signature(
            pack_id="demo_pack",
            version="1.0.0",
            signature_path=sig,
            bundle_path=_bundle_for(sig),
            blob_path=blob,
            trust_root=trust_root,
        )
        rec = _read_shim_recording(shim)
        argv = rec["argv"]
        # Argv is list-form. asyncio.create_subprocess_exec passes each
        # element as a separate argv slot — no shell parsing.
        assert argv[0] == str(shim)
        assert "verify-blob" in argv
        # R3 reviewer-P1 fix: ``cosign verify-blob`` reports verification
        # by exit code; ``--output json`` belongs to OCI ``cosign verify``
        # and is NOT supported by verify-blob. Argv must NOT pass it.
        assert "--output" not in argv, (
            "argv passes --output, which cosign verify-blob does not "
            "support; verification signal is the exit code"
        )
        # Trust root + signature path are passed via explicit flags.
        assert "--key" in argv
        assert "--signature" in argv
        # cosign 3.x legacy-compat (ADR-016): --bundle <bundle.sigstore>
        # + the two offline-verify flags ride the verify-blob argv.
        assert "--bundle" in argv
        assert argv[argv.index("--bundle") + 1].endswith("bundle.sigstore")
        assert "--insecure-ignore-tlog" in argv
        assert "--new-bundle-format=false" in argv
        # The blob path is the trailing positional arg.
        assert argv[-1].endswith(".whl")

    async def test_subprocess_env_is_minimal_no_passthrough(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """§2 invariant 5: ``os.environ`` MUST NOT pass through to
        cosign. The trust gate sets an explicit minimal env. A
        sentinel env var on the test process must not appear in the
        shim's recorded env."""
        monkeypatch.setenv("COGNIC_SECRET_LEAK_CANARY", "must-not-appear")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "must-not-appear")
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "envcheck", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        await gate.verify_pack_signature(
            pack_id="envcheck",
            version="1.0.0",
            signature_path=sig,
            bundle_path=_bundle_for(sig),
            blob_path=blob,
            trust_root=trust_root,
        )
        rec = _read_shim_recording(shim)
        env = rec["env"]
        # Only the two minimal vars are present.
        assert env.get("PATH") == "/usr/local/bin:/usr/bin"
        assert env.get("HOME") == "/tmp"
        assert "COGNIC_SECRET_LEAK_CANARY" not in env
        assert "AWS_ACCESS_KEY_ID" not in env

    async def test_happy_path_returns_signature_digest(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """``cosign verify-blob`` reports verification by exit code
        only (R3 reviewer-P1 fix); the shim writes its conventional
        "Verified OK" to stderr and exits 0. The trust gate trusts
        the exit code — never parses stdout/stderr — and returns
        the SHA-256 of the .sig file as ``signature_digest``."""
        sig_bytes = b"happy-path-sig-bytes-" + os.urandom(32)
        shim = _make_cosign_shim(
            tmp_path,
            response_stdout="",
            response_stderr="Verified OK",
            exit_code=0,
        )
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(
            attestation_root, "happy_pack", "1.0.0", sig_bytes=sig_bytes
        )
        trust_root = _make_trust_root(trust_root_prefix)
        result = await gate.verify_pack_signature(
            pack_id="happy_pack",
            version="1.0.0",
            signature_path=sig,
            bundle_path=_bundle_for(sig),
            blob_path=blob,
            trust_root=trust_root,
        )
        assert isinstance(result, CosignVerificationResult)
        assert result.verified is True
        assert result.pack_id == "happy_pack"
        assert result.version == "1.0.0"
        # signature_digest is the SHA-256 of the .sig file content.
        assert result.signature_digest == hashlib.sha256(sig_bytes).hexdigest()

    async def test_bundle_path_required_keyword(self) -> None:
        """bundle_path is a required keyword-only parameter (Fork-A)."""
        params = inspect.signature(TrustGate.verify_pack_signature).parameters
        assert "bundle_path" in params
        assert params["bundle_path"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["bundle_path"].default is inspect.Parameter.empty

    async def test_bundle_path_traversal_rejected(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """A bundle_path escaping signature_root_path fails closed."""
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "esc_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(PathTraversalError):
            await gate.verify_pack_signature(
                pack_id="esc_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=attestation_root / ".." / "escape.sigstore",
                blob_path=blob,
                trust_root=trust_root,
            )

    async def test_signature_digest_is_sha256_of_cosign_sig_unchanged(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """signature_digest stays the SHA-256 of cosign.sig (not the bundle)."""
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(
            attestation_root, "dig_pack", "1.0.0", sig_bytes=b"known-sig-bytes"
        )
        trust_root = _make_trust_root(trust_root_prefix)
        result = await gate.verify_pack_signature(
            pack_id="dig_pack",
            version="1.0.0",
            signature_path=sig,
            bundle_path=_bundle_for(sig),
            blob_path=blob,
            trust_root=trust_root,
        )
        assert result.signature_digest == hashlib.sha256(b"known-sig-bytes").hexdigest()


# ---------------------------------------------------------------------------
# TestSubprocessFailureClasses — exit-code semantics, OSError taxonomy,
# stdout/stderr privacy.
# ---------------------------------------------------------------------------


class TestSubprocessFailureClasses:
    async def test_non_zero_exit_fails_closed(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """R3 reviewer-P1: ``cosign verify-blob`` reports verification
        by exit code only. Non-zero MUST fail-closed."""
        shim = _make_cosign_shim(tmp_path, exit_code=1, response_stderr="cosign: bad signature")
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "fail_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(CosignVerificationFailed, match="returncode=1"):
            await gate.verify_pack_signature(
                pack_id="fail_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )

    async def test_non_zero_exit_does_not_leak_stderr_or_stdout_content(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """Error messages MUST NOT include raw cosign stderr or stdout
        — privacy + log-injection control. Both streams can carry
        attacker-influenced content if the signature blob is hostile.
        Only SHA-256 + length appear, for operator log correlation
        (R3 reviewer-P2 dissolves the previous payload-keys leak by
        removing JSON parsing entirely; this test pins the discipline
        for both streams)."""
        secret_stderr = "ATTACKER_LEAK: BANK_TRANSFER_ROUTING=12345"
        secret_stdout = "TENANT_SECRET: customer-list-12345"
        shim = _make_cosign_shim(
            tmp_path,
            exit_code=2,
            response_stderr=secret_stderr,
            response_stdout=secret_stdout,
        )
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "leak_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(CosignVerificationFailed) as exc:
            await gate.verify_pack_signature(
                pack_id="leak_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )
        msg = str(exc.value)
        # Stderr secrets stay buried.
        assert "ATTACKER_LEAK" not in msg
        assert "BANK_TRANSFER_ROUTING" not in msg
        # Stdout secrets stay buried too (R3 reviewer-P2: previous code
        # sometimes surfaced JSON keys from stdout).
        assert "TENANT_SECRET" not in msg
        assert "customer-list" not in msg
        # SHA-256 + length ARE present for log correlation.
        assert hashlib.sha256(secret_stderr.encode()).hexdigest()[:16] in msg
        assert f"stderr_len={len(secret_stderr)}" in msg
        assert hashlib.sha256(secret_stdout.encode()).hexdigest()[:16] in msg
        assert f"stdout_len={len(secret_stdout)}" in msg

    async def test_subprocess_launch_oserror_wrapped(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """R3 reviewer-P2: ``asyncio.create_subprocess_exec`` can raise
        OSError on launch (exec-format error, EACCES, ENOEXEC, race
        between shutil.which and exec). Without the wrapper, raw
        OSError escapes the TrustGateError taxonomy and T10 cannot
        convert the failure into a clean
        ``cosign_verification_failed`` registration refusal.

        Setup: write a file at a real path WITHOUT the exec bit, and
        coerce ``shutil.which`` to return that path so the trust gate
        constructs successfully. The actual ``create_subprocess_exec``
        then fails with PermissionError (a subclass of OSError) — and
        the wrapper must catch + re-raise as
        ``CosignVerificationFailed``."""
        non_exec = tmp_path / "cosign-no-exec.py"
        non_exec.write_text("#!/usr/bin/env python3\nimport sys; sys.exit(0)\n")
        non_exec.chmod(0o644)  # no exec bit

        # Force shutil.which to "find" the non-exec file so TrustGate
        # construction succeeds. The real EACCES then fires at exec().
        # Patch the global ``shutil.which`` since the trust-gate module
        # imports it as ``import shutil`` and resolves at call time.
        import shutil as _shutil

        monkeypatch.setattr(_shutil, "which", lambda _name: str(non_exec))
        settings = settings_factory(cosign_path=str(non_exec))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        assert gate.cosign_bin == str(non_exec)
        sig, blob = _make_attestation_files(attestation_root, "exec_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(CosignVerificationFailed, match="failed to launch cosign"):
            await gate.verify_pack_signature(
                pack_id="exec_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )

    async def test_signature_hashing_oserror_wrapped(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """R3 reviewer-P2: ``_hash_file`` runs AFTER cosign returns
        verified. If the .sig file is removed, swapped to unreadable,
        or the FS errors out between cosign's read and our hash, a
        raw OSError escapes the TrustGateError taxonomy. The wrapper
        catches it and re-raises as CosignVerificationFailed."""
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "rmsig_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)

        from cognic_agentos.protocol import trust_gate as _tg

        def _failing_hash(path: Path) -> str:
            err = OSError(2, "No such file or directory")
            err.errno = 2
            raise err

        monkeypatch.setattr(_tg, "_hash_file", _failing_hash)

        with pytest.raises(
            CosignVerificationFailed, match="signature digest hashing failed AFTER cosign"
        ):
            await gate.verify_pack_signature(
                pack_id="rmsig_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )


# ---------------------------------------------------------------------------
# TestTimeout — strict timeout SIGKILLs the process AND emits audit row.
# ---------------------------------------------------------------------------


class TestTimeout:
    async def test_timeout_kills_process_and_emits_audit_event(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        engine: AsyncEngine,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        # Shim sleeps for 5s; trust gate timeout is 0.5s.
        shim = _make_cosign_shim(tmp_path, sleep_s=5.0)
        settings = settings_factory(cosign_path=str(shim), cosign_verify_timeout_s=0.5)
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "slow_pack", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(CosignVerificationFailed, match=r"timed out after 0\.5s"):
            await gate.verify_pack_signature(
                pack_id="slow_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
                request_id="req-timeout-1",
                tenant_id="tenant-timeout",
            )
        # Audit emission lands BEFORE the raise so the evidence chain
        # records the timeout even when the caller fails.
        rows = await _read_audit_events(engine)
        assert len(rows) == 1
        row = rows[0]
        assert row["event_type"] == "trust_gate.cosign_timeout"
        assert row["request_id"] == "req-timeout-1"
        assert row["tenant_id"] == "tenant-timeout"
        assert row["payload"]["pack_id"] == "slow_pack"
        assert row["payload"]["version"] == "1.0.0"
        assert row["payload"]["timeout_s"] == 0.5
        assert "ISO42001.A.7.4" in (row["iso_controls"] or [])


# ---------------------------------------------------------------------------
# TestCosignNotInstalled — missing binary deferred to first call.
# ---------------------------------------------------------------------------


class TestCosignNotInstalled:
    async def test_construction_does_not_fail_when_cosign_missing(
        self, settings_factory: Any, audit_store: AuditStore
    ) -> None:
        """§2 invariant 2: kernel-image boot must not fail when only
        running tests that don't touch the trust gate. Construction
        with a non-existent ``cosign_path`` must succeed."""
        settings = settings_factory(cosign_path="/nonexistent/cosign-binary")
        gate = TrustGate(settings=settings, audit_store=audit_store)
        assert gate.cosign_bin is None  # shutil.which returned None

    async def test_first_verify_call_raises_cosign_not_installed(
        self,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        settings = settings_factory(cosign_path="/nonexistent/cosign-binary")
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "noinstall", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(CosignNotInstalledError, match="cosign binary not found"):
            await gate.verify_pack_signature(
                pack_id="noinstall",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )


# ---------------------------------------------------------------------------
# TestRequireCosignFalse — dev override skips subprocess entirely.
# ---------------------------------------------------------------------------


class TestRequireCosignFalse:
    async def test_skips_when_require_cosign_false(
        self,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        """The ``require_cosign=False`` setting is a documented dev-
        iteration override (Settings docstring + AGENTS.md). The trust
        gate honours it by short-circuiting with a synthetic
        ``cosign-skipped`` digest sentinel — operators can detect this
        in registry outcomes and refuse to ship to production."""
        # No cosign binary at all — would normally raise
        # CosignNotInstalledError.
        settings = settings_factory(cosign_path="/nonexistent/cosign-binary", require_cosign=False)
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "dev_pack", "0.0.1")
        trust_root = _make_trust_root(trust_root_prefix)
        result = await gate.verify_pack_signature(
            pack_id="dev_pack",
            version="0.0.1",
            signature_path=sig,
            bundle_path=_bundle_for(sig),
            blob_path=blob,
            trust_root=trust_root,
        )
        assert result.verified is True
        assert result.signature_digest.startswith("cosign-skipped:")


# ---------------------------------------------------------------------------
# TestPathTraversalAtVerifyBoundary — verify call rejects bad paths.
# ---------------------------------------------------------------------------


class TestPathTraversalAtVerifyBoundary:
    async def test_signature_path_outside_root_rejected(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        outside_sig = tmp_path / "rogue.sig"
        outside_sig.write_bytes(b"x")
        _, blob = _make_attestation_files(attestation_root, "boundary", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(PathTraversalError):
            await gate.verify_pack_signature(
                pack_id="boundary",
                version="1.0.0",
                signature_path=outside_sig,
                bundle_path=_bundle_for(blob),
                blob_path=blob,
                trust_root=trust_root,
            )

    async def test_trust_root_outside_prefix_rejected(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "tr_pack", "1.0.0")
        outside_root = tmp_path / "rogue-trust-root.pem"
        outside_root.write_bytes(b"x")
        with pytest.raises(PathTraversalError):
            await gate.verify_pack_signature(
                pack_id="tr_pack",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=outside_root,
            )

    async def test_invalid_pack_id_rejected_at_verify_boundary(
        self,
        tmp_path: Path,
        settings_factory: Any,
        audit_store: AuditStore,
        attestation_root: Path,
        trust_root_prefix: Path,
    ) -> None:
        shim = _make_cosign_shim(tmp_path)
        settings = settings_factory(cosign_path=str(shim))
        gate = TrustGate(settings=settings, audit_store=audit_store)
        sig, blob = _make_attestation_files(attestation_root, "demo", "1.0.0")
        trust_root = _make_trust_root(trust_root_prefix)
        with pytest.raises(ValueError, match="invalid pack_id"):
            await gate.verify_pack_signature(
                pack_id="evil; rm -rf /",
                version="1.0.0",
                signature_path=sig,
                bundle_path=_bundle_for(sig),
                blob_path=blob,
                trust_root=trust_root,
            )


# ---------------------------------------------------------------------------
# TestSourceLevelInvariants — module source MUST NOT contain the patterns
# the security model forbids. Belt-and-suspenders against future regressions.
# ---------------------------------------------------------------------------


class TestSourceLevelInvariants:
    def test_module_does_not_import_or_call_subprocess_run_or_popen(self) -> None:
        """§2 invariant 1 belt-and-suspenders: ``subprocess.run`` and
        ``subprocess.Popen`` accept ``shell=True`` and a string command
        line. ``asyncio.create_subprocess_exec`` does not. AST-walked
        so docstring/comment mentions of these names (which are fine —
        they're discussing what NOT to do) don't false-positive.
        """
        import ast

        tree = ast.parse(inspect.getsource(_tg_mod))

        # 1. ``subprocess`` must not be imported at all.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "subprocess", (
                        "trust_gate.py imports the synchronous "
                        "``subprocess`` module which accepts shell=True; "
                        "use asyncio.create_subprocess_exec only"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "subprocess", (
                    "trust_gate.py imports from ``subprocess`` — forbidden"
                )

        # 2. No call expression resolves to ``subprocess.<anything>``
        # (defence in depth — even if subprocess were aliased).
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "subprocess"
            ):
                raise AssertionError(
                    f"trust_gate.py references subprocess.{node.attr} "
                    f"at line {node.lineno} — the sync subprocess module "
                    f"accepts shell=True; use asyncio.create_subprocess_exec"
                )

        # 3. No ``shell=True`` keyword on ANY call.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        raise AssertionError(
                            f"trust_gate.py passes shell=True at line "
                            f"{node.lineno} — forbidden per §2 invariant 1"
                        )

    def test_module_does_not_passthrough_os_environ_to_subprocess(self) -> None:
        """§2 invariant 5: ``os.environ`` MUST NOT be passed to the
        cosign subprocess. AST-walked: looks for any call with ``env=``
        whose value reads from ``os.environ`` (direct, ``.copy()``,
        ``dict(os.environ)``, or ``{**os.environ, ...}``)."""
        import ast

        tree = ast.parse(inspect.getsource(_tg_mod))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "env":
                    continue
                # Walk the env= argument's subtree for any os.environ
                # reference. Catches direct, .copy(), dict(...), and
                # dict-spread patterns.
                for sub in ast.walk(kw.value):
                    if (
                        isinstance(sub, ast.Attribute)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id == "os"
                        and sub.attr == "environ"
                    ):
                        raise AssertionError(
                            f"trust_gate.py: env= argument at line "
                            f"{node.lineno} reads from os.environ — "
                            f"forbidden per §2 invariant 5"
                        )


# ---------------------------------------------------------------------------
# TestExceptionTaxonomy — TrustGateError is the catch-all base class.
# ---------------------------------------------------------------------------


class TestExceptionTaxonomy:
    def test_all_trust_gate_failures_subclass_trust_gate_error(self) -> None:
        """T10 catches ``TrustGateError`` to refuse pack registration
        with ``refusal_reason="cosign_verification_failed"``. Each
        narrower failure must be catchable through the base."""
        assert issubclass(CosignNotInstalledError, TrustGateError)
        assert issubclass(CosignVerificationFailed, TrustGateError)
        assert issubclass(PathTraversalError, TrustGateError)

    def test_path_traversal_also_value_error(self) -> None:
        """``PathTraversalError`` doubles as ``ValueError`` so the
        stdlib ``except ValueError:`` idiom catches it (the local
        object-store adapter follows the same convention)."""
        assert issubclass(PathTraversalError, ValueError)


# ---------------------------------------------------------------------------
# TestVerifyJwsBlobNegativePaths — Sprint-6 amendment (post-T14, pre-T15).
#
# ``verify_jws_blob`` is the runtime trust path the Sprint-6 A2A AgentCard
# verifier rides on. Its happy-path is exercised end-to-end by
# ``test_a2a_agent_cards.py`` against a real keypair + real Vault payload,
# and its tampered-payload regression lives in
# ``test_a2a_fixture_pack_admission.py`` (BadSignatureError → TrustGateError).
# This section pins the EIGHT named negative-path arms inside
# ``verify_jws_blob`` that the integration paths don't directly exercise:
#
#   1. Vault read failure (secret_adapter.read raises a non-async-cancelled
#      Exception → wrapped as TrustGateError).
#   2. Trust-root payload not a dict (Vault returned str/list).
#   3. ``keys`` field not a list.
#   4. Malformed key entry SKIP (continue branch — non-dict entry mixed
#      with valid entries; the verifier silently skips and proceeds).
#   5. No usable keys after filtering (every entry malformed) → TrustGateError.
#   6. JWS protected header missing ``kid`` → TrustGateError.
#   7. Malformed PEM at the JWS's kid → RSAKey.import_key raises →
#      TrustGateError.
#   8. Unparseable / detached-payload verification failure (joserfc raises
#      a non-BadSignatureError subclass of JoseError — e.g.,
#      ``UnsupportedAlgorithmError``) → TrustGateError.
#
# These eight arms together close the critical-controls coverage gap on
# trust_gate.py before Sprint-6 T15 extends the gate to the A2A septet
# (per the per-file 95% line / 90% branch floor in
# tools/check_critical_coverage.py).
# ---------------------------------------------------------------------------


class TestVerifyJwsBlobNegativePaths:
    """Eight focused negative-path arms for ``verify_jws_blob``.

    Each arm constructs a real :class:`TrustGate` with a mocked
    ``secret_adapter`` (the subject IS the trust gate's branching;
    Vault transport is not the subject). RSA keypair generation is
    real but module-scoped via the existing fixture pattern."""

    @staticmethod
    def _make_trust_gate(
        *,
        secret_adapter_response: Any | None = None,
        secret_adapter_exc: Exception | None = None,
    ) -> TrustGate:
        from unittest.mock import AsyncMock, MagicMock

        secret_adapter = MagicMock()
        if secret_adapter_exc is not None:
            secret_adapter.read = AsyncMock(side_effect=secret_adapter_exc)
        else:
            secret_adapter.read = AsyncMock(return_value=secret_adapter_response)
        audit_store = MagicMock()
        audit_store.append = AsyncMock(return_value=(None, b""))
        return TrustGate(
            settings=build_settings_without_env_file(),
            audit_store=audit_store,
            secret_adapter=secret_adapter,
        )

    @staticmethod
    def _real_keypair() -> tuple[bytes, bytes]:
        """Generate a fresh RSA keypair for the amendment arms.

        Module-scoping at the class level isn't worth it: the negative-
        path arms each touch the keyring once or never; total RSA cost
        across the section stays under one second."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pem, pub_pem

    @staticmethod
    def _sign_detached(
        priv_pem: bytes, *, kid: str = "k1", alg: str = "RS256"
    ) -> tuple[bytes, bytes]:
        """Produce a detached compact JWS over a fixed payload + return
        ``(jws_bytes, payload_bytes)``."""
        from joserfc import jws as jws_module
        from joserfc.jwk import RSAKey

        priv_key = RSAKey.import_key(priv_pem)
        payload = b"trust-gate-amendment-payload"
        compact = jws_module.serialize_compact({"alg": alg, "kid": kid}, payload, priv_key)
        parts = compact.split(".")
        detached = f"{parts[0]}..{parts[2]}".encode()
        return detached, payload

    # --- arm 1 ----------------------------------------------------------
    async def test_vault_read_failure_wraps_as_trust_gate_error(self) -> None:
        priv_pem, _ = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem)
        gate = self._make_trust_gate(secret_adapter_exc=RuntimeError("vault transport down"))
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload_bytes,
                tenant_id="bank_a",
            )
        # Closed-enum message includes the wrapped exception's class
        # name (NOT the raw text per Sprint-5 T15 R1 P2 #3 doctrine).
        assert "trust root read failed" in str(excinfo.value)
        assert "RuntimeError" in str(excinfo.value)

    # --- arm 2 ----------------------------------------------------------
    async def test_non_dict_trust_root_payload_refused(self) -> None:
        priv_pem, _ = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem)
        # Vault returns a list instead of the expected dict — defensive
        # validator must refuse rather than KeyError downstream.
        gate = self._make_trust_gate(secret_adapter_response=["not", "a", "dict"])
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload_bytes,
                tenant_id="bank_a",
            )
        assert "not a mapping" in str(excinfo.value)

    # --- arm 3 ----------------------------------------------------------
    async def test_non_list_keys_field_refused(self) -> None:
        priv_pem, _ = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem)
        # ``keys`` is a string instead of a list of {kid, pem} dicts.
        gate = self._make_trust_gate(secret_adapter_response={"keys": "this-should-be-a-list"})
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload_bytes,
                tenant_id="bank_a",
            )
        assert "keys" in str(excinfo.value) and "not a list" in str(excinfo.value)

    # --- arm 4 ----------------------------------------------------------
    async def test_malformed_key_entry_skipped_silently(self) -> None:
        """One bad entry mixed with one good entry — the bad entry is
        silently skipped (the ``continue`` branch in the for-loop)
        and the good entry verifies the JWS. The test passes IFF the
        verifier reaches the good entry, which is only possible if
        the bad entry was skipped (not raised on)."""
        priv_pem, pub_pem = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem, kid="good-kid")
        # Mix of malformed entries (None, non-dict, dict-with-int-kid)
        # and one valid entry whose kid matches the JWS header.
        gate = self._make_trust_gate(
            secret_adapter_response={
                "keys": [
                    None,
                    "not-a-dict",
                    {"kid": 1234, "pem": pub_pem.decode()},  # non-str kid → kept as filter
                    {"kid": "good-kid", "pem": pub_pem.decode()},
                ]
            }
        )
        # No exception → verification succeeded against the good entry
        # → bad entries were silently skipped.
        await gate.verify_jws_blob(
            jws_bytes=jws_bytes,
            payload_bytes=payload_bytes,
            tenant_id="bank_a",
        )

    # --- arm 5 ----------------------------------------------------------
    async def test_no_usable_keys_after_filtering_refused(self) -> None:
        priv_pem, _ = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem)
        # Every entry malformed in a different way — keyring ends up
        # empty after filtering.
        gate = self._make_trust_gate(
            secret_adapter_response={
                "keys": [
                    None,
                    "not-a-dict",
                    {"kid": 5, "pem": "x"},  # non-str kid
                    {"kid": "k", "pem": 9},  # non-str pem
                    {},  # empty dict
                ]
            }
        )
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload_bytes,
                tenant_id="bank_a",
            )
        assert "no usable keys" in str(excinfo.value)

    # --- arm 6 ----------------------------------------------------------
    async def test_missing_kid_in_jws_header_refused(self) -> None:
        """JWS header has ``alg`` but no ``kid`` — the verifier cannot
        resolve a specific key on the allow-list and refuses with the
        closed-enum message. Note: a JWS with NO alg fires earlier in
        the deserialize step (``MissingAlgorithmError``); to isolate the
        ``kid is None`` arm specifically, we sign a JWS with a kid then
        strip it from the header by re-serialising at the joserfc
        layer."""
        from joserfc import jws as jws_module
        from joserfc.jwk import RSAKey

        priv_pem, pub_pem = self._real_keypair()
        priv_key = RSAKey.import_key(priv_pem)
        payload = b"missing-kid-payload"
        # serialize_compact with header={"alg": "RS256"} only — no kid.
        compact = jws_module.serialize_compact({"alg": "RS256"}, payload, priv_key)
        parts = compact.split(".")
        detached = f"{parts[0]}..{parts[2]}".encode()

        # Vault has ANY non-empty keyring so the no-usable-keys path
        # doesn't fire first.
        gate = self._make_trust_gate(
            secret_adapter_response={"keys": [{"kid": "some-kid", "pem": pub_pem.decode()}]}
        )
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=detached,
                payload_bytes=payload,
                tenant_id="bank_a",
            )
        assert "missing 'kid'" in str(excinfo.value)

    # --- arm 7 ----------------------------------------------------------
    async def test_malformed_pem_at_jws_kid_refused(self) -> None:
        """Vault stores a string at the JWS's kid that is NOT a valid
        PEM. ``RSAKey.import_key`` raises; the verifier wraps as
        ``TrustGateError`` (NOT a kid-not-allowlisted; kid IS on the
        list — the PEM itself is malformed)."""
        priv_pem, _ = self._real_keypair()
        jws_bytes, payload_bytes = self._sign_detached(priv_pem, kid="malformed-kid")
        gate = self._make_trust_gate(
            secret_adapter_response={
                "keys": [{"kid": "malformed-kid", "pem": "this is not a valid pem"}]
            }
        )
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload_bytes,
                tenant_id="bank_a",
            )
        assert "public key import failed" in str(excinfo.value)

    # --- arm 8 ----------------------------------------------------------
    async def test_deserialize_failure_non_bad_signature_wraps_as_trust_gate_error(
        self,
    ) -> None:
        """The deserialize step raises a non-``BadSignatureError``
        subclass of ``JoseError`` — this maps to the
        ``DecodeError, JoseError, ValueError`` arm distinct from the
        signature-mismatch arm. We trigger
        :class:`UnsupportedAlgorithmError` by handing the verifier a
        JWS whose protected header carries a closed-enum-spec
        algorithm not in the resolution-allowed list (alg=ES256
        header → algorithms=[ES256] passed to deserialize → joserfc
        rejects ES256 against an RSA key)."""
        import base64
        import json as _json

        _priv_pem, pub_pem = self._real_keypair()
        # Construct a JWS-shape with header alg=ES256, kid=test-kid
        # (a 3-segment value extract_compact tolerates). The signature
        # segment is base64-valid but the algorithm/key mismatch
        # surfaces on deserialize.
        header = {"alg": "ES256", "kid": "test-kid"}
        h_seg = base64.urlsafe_b64encode(_json.dumps(header).encode()).rstrip(b"=").decode()
        # 64 bytes of zeros = valid ES256-shaped signature space, but
        # joserfc rejects on alg/key mismatch before checking the bytes.
        sig_seg = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
        detached = f"{h_seg}..{sig_seg}".encode()
        gate = self._make_trust_gate(
            secret_adapter_response={"keys": [{"kid": "test-kid", "pem": pub_pem.decode()}]}
        )
        with pytest.raises(TrustGateError) as excinfo:
            await gate.verify_jws_blob(
                jws_bytes=detached,
                payload_bytes=b"some-payload",
                tenant_id="bank_a",
            )
        # Either "JWS unparseable" (if extract_compact rejects on
        # algorithm-resolve) OR "JWS detached-payload verification
        # failed" (if it reaches deserialize). Both are TrustGateError;
        # both pin the closed-enum mapping. Assert the broad message
        # shape — a future joserfc change that moves the rejection
        # earlier in the pipeline is still caught.
        msg = str(excinfo.value)
        assert ("JWS unparseable" in msg) or ("JWS detached-payload" in msg)
