"""Real-cosign 3.x proof of the CLI/pack legacy-compat bridge (ADR-016).

Env-gated on ``COGNIC_RUN_COSIGN_INTEGRATION=1``. Default ``pytest`` runs
skip the module. When opted in, the fixture **FAILS LOUD** if cosign is
missing from PATH (``AssertionError`` -> pytest ERROR, never SKIP) — the
opt-in env var is the "I have cosign" contract.

Proves: real ``agentos sign-blob`` produces an OFFLINE ``cosign.sig`` +
``bundle.sigstore`` on cosign 3.x (no Rekor tlog entry under either the
legacy ``rekorBundle`` or the new ``tlogEntries`` key), and BOTH verify
shapes — ``cli/verify.py``'s ``_exec_cosign_verify_blob`` (Task 2 flags)
and the runtime ``protocol/trust_gate.py``'s ``verify_pack_signature``
(Task 3 bundle + offline flags) — accept it. This is the end-to-end
validation that the cosign-3.x legacy-compat bridge works on real cosign,
and unblocks Proof 1a Task 6.

Constructed to mirror the sibling real-cosign proof
``tests/integration/models/test_real_cosign_proof.py``: module-level
``skipif``, a fail-loud keypair fixture, and keys minted under
``tmp_path`` (never in the repo).

**Real cosign 3.0.6 bundle shape (offline, legacy format):** with
``--tlog-upload=false --use-signing-config=false --new-bundle-format=false``
the produced ``bundle.sigstore`` is ``{"base64Signature": "<b64>"}`` — the
ONLY top-level key is ``base64Signature``. Neither ``tlogEntries`` (new
format) nor ``rekorBundle`` (legacy format) is present, so both ``.get()``
lookups below return ``None``. The offline assertion is therefore correct
AND non-vacuous: a tlog-uploaded legacy bundle WOULD embed ``rekorBundle``.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from typer.testing import CliRunner

from cognic_agentos.cli import app
from cognic_agentos.cli.verify import _exec_cosign_verify_blob
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.trust_gate import TrustGate

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_COSIGN_INTEGRATION") != "1",
    reason=(
        "real-cosign CLI/pack proof; opt in via COGNIC_RUN_COSIGN_INTEGRATION=1 "
        "(requires cosign on PATH at the target version — fails loud if missing)"
    ),
)


@pytest.fixture
def real_cosign(tmp_path: Path) -> dict[str, Any]:
    """Mint a real cosign keypair (empty password) under ``tmp_path``.

    **Fail-loud contract**: when the env-gate is opted in but ``cosign``
    is missing from PATH, this raises ``AssertionError`` — pytest reports
    ERROR (not SKIP), per the opt-in "I have cosign" contract. The keypair
    lives under ``tmp_path`` (pytest temp, auto-cleaned), never in the repo.
    """
    cosign = shutil.which("cosign")
    assert cosign is not None, (
        "cosign binary not found on PATH; opt-in env "
        "COGNIC_RUN_COSIGN_INTEGRATION=1 implies cosign is available — this "
        "fixture fails LOUD rather than silently skipping the proof."
    )
    env = {
        "COSIGN_PASSWORD": "",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
    }
    keys = tmp_path / "keys"
    keys.mkdir()
    subprocess.run(
        [cosign, "generate-key-pair"],
        cwd=keys,
        env=env,
        check=True,
        capture_output=True,
    )
    private = keys / "cosign.key"
    public = keys / "cosign.pub"
    assert private.exists(), "cosign generate-key-pair did not write cosign.key"
    assert public.exists(), "cosign generate-key-pair did not write cosign.pub"
    return {"cosign": cosign, "private": private, "public": public}


async def test_cli_sign_then_verify_offline_roundtrip_on_real_cosign(
    real_cosign: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real ``agentos sign-blob`` → offline bundle → both verify shapes pass.

    Drives the ACTUAL fixed argv sites on real cosign 3.x: ``cli/sign.py``
    (via ``agentos sign-blob``), ``cli/verify.py``
    (``_exec_cosign_verify_blob``), and ``protocol/trust_gate.py``
    (``verify_pack_signature``); asserts the produced bundle carries no
    transparency-log entry.
    """
    cosign: str = str(real_cosign["cosign"])
    public_key: Path = real_cosign["public"]
    private_key: Path = real_cosign["private"]

    # Layout: ``signature_root_path`` holds the wheel + the produced
    # cosign.sig + bundle.sigstore; ``trust_root_prefix/_default`` holds the
    # public trust root. This satisfies verify_pack_signature's path-
    # canonicalisation invariants (sig/blob/bundle under signature_root_path;
    # trust root under trust_root_prefix).
    sig_root = tmp_path / "sig_root"
    sig_root.mkdir()
    trust_prefix = tmp_path / "trust_prefix"
    (trust_prefix / "_default").mkdir(parents=True)
    trust_root = trust_prefix / "_default" / "cosign.pub"
    trust_root.write_bytes(public_key.read_bytes())

    wheel = sig_root / "demo_pack-1.0.0-py3-none-any.whl"
    wheel.write_bytes(b"real-cosign-3x-proof-wheel-bytes")

    # 1) Real ``agentos sign-blob`` — Task 1's fixed argv produces the
    #    detached cosign.sig + the OFFLINE bundle on cosign 3.x. The command
    #    resolves cosign + the signing key from Settings (env aliases
    #    COGNIC_COSIGN_PATH / COGNIC_SIGNING_KEY_PATH, exactly as
    #    test_cli_sign.py drives it); its cosign subprocess overlays
    #    COSIGN_PASSWORD="" itself, so no parent-env password is needed.
    #
    #    The ``sign-blob`` command calls ``asyncio.run(run_sign_blob(...))``
    #    internally (cli/__init__.py:760); this test runs inside the
    #    pytest-asyncio event loop, so the sync ``CliRunner().invoke`` MUST
    #    run in a worker thread (asyncio.to_thread) where no loop is running
    #    — otherwise the nested asyncio.run() raises "cannot be called from a
    #    running event loop".
    monkeypatch.setenv("COGNIC_COSIGN_PATH", cosign)
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(private_key))
    runner = CliRunner()
    result = await asyncio.to_thread(lambda: runner.invoke(app, ["sign-blob", str(wheel)]))
    assert result.exit_code == 0, (
        f"agentos sign-blob failed: exit={result.exit_code} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    sig = wheel.parent / "cosign.sig"
    bundle = wheel.parent / "bundle.sigstore"
    assert sig.is_file() and sig.stat().st_size > 0, "cosign.sig not produced / empty"
    assert bundle.is_file() and bundle.stat().st_size > 0, "bundle.sigstore not produced / empty"

    # 2) OFFLINE assertion. ``--tlog-upload=false`` meant nothing was
    #    uploaded to Rekor, so the legacy bundle carries no transparency-log
    #    proof under either the new (``tlogEntries``) or legacy
    #    (``rekorBundle``) key. On real cosign 3.0.6 the only top-level key
    #    is ``base64Signature`` → both ``.get()`` return None (falsy). The
    #    assertion is correct AND non-vacuous (a tlog-uploaded legacy bundle
    #    WOULD embed ``rekorBundle``).
    bundle_json = json.loads(bundle.read_text())
    assert not bundle_json.get("tlogEntries"), (
        f"bundle has tlogEntries — not offline. top-level keys={sorted(bundle_json)}"
    )
    assert not bundle_json.get("rekorBundle"), (
        f"bundle has rekorBundle — not offline. top-level keys={sorted(bundle_json)}"
    )

    # 3) cli/verify.py argv shape verifies on real cosign (Task 2 flags:
    #    --insecure-ignore-tlog --new-bundle-format=false). Returns None on
    #    success.
    verify_finding = await _exec_cosign_verify_blob(
        cosign,
        wheel,
        sig_path=sig,
        bundle_path=bundle,
        trust_root_path=str(trust_root),
        timeout_s=30.0,
    )
    assert verify_finding is None, (
        f"cli/verify.py verify-blob rejected the offline pack: {verify_finding}"
    )

    # 4) Runtime trust_gate.verify_pack_signature round-trip (Task 3 bundle +
    #    offline flags) verifies the same artifacts on real cosign. Settings
    #    constructed exactly as the test_trust_gate.py ``settings_factory``
    #    does (build_settings_without_env_file + model_copy). The AuditStore
    #    needs a real AsyncEngine but the green path never touches it (it is
    #    only read on the timeout path), so a bare in-memory engine suffices.
    settings = build_settings_without_env_file().model_copy(
        update={
            "cosign_path": cosign,
            "require_cosign": True,
            "cosign_verify_timeout_s": 30.0,
            "signature_root_path": sig_root,
            "trust_root_prefix": trust_prefix,
        }
    )
    engine = create_async_engine("sqlite+aiosqlite://")
    try:
        gate = TrustGate(settings=settings, audit_store=AuditStore(engine))
        verified = await gate.verify_pack_signature(
            pack_id="demo_pack",
            version="1.0.0",
            signature_path=sig,
            bundle_path=bundle,
            blob_path=wheel,
            trust_root=trust_root,
        )
    finally:
        await engine.dispose()

    assert verified.verified is True, "runtime trust_gate rejected the offline pack"
    assert verified.signature_digest != "cosign-skipped:require_cosign=false", (
        "trust_gate took the require_cosign=False skip path — real cosign did not run"
    )
