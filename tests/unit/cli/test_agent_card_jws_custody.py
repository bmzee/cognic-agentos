"""M8 finding #4 (2026-07-06) — AgentCard-JWS custody split regressions.

Finding #4 (maintainer-verified): the agent-pack AgentCard-JWS sign arm
was never live-executable. Three defects, each pinned here:

  - **4a packaging** — ``_sign_agent_card_jws_bytes`` imports ``joserfc``
    which lived ONLY under the kernel's ``adapters`` extra; bare
    ``cognic-agentos`` installs (every pack repo's dev extra) crashed
    ``ModuleNotFoundError`` on ``agentos sign --bundle .`` for agent
    packs. Fix: ``joserfc == 1.6.4`` moves to base ``[project]``
    dependencies (Section H pins the pyproject shape).
  - **4b crash-not-refusal** — ``_sign_agent_card_jws_to_disk``'s
    wrapper caught ``(OSError, RuntimeError, ValueError, TypeError)``
    while its docstring claimed "wraps any exception";
    ``ImportError`` / ``ModuleNotFoundError`` escaped as a raw
    traceback with NO ``sign-bundle:`` verdict line. Fix: the except
    tuple gains ``ImportError`` (Section C pins structured refusal +
    verdict + no-traceback), and ``_sign_agent_card_jws_bytes``
    translates joserfc ``JoseError`` subclasses (e.g. an EC key fed to
    ``RSAKey.import_key`` raises ``InvalidKeyTypeError`` which does NOT
    subclass ValueError) into ``ValueError`` so the wrapper's closed
    tuple keeps every key-material failure structural (Section D).
  - **4c key-type collision** — the JWS arm consumed the SAME resolved
    ``signing_key_path`` as cosign. The cosign key
    (sigstore-encrypted format) and the RS256 AgentCard-JWS key
    (unencrypted RSA PEM) are DIFFERENT CRYPTOGRAPHIC IDENTITIES; no
    file satisfies both. Fix: separate custody —
    ``Settings.agent_card_jws_signing_key_path``
    (``COGNIC_AGENT_CARD_JWS_SIGNING_KEY_PATH``) on the sign side and
    ``Settings.agent_card_jws_trust_root_path``
    (``COGNIC_AGENT_CARD_JWS_TRUST_ROOT_PATH``) + the
    ``--agent-card-trust-root`` verify flag + the tracked pack-root
    ``agent-card.pub`` convention on the verify side. Verify Step 9
    resolves **flag → setting → pack-root ``agent-card.pub``** and
    NEVER the cosign trust root (Sections A/B/E pin both directions).

Threat-model-revert pins the controller re-runs:
  (i) point verify Step 9 back at the cosign trust root → Section A's
      ``test_sign_and_verify_e2e_with_separate_cosign_and_jws_identities``
      FAILS (its cosign root is a decoy RSA key that cannot verify the
      JWS) and ``test_verify_fails_when_agent_card_trust_root_is_decoy``
      keeps the inverse direction honest.
  (ii) re-narrow the wrapper except tuple (drop ImportError) → Section
      C's missing-joserfc structured-refusal tests FAIL with a raw
      traceback.

Real material only: RSA keypairs are generated in-test via
``cryptography``; the cosign-side key file uses the real on-disk
``ENCRYPTED SIGSTORE PRIVATE KEY`` PEM shape ``cosign generate-key-pair``
produces; the staged packs are the T14 fixture pack signed through the
real orchestrators (cosign subprocess shimmed as in test_cli_sign.py —
the JWS path is REAL joserfc end-to-end).
"""

from __future__ import annotations

import ast
import base64
import inspect
import json
import sys
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app
from tests.unit.cli import test_cli_sign as sign_helpers
from tests.unit.cli import test_cli_verify as verify_helpers

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SIGN_TARGET_PACK: Path = _REPO_ROOT / "tests" / "fixtures" / "cli_sign_target_pack"
_FIXTURE_PRIVATE_PEM: Path = (
    _SIGN_TARGET_PACK / "attestations" / "test-signing" / "test_signing_key.private.pem"
)
_FIXTURE_PUBLIC_PEM: Path = (
    _SIGN_TARGET_PACK / "attestations" / "test-signing" / "test_signing_key.public.pem"
)

_JWS_KEY_ENV = "COGNIC_AGENT_CARD_JWS_SIGNING_KEY_PATH"
_JWS_TRUST_ROOT_ENV = "COGNIC_AGENT_CARD_JWS_TRUST_ROOT_PATH"

# Prod-safe sibling kwargs for prod-profile Settings constructions —
# mirrors tests/unit/test_config.py so the ONLY validator under test can
# fire (the strict-profile embedding/image guards otherwise raise first).
_PROD_EMBED_MODEL = "prod-embedding-model"
_PROD_RUNTIME_IMAGE = "ghcr.io/cognic-test/sandbox-runtime-python@sha256:" + "0" * 64
_PROD_PROXY_IMAGE = "ghcr.io/cognic-test/sandbox-egress-proxy@sha256:" + "0" * 64


# ---------------------------------------------------------------------------
# Real-material helpers
# ---------------------------------------------------------------------------


def _generate_rsa_keypair(target_dir: Path, *, stem: str) -> tuple[Path, Path]:
    """Generate a REAL RSA-2048 keypair via ``cryptography`` and write
    ``<stem>.private.pem`` (PKCS8, unencrypted — the JWS custody
    format) + ``<stem>.public.pem`` (SubjectPublicKeyInfo)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = target_dir / f"{stem}.private.pem"
    public_path = target_dir / f"{stem}.public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return private_path, public_path


def _write_sigstore_encrypted_key(target_dir: Path) -> Path:
    """Write a key file in the REAL on-disk shape ``cosign
    generate-key-pair`` produces: a PEM block labelled ``ENCRYPTED
    SIGSTORE PRIVATE KEY`` whose body is base64 of the scrypt +
    nacl/secretbox envelope JSON. This is the cosign-custody format the
    JWS arm must REFUSE structurally (it is not an RSA PEM and cannot
    be imported by joserfc without the sigstore KDF)."""
    envelope = (
        b'{"kdf":{"name":"scrypt","params":{"N":32768,"r":8,"p":1},'
        b'"salt":"c2FsdC1zYWx0LXNhbHQtc2FsdA=="},'
        b'"cipher":{"name":"nacl/secretbox","nonce":"bm9uY2Utbm9uY2Utbm9uY2U="},'
        b'"ciphertext":"ZGVhZGJlZWZkZWFkYmVlZg=="}'
    )
    body = base64.b64encode(envelope).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    key_path = target_dir / "cosign_sigstore.key"
    key_path.write_text(
        "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
        f"{wrapped}\n"
        "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
    )
    return key_path


def _sign_agent_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    cosign_key: Path | str,
    jws_key: Path | str | None,
) -> tuple[Path, CliRunner]:
    """Stage the T14 agent fixture pack + run ``sign --bundle`` through
    the shim set with SEPARATE cosign / JWS key custody. Returns the
    staged pack path + the runner WITHOUT asserting the exit code (the
    refusal-path tests inspect the result themselves)."""
    shims = sign_helpers._stage_full_shim_set(tmp_path)
    pack = sign_helpers._stage_pack_with_wheel(tmp_path)
    sign_helpers._set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path=cosign_key if isinstance(cosign_key, str) else str(cosign_key),
        agent_card_jws_signing_key_path=jws_key,
    )
    return pack, CliRunner()


# ---------------------------------------------------------------------------
# Section A — separate-custody e2e (finding #4c) + the in-toto pin
# ---------------------------------------------------------------------------


def test_sign_and_verify_e2e_with_separate_cosign_and_jws_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The finding-#4 live scenario, fixed: the cosign signing key is a
    sigstore-encrypted-format file (the ONLY format real cosign
    accepts) while the AgentCard JWS signs with a SEPARATE in-test
    RSA identity. Sign emits the real JWS at the manifest-declared
    path; verify Step 9 verifies it against the RSA PUBLIC key via
    ``--agent-card-trust-root``.

    TM-revert pin (i): the COSIGN trust root passed to verify is a
    DECOY RSA public key that cannot verify the JWS — re-pointing
    Step 9 at the cosign trust root makes this test FAIL."""
    jws_private, jws_public = _generate_rsa_keypair(tmp_path, stem="jws_identity")
    _decoy_private, decoy_public = _generate_rsa_keypair(tmp_path, stem="decoy_identity")
    cosign_key = _write_sigstore_encrypted_key(tmp_path)

    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=cosign_key, jws_key=jws_private
    )
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"sign --bundle exited {result.exit_code}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )

    # The real JWS landed at the manifest-declared path and verifies
    # against the JWS public key (real joserfc detached-payload path).
    jws_path = pack / "agent_cards" / "agent-card.jws"
    assert jws_path.is_file()
    from joserfc import jws as _jws
    from joserfc.jwk import RSAKey

    public_key = RSAKey.import_key(jws_public.read_bytes())
    card_payload = (pack / "agent_cards" / "agent-card.json").read_bytes()
    verified = _jws.deserialize_compact(
        jws_path.read_bytes().decode("ascii"), public_key, payload=card_payload
    )
    assert verified is not None

    # Dispatch pin #5 — the in-toto expected-artifact set includes the
    # agent-pack JWS path (already rendered by sign step 9; pinned here
    # on REAL produced material).
    intoto = json.loads((pack / "attestations" / "intoto-layout.json").read_text())
    assert any(p.endswith("agent_cards/agent-card.jws") for p in intoto["artifact_paths"]), (
        f"in-toto artifact_paths missing the AgentCard JWS: {intoto['artifact_paths']!r}"
    )

    # Verify: cosign trust root = DECOY public key (the cosign shim
    # exits 0 regardless — but if Step 9 read this root, JWS
    # verification would fail); agent-card trust root = the REAL JWS
    # public key via the new flag.
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch, cosign_path=verify_shim, trust_root=decoy_public
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)
    result = runner.invoke(
        app,
        ["verify", "--agent-card-trust-root", str(jws_public), "--json", str(pack)],
    )
    assert result.exit_code == 0, (
        f"verify exited {result.exit_code}; stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    assert payload["overall_status"] == "pass"
    assert any(a.endswith("agent-card.jws") for a in payload["artifacts_verified"])


def test_verify_fails_when_agent_card_trust_root_is_decoy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inverse separation pin: the COSIGN trust root carries the RIGHT
    JWS public key while ``--agent-card-trust-root`` carries a decoy —
    verify MUST fail ``verify_agent_card_jws_invalid``. If Step 9 fell
    back to the cosign root, this would wrongly pass."""
    jws_private, jws_public = _generate_rsa_keypair(tmp_path, stem="jws_identity")
    _decoy_private, decoy_public = _generate_rsa_keypair(tmp_path, stem="decoy_identity")
    cosign_key = _write_sigstore_encrypted_key(tmp_path)

    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=cosign_key, jws_key=jws_private
    )
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch, cosign_path=verify_shim, trust_root=jws_public
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)
    result = runner.invoke(app, ["verify", "--agent-card-trust-root", str(decoy_public), str(pack)])
    assert result.exit_code == 1
    assert "verify_agent_card_jws_invalid" in result.stderr


# ---------------------------------------------------------------------------
# Section B — wrong JWS public key (dispatch test #2)
# ---------------------------------------------------------------------------


def test_verify_wrong_jws_public_key_fails_agent_card_jws_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pack signed with the fixture JWS key verified against a WRONG
    RSA public key → ``verify_agent_card_jws_invalid`` (jws_bad_signature)."""
    _wrong_private, wrong_public = _generate_rsa_keypair(tmp_path, stem="wrong_identity")
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    result = CliRunner().invoke(
        app, ["verify", "--agent-card-trust-root", str(wrong_public), "--json", str(pack)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    reasons = {f["reason"] for f in payload["findings"]}
    assert "verify_agent_card_jws_invalid" in reasons
    modes = {f["payload"].get("failure_mode") for f in payload["findings"]}
    assert "jws_bad_signature" in modes


# ---------------------------------------------------------------------------
# Section C — missing joserfc → structured refusal (finding #4b)
# ---------------------------------------------------------------------------


def test_sign_missing_joserfc_emits_structured_refusal_not_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sys.modules poisoning makes ``from joserfc import ...`` raise at
    the JWS arm's function-local import site — the EXACT finding-#4
    live failure class. Post-fix: closed-enum
    ``sign_agent_card_jws_signing_failed``, verdict line emitted, NO
    raw traceback.

    TM-revert pin (ii): re-narrowing the wrapper except tuple (dropping
    ImportError) makes this test fail with a raw traceback."""
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=_FIXTURE_PRIVATE_PEM
    )
    monkeypatch.setitem(sys.modules, "joserfc", None)

    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"sign --bundle escaped with a raw exception: {result.exception!r}"
    )
    assert result.exit_code == 1
    # Verdict line ALWAYS emitted (the pre-fix crash printed none).
    assert "sign-bundle: FAIL" in result.stdout
    assert "sign_agent_card_jws_signing_failed" in result.stderr
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined


def test_sign_missing_joserfc_json_mode_names_module_and_remedy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--json mode: the structured finding names the missing module +
    the install remedy (joserfc rides the base dependency set as of
    finding #4, so a missing module means a broken / stale install)."""
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=_FIXTURE_PRIVATE_PEM
    )
    monkeypatch.setitem(sys.modules, "joserfc", None)

    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    jws_findings = [
        f for f in payload["findings"] if f["reason"] == "sign_agent_card_jws_signing_failed"
    ]
    assert jws_findings, payload["findings"]
    finding = jws_findings[0]
    assert finding["payload"].get("missing_module") == "joserfc"
    assert "joserfc" in finding["message"]
    # The remedy names the base-dependency posture (not the stale
    # 'adapters extra' guidance the pre-#4 packaging implied).
    assert "base" in finding["message"]


def test_sign_module_not_found_error_from_jws_helper_is_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``ModuleNotFoundError`` raised from the module-level JWS
    helper (its docstring documents monkeypatch-to-raise as the pinned
    seam) collapses into the closed-enum refusal — the
    ModuleNotFoundError leg of the extended except tuple."""
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=_FIXTURE_PRIVATE_PEM
    )

    import cognic_agentos.cli.sign as sign_module

    def _raise_module_not_found(*args: object, **kwargs: object) -> bytes:
        raise ModuleNotFoundError("No module named 'joserfc'", name="joserfc")

    monkeypatch.setattr(sign_module, "_sign_agent_card_jws_bytes", _raise_module_not_found)

    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_agent_card_jws_signing_failed"
        and f["payload"].get("missing_module") == "joserfc"
        for f in payload["findings"]
    )


# ---------------------------------------------------------------------------
# Section D — key-type collision + no-fallback custody (finding #4c)
# ---------------------------------------------------------------------------


def test_sigstore_encrypted_key_fed_to_jws_arm_refuses_structurally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cosign custody format (ENCRYPTED SIGSTORE PRIVATE KEY)
    pointed at the JWS arm → structured refusal, never a crash. The
    two custody formats are mutually unsatisfiable — this is the
    collision half of finding #4c."""
    cosign_key = _write_sigstore_encrypted_key(tmp_path)
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=cosign_key
    )

    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.exit_code == 1
    assert "sign-bundle: FAIL" in result.stdout
    assert "sign_agent_card_jws_signing_failed" in result.stderr
    assert "Traceback" not in (result.stdout + result.stderr)
    # No JWS artifact produced.
    assert not (pack / "agent_cards" / "agent-card.jws").exists()


def test_ec_key_fed_to_jws_arm_refuses_structurally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An EC private PEM fed to the RS256 JWS arm raises joserfc's
    ``InvalidKeyTypeError`` (a JoseError subclass that does NOT
    subclass ValueError) — pre-hardening it escaped the wrapper tuple
    as a raw traceback; post-fix the helper translates JoseError →
    ValueError so the refusal stays structural."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = tmp_path / "ec_identity.private.pem"
    ec_pem.write_bytes(
        ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=ec_pem
    )

    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.exit_code == 1
    assert "sign_agent_card_jws_signing_failed" in result.stderr
    assert "Traceback" not in (result.stdout + result.stderr)


def test_jws_arm_never_falls_back_to_cosign_signing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Behavioral no-fallback pin: ``signing_key_path`` carries a VALID
    RSA PEM (which WOULD satisfy joserfc if any fallback existed)
    while ``agent_card_jws_signing_key_path`` is UNSET → the agent-pack
    sign REFUSES naming the JWS setting, and no JWS is produced."""
    pack, runner = _sign_agent_pack(
        tmp_path, monkeypatch, cosign_key=_FIXTURE_PRIVATE_PEM, jws_key=None
    )
    monkeypatch.delenv(_JWS_KEY_ENV, raising=False)

    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    jws_findings = [
        f for f in payload["findings"] if f["reason"] == "sign_agent_card_jws_signing_failed"
    ]
    assert jws_findings, payload["findings"]
    assert "agent_card_jws_signing_key_path" in jws_findings[0]["message"]
    assert _JWS_KEY_ENV in jws_findings[0]["message"]
    assert not (pack / "agent_cards" / "agent-card.jws").exists()


def test_tool_pack_sign_does_not_require_jws_signing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kind gating: a NON-agent pack signs cleanly with the JWS custody
    setting entirely unset — the separate custody is agent-only."""
    import shutil as _shutil

    shims = sign_helpers._stage_full_shim_set(
        tmp_path,
        project_name="cognic-tool-sign-target",
    )
    pack = tmp_path / "tool_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    body = body.replace('kind = "agent"', 'kind = "tool"')
    body = body.replace(
        'pack_id = "cognic-agent-sign-target"', 'pack_id = "cognic-tool-sign-target"'
    )
    lines = [
        line
        for line in body.splitlines()
        if "agent_card_url" not in line and "agent_card_jws_path" not in line
    ]
    # Drop the [a2a] + [agent] blocks (agent-only) — mirrors the
    # finding-#3 instruction-pack staging in test_cli_sign.py.
    pruned: list[str] = []
    in_skipped_block = False
    for line in lines:
        if line.startswith("[a2a]") or line.startswith("[agent]"):
            in_skipped_block = True
            continue
        if in_skipped_block and line.startswith("["):
            in_skipped_block = False
        if in_skipped_block:
            continue
        pruned.append(line)
    manifest_path.write_text("\n".join(pruned) + "\n")
    pyproject_path = pack / "pyproject.toml"
    pyproject_path.write_text(
        pyproject_path.read_text().replace(
            'name = "cognic-agent-sign-target"', 'name = "cognic-tool-sign-target"'
        )
    )
    sign_helpers._rewrite_fixture_lock_root(pack, project_name="cognic-tool-sign-target")
    # A REAL PEP-427-complete TOOL wheel built in-test (the house
    # pattern — the fixture pack ships NO dist/ on disk): cognic.tools
    # entry point + METADATA Name matching the wheel filename so the
    # wheel-integrity kind derivation yields "tool".
    import zipfile as _zipfile

    dist = pack / "dist"
    dist.mkdir(exist_ok=True)
    wheel = dist / "cognic_tool_sign_target-0.1.0-py3-none-any.whl"
    dist_info = "cognic_tool_sign_target-0.1.0.dist-info"
    pkg = "cognic_tool_sign_target"
    wheel_members: dict[str, str] = {
        f"{pkg}/__init__.py": "",
        f"{pkg}/tool.py": "class SignTargetTool:\n    pass\n",
        f"{dist_info}/entry_points.txt": (
            f"[cognic.tools]\nsign_target = {pkg}.tool:SignTargetTool\n"
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\nName: cognic_tool_sign_target\nVersion: 0.1.0\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: agentos-test-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    record_lines = [f"{m},," for m in [*sorted(wheel_members), f"{dist_info}/RECORD"]]
    wheel_members[f"{dist_info}/RECORD"] = "\n".join(record_lines) + "\n"
    with _zipfile.ZipFile(wheel, "w", _zipfile.ZIP_DEFLATED) as zf:
        for member_name, payload in wheel_members.items():
            zf.writestr(member_name, payload)
    sign_helpers._set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        agent_card_jws_signing_key_path=None,
    )
    monkeypatch.delenv(_JWS_KEY_ENV, raising=False)

    result = CliRunner().invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"tool-pack sign required the JWS key: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_jws_arm_key_resolution_ast_pin() -> None:
    """AST pin: (a) every ``_sign_agent_card_jws_to_disk`` call site
    threads the SEPARATELY-resolved ``jws_key_path`` (never the cosign
    ``key_path``); (b) the JWS resolver wrapper reads
    ``settings.agent_card_jws_signing_key_path`` and NEVER
    ``settings.signing_key_path``."""
    import cognic_agentos.cli.sign as sign_module

    tree = ast.parse(inspect.getsource(sign_module))

    call_sites = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_sign_agent_card_jws_to_disk"
    ]
    assert call_sites, "no _sign_agent_card_jws_to_disk call sites found"
    for call in call_sites:
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        assert "agent_card_jws_signing_key_path" in kwargs, (
            "JWS call site does not thread the custody-split key kwarg"
        )
        value = kwargs["agent_card_jws_signing_key_path"]
        assert isinstance(value, ast.Name) and value.id == "jws_key_path", (
            f"JWS call site threads {ast.dump(value)} — expected the "
            "separately-resolved jws_key_path"
        )

    resolver = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_resolve_agent_card_jws_signing_key_path"
        ),
        None,
    )
    assert resolver is not None, "JWS key resolver wrapper missing"
    attribute_reads = {
        node.attr
        for node in ast.walk(resolver)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "settings"
    }
    assert "agent_card_jws_signing_key_path" in attribute_reads
    assert "signing_key_path" not in attribute_reads, (
        "the JWS resolver must NEVER read settings.signing_key_path (finding #4c)"
    )


def test_run_sign_bundle_inner_agent_without_resolved_jws_key_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive fail-closed branch: ``_run_sign_bundle_inner`` reached
    with an agent pack but ``jws_key_path=None`` (only possible if the
    manifest kind changed between the outer peek and the inner read)
    refuses structurally instead of crash-signing with no key."""
    import asyncio

    import cognic_agentos.cli.sign as sign_module

    shims = sign_helpers._stage_full_shim_set(tmp_path)
    pack = sign_helpers._stage_pack_with_wheel(tmp_path)
    report = asyncio.run(
        sign_module._run_sign_bundle_inner(
            pack_path=pack,
            cosign_bin=str(shims["cosign"]),
            syft_bin=str(shims["syft"]),
            grype_bin=str(shims["grype"]),
            license_bin=str(shims["license_auditor"]),
            key_path=str(_FIXTURE_PRIVATE_PEM),
            signing_key_reference=str(_FIXTURE_PRIVATE_PEM),
            jws_key_path=None,
            findings=[],
            dev_mode_skip_cosign=False,
        )
    )
    assert report.overall_status == "fail"
    assert any(
        f.reason == "sign_agent_card_jws_signing_failed"
        and f.payload.get("failure_mode") == "agent_card_jws_signing_key_not_resolved"
        for f in report.findings
    )


# ---------------------------------------------------------------------------
# Section E — verify-side resolution precedence + pack-root agent-card.pub
# ---------------------------------------------------------------------------


def test_verify_pack_root_agent_card_pub_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No flag + no setting → verify Step 9 falls back to the tracked
    pack-root ``agent-card.pub`` convention (the fixture pack commits
    one, mirroring ``cosign.pub`` custody)."""
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    assert (pack / "agent-card.pub").is_file(), (
        "fixture pack must ship the tracked pack-root agent-card.pub"
    )
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)

    result = CliRunner().invoke(app, ["verify", str(pack)])
    assert result.exit_code == 0, (
        f"pack-root fallback failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "verify: PASS" in result.stdout


def test_verify_pack_root_agent_card_pub_wrong_key_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pack-root ``agent-card.pub`` is actually READ: overwrite it
    with a decoy public key → Step 9 fails ``verify_agent_card_jws_invalid``."""
    _decoy_private, decoy_public = _generate_rsa_keypair(tmp_path, stem="decoy_identity")
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    (pack / "agent-card.pub").write_bytes(decoy_public.read_bytes())
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)

    result = CliRunner().invoke(app, ["verify", str(pack)])
    assert result.exit_code == 1
    assert "verify_agent_card_jws_invalid" in result.stderr


def test_verify_flag_beats_setting_and_pack_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Precedence: flag → setting → pack-root. Setting + pack-root both
    carry decoys; the flag carries the right key → PASS."""
    _decoy_private, decoy_public = _generate_rsa_keypair(tmp_path, stem="decoy_identity")
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    (pack / "agent-card.pub").write_bytes(decoy_public.read_bytes())
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.setenv(_JWS_TRUST_ROOT_ENV, str(decoy_public))

    result = CliRunner().invoke(
        app,
        [
            "verify",
            "--agent-card-trust-root",
            str(verify_helpers._TEST_PUBLIC_PEM),
            str(pack),
        ],
    )
    assert result.exit_code == 0, (
        f"flag precedence failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_verify_setting_beats_pack_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Precedence: the setting carries the right key while the pack-root
    file is a decoy → PASS via the setting."""
    _decoy_private, decoy_public = _generate_rsa_keypair(tmp_path, stem="decoy_identity")
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    (pack / "agent-card.pub").write_bytes(decoy_public.read_bytes())
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.setenv(_JWS_TRUST_ROOT_ENV, str(verify_helpers._TEST_PUBLIC_PEM))

    result = CliRunner().invoke(app, ["verify", str(pack)])
    assert result.exit_code == 0, (
        f"setting precedence failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_verify_agent_card_trust_root_unset_refuses_with_failure_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No flag, no setting, no pack-root ``agent-card.pub`` → Step 9
    refuses ``verify_trust_root_path_unresolvable`` with
    ``failure_mode=agent_card_trust_root_unset`` naming all three
    sources — NEVER a silent fall-back to the cosign trust root."""
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    (pack / "agent-card.pub").unlink()
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)

    result = CliRunner().invoke(app, ["verify", "--json", str(pack)])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    matching = [
        f
        for f in payload["findings"]
        if f["reason"] == "verify_trust_root_path_unresolvable"
        and f["payload"].get("failure_mode") == "agent_card_trust_root_unset"
    ]
    assert matching, payload["findings"]
    message = matching[0]["message"]
    assert "--agent-card-trust-root" in message
    assert _JWS_TRUST_ROOT_ENV in message
    assert "agent-card.pub" in message


def test_verify_tool_pack_needs_no_agent_card_trust_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kind gating on the verify side: tool packs verify cleanly with
    the agent-card trust root entirely unset (Step 9 is agent-only)."""
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch, kind="tool")
    pack_root_pub = pack / "agent-card.pub"
    if pack_root_pub.exists():
        pack_root_pub.unlink()
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.delenv(_JWS_TRUST_ROOT_ENV, raising=False)

    result = CliRunner().invoke(app, ["verify", str(pack)])
    assert result.exit_code == 0, (
        f"tool pack required an agent-card trust root: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_verify_agent_card_trust_root_via_vault_uri(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agent-card trust root supports the same ``vault://`` custody
    as the cosign trust root (production parity) — resolved via the
    SecretAdapter, verified, tempfile cleaned up."""
    pack = verify_helpers._stage_signed_pack(tmp_path, monkeypatch)
    verify_shim = verify_helpers._make_cosign_shim(tmp_path, exit_code=0)
    verify_helpers._wire_verify_settings(
        monkeypatch,
        cosign_path=verify_shim,
        trust_root=verify_helpers._TEST_PUBLIC_PEM,
    )
    monkeypatch.setenv(_JWS_TRUST_ROOT_ENV, "vault://trust/agent-card-pub")

    import cognic_agentos.cli.verify as verify_module

    class _InMemorySecretAdapter:
        async def read(self, path: str) -> dict[str, bytes]:
            assert path == "trust/agent-card-pub"
            return {"key": verify_helpers._TEST_PUBLIC_PEM.read_bytes()}

    monkeypatch.setattr(
        verify_module, "_build_secret_adapter", lambda settings: _InMemorySecretAdapter()
    )

    result = CliRunner().invoke(app, ["verify", str(pack)])
    assert result.exit_code == 0, (
        f"vault agent-card trust root failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Section F — Settings custody (prod fixture-tree guard, sibling parity)
# ---------------------------------------------------------------------------


def test_prod_profile_rejects_fixture_tree_agent_card_jws_signing_key() -> None:
    """The new signing-key setting mirrors the Sprint-7A R9 P2 #1 prod
    guard: prod profile + a path under tests/fixtures/ (or examples/)
    raises the closed-enum ValidationError."""
    from pydantic import ValidationError

    from cognic_agentos.core.config import Settings

    with pytest.raises(ValidationError) as excinfo:
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            runtime_profile="prod",
            # Prod-safe siblings (the test_config.py convention) so the
            # ONLY failing validator is the JWS-key guard under test —
            # not the unrelated strict-profile embedding/image guards.
            embedding_model=_PROD_EMBED_MODEL,
            sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
            sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
            agent_card_jws_signing_key_path="tests/fixtures/cli_sign_target_pack/attestations/test-signing/test_signing_key.private.pem",
        )
    assert "agent_card_jws_signing_key_path_under_test_fixture_tree_in_prod" in str(excinfo.value)


def test_prod_profile_allows_vault_uri_and_outside_tree_agent_card_jws_key(
    tmp_path: Path,
) -> None:
    """URI-shaped values + operator paths outside the fixture trees
    pass the prod guard (mirrors the sibling guard's allowed shapes)."""
    from cognic_agentos.core.config import Settings

    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        runtime_profile="prod",
        embedding_model=_PROD_EMBED_MODEL,
        sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
        sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        agent_card_jws_signing_key_path="vault://secret/agent-card-jws-key",
    )
    assert settings.agent_card_jws_signing_key_path == "vault://secret/agent-card-jws-key"
    outside = tmp_path / "operator" / "agent-card-jws.private.pem"
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        runtime_profile="prod",
        embedding_model=_PROD_EMBED_MODEL,
        sandbox_canonical_runtime_python_image=_PROD_RUNTIME_IMAGE,
        sandbox_canonical_egress_proxy_image=_PROD_PROXY_IMAGE,
        agent_card_jws_signing_key_path=str(outside),
    )
    assert settings.agent_card_jws_signing_key_path == str(outside)


def test_dev_profile_allows_fixture_tree_agent_card_jws_key() -> None:
    """Dev / test profiles MUST accept fixture-tree keys (the unit lane
    signs with the committed test-only RSA keypair)."""
    from cognic_agentos.core.config import Settings

    settings = Settings(
        runtime_profile="dev",
        agent_card_jws_signing_key_path=str(_FIXTURE_PRIVATE_PEM),
    )
    assert settings.agent_card_jws_signing_key_path == str(_FIXTURE_PRIVATE_PEM)


# ---------------------------------------------------------------------------
# Section G — packaging (finding #4a) + release-asset story (dispatch #6)
# ---------------------------------------------------------------------------


def test_joserfc_is_base_dependency_not_adapters_extra() -> None:
    """Finding #4a: ``joserfc == 1.6.4`` lives in base ``[project]``
    dependencies (agentos sign/verify must work in a bare pack-authoring
    venv; core/agent/query_context.py must work in the kernel image) —
    and is GONE from the adapters extra."""
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text())
    base_deps = pyproject["project"]["dependencies"]
    assert any(d.replace(" ", "") == "joserfc==1.6.4" for d in base_deps), (
        f"joserfc == 1.6.4 missing from base [project] dependencies: {base_deps!r}"
    )
    adapters = pyproject["project"]["optional-dependencies"]["adapters"]
    assert not any("joserfc" in d for d in adapters), (
        f"joserfc must not remain in the adapters extra: {adapters!r}"
    )


def test_agent_scaffold_documents_jws_custody_and_release_assets(
    tmp_path: Path,
) -> None:
    """Dispatch #6 — the agent-pack release-asset story (rendered by
    ``agentos init-agent``) names the custody split + the tracked
    ``agent-card.pub`` + the ``agent-card.jws`` release assets."""
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as fs_root:
        result = runner.invoke(app, ["init-agent", "example"])
        assert result.exit_code == 0, (
            f"init-agent failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        readme = (Path(fs_root) / "cognic-agent-example" / "README.md").read_text()
        workflow = (
            Path(fs_root)
            / "cognic-agent-example"
            / ".github"
            / "workflows"
            / "sign-and-publish.yml"
        ).read_text()
    for surface, text in (("README.md", readme), ("workflow", workflow)):
        assert "agent-card.pub" in text, f"{surface} missing the agent-card.pub asset"
    assert "agent-card.jws" in readme
    assert _JWS_KEY_ENV in readme
    assert "--agent-card-trust-root" in readme
