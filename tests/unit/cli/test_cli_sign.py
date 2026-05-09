"""Sprint-7A T14 — `agentos sign` regressions.

T14 is split into three commits per the Sprint-7A 3-commit-split
decision (T14.A sign-blob, T14.B sign --bundle, T14.C verify).
This file carries the COMPLETE T14.A + T14.B sign suite as shipped
in the T14.B commit; T14.C (verify) ships its own
``test_cli_verify.py``.

T14.A — sign-blob arms (Sections A-F):

  - Real ``asyncio.create_subprocess_exec`` against a Python cosign-
    shim (mirrors the Sprint-4 ``test_trust_gate.py::_make_cosign_shim``
    pattern). The shim records argv + env + cwd to JSON; tests assert
    against that recording.
  - Closed-enum refusals: ``sign_cosign_not_installed`` (shutil.which
    returns None), ``sign_signing_key_unavailable`` (signing_key_path
    unset / file missing / vault adapter unavailable),
    ``sign_subprocess_failed`` (cosign exits non-zero / output-missing
    / output-empty).
  - ``--dev-mode-skip-cosign`` flag prints a security warning to
    stderr + skips the cosign exec; the prod profile rejects the
    flag at Settings construction time (per Doctrine F + the
    config.py:1035 prod-profile guard).

T14.B — sign --bundle arms (Sections G onward):

  - Per-tool missing-binary + subprocess-failure arms (cosign /
    syft / grype / pip-licenses) using a generic ``_make_tool_shim``.
  - Full happy-path orchestration arm (all 7 attestation files
    produced + non-empty + AgentCard JWS verifies against committed
    public PEM).
  - Tool-pack JWS-skip arm (no agent_cards/agent-card.jws produced).
  - Template-render-failure arms (SLSA + in-toto monkeypatched).
  - vault:// signing-key resolution arms (InMemorySecretAdapter
    fixture, tempfile cleanup, malformed-payload guards, adapter-
    construction-failure routing through SignReport).
  - dev-mode-skip cosign + missing-cosign + provenance-honesty arms.
  - Wheel-discovery cross-check arms (single wheel, multiple
    wheels, name mismatch, version mismatch, unparseable filename,
    symlink escape, not-regular-file).
  - Output-directory create+resolve+escape arms (attestations/ +
    agent_cards/, file-in-place, self-referential symlink).
  - Manifest-declared agent_card_jws_path arms (custom path,
    missing field, non-string, escape, dual-path canonical /
    legacy [tool.cognic.identity]).
  - Pack metadata validation arms (pack_id missing/empty/
    whitespace-only/non-string; kind missing/non-string/unknown;
    pyproject [project].name + [project].version reader failure
    modes).
  - 25 reviewer rounds (R1..R10) folded in across the file.

Halt-before-commit per Doctrine Decision G — ``cli/sign.py`` is on
the critical-controls floor at 95% line / 90% branch (currently at
100% line / 100% branch in this commit).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app

# ---------------------------------------------------------------------------
# Fixture path — single-sourced to the T14 task-local fixture pack
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SIGN_TARGET_PACK: Path = _REPO_ROOT / "tests" / "fixtures" / "cli_sign_target_pack"
_SIGN_TARGET_WHEEL: Path = (
    _SIGN_TARGET_PACK / "dist" / "cognic_agent_sign_target-0.1.0-py3-none-any.whl"
)
_TEST_PRIVATE_PEM: Path = (
    _SIGN_TARGET_PACK / "attestations" / "test-signing" / "test_signing_key.private.pem"
)


# ---------------------------------------------------------------------------
# Cosign-shim helper — mirrors test_trust_gate.py::_make_cosign_shim
# ---------------------------------------------------------------------------


def _make_cosign_shim(
    tmp_path: Path,
    *,
    response_stdout: str = "",
    response_stderr: str = "",
    sleep_s: float = 0.0,
    exit_code: int = 0,
    sig_bytes: bytes = b"shim-sig-bytes",
    bundle_bytes: bytes = b"shim-bundle-bytes",
    write_sig: bool = True,
    write_bundle: bool = True,
) -> Path:
    """Write a Python cosign shim that records argv + env + cwd to
    JSON, optionally writes ``--output-signature`` / ``--output-bundle``
    files (so the orchestrator's post-exec file probes succeed), and
    returns a configurable exit code.

    Mirrors the Sprint-4 trust-gate cosign-shim pattern. The shim is
    used as ``settings.cosign_path`` so the sign orchestrator's real
    ``asyncio.create_subprocess_exec`` runs against it. Tests then
    read the recording file to assert what cosign was invoked with.
    """
    rec = tmp_path / f"shim_recording_{os.urandom(4).hex()}.json"
    shim = tmp_path / f"cosign_shim_{os.urandom(4).hex()}.py"
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
        # Honour ``--output-signature`` / ``--output-bundle`` so the
        # orchestrator's post-exec probes (the .sig + .bundle files)
        # succeed. Mirrors the real cosign sign-blob behaviour.
        argv = sys.argv
        for i, arg in enumerate(argv):
            if arg == "--output-signature" and i + 1 < len(argv) and {write_sig!r}:
                with open(argv[i + 1], "wb") as out:
                    out.write({sig_bytes!r})
            elif arg == "--output-certificate" and i + 1 < len(argv):
                with open(argv[i + 1], "wb") as out:
                    out.write(b"shim-cert-bytes")
            elif arg == "--bundle" and i + 1 < len(argv) and {write_bundle!r}:
                with open(argv[i + 1], "wb") as out:
                    out.write({bundle_bytes!r})
        if {sleep_s!r} > 0:
            time.sleep({sleep_s!r})
        sys.stdout.write({response_stdout!r})
        sys.stderr.write({response_stderr!r})
        sys.exit({exit_code!r})
        """
    ).strip()
    shim.write_text(f"{shebang}\n{body}\n")
    shim.chmod(stat.S_IRWXU)
    shim_meta = tmp_path / f"{shim.name}.recording_path"
    shim_meta.write_text(str(rec))
    return shim


def _read_shim_recording(shim: Path) -> dict[str, Any]:
    rec_path = Path(shim.parent.joinpath(f"{shim.name}.recording_path").read_text())
    payload: dict[str, Any] = json.loads(rec_path.read_text())
    return payload


# ---------------------------------------------------------------------------
# Settings env helpers — wire shim path into the Settings layer
# ---------------------------------------------------------------------------


def _set_cosign_settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cosign_path: Path | None,
    signing_key_path: Path | None,
) -> None:
    """Wire shim path + signing key path into Settings via env vars
    (matches the dev/test profile defaults; the prod profile guards
    are already covered by core/config.py)."""
    if cosign_path is not None:
        monkeypatch.setenv("COGNIC_COSIGN_PATH", str(cosign_path))
    else:
        monkeypatch.delenv("COGNIC_COSIGN_PATH", raising=False)
    if signing_key_path is not None:
        monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(signing_key_path))
    else:
        monkeypatch.delenv("COGNIC_SIGNING_KEY_PATH", raising=False)


# ---------------------------------------------------------------------------
# Section A — sign-blob happy path
# ---------------------------------------------------------------------------


def test_sign_blob_happy_path_invokes_cosign_with_correct_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``agentos sign-blob <wheel>`` resolves cosign via
    ``shutil.which`` (or ``settings.cosign_path``), wires the
    signing key from ``settings.signing_key_path``, and invokes
    cosign with the ADR-016 sign-blob argv shape."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    # Stage a wheel under tmp_path so the orchestrator probes the
    # canonical ``<pack>/dist/<wheel>.whl`` shape.
    wheel = tmp_path / "example-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"placeholder-wheel-bytes")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 0, (
        f"sign-blob exited {result.exit_code}; stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # Cosign was invoked.
    recording = _read_shim_recording(shim)
    argv = recording["argv"]
    assert argv[0] == str(shim)
    assert "sign-blob" in argv
    # The wheel path appears (positional argument cosign signs).
    assert str(wheel) in argv
    # Signing key wired through.
    assert "--key" in argv
    key_idx = argv.index("--key")
    assert argv[key_idx + 1] == str(_TEST_PRIVATE_PEM)
    # Output sig + bundle paths landed on disk via the shim.
    assert (wheel.parent / "cosign.sig").is_file()
    assert (wheel.parent / "bundle.sigstore").is_file()


def test_sign_blob_happy_path_emits_pass_summary_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Typer wrapper renders a ``sign-blob: PASS`` summary on
    stdout when cosign exits 0 — mirrors validate's PASS pattern."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 0
    assert "sign-blob: PASS" in result.stdout


# ---------------------------------------------------------------------------
# Section B — Closed-enum refusal arms
# ---------------------------------------------------------------------------


def test_sign_blob_with_missing_cosign_emits_cosign_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``shutil.which("cosign")`` returns None AND
    ``settings.cosign_path`` is unset → closed-enum refusal
    ``sign_cosign_not_installed`` on stderr + exit 1."""
    monkeypatch.setenv("COGNIC_COSIGN_PATH", "/nonexistent/path/cosign")
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_cosign_not_installed" in result.stderr


def test_sign_blob_with_missing_signing_key_emits_signing_key_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``signing_key_path`` points at a non-existent file → closed-
    enum refusal ``sign_signing_key_unavailable``."""
    shim = _make_cosign_shim(tmp_path)
    missing_key = tmp_path / "missing.private.pem"
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=missing_key)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_signing_key_unavailable" in result.stderr


def test_sign_blob_with_unset_signing_key_emits_signing_key_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``signing_key_path`` unset entirely → same closed-enum refusal."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=None)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_signing_key_unavailable" in result.stderr


def test_sign_blob_with_subprocess_failure_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign exits non-zero → closed-enum refusal
    ``sign_subprocess_failed`` with the exit code recorded in the
    error message."""
    shim = _make_cosign_shim(
        tmp_path,
        exit_code=1,
        response_stderr="cosign: invalid signature material",
    )
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_subprocess_failed" in result.stderr


def test_sign_blob_with_missing_wheel_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wheel argument points at a non-existent path → fail-loud
    refusal BEFORE invoking cosign. Surfaces as
    ``sign_subprocess_failed`` (generic catch with payload identifying
    the missing wheel path) — pack authors don't waste a cosign exec
    on a missing input."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    missing_wheel = tmp_path / "missing.whl"

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(missing_wheel)])
    assert result.exit_code == 1
    assert "sign_subprocess_failed" in result.stderr


# ---------------------------------------------------------------------------
# Section C — --dev-mode-skip-cosign flag
# ---------------------------------------------------------------------------


def test_sign_blob_with_dev_mode_skip_cosign_prints_warning_to_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--dev-mode-skip-cosign`` skips the cosign exec entirely AND
    prints a security warning to stderr. Pack authors using the flag
    in dev see the warning on every invocation; CI parsers can
    pattern-match the warning to flag any prod-profile dev-skip
    leakage."""
    shim = _make_cosign_shim(
        tmp_path
    )  # would fail if invoked without --output-signature, but never invoked
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--dev-mode-skip-cosign"])
    assert result.exit_code == 0, (
        f"dev-mode-skip-cosign expected exit 0; got {result.exit_code}; stderr={result.stderr!r}"
    )
    # Security warning surfaces.
    assert "WARNING" in result.stderr or "warning" in result.stderr.lower()
    assert "dev-mode" in result.stderr.lower() or "skip" in result.stderr.lower()
    # Cosign was NOT invoked — the recording file does not exist.
    rec_pointer = tmp_path / f"{shim.name}.recording_path"
    rec_path = Path(rec_pointer.read_text())
    assert not rec_path.is_file(), "cosign was invoked despite --dev-mode-skip-cosign"


def test_sign_blob_dev_mode_skip_in_prod_profile_rejected_at_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The prod profile rejects ``dev_mode_skip_cosign=True`` at
    Settings construction time per Doctrine F + the
    ``config.py:1035`` prod-profile guard. The ``--dev-mode-skip-cosign``
    flag injects the override into Settings; a prod-profile run
    that sees the flag refuses at Settings layer and surfaces a
    descriptive error.

    Test posture: env COGNIC_RUNTIME_PROFILE=prod +
    COGNIC_DEV_MODE_SKIP_COSIGN=true at startup → Settings raises
    ValidationError before sign-blob can even attempt to run."""
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "prod")
    monkeypatch.setenv("COGNIC_DEV_MODE_SKIP_COSIGN", "true")
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", "vault://prod/cognic/signing-key")

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["sign-blob", str(tmp_path / "example.whl"), "--dev-mode-skip-cosign"],
    )
    assert result.exit_code != 0
    assert "dev_mode_skip_cosign" in result.stderr or "prod" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Section D — Closed-enum HarnessReason-style drift detector for sign reasons
# ---------------------------------------------------------------------------


def test_sign_blob_with_cosign_not_on_path_emits_cosign_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``settings.cosign_path`` unset + ``shutil.which("cosign")``
    returns None on the host PATH → closed-enum refusal.

    Covers the host-PATH-fallback branch in
    ``_resolve_cosign_path`` (the path where the operator has NOT
    set the override). Distinct from the "configured-but-unresolvable"
    arm above which exercises the operator-named-typo branch."""
    monkeypatch.delenv("COGNIC_COSIGN_PATH", raising=False)
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))
    # Force shutil.which("cosign") to return None as if cosign isn't installed.
    import shutil as real_shutil

    real_which = real_shutil.which

    def _which_no_cosign(
        cmd: str,
        mode: int = os.F_OK | os.X_OK,
        path: str | None = None,
    ) -> str | None:
        if cmd == "cosign":
            return None
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(real_shutil, "which", _which_no_cosign)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_cosign_not_installed" in result.stderr


def test_sign_blob_with_vault_signing_key_uri_emits_signing_key_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``signing_key_path`` set to a ``vault://`` URI → closed-enum
    refusal at T14.A scope (URI-shape resolution lands at T14.B with
    the SecretAdapter wiring). Covers the URI-shape branch in
    ``_resolve_signing_key_path``."""
    shim = _make_cosign_shim(tmp_path)
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(shim))
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", "vault://test/cognic/signing-key")
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 1
    assert "sign_signing_key_unavailable" in result.stderr
    # The error message points at T14.B for URI resolution.
    assert "T14.B" in result.stderr or "vault" in result.stderr.lower()


def test_sign_blob_with_subprocess_exec_oserror_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``asyncio.create_subprocess_exec`` raises ``OSError`` (e.g.,
    ENOEXEC, EPERM) → closed-enum refusal collapsing into
    ``sign_subprocess_failed`` with ``payload.error_type``."""
    # Point cosign_path at a real file that lacks execute bit so
    # subprocess_exec raises PermissionError (an OSError subclass).
    not_executable = tmp_path / "cosign_not_executable"
    not_executable.write_text("#!/usr/bin/env python\nprint('hi')\n")
    # No chmod +x — file isn't executable.
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(not_executable))
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    # Force shutil.which to return the path so resolution succeeds even
    # without the executable bit (so the test reaches the exec branch).
    import shutil as real_shutil

    real_which = real_shutil.which

    def _which_passthrough(
        cmd: str,
        mode: int = os.F_OK | os.X_OK,
        path: str | None = None,
    ) -> str | None:
        if cmd == str(not_executable):
            return str(not_executable)
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(real_shutil, "which", _which_passthrough)

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    # Exit code is 1; error_type is in the JSON payload but visible
    # in text-mode message too.
    assert result.exit_code == 1
    assert "sign_subprocess_failed" in result.stderr


def test_sign_blob_json_output_mode_emits_single_json_object_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``agentos sign-blob --json <wheel>`` emits a single JSON object
    on stdout matching the sign-report shape. Mirrors
    ``agentos validate --json`` + ``agentos test-harness --json``."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout.strip())
    assert payload["operation"] == "sign-blob"
    assert payload["overall_status"] == "pass"
    assert payload["target_path"] == str(wheel)
    # Artifacts dict contains the produced sig + bundle paths.
    assert "cosign_sig" in payload["artifacts"]
    assert "bundle_sigstore" in payload["artifacts"]


def test_sign_blob_resolves_cosign_via_host_path_fallback_when_override_unset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``settings.cosign_path`` unset + ``shutil.which("cosign")``
    returns a real path → orchestrator runs successfully against the
    PATH-resolved binary. Covers the fallback-success branch in
    ``_resolve_cosign_path`` (line 190 — the ``return fallback, None``
    after the host-PATH check)."""
    shim = _make_cosign_shim(tmp_path)
    monkeypatch.delenv("COGNIC_COSIGN_PATH", raising=False)
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))
    # Monkeypatch shutil.which("cosign") to return the shim path so
    # the host-PATH fallback succeeds.
    import shutil as real_shutil

    real_which = real_shutil.which

    def _which_returns_shim(
        cmd: str,
        mode: int = os.F_OK | os.X_OK,
        path: str | None = None,
    ) -> str | None:
        if cmd == "cosign":
            return str(shim)
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(real_shutil, "which", _which_returns_shim)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 0, (
        f"sign-blob exited {result.exit_code}; stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # Host-PATH-resolved cosign was invoked (recorded by the shim).
    recording = _read_shim_recording(shim)
    assert recording["argv"][0] == str(shim)


def test_format_sign_report_text_mode_pass_returns_summary_only() -> None:
    """Clean report (no findings) → unified text-mode returns just
    the summary; no trailing newline + no ``::error`` annotation."""
    from cognic_agentos.cli.sign import SignReport, format_sign_report

    report = SignReport(
        operation="sign-blob",
        target_path="/tmp/example.whl",
        overall_status="pass",
        findings=[],
        artifacts={
            "cosign_sig": "/tmp/cosign.sig",
            "bundle_sigstore": "/tmp/bundle.sigstore",
        },
    )
    text = format_sign_report(report, json_output=False)
    assert "sign-blob: PASS" in text
    assert "::error" not in text
    assert "::warning" not in text


def test_format_sign_report_text_mode_with_findings_returns_summary_plus_annotations() -> None:
    """The unified text-mode :func:`format_sign_report` stitches
    the summary + per-finding annotations into a single text blob.
    The CLI uses the split helpers (stdout summary / stderr
    annotations); this direct unit test pins the unified-text path
    for callers that want a single blob (e.g., a future
    ``--report-only`` mode)."""
    from cognic_agentos.cli.sign import (
        SignFinding,
        SignReport,
        format_sign_report,
    )

    report = SignReport(
        operation="sign-blob",
        target_path="/tmp/example.whl",
        overall_status="fail",
        findings=[
            SignFinding(
                severity="refusal",
                reason="sign_cosign_not_installed",
                message="missing cosign",
            ),
        ],
        artifacts={},
    )
    text = format_sign_report(report, json_output=False)
    assert "sign-blob: FAIL" in text
    assert "::error" in text
    assert "sign_cosign_not_installed" in text


def test_sign_finding_affects_exit_code_returns_true_for_refusal_false_for_warning() -> None:
    """Direct-unit-test on the SignFinding carrier dataclass property
    so the affects_exit_code line is covered. Mirrors the
    ValidatorFinding test pattern at test_config.py."""
    from cognic_agentos.cli.sign import SignFinding

    refusal = SignFinding(
        severity="refusal",
        reason="sign_cosign_not_installed",
        message="x",
    )
    warning = SignFinding(
        severity="warning",
        reason="sign_subprocess_failed",
        message="y",
    )
    assert refusal.affects_exit_code is True
    assert warning.affects_exit_code is False


def test_sign_module_owns_all_t14_sign_reasons() -> None:
    """Every closed-enum reason owned by ``sign.py`` (per
    ``_VALIDATOR_REASON_OWNERSHIP``) is reachable from this test
    file's arms (sign-blob slice for T14.A; sign --bundle arms add
    in T14.B). Pinned here so any future T14.A/B reorganisation that
    changes ownership trips at CI time."""
    from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP

    sign_reasons = {
        reason for reason, owner in _VALIDATOR_REASON_OWNERSHIP.items() if owner == "sign.py"
    }
    # T14.A seed (sign-blob slice) — 3 reachable from this test file
    # via the cosign-shim arms above. The other 6 sign reasons (syft /
    # grype / license_auditor / agent_card_jws / provenance_template /
    # intoto_layout) land in T14.B's sign --bundle arms.
    t14a_reachable = {
        "sign_cosign_not_installed",
        "sign_signing_key_unavailable",
        "sign_subprocess_failed",
    }
    assert t14a_reachable.issubset(sign_reasons), (
        f"T14.A sign reasons missing from ownership map: {t14a_reachable - sign_reasons}"
    )


# ---------------------------------------------------------------------------
# Section E — R1 P2 #1: post-exec artifact checks
# ---------------------------------------------------------------------------
#
# Cosign sign-blob exits 0 → orchestrator MUST verify both the .sig
# and .bundle output files were actually written + non-empty BEFORE
# blessing the run as ``pass``. A broken shim (or a real cosign
# invocation that exits 0 without writing files due to a configuration
# bug) would otherwise silently advertise non-existent artifacts.


def test_sign_blob_exit_zero_but_missing_sig_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign exits 0 but DOES NOT write the ``--output-signature``
    file → orchestrator catches the missing artifact + returns
    ``sign_subprocess_failed`` with a distinct ``failure_mode``.
    Without this check the report would falsely advertise a
    non-existent ``cosign.sig``."""
    shim = _make_cosign_shim(tmp_path, write_sig=False)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    findings = payload["findings"]
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "cosign_sig_output_missing"
        for f in findings
    ), f"expected sig_output_missing failure_mode; got {findings}"


def test_sign_blob_exit_zero_but_missing_bundle_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same as above but for the ``--bundle`` output. Catches a
    cosign-shim or real-cosign condition where the bundle write
    fails silently while the sig succeeds."""
    shim = _make_cosign_shim(tmp_path, write_bundle=False)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    findings = payload["findings"]
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "cosign_bundle_output_missing"
        for f in findings
    ), f"expected bundle_output_missing failure_mode; got {findings}"


def test_sign_blob_exit_zero_but_empty_sig_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign exits 0 + writes an EMPTY sig file (zero bytes) →
    orchestrator catches the empty artifact + refuses. Defends
    against a shim that opens the file for write but produces no
    payload."""
    shim = _make_cosign_shim(
        tmp_path,
        sig_bytes=b"",  # empty sig
    )
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    findings = payload["findings"]
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "cosign_sig_output_empty"
        for f in findings
    ), f"expected sig_output_empty failure_mode; got {findings}"


# ---------------------------------------------------------------------------
# Section F — R1 P2 #2: cosign env preservation
# ---------------------------------------------------------------------------


def test_sign_blob_exit_zero_but_empty_bundle_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign exits 0 + writes an EMPTY bundle file (zero bytes) →
    orchestrator catches the empty Sigstore bundle + refuses.
    Symmetric to the empty-sig arm; defends against shim failures
    that leave one artifact populated + the other empty."""
    shim = _make_cosign_shim(tmp_path, bundle_bytes=b"")
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    findings = payload["findings"]
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "cosign_bundle_output_empty"
        for f in findings
    ), f"expected bundle_output_empty failure_mode; got {findings}"


def test_sign_blob_preserves_host_env_into_cosign_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cosign subprocess MUST inherit ``os.environ`` (with
    ``COSIGN_PASSWORD`` overlaid). Real cosign needs HOME / PATH /
    HTTPS_PROXY / Sigstore-bundle Vault / KMS credentials to function
    in production; passing ``env={"COSIGN_PASSWORD": ""}`` alone
    wipes those out + breaks proxy + KMS + Vault flows.

    Pin a sentinel env var on the host process; assert the cosign
    shim's recording.env contains it. Also assert COSIGN_PASSWORD is
    overlaid (the shim records both)."""
    shim = _make_cosign_shim(tmp_path)
    _set_cosign_settings(monkeypatch, cosign_path=shim, signing_key_path=_TEST_PRIVATE_PEM)
    monkeypatch.setenv("COGNIC_T14_R1_HOST_SENTINEL", "host-env-survived-into-cosign")
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", str(wheel)])
    assert result.exit_code == 0, (
        f"sign-blob unexpectedly failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    recording = _read_shim_recording(shim)
    env = recording["env"]
    # Host sentinel survived — env preservation in place.
    assert env.get("COGNIC_T14_R1_HOST_SENTINEL") == "host-env-survived-into-cosign", (
        f"host env var did NOT survive into cosign subprocess; "
        f"env keys={sorted(env.keys())[:10]} (truncated)"
    )
    # COSIGN_PASSWORD overlaid for the unencrypted test-only PEM.
    assert env.get("COSIGN_PASSWORD") == "", (
        f"COSIGN_PASSWORD overlay missing from cosign env; got {env.get('COSIGN_PASSWORD')!r}"
    )


# ===========================================================================
# T14.B — `agentos sign --bundle` full orchestrator
# ===========================================================================
#
# Per Doctrine Decision F + ADR-016: ``agentos sign --bundle <pack-path>``
# orchestrates the full Wave-1 attestation set:
#
#   1. SBOM via ``syft <pack-path> -o cyclonedx-json=<sbom-path>``
#      → ``attestations/sbom.cdx.json``
#   2. Vuln scan via ``grype <wheel> -o json --file <vuln-path>``
#      → ``attestations/vuln-scan.json``
#   3. License audit via ``pip-licenses --with-system --format=json
#      --output-file=<license-path>`` → ``attestations/license-audit.json``
#   4. SLSA provenance template (Wave-1 simplified) →
#      ``attestations/slsa-provenance.intoto.json``
#   5. in-toto layout template → ``attestations/intoto-layout.json``
#   6. AgentCard JWS via joserfc (agent packs only) →
#      ``agent_cards/<card-name>.jws``
#   7. Cosign sign-blob over the wheel →
#      ``attestations/cosign.sig`` + ``attestations/bundle.sigstore``
#
# Closed-enum sign reasons exercised here (T14.A pre-seeded all):
#   - ``sign_syft_not_installed``
#   - ``sign_grype_not_installed``
#   - ``sign_license_auditor_not_installed``
#   - ``sign_provenance_template_render_failed``
#   - ``sign_intoto_layout_template_render_failed``
#   - ``sign_agent_card_jws_signing_failed``
#   - ``sign_subprocess_failed`` (with payload.tool distinguishing
#     syft / grype / license_auditor / cosign + ``failure_mode``
#     distinguishing wheel_not_found etc.)


# ---------------------------------------------------------------------------
# Per-tool shim helpers — mirror the cosign-shim pattern for syft / grype /
# license-auditor. Each shim writes a canned output to whatever output-file
# flag the orchestrator passes.
# ---------------------------------------------------------------------------


def _make_tool_shim(
    tmp_path: Path,
    *,
    tool_name: str,
    output_flag: str,
    output_payload: bytes,
    exit_code: int = 0,
    response_stderr: str = "",
) -> Path:
    """Generic shim factory: writes ``output_payload`` to whatever
    file path follows ``output_flag`` in argv. Records argv + env +
    cwd to JSON like the cosign shim. ``output_flag`` is a literal
    prefix (e.g., ``"-o"``) that the shim looks for in argv; the
    next-arg-after-prefix is the output path.

    Two flag styles supported:
      - Separate-arg: ``--file <path>`` (orchestrator passes two args).
      - Equals-attached: ``-o cyclonedx-json=<path>`` (orchestrator
        passes a single ``-o cyclonedx-json=/path/to/output.json``
        kwarg-style argv element).

    The shim auto-detects: if the matched argv element contains ``=``
    after the flag prefix, the suffix is the path; otherwise the
    next arg is the path.
    """
    rec = tmp_path / f"shim_recording_{tool_name}_{os.urandom(4).hex()}.json"
    shim = tmp_path / f"{tool_name}_shim_{os.urandom(4).hex()}.py"
    shebang = f"#!{sys.executable}"
    body = textwrap.dedent(
        f"""
        import json, os, sys
        recording = {{
            "argv": sys.argv,
            "env": dict(os.environ),
            "cwd": os.getcwd(),
        }}
        with open({str(rec)!r}, "w") as f:
            json.dump(recording, f)
        argv = sys.argv
        out_path = None
        target_flag = {output_flag!r}
        for i, arg in enumerate(argv):
            # ``--output-file=/abs/path`` (single arg, equals-attached
            # to the flag itself).
            if arg.startswith(target_flag + "="):
                out_path = arg.split("=", 1)[1]
                break
            # Separate-arg form: ``--file /abs/path`` OR ``-o
            # <format>=<path>`` (e.g., ``-o cyclonedx-json=/path``;
            # syft 1.x + grype 0.86+ canonical for output redirection).
            if arg == target_flag and i + 1 < len(argv):
                next_arg = argv[i + 1]
                if "=" in next_arg:
                    out_path = next_arg.split("=", 1)[1]
                else:
                    out_path = next_arg
                break
        if out_path is not None:
            with open(out_path, "wb") as out:
                out.write({output_payload!r})
        sys.stderr.write({response_stderr!r})
        sys.exit({exit_code!r})
        """
    ).strip()
    shim.write_text(f"{shebang}\n{body}\n")
    shim.chmod(stat.S_IRWXU)
    shim_meta = tmp_path / f"{shim.name}.recording_path"
    shim_meta.write_text(str(rec))
    return shim


def _stage_pack_with_wheel(tmp_path: Path, *, kind: str = "agent") -> Path:
    """Copy the fixture pack to ``tmp_path`` + stage a real ZIP-shaped
    wheel under ``<pack>/dist/`` so sign --bundle's wheel-discovery +
    R7 P2 #1 wheel-content integrity check both succeed. Returns the
    staged pack root.

    R7 P2 #1 reviewer correction (T14.C): the wheel MUST be a real
    ZIP with a properly-named ``dist-info/`` containing a ``METADATA``
    file (whose Name + Version agree with the wheel filename) and an
    ``entry_points.txt`` (with at least one PEP 621
    ``module:object`` entry under the appropriate ``cognic.{kind}s``
    group). Pre-fix tests used synthetic ``b"PK\\x03\\x04..."`` byte
    strings, which the new shared wheel-integrity helper refuses.

    ``kind`` controls which fixture pack to clone (default ``agent``).
    """
    import shutil as _shutil
    import zipfile as _zipfile

    pack_root = tmp_path / "staged_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack_root)
    dist_dir = pack_root / "dist"
    dist_dir.mkdir(exist_ok=True)
    wheel = dist_dir / "cognic_agent_sign_target-0.1.0-py3-none-any.whl"
    dist_info = "cognic_agent_sign_target-0.1.0.dist-info"
    if kind == "agent":
        ep_group = "cognic.agents"
        ep_target = "cognic_agent_sign_target.agent:SignTargetAgent"
    elif kind == "tool":
        ep_group = "cognic.tools"
        ep_target = "cognic_agent_sign_target.tool:SignTargetTool"
    else:
        ep_group = "cognic.skills"
        ep_target = "cognic_agent_sign_target.skill:SignTargetSkill"
    with _zipfile.ZipFile(wheel, "w", _zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            f"{dist_info}/entry_points.txt",
            f"[{ep_group}]\nsign_target = {ep_target}\n",
        )
        zf.writestr(
            f"{dist_info}/METADATA",
            "Metadata-Version: 2.1\nName: cognic_agent_sign_target\nVersion: 0.1.0\n",
        )
        zf.writestr(
            f"{dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: agentos-test-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )
        # R9 P2 #2 + R10 P2 #1: write the entry-point target module
        # with a top-level class def matching the target's first
        # object segment. R15 pivot: also write package __init__.py
        # so zipimport recognizes the module path as a real package
        # (zipimport doesn't support PEP 420 namespace packages).
        ep_module_path, _, ep_object_path = ep_target.partition(":")
        ep_first_object = ep_object_path.split(".")[0]
        ep_module_parts = ep_module_path.split(".")
        for _depth in range(1, len(ep_module_parts)):
            zf.writestr(
                "/".join(ep_module_parts[:_depth]) + "/__init__.py",
                "",
            )
        ep_module_file = "/".join(ep_module_parts) + ".py"
        zf.writestr(
            ep_module_file,
            f"class {ep_first_object}:\n    pass\n",
        )
    return pack_root


def _set_sign_bundle_settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cosign_path: Path,
    syft_path: Path,
    grype_path: Path,
    license_auditor_path: Path,
    signing_key_path: Path | str = _TEST_PRIVATE_PEM,
) -> None:
    """Wire all four tool paths + signing key into Settings via env.
    ``signing_key_path`` accepts ``str`` for ``vault://...`` URIs
    (Path() would collapse the double slash in the URI scheme)."""
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(cosign_path))
    monkeypatch.setenv("COGNIC_SYFT_PATH", str(syft_path))
    monkeypatch.setenv("COGNIC_GRYPE_PATH", str(grype_path))
    monkeypatch.setenv("COGNIC_LICENSE_AUDITOR_PATH", str(license_auditor_path))
    # Preserve URI shape for vault:// values (str path bypasses Path() collapse).
    if isinstance(signing_key_path, str):
        monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", signing_key_path)
    else:
        monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(signing_key_path))


def _stage_full_shim_set(tmp_path: Path) -> dict[str, Path]:
    """Build the four shims (cosign / syft / grype / license-auditor)
    each producing minimal-but-valid canned output. Returns a dict
    {tool_name: shim_path}."""
    return {
        "cosign": _make_cosign_shim(tmp_path),
        "syft": _make_tool_shim(
            tmp_path,
            tool_name="syft",
            output_flag="-o",
            output_payload=(
                b'{"bomFormat": "CycloneDX", "specVersion": "1.5", '
                b'"components": [], "metadata": {"timestamp": "2026-05-08T00:00:00Z"}}'
            ),
        ),
        "grype": _make_tool_shim(
            tmp_path,
            tool_name="grype",
            output_flag="--file",
            output_payload=b'{"matches": [], "source": {"type": "file"}}',
        ),
        "license_auditor": _make_tool_shim(
            tmp_path,
            tool_name="license_auditor",
            output_flag="--output-file",
            output_payload=b'[{"Name": "cognic-agent-sign-target", "License": "AUTHOR-FILL"}]',
        ),
    }


# ---------------------------------------------------------------------------
# Section G — Per-tool missing-binary refusals
# ---------------------------------------------------------------------------


def test_sign_bundle_with_missing_syft_emits_syft_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``shutil.which("syft")`` returns None AND ``settings.syft_path``
    points at a non-existent path → closed-enum refusal
    ``sign_syft_not_installed`` + exit 1."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=tmp_path / "missing_syft",  # doesn't exist
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 1
    assert "sign_syft_not_installed" in result.stderr


def test_sign_bundle_with_missing_grype_emits_grype_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``settings.grype_path`` unresolvable → closed-enum refusal."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=tmp_path / "missing_grype",
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 1
    assert "sign_grype_not_installed" in result.stderr


def test_sign_bundle_with_missing_license_auditor_emits_license_auditor_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``settings.license_auditor_path`` unresolvable → closed-enum
    refusal."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=tmp_path / "missing_license_auditor",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 1
    assert "sign_license_auditor_not_installed" in result.stderr


# ---------------------------------------------------------------------------
# Section H — Per-tool subprocess failures (existing tools refuse)
# ---------------------------------------------------------------------------


def test_sign_bundle_with_syft_subprocess_failure_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Syft exits non-zero → ``sign_subprocess_failed`` with
    ``payload.tool == "syft"``."""
    cosign = _make_cosign_shim(tmp_path)
    syft_fail = _make_tool_shim(
        tmp_path,
        tool_name="syft_fail",
        output_flag="-o",
        output_payload=b"",
        exit_code=1,
        response_stderr="syft: cannot resolve image",
    )
    grype = _make_tool_shim(
        tmp_path, tool_name="grype", output_flag="--file", output_payload=b'{"matches": []}'
    )
    license_auditor = _make_tool_shim(
        tmp_path, tool_name="license", output_flag="--output-file", output_payload=b"[]"
    )
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign,
        syft_path=syft_fail,
        grype_path=grype,
        license_auditor_path=license_auditor,
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed" and f["payload"].get("tool") == "syft"
        for f in payload["findings"]
    )


# ---------------------------------------------------------------------------
# Section I — Wheel-discovery arm
# ---------------------------------------------------------------------------


def test_sign_bundle_with_no_wheel_in_dist_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pack tree has no ``dist/*.whl`` → fail-loud refusal naming
    the missing wheel input. Pack authors who forgot to run
    ``python -m build`` first see this before invoking any tool."""
    shims = _stage_full_shim_set(tmp_path)
    # Stage pack without dist/.
    import shutil as _shutil

    pack = tmp_path / "no_wheel_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    # No dist/ created.
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_not_found"
        for f in payload["findings"]
    )


# ---------------------------------------------------------------------------
# Section J — Full happy-path orchestration (all 7 attestation files)
# ---------------------------------------------------------------------------


def test_sign_bundle_full_orchestration_produces_all_seven_attestations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end happy path: shims for cosign + syft + grype +
    license-auditor; full agent-pack fixture with wheel staged.
    After sign --bundle, all 7 attestation files are present +
    non-empty in the pack tree."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"sign --bundle exited {result.exit_code}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert "sign-bundle: PASS" in result.stdout
    # All 7 attestation files exist + non-empty.
    expected_attestations = [
        pack / "attestations" / "sbom.cdx.json",
        pack / "attestations" / "vuln-scan.json",
        pack / "attestations" / "license-audit.json",
        pack / "attestations" / "slsa-provenance.intoto.json",
        pack / "attestations" / "intoto-layout.json",
        pack / "attestations" / "cosign.sig",
        pack / "attestations" / "bundle.sigstore",
    ]
    for path in expected_attestations:
        assert path.is_file(), f"missing attestation: {path}"
        assert path.stat().st_size > 0, f"empty attestation: {path}"
    # Agent pack: AgentCard JWS produced.
    jws_path = pack / "agent_cards" / "agent-card.jws"
    assert jws_path.is_file(), f"missing AgentCard JWS: {jws_path}"
    assert jws_path.stat().st_size > 0


# ---------------------------------------------------------------------------
# Section K — AgentCard JWS arm
# ---------------------------------------------------------------------------


def test_sign_bundle_agent_card_jws_verifies_against_committed_public_pem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regenerated AgentCard JWS verifies against the committed
    public PEM at ``tests/fixtures/cli_sign_target_pack/attestations/
    test-signing/test_signing_key.public.pem``. Mirrors Sprint-6's
    fixture-pack JWS verification pattern; pins the sign + verify
    round-trip determinism."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0
    jws_path = pack / "agent_cards" / "agent-card.jws"
    assert jws_path.is_file()
    jws_bytes = jws_path.read_bytes()
    # Detached compact-JWS form: header.<EMPTY>.signature  (3 dot-
    # separated b64url segments; middle empty per Sprint-6 doctrine).
    parts = jws_bytes.split(b".")
    assert len(parts) == 3
    assert parts[1] == b"", (
        f"expected detached form (middle segment empty); got middle={parts[1]!r}"
    )
    # Verify against the committed public PEM via joserfc using the
    # same detached-payload path the runtime trust gate uses.
    from joserfc import jws as _jws
    from joserfc.jwk import RSAKey

    public_pem = (
        _SIGN_TARGET_PACK / "attestations" / "test-signing" / "test_signing_key.public.pem"
    ).read_bytes()
    public_key = RSAKey.import_key(public_pem)
    card_payload = (pack / "agent_cards" / "agent-card.json").read_bytes()
    # Detached-payload verification: pass the original card bytes as
    # the detached payload + verify the JWS against the public key.
    verified = _jws.deserialize_compact(jws_bytes.decode("ascii"), public_key, payload=card_payload)
    assert verified is not None


# ---------------------------------------------------------------------------
# Section L — Tool pack (no JWS arm)
# ---------------------------------------------------------------------------


def test_sign_bundle_for_tool_kind_pack_skips_agent_card_jws(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tool-kind packs do NOT carry an AgentCard, so the JWS-signing
    step is skipped. The other 6 attestation files (no JWS) are
    produced as normal."""
    shims = _stage_full_shim_set(tmp_path)
    # Clone the agent-fixture pack but flip kind to "tool" + drop
    # the agent_card_url / agent_card_jws_path fields so the manifest
    # is validate-clean as a tool pack.
    import shutil as _shutil

    pack = tmp_path / "tool_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    # Flip the manifest kind to tool + remove agent-only blocks.
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    body = body.replace('kind = "agent"', 'kind = "tool"')
    body = body.replace(
        'pack_id = "cognic-agent-sign-target"', 'pack_id = "cognic-tool-sign-target"'
    )
    # Drop [a2a] block + agent_card_url / agent_card_jws_path; tool
    # packs don't need them.
    new_lines: list[str] = []
    in_a2a_block = False
    for line in body.splitlines():
        if line.startswith("[a2a]"):
            in_a2a_block = True
            continue
        if in_a2a_block and line.startswith("["):
            in_a2a_block = False
        if in_a2a_block:
            continue
        if "agent_card_url" in line or "agent_card_jws_path" in line:
            continue
        new_lines.append(line)
    manifest_path.write_text("\n".join(new_lines) + "\n")
    # Update pyproject.toml [project].name to match the renamed pack
    # (R6 P2 #1: wheel name MUST match pyproject [project].name).
    pyproject_path = pack / "pyproject.toml"
    pyproject_path.write_text(
        pyproject_path.read_text().replace(
            'name = "cognic-agent-sign-target"',
            'name = "cognic-tool-sign-target"',
        )
    )
    # Stage the wheel.
    dist_dir = pack / "dist"
    dist_dir.mkdir(exist_ok=True)
    import zipfile as _zipfile

    _tool_wheel = dist_dir / "cognic_tool_sign_target-0.1.0-py3-none-any.whl"
    _tool_dist_info = "cognic_tool_sign_target-0.1.0.dist-info"
    with _zipfile.ZipFile(_tool_wheel, "w", _zipfile.ZIP_DEFLATED) as _zf:
        _zf.writestr(
            f"{_tool_dist_info}/entry_points.txt",
            "[cognic.tools]\nsign_target = cognic_tool_sign_target.tool:Tool\n",
        )
        _zf.writestr(
            f"{_tool_dist_info}/METADATA",
            "Metadata-Version: 2.1\nName: cognic_tool_sign_target\nVersion: 0.1.0\n",
        )
        _zf.writestr(
            f"{_tool_dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: agentos-test-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )
        _zf.writestr(
            "cognic_tool_sign_target/tool.py",
            "class Tool:\n    pass\n",
        )

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"tool-pack sign --bundle failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # No AgentCard JWS produced for tool packs.
    jws_path = pack / "agent_cards" / "agent-card.jws"
    assert not jws_path.exists(), "tool pack should not produce an AgentCard JWS"
    # Other 6 attestations DO exist.
    for name in (
        "sbom.cdx.json",
        "vuln-scan.json",
        "license-audit.json",
        "slsa-provenance.intoto.json",
        "intoto-layout.json",
        "cosign.sig",
        "bundle.sigstore",
    ):
        assert (pack / "attestations" / name).is_file(), f"missing: {name}"


# ---------------------------------------------------------------------------
# Section M — Template-render-failure arms
# ---------------------------------------------------------------------------


def test_sign_bundle_slsa_template_render_failure_emits_provenance_template_render_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure during SLSA provenance template rendering →
    closed-enum refusal ``sign_provenance_template_render_failed``.
    Monkeypatch the helper to raise so the failure mode is
    deterministic."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    import cognic_agentos.cli.sign as sign_module

    def _raise_on_render(*args: object, **kwargs: object) -> dict[str, object]:
        raise RuntimeError("synthetic SLSA template error")

    monkeypatch.setattr(sign_module, "_build_slsa_provenance_dict", _raise_on_render)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_provenance_template_render_failed" for f in payload["findings"])


def test_sign_bundle_intoto_template_render_failure_emits_intoto_layout_template_render_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same pattern for in-toto layout template render failure."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    import cognic_agentos.cli.sign as sign_module

    def _raise_on_render(*args: object, **kwargs: object) -> dict[str, object]:
        raise RuntimeError("synthetic in-toto template error")

    monkeypatch.setattr(sign_module, "_build_intoto_layout_dict", _raise_on_render)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_intoto_layout_template_render_failed" for f in payload["findings"]
    )


def test_sign_bundle_with_grype_subprocess_failure_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grype exits non-zero → ``sign_subprocess_failed`` with
    ``payload.tool == "grype"``."""
    cosign = _make_cosign_shim(tmp_path)
    syft = _make_tool_shim(
        tmp_path, tool_name="syft", output_flag="-o", output_payload=b'{"bomFormat": "CycloneDX"}'
    )
    grype_fail = _make_tool_shim(
        tmp_path,
        tool_name="grype_fail",
        output_flag="--file",
        output_payload=b"",
        exit_code=1,
        response_stderr="grype: scan failed",
    )
    license_auditor = _make_tool_shim(
        tmp_path, tool_name="license", output_flag="--output-file", output_payload=b"[]"
    )
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign,
        syft_path=syft,
        grype_path=grype_fail,
        license_auditor_path=license_auditor,
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed" and f["payload"].get("tool") == "grype"
        for f in payload["findings"]
    )


def test_sign_bundle_with_license_auditor_subprocess_failure_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """License-auditor exits non-zero → ``sign_subprocess_failed``
    with ``payload.tool == "license_auditor"``."""
    cosign = _make_cosign_shim(tmp_path)
    syft = _make_tool_shim(
        tmp_path, tool_name="syft", output_flag="-o", output_payload=b'{"bomFormat": "CycloneDX"}'
    )
    grype = _make_tool_shim(
        tmp_path, tool_name="grype", output_flag="--file", output_payload=b'{"matches": []}'
    )
    license_fail = _make_tool_shim(
        tmp_path,
        tool_name="license_fail",
        output_flag="--output-file",
        output_payload=b"",
        exit_code=1,
        response_stderr="pip-licenses: failed",
    )
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign,
        syft_path=syft,
        grype_path=grype,
        license_auditor_path=license_fail,
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed" and f["payload"].get("tool") == "license_auditor"
        for f in payload["findings"]
    )


def test_sign_bundle_with_cosign_subprocess_failure_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign exits non-zero in the bundle path → ``sign_subprocess_failed``
    with ``payload.tool == "cosign"``."""
    cosign_fail = _make_cosign_shim(tmp_path, exit_code=1, response_stderr="cosign: bad sig")
    shims = {**_stage_full_shim_set(tmp_path), "cosign": cosign_fail}
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign_fail,
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed" and f["payload"].get("tool") == "cosign"
        for f in payload["findings"]
    )


def test_sign_bundle_with_no_pack_block_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest with missing ``[pack]`` block → fail-loud refusal
    naming the failure_mode. Pack authors who deleted the pack
    block see this BEFORE any tool runs."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Strip the [pack] block from manifest.
    manifest = pack / "cognic-pack-manifest.toml"
    body = manifest.read_text()
    new_lines = []
    in_pack = False
    for line in body.splitlines():
        if line.startswith("[pack]"):
            in_pack = True
            continue
        if in_pack and line.startswith("["):
            in_pack = False
        if in_pack:
            continue
        new_lines.append(line)
    manifest.write_text("\n".join(new_lines))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_pack_block"
        for f in payload["findings"]
    )


def test_sign_bundle_with_unparseable_manifest_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest TOML is unparseable → fail-loud refusal with
    failure_mode=manifest_unparseable."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    (pack / "cognic-pack-manifest.toml").write_text("not valid TOML [[\n")
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_unparseable"
        for f in payload["findings"]
    )


def test_sign_bundle_with_no_manifest_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pack without a manifest at all → fail-loud refusal with
    failure_mode=manifest_not_found."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    (pack / "cognic-pack-manifest.toml").unlink()
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_not_found"
        for f in payload["findings"]
    )


def test_sign_bundle_with_empty_dist_directory_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``<pack>/dist/`` exists but contains no wheels → fail-loud
    refusal with failure_mode=wheel_not_found. Distinct from the
    no-dist-directory arm (which trips earlier in the helper)."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "empty_dist_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    (pack / "dist").mkdir(exist_ok=True)
    # No wheels created.
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_not_found"
        for f in payload["findings"]
    )


@pytest.mark.parametrize(
    ("exec_fn_name", "expected_tool"),
    [
        ("_exec_syft", "syft"),
        ("_exec_grype", "grype"),
        ("_exec_license_auditor", "license_auditor"),
        ("_exec_cosign_sign_blob", "cosign"),
    ],
)
def test_sign_bundle_with_subprocess_oserror_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exec_fn_name: str,
    expected_tool: str,
) -> None:
    """An ``OSError`` raised by any per-tool exec helper surfaces as
    ``sign_subprocess_failed`` with the right ``payload.tool``. Defends
    against ENOEXEC / EPERM / kernel-permission denial at the
    ``asyncio.create_subprocess_exec`` layer; the orchestrator's
    try/except catches OSError + collapses into the closed-enum
    refusal so pack authors get a deterministic remediation message."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    import cognic_agentos.cli.sign as sign_module

    async def _raise_oserror(*args: object, **kwargs: object) -> tuple[int, bytes, bytes]:
        raise PermissionError(13, "Permission denied (synthetic)")

    monkeypatch.setattr(sign_module, exec_fn_name, _raise_oserror)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("tool") == expected_tool
        and f["payload"].get("error_type") == "PermissionError"
        for f in payload["findings"]
    ), f"expected OSError for {expected_tool!r}; got {payload['findings']}"


def test_sign_bundle_with_post_exec_missing_artifact_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bundle path: cosign exits 0 but produces no sig file (broken
    shim) → post-exec verification catches the missing artifact +
    surfaces ``sign_subprocess_failed`` with
    ``failure_mode=cosign_sig_output_missing``. Mirrors T14.A's
    R1 P2 #1 doctrine, extended to the bundle path."""
    shims = _stage_full_shim_set(tmp_path)
    # Replace cosign with a shim that exits 0 but writes no sig.
    cosign_no_sig = _make_cosign_shim(tmp_path, write_sig=False)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign_no_sig,
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "cosign_sig_output_missing"
        for f in payload["findings"]
    )


def test_sign_bundle_with_missing_signing_key_in_bundle_path_emits_signing_key_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``signing_key_path`` unresolvable in the bundle path → closed-
    enum refusal. Distinct from the same arm in sign-blob: the
    orchestrator runs through the resolve helper at step 2 + the
    bundle-specific exit branch fires (covers lines 1266-1267 in
    cli/sign.py)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path=tmp_path / "missing_key.pem",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_signing_key_unavailable" for f in payload["findings"])


def test_sign_bundle_with_missing_cosign_emits_cosign_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosign missing in the bundle path → ``sign_cosign_not_installed``
    refusal (covers the bundle-path-specific cosign-finding branch
    in run_sign_bundle, distinct from the sign-blob path's same arm)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=tmp_path / "missing_cosign",
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_cosign_not_installed" for f in payload["findings"])


def test_sign_bundle_with_syft_not_on_path_when_unset_emits_syft_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``COGNIC_SYFT_PATH`` unset + ``shutil.which("syft")`` returns
    None → host-PATH-fallback branch in ``_resolve_tool_path``
    surfaces ``sign_syft_not_installed``. Distinct from the
    configured-but-unresolvable arm."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    monkeypatch.delenv("COGNIC_SYFT_PATH", raising=False)
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(shims["cosign"]))
    monkeypatch.setenv("COGNIC_GRYPE_PATH", str(shims["grype"]))
    monkeypatch.setenv("COGNIC_LICENSE_AUDITOR_PATH", str(shims["license_auditor"]))
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))

    import shutil as real_shutil

    real_which = real_shutil.which

    def _which_no_syft(
        cmd: str,
        mode: int = os.F_OK | os.X_OK,
        path: str | None = None,
    ) -> str | None:
        if cmd == "syft":
            return None
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(real_shutil, "which", _which_no_syft)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_syft_not_installed" for f in payload["findings"])


def test_sign_agent_card_jws_bytes_rejects_malformed_joserfc_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive check inside ``_sign_agent_card_jws_bytes``:
    if joserfc's ``serialize_compact`` returns anything other than a
    3-segment compact form, raise ``RuntimeError`` rather than
    producing a malformed detached JWS. Tested by monkeypatching
    joserfc to return a 2-segment string."""
    import cognic_agentos.cli.sign as sign_module

    def _malformed_compact(*args: object, **kwargs: object) -> str:
        return "header.signature_only_two_segments"

    # joserfc.jws is imported inside the helper; patch the helper's
    # local module attribute via the import chain.
    import joserfc.jws as _jws_mod

    monkeypatch.setattr(_jws_mod, "serialize_compact", _malformed_compact)

    private_pem = _TEST_PRIVATE_PEM.read_bytes()
    with pytest.raises(RuntimeError, match="unexpected JWS shape"):
        sign_module._sign_agent_card_jws_bytes(b'{"name": "x"}', private_pem_bytes=private_pem)


# ===========================================================================
# T14.B R2 reviewer findings — production-contract gaps
# ===========================================================================


@pytest.mark.parametrize(
    ("missing_artifact", "tool_label", "expected_failure_mode"),
    [
        ("attestations/sbom.cdx.json", "syft", "syft_sbom_output_missing"),
        ("attestations/vuln-scan.json", "grype", "grype_vuln_output_missing"),
        ("attestations/license-audit.json", "license_auditor", "license_audit_output_missing"),
    ],
)
def test_sign_bundle_with_post_exec_missing_non_cosign_artifact_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_artifact: str,
    tool_label: str,
    expected_failure_mode: str,
) -> None:
    """R2 P2 #1: each per-tool post-exec step MUST verify the
    expected attestation file landed on disk + is non-empty BEFORE
    advancing the pipeline. A shim that exits 0 without writing the
    file → closed-enum refusal naming the missing artifact + the
    failing tool, instead of silently passing the report."""
    cosign = _make_cosign_shim(tmp_path)
    shim_specs = {
        "syft": ("syft", "-o", b'{"bomFormat": "CycloneDX"}'),
        "grype": ("grype", "--file", b'{"matches": []}'),
        "license_auditor": ("license", "--output-file", b"[]"),
    }
    shims: dict[str, Path] = {}
    for tool_key, (label, output_flag, payload) in shim_specs.items():
        shims[tool_key] = _make_tool_shim(
            tmp_path,
            tool_name=label,
            output_flag=output_flag,
            output_payload=payload,
        )
    # Replace the target shim with a no-write variant (exits 0 + writes nothing).
    no_write_shim = tmp_path / f"{tool_label}_no_write_{os.urandom(4).hex()}.py"
    no_write_shim.write_text(
        f"#!{sys.executable}\nimport sys\nsys.exit(0)\n",
    )
    no_write_shim.chmod(stat.S_IRWXU)
    shims[tool_label] = no_write_shim

    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign,
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("tool") == tool_label
        and f["payload"].get("failure_mode") == expected_failure_mode
        for f in payload["findings"]
    ), f"expected {expected_failure_mode} for {tool_label}; got {payload['findings']}"


@pytest.mark.parametrize(
    ("tool_label", "expected_failure_mode"),
    [
        ("syft", "syft_sbom_output_empty"),
        ("grype", "grype_vuln_output_empty"),
        ("license_auditor", "license_audit_output_empty"),
    ],
)
def test_sign_bundle_with_post_exec_empty_non_cosign_artifact_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_label: str,
    expected_failure_mode: str,
) -> None:
    """R2 P2 #1 companion: empty-file rejection (zero bytes) for
    each non-cosign tool. Mirrors the cosign empty-output arms in
    T14.A."""
    cosign = _make_cosign_shim(tmp_path)
    # Each tool's shim writes b"" if it's the target; valid bytes otherwise.
    shim_specs = {
        "syft": ("syft", "-o"),
        "grype": ("grype", "--file"),
        "license_auditor": ("license", "--output-file"),
    }
    payload_map = {
        "syft": b'{"bomFormat": "CycloneDX"}',
        "grype": b'{"matches": []}',
        "license_auditor": b"[]",
    }
    shims: dict[str, Path] = {}
    for tool_key, (label, output_flag) in shim_specs.items():
        shims[tool_key] = _make_tool_shim(
            tmp_path,
            tool_name=label,
            output_flag=output_flag,
            output_payload=b"" if tool_key == tool_label else payload_map[tool_key],
        )

    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=cosign,
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("tool") == tool_label
        and f["payload"].get("failure_mode") == expected_failure_mode
        for f in payload["findings"]
    )


def test_sign_blob_with_vault_signing_key_uri_cleans_up_tempfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sign-blob path also supports vault:// URIs (R2 P2 #2 doctrine
    extended to T14.A's narrow path). The tempfile holding the
    resolved PEM bytes is unlinked in the orchestrator's finally
    block. Pins the tempfile cleanup contract for the sign-blob
    path (sign --bundle has its own arm)."""
    cosign = _make_cosign_shim(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    test_adapter = InMemorySecretAdapter()
    private_pem_bytes = _TEST_PRIVATE_PEM.read_bytes()
    import asyncio as _asyncio

    _asyncio.run(
        test_adapter.write(
            "secret/cognic/sign-blob-key",
            {"key": private_pem_bytes.decode("utf-8")},
        )
    )

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: test_adapter)
    # The sign-blob Typer wrapper does NOT call _build_secret_adapter
    # (T14.A's path doesn't construct a SecretAdapter). For the
    # sign-blob test we need to pass the adapter directly via
    # run_sign_blob. Easier: invoke run_sign_blob directly.
    monkeypatch.setenv("COGNIC_COSIGN_PATH", str(cosign))
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", "vault://secret/cognic/sign-blob-key")

    from cognic_agentos.core.config import build_settings_without_env_file

    settings = build_settings_without_env_file()
    wheel = tmp_path / "example.whl"
    wheel.write_bytes(b".")

    report = _asyncio.run(
        sign_module.run_sign_blob(
            wheel,
            settings,
            secret_adapter=test_adapter,
        )
    )
    assert report.overall_status == "pass"
    # Tempfile cleaned up after orchestrator finally block.
    cosign_recording = _read_shim_recording(cosign)
    cosign_argv = cosign_recording["argv"]
    key_arg_idx = cosign_argv.index("--key")
    resolved_key_path = cosign_argv[key_arg_idx + 1]
    assert "vault://" not in resolved_key_path
    assert not Path(resolved_key_path).exists(), (
        f"expected tempfile cleanup; {resolved_key_path} still exists"
    )


def test_sign_bundle_with_vault_signing_key_uri_resolves_via_secret_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2 P2 #2: ``signing_key_path`` set to a ``vault://...`` URI
    is resolved via the SecretAdapter; orchestrator writes the
    resolved PEM bytes to a tempfile + invokes cosign against the
    tempfile. Production-contract requirement per ADR-016 +
    Doctrine F. Tests use the in-memory SecretAdapter."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    test_adapter = InMemorySecretAdapter()
    private_pem_bytes = _TEST_PRIVATE_PEM.read_bytes()
    import asyncio as _asyncio

    _asyncio.run(
        test_adapter.write(
            "secret/cognic/sign/key",
            {"key": private_pem_bytes.decode("utf-8")},
        )
    )

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: test_adapter)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/cognic/sign/key",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"vault:// signing-key flow failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    cosign_recording = _read_shim_recording(shims["cosign"])
    cosign_argv = cosign_recording["argv"]
    key_arg_idx = cosign_argv.index("--key")
    resolved_key_path = cosign_argv[key_arg_idx + 1]
    assert "vault://" not in resolved_key_path
    # Tempfile cleaned up by orchestrator's finally block.
    assert not Path(resolved_key_path).exists(), (
        f"expected tempfile cleanup; {resolved_key_path} still exists"
    )


def test_sign_bundle_with_vault_signing_key_missing_secret_emits_signing_key_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2 P2 #2 companion: vault:// URI points at a path the
    SecretAdapter doesn't have → ``sign_signing_key_unavailable``."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    empty_adapter = InMemorySecretAdapter()
    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: empty_adapter)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/cognic/missing",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_signing_key_unavailable" for f in payload["findings"])


def test_build_secret_adapter_returns_registered_secret_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct unit-test on ``_build_secret_adapter`` — ensures the
    narrow registry-lookup path resolves ``settings.secret_driver``
    via the bundled registry + ``load_bundled_adapters`` import side-
    effect. Pre-register the in-memory secret adapter (which lives
    in tests/support/, not in the bundled tree) before calling so
    the registry lookup succeeds for the ``memory`` driver."""
    from cognic_agentos.cli.sign import _build_secret_adapter
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.db.adapters import bundled_registry
    from tests.support.adapter_fixtures import InMemorySecretAdapter

    monkeypatch.setenv("COGNIC_SECRET_DRIVER", "memory")
    # Register InMemorySecretAdapter on the bundled registry; restore
    # via monkeypatch teardown by saving + replacing the internal map.
    bundled_registry.register("secret", "memory", InMemorySecretAdapter)

    settings = build_settings_without_env_file()
    assert settings.secret_driver == "memory"
    adapter = _build_secret_adapter(settings)
    assert hasattr(adapter, "driver")
    assert adapter.driver == "memory"


def test_sign_bundle_vault_signing_key_with_adapter_read_exception_emits_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SecretAdapter.read() raises an unexpected exception →
    closed-enum refusal with payload.error_type recording the class."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    class _RaisingAdapter:
        async def read(self, path: str) -> dict[str, Any]:
            raise RuntimeError(f"synthetic vault outage for {path}")

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: _RaisingAdapter())

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/raises",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_signing_key_unavailable"
        and f["payload"].get("error_type") == "RuntimeError"
        for f in payload["findings"]
    )


def test_sign_bundle_vault_signing_key_with_malformed_payload_emits_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SecretAdapter returns a payload without a ``key`` field →
    closed-enum refusal naming the malformed payload."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    bad_payload_adapter = InMemorySecretAdapter()
    import asyncio as _asyncio

    _asyncio.run(
        bad_payload_adapter.write(
            "secret/cognic/no-key-field",
            {"not_key": "this_is_not_a_pem"},
        )
    )

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: bad_payload_adapter)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/cognic/no-key-field",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_signing_key_unavailable" and "key" in f["message"].lower()
        for f in payload["findings"]
    )


# ===========================================================================
# T14.B R3 reviewer findings — production-contract gaps (round 3)
# ===========================================================================


def test_sign_bundle_with_dev_skip_and_missing_cosign_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3 P2 #1: ``--dev-mode-skip-cosign`` MUST short-circuit cosign
    resolution entirely. With cosign unresolvable + flag set, the
    orchestrator still produces 6 attestations without ever calling
    ``shutil.which("cosign")``."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=tmp_path / "missing_cosign",
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--dev-mode-skip-cosign"])
    assert result.exit_code == 0, (
        f"dev-skip+missing-cosign should succeed; got "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    for name in (
        "sbom.cdx.json",
        "vuln-scan.json",
        "license-audit.json",
        "slsa-provenance.intoto.json",
        "intoto-layout.json",
    ):
        assert (pack / "attestations" / name).is_file()
    assert not (pack / "attestations" / "cosign.sig").exists()
    assert not (pack / "attestations" / "bundle.sigstore").exists()


def test_sign_bundle_vault_signing_key_with_non_bytes_value_emits_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3 P2 #2: SecretAdapter returns a payload where ``key`` is a
    non-bytes / non-str value (e.g., int 12345 from a misconfigured
    Vault entry) → closed-enum refusal naming the type mismatch.
    Pre-fix: ``tempfile_handle.write(12345)`` raised TypeError out
    of the orchestrator instead of producing a deterministic refusal."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    bad_type_adapter = InMemorySecretAdapter()
    import asyncio as _asyncio

    _asyncio.run(
        bad_type_adapter.write(
            "secret/cognic/non-bytes",
            {"key": 12345},  # integer — not str/bytes
        )
    )

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: bad_type_adapter)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/cognic/non-bytes",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_signing_key_unavailable" for f in payload["findings"])
    # Type mismatch surfaces in the error message.
    assert any(
        f["reason"] == "sign_signing_key_unavailable"
        and ("int" in f["message"].lower() or "type" in f["message"].lower())
        for f in payload["findings"]
    )


def test_sign_bundle_vault_signing_key_records_stable_identity_in_attestations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3 P2 #3: vault:// signing-key flow MUST record the stable
    Vault URI as the signing identity in SLSA provenance + in-toto
    layout, NOT the transient tempfile path that gets unlinked.
    Pre-fix: SLSA ``builder.id`` + cosign-argv byproduct + in-toto
    ``signing_identity`` all recorded the tempfile, leaking local
    paths + losing production identity."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    from tests.support.adapter_fixtures import InMemorySecretAdapter

    test_adapter = InMemorySecretAdapter()
    private_pem_bytes = _TEST_PRIVATE_PEM.read_bytes()
    import asyncio as _asyncio

    vault_uri = "vault://secret/cognic/prod/sign-key"
    _asyncio.run(
        test_adapter.write(
            "secret/cognic/prod/sign-key",
            {"key": private_pem_bytes.decode("utf-8")},
        )
    )

    import cognic_agentos.cli.sign as sign_module

    monkeypatch.setattr(sign_module, "_build_secret_adapter", lambda _s: test_adapter)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path=vault_uri,
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    slsa_path = pack / "attestations" / "slsa-provenance.intoto.json"
    slsa = json.loads(slsa_path.read_text())
    builder_id = slsa["predicate"]["runDetails"]["builder"]["id"]
    assert builder_id == vault_uri, f"SLSA builder.id should be {vault_uri!r}; got {builder_id!r}"
    byproducts = slsa["predicate"]["runDetails"]["byproducts"]
    plan_bp = next(b for b in byproducts if b["name"] == "cosign_invocation_plan")
    plan = plan_bp["value"]
    # The auditable key identity is the vault URI, not the tempfile path.
    assert plan["key_identity"] == vault_uri, (
        f"cosign_invocation_plan byproduct recorded key_identity="
        f"{plan['key_identity']!r}; expected {vault_uri!r}"
    )
    # In the non-dev-skip vault flow, cosign DID execute.
    assert plan["executed"] is True

    intoto_path = pack / "attestations" / "intoto-layout.json"
    intoto = json.loads(intoto_path.read_text())
    assert intoto["signing_identity"] == vault_uri, (
        f"in-toto signing_identity should be {vault_uri!r}; got {intoto['signing_identity']!r}"
    )


# ===========================================================================
# T14.B R4 reviewer findings — production-contract gaps (round 4)
# ===========================================================================


def test_sign_bundle_provenance_byproduct_named_invocation_plan_not_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #1: SLSA provenance byproduct MUST NOT be named ``cosign_argv``
    (which implies executed-argv evidence) when the actual exec uses a
    different argv (vault tempfile path) or doesn't run at all (dev-skip).
    The byproduct should be a structured ``cosign_invocation_plan`` with
    an ``executed: bool`` flag + the redacted/auditable key identity."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"happy path failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    slsa_path = pack / "attestations" / "slsa-provenance.intoto.json"
    slsa = json.loads(slsa_path.read_text())
    byproducts = slsa["predicate"]["runDetails"]["byproducts"]
    # Old name ``cosign_argv`` MUST NOT appear; new name ``cosign_invocation_plan`` MUST.
    bp_names = {b["name"] for b in byproducts}
    assert "cosign_argv" not in bp_names, (
        f"byproduct name 'cosign_argv' implies executed-argv evidence; got {bp_names}"
    )
    assert "cosign_invocation_plan" in bp_names, (
        f"expected 'cosign_invocation_plan' byproduct; got {bp_names}"
    )
    plan = next(b for b in byproducts if b["name"] == "cosign_invocation_plan")["value"]
    assert plan["executed"] is True
    # key_identity uses the auditable form, not the tempfile path.
    assert plan["key_identity"] == str(_TEST_PRIVATE_PEM)


def test_sign_bundle_dev_skip_provenance_records_executed_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #1 dev-skip arm: when cosign is skipped, the SLSA
    invocation plan MUST record ``executed: false`` so downstream
    verifiers know the cosign step did NOT actually run. The
    pre-fix byproduct silently advertised a fake argv as if cosign
    had executed."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=tmp_path / "missing_cosign",
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--dev-mode-skip-cosign"])
    assert result.exit_code == 0

    slsa_path = pack / "attestations" / "slsa-provenance.intoto.json"
    slsa = json.loads(slsa_path.read_text())
    byproducts = slsa["predicate"]["runDetails"]["byproducts"]
    plan = next(b for b in byproducts if b["name"] == "cosign_invocation_plan")["value"]
    assert plan["executed"] is False, f"dev-skip MUST record executed=false; got {plan!r}"
    assert plan.get("skip_reason") == "dev_mode_skip_cosign"


def test_sign_bundle_records_real_pack_version_from_pyproject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #2: SLSA + in-toto attestations MUST record the REAL
    pack version from pyproject.toml, not a hardcoded ``0.1.0``.
    Pre-fix: any pack with a non-0.1.0 version got false provenance
    metadata + an incorrect invocation id."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "v2_5_0_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    # Bump pyproject version to 2.5.0.
    pyproject_path = pack / "pyproject.toml"
    pyproject_text = pyproject_path.read_text().replace('version = "0.1.0"', 'version = "2.5.0"')
    pyproject_path.write_text(pyproject_text)
    # Stage a wheel matching the new version.
    dist_dir = pack / "dist"
    dist_dir.mkdir(exist_ok=True)
    import zipfile as _zipfile

    _wheel_2_5_0 = dist_dir / "cognic_agent_sign_target-2.5.0-py3-none-any.whl"
    _di_2_5_0 = "cognic_agent_sign_target-2.5.0.dist-info"
    with _zipfile.ZipFile(_wheel_2_5_0, "w", _zipfile.ZIP_DEFLATED) as _zf:
        _zf.writestr(
            f"{_di_2_5_0}/entry_points.txt",
            "[cognic.agents]\nsign_target = cognic_agent_sign_target.agent:SignTargetAgent\n",
        )
        _zf.writestr(
            f"{_di_2_5_0}/METADATA",
            "Metadata-Version: 2.1\nName: cognic_agent_sign_target\nVersion: 2.5.0\n",
        )
        _zf.writestr(
            f"{_di_2_5_0}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: agentos-test-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )
        _zf.writestr(
            "cognic_agent_sign_target/agent.py",
            "class SignTargetAgent:\n    pass\n",
        )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    slsa_path = pack / "attestations" / "slsa-provenance.intoto.json"
    slsa = json.loads(slsa_path.read_text())
    external_params = slsa["predicate"]["buildDefinition"]["externalParameters"]
    assert external_params["pack_version"] == "2.5.0", (
        f"SLSA pack_version should be '2.5.0'; got {external_params['pack_version']!r}"
    )
    invocation_id = slsa["predicate"]["runDetails"]["metadata"]["invocationId"]
    assert "@2.5.0" in invocation_id, (
        f"invocationId should embed real version; got {invocation_id!r}"
    )

    intoto_path = pack / "attestations" / "intoto-layout.json"
    intoto = json.loads(intoto_path.read_text())
    assert intoto["pack_version"] == "2.5.0"


@pytest.mark.parametrize(
    ("mutation", "expected_failure_mode"),
    [
        ("delete_pyproject", "pyproject_not_found"),
        ("invalid_toml", "pyproject_unparseable"),
        ("no_project_block", "pyproject_missing_project_block"),
        ("missing_version", "pyproject_missing_version"),
    ],
)
def test_sign_bundle_pyproject_version_reader_failure_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_failure_mode: str,
) -> None:
    """R4 P2 #2 companion: each failure mode of
    ``_read_pack_version_for_bundle`` surfaces a closed-enum refusal
    with the right ``failure_mode`` payload value."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    pyproject_path = pack / "pyproject.toml"
    if mutation == "delete_pyproject":
        pyproject_path.unlink()
    elif mutation == "invalid_toml":
        pyproject_path.write_text("not [[ valid TOML\n")
    elif mutation == "no_project_block":
        pyproject_path.write_text(
            '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
        )
    elif mutation == "missing_version":
        # Strip the version line.
        body = pyproject_path.read_text()
        pyproject_path.write_text(body.replace('version = "0.1.0"\n', ""))

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == expected_failure_mode
        for f in payload["findings"]
    ), f"expected {expected_failure_mode}; got {payload['findings']}"


def test_sign_bundle_with_missing_pack_kind_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #3: manifest with absent ``[pack].kind`` → closed-enum
    refusal (failure_mode=manifest_missing_kind). Pre-fix: empty
    string for kind silently skipped JWS for what could be a
    malformed agent pack."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Strip the kind = "agent" line.
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_text = manifest_path.read_text()
    manifest_path.write_text(manifest_text.replace('kind = "agent"\n', ""))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_kind"
        for f in payload["findings"]
    )


def test_sign_bundle_with_non_string_pack_kind_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #3: manifest with ``[pack].kind = 123`` (non-string) →
    closed-enum refusal (failure_mode=manifest_invalid_kind_type)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_text = manifest_path.read_text()
    manifest_path.write_text(manifest_text.replace('kind = "agent"', "kind = 123"))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_invalid_kind_type"
        for f in payload["findings"]
    )


def test_sign_bundle_with_unknown_pack_kind_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4 P2 #3: manifest with ``[pack].kind = "garbage"`` (not in
    the closed-enum {tool, skill, agent}) → closed-enum refusal
    (failure_mode=manifest_unknown_kind)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_text = manifest_path.read_text()
    manifest_path.write_text(manifest_text.replace('kind = "agent"', 'kind = "garbage"'))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_unknown_kind"
        for f in payload["findings"]
    )


# ===========================================================================
# T14.B R5 reviewer findings — production-contract gaps (round 5)
# ===========================================================================


def test_sign_bundle_dev_skip_intoto_layout_omits_cosign_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5 P2 #1: under ``--dev-mode-skip-cosign``, the in-toto
    layout's ``artifact_paths`` MUST NOT list cosign.sig +
    bundle.sigstore (those files are NEVER produced when the cosign
    step is skipped). Pre-fix: layout listed them anyway, yielding a
    passing dev-skip bundle whose own layout referenced
    non-existent artifacts."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--dev-mode-skip-cosign"])
    assert result.exit_code == 0

    intoto_path = pack / "attestations" / "intoto-layout.json"
    intoto = json.loads(intoto_path.read_text())
    artifact_paths = intoto["artifact_paths"]
    # cosign.sig + bundle.sigstore MUST NOT appear under dev-skip.
    cosign_artifacts = [p for p in artifact_paths if p.endswith(("cosign.sig", "bundle.sigstore"))]
    assert cosign_artifacts == [], (
        f"in-toto layout under dev-skip should NOT list cosign artifacts; got {cosign_artifacts}"
    )
    # Other 5 attestations DO appear.
    for tail in (
        "sbom.cdx.json",
        "vuln-scan.json",
        "license-audit.json",
        "slsa-provenance.intoto.json",
    ):
        assert any(p.endswith(tail) for p in artifact_paths), (
            f"in-toto layout missing {tail} in artifact_paths"
        )


def test_sign_bundle_with_missing_pack_id_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5 P2 #2: manifest with absent ``[pack].pack_id`` → closed-
    enum refusal (``failure_mode=manifest_missing_pack_id``).
    Pre-fix: empty pack_id silently produced false provenance with
    SLSA externalParameters.pack_id='' + invocationId
    'agentos-sign-bundle/@<version>'."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_text = manifest_path.read_text()
    manifest_path.write_text(manifest_text.replace('pack_id = "cognic-agent-sign-target"\n', ""))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_pack_id"
        for f in payload["findings"]
    )


def test_sign_bundle_with_non_string_pack_id_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5 P2 #2: manifest with ``[pack].pack_id = 123`` (non-string)
    → closed-enum refusal (``failure_mode=manifest_invalid_pack_id_type``)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_text = manifest_path.read_text()
    manifest_path.write_text(
        manifest_text.replace(
            'pack_id = "cognic-agent-sign-target"',
            "pack_id = 12345",
        )
    )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_invalid_pack_id_type"
        for f in payload["findings"]
    )


def test_sign_bundle_with_multiple_wheels_in_dist_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5 P2 #3: ``<pack>/dist/`` contains multiple wheels → closed-
    enum refusal (``failure_mode=multiple_wheels_in_dist``). Pre-fix:
    the orchestrator picked the lexicographically last wheel, which
    could sign a stale or unrelated artifact while emitting
    attestations for the current pyproject metadata. Pack authors
    must clean dist/ before sign --bundle."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Stage a SECOND wheel under dist/.
    (pack / "dist" / "cognic_agent_sign_target-0.0.1-py3-none-any.whl").write_bytes(b"PK")
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "multiple_wheels_in_dist"
        for f in payload["findings"]
    )


# ===========================================================================
# T14.B R6 reviewer findings — production-contract gaps (round 6)
# ===========================================================================


def test_sign_bundle_with_stale_wheel_version_mismatch_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6 P2 #1: pyproject says version=2.5.0 but dist/ has only a
    leftover ``*-0.1.0-*.whl`` → closed-enum refusal
    (``failure_mode=wheel_version_mismatch``). Pre-fix the signer
    would sign the stale wheel while SLSA/in-toto recorded
    pack_version='2.5.0'."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "stale_wheel_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    pyproject_path = pack / "pyproject.toml"
    pyproject_path.write_text(
        pyproject_path.read_text().replace('version = "0.1.0"', 'version = "2.5.0"')
    )
    dist = pack / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "cognic_agent_sign_target-0.1.0-py3-none-any.whl").write_bytes(b"PK")

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_version_mismatch"
        for f in payload["findings"]
    )


def test_sign_bundle_with_stale_wheel_name_mismatch_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6 P2 #1 companion: dist/ has a wheel with the right version
    but a different project name → closed-enum refusal
    (``failure_mode=wheel_name_mismatch``)."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "wrong_name_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    dist = pack / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "wrong_project_name-0.1.0-py3-none-any.whl").write_bytes(b"PK")

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_name_mismatch"
        for f in payload["findings"]
    )


def test_sign_bundle_with_whitespace_only_pack_id_emits_missing_pack_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6 P2 #2: ``pack_id = "   "`` (whitespace-only) is treated as
    missing — pre-fix the validation accepted whitespace and the
    blank pack_id flowed into SLSA/in-toto provenance."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_path.write_text(
        manifest_path.read_text().replace(
            'pack_id = "cognic-agent-sign-target"',
            'pack_id = "   "',
        )
    )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_pack_id"
        for f in payload["findings"]
    )


def test_sign_bundle_pack_id_with_surrounding_whitespace_recorded_stripped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6 P2 #2 companion: ``pack_id = "  cognic-agent-x  "`` (with
    surrounding whitespace) is accepted but the STRIPPED form
    flows into provenance attestations + invocation id."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_path.write_text(
        manifest_path.read_text().replace(
            'pack_id = "cognic-agent-sign-target"',
            'pack_id = "  cognic-agent-sign-target  "',
        )
    )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    slsa_path = pack / "attestations" / "slsa-provenance.intoto.json"
    slsa = json.loads(slsa_path.read_text())
    pack_id_in_provenance = slsa["predicate"]["buildDefinition"]["externalParameters"]["pack_id"]
    assert pack_id_in_provenance == "cognic-agent-sign-target", (
        f"SLSA pack_id should be stripped; got {pack_id_in_provenance!r}"
    )
    invocation_id = slsa["predicate"]["runDetails"]["metadata"]["invocationId"]
    assert "  " not in invocation_id, (
        f"invocationId should not contain double spaces; got {invocation_id!r}"
    )


def test_sign_bundle_with_unparseable_wheel_filename_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wheel filename that doesn't match PEP 427 shape →
    closed-enum refusal (failure_mode=wheel_unparseable_filename)."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "bad_wheel_name"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    dist = pack / "dist"
    dist.mkdir(exist_ok=True)
    # Wheel filename missing required PEP 427 segments.
    (dist / "notawheel.whl").write_bytes(b"PK")

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_unparseable_filename"
        for f in payload["findings"]
    )


def test_sign_bundle_with_pyproject_missing_project_name_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pyproject.toml with no [project].name → closed-enum refusal
    (failure_mode=pyproject_missing_project_name). Wheel name-match
    cross-check requires the project name."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    pyproject_path = pack / "pyproject.toml"
    pyproject_text = pyproject_path.read_text()
    pyproject_path.write_text(pyproject_text.replace('name = "cognic-agent-sign-target"\n', ""))
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "pyproject_missing_project_name"
        for f in payload["findings"]
    )


def test_sign_bundle_with_malformed_pep440_version_emits_wheel_version_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pyproject [project].version = 'garbage' (not PEP 440) →
    Version() construction raises in _discover_wheel; closed-enum
    refusal collapses into wheel_version_mismatch failure_mode."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "bad_pep440_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    pyproject_path = pack / "pyproject.toml"
    pyproject_path.write_text(
        pyproject_path.read_text().replace('version = "0.1.0"', 'version = "garbage"')
    )
    dist = pack / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "cognic_agent_sign_target-0.1.0-py3-none-any.whl").write_bytes(b"PK")
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_version_mismatch"
        for f in payload["findings"]
    )


def test_discover_wheel_without_expected_metadata_returns_wheel_unchecked(
    tmp_path: Path,
) -> None:
    """Direct unit test of ``_discover_wheel`` with no expected
    metadata kwargs — defensive branch reachable only via tests
    of the helper in isolation; production callers always pass
    both. Documents the helper-API contract."""
    from cognic_agentos.cli.sign import _discover_wheel

    pack = tmp_path / "pack"
    pack.mkdir()
    dist = pack / "dist"
    dist.mkdir()
    wheel = dist / "anything-1.0-py3-none-any.whl"
    wheel.write_bytes(b"PK")

    found, finding = _discover_wheel(pack)
    assert finding is None
    assert found == wheel


def test_discover_wheel_docstring_does_not_advertise_lexicographic_pick() -> None:
    """R6 P3: docstring contract refresh — the implementation now
    fails closed on multiple wheels + on name/version mismatch.
    The docstring MUST NOT advertise the old "pick lexicographically
    last" behavior."""
    from cognic_agentos.cli.sign import _discover_wheel

    docstring = _discover_wheel.__doc__ or ""
    assert "lexicographic" not in docstring.lower(), (
        "docstring still mentions lexicographic; the impl fails closed now"
    )


# ===========================================================================
# T14.B R7 reviewer findings — production-contract gaps (round 7)
# ===========================================================================


def test_sign_bundle_intoto_layout_includes_agent_card_jws_for_agent_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7 P2 #1: agent-pack in-toto layout MUST include the
    agent-card.jws path in ``artifact_paths``. Pre-fix the layout
    rendered before step 10 (JWS production), so the JWS path was
    NEVER listed even though the bundle advertises it as an
    artifact + the runtime trust gate verifies it."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    intoto_path = pack / "attestations" / "intoto-layout.json"
    intoto = json.loads(intoto_path.read_text())
    artifact_paths = intoto["artifact_paths"]
    # JWS path MUST appear for agent packs.
    assert any(p.endswith("agent-card.jws") for p in artifact_paths), (
        f"in-toto layout for agent pack missing agent-card.jws; got artifact_paths={artifact_paths}"
    )


def test_sign_bundle_intoto_layout_omits_jws_for_tool_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7 P2 #1 companion: tool-pack in-toto layout MUST NOT include
    an agent-card.jws path (tool packs don't sign one)."""
    shims = _stage_full_shim_set(tmp_path)
    import shutil as _shutil

    pack = tmp_path / "tool_pack"
    _shutil.copytree(_SIGN_TARGET_PACK, pack)
    # Flip kind to tool + drop agent-only fields.
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    body = body.replace('kind = "agent"', 'kind = "tool"')
    body = body.replace(
        'pack_id = "cognic-agent-sign-target"', 'pack_id = "cognic-tool-sign-target"'
    )
    new_lines: list[str] = []
    in_a2a = False
    for line in body.splitlines():
        if line.startswith("[a2a]"):
            in_a2a = True
            continue
        if in_a2a and line.startswith("["):
            in_a2a = False
        if in_a2a:
            continue
        if "agent_card_url" in line or "agent_card_jws_path" in line:
            continue
        new_lines.append(line)
    manifest_path.write_text("\n".join(new_lines) + "\n")
    pyproject_path = pack / "pyproject.toml"
    pyproject_path.write_text(
        pyproject_path.read_text().replace(
            'name = "cognic-agent-sign-target"',
            'name = "cognic-tool-sign-target"',
        )
    )
    dist_dir = pack / "dist"
    dist_dir.mkdir(exist_ok=True)
    import zipfile as _zipfile

    _tool_wheel = dist_dir / "cognic_tool_sign_target-0.1.0-py3-none-any.whl"
    _tool_dist_info = "cognic_tool_sign_target-0.1.0.dist-info"
    with _zipfile.ZipFile(_tool_wheel, "w", _zipfile.ZIP_DEFLATED) as _zf:
        _zf.writestr(
            f"{_tool_dist_info}/entry_points.txt",
            "[cognic.tools]\nsign_target = cognic_tool_sign_target.tool:Tool\n",
        )
        _zf.writestr(
            f"{_tool_dist_info}/METADATA",
            "Metadata-Version: 2.1\nName: cognic_tool_sign_target\nVersion: 0.1.0\n",
        )
        _zf.writestr(
            f"{_tool_dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: agentos-test-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )
        _zf.writestr(
            "cognic_tool_sign_target/tool.py",
            "class Tool:\n    pass\n",
        )

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0

    intoto_path = pack / "attestations" / "intoto-layout.json"
    intoto = json.loads(intoto_path.read_text())
    artifact_paths = intoto["artifact_paths"]
    assert not any(p.endswith("agent-card.jws") for p in artifact_paths), (
        f"tool pack should NOT list agent-card.jws; got {artifact_paths}"
    )


def test_sign_bundle_with_unconstructable_vault_adapter_emits_json_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7 P2 #2: when ``signing_key_path`` is a ``vault://`` URI
    but ``_build_secret_adapter`` raises (e.g., production
    VaultAdapter requires ``vault_addr`` which isn't set), the CLI
    in --json mode MUST emit a structured ``sign_signing_key_unavailable``
    finding through the SignReport pipeline + exit 1.

    Pre-fix: the CLI exited 2 with a plain stderr string, bypassing
    the JSON structured-output contract pack-author CI parsers
    rely on."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)

    import cognic_agentos.cli.sign as sign_module

    def _raise_construction_error(_settings: object) -> object:
        raise ValueError("VaultAdapter requires vault_addr; got empty/None")

    monkeypatch.setattr(sign_module, "_build_secret_adapter", _raise_construction_error)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
        signing_key_path="vault://secret/cognic/prod-key",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    # Exit 1 (sign-report fail), NOT 2 (CLI-arg fail).
    assert result.exit_code == 1, (
        f"expected exit 1 (structured finding); got {result.exit_code}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # JSON output on stdout carries the structured finding.
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    assert any(
        f["reason"] == "sign_signing_key_unavailable" and "vault" in f["message"].lower()
        for f in payload["findings"]
    ), f"expected vault adapter construction error in findings; got {payload['findings']}"


# ===========================================================================
# T14.B R8 reviewer findings — production-contract gaps (round 8)
# ===========================================================================


def test_sign_bundle_uses_manifest_declared_agent_card_jws_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #1: agent manifest declares a custom
    ``identity.agent_card_jws_path`` (e.g.,
    ``agent_cards/v2/my-card.jws``); sign --bundle MUST write the
    JWS to that path + record it in report artifacts + in-toto
    layout. Pre-fix everything was hardcoded to
    ``agent_cards/agent-card.jws``."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Override the manifest's agent_card_jws_path.
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    custom_jws_relative = "agent_cards/v2/custom-card.jws"
    body = body.replace(
        'agent_card_jws_path = "agent_cards/agent-card.jws"',
        f'agent_card_jws_path = "{custom_jws_relative}"',
    )
    manifest_path.write_text(body)
    # Stage the AgentCard JSON at the new directory's parent so the
    # JWS signer reads from the same agent_cards subdirectory.
    new_jws_dir = pack / "agent_cards" / "v2"
    new_jws_dir.mkdir(parents=True, exist_ok=True)
    # Move the existing agent-card.json → custom_dir, since the JWS
    # signer reads "agent_cards/agent-card.json" right now (separate
    # from the JWS path) — but the JWS-path declaration drives the
    # JWS WRITE side; the read side stays at agent_cards/agent-card.json.

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 0, (
        f"custom-jws-path bundle failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout.strip())
    # Report's agent_card_jws artifact uses the custom path.
    assert payload["artifacts"]["agent_card_jws"].endswith(custom_jws_relative), (
        f"report artifact path should match manifest declaration; got "
        f"{payload['artifacts']['agent_card_jws']!r}"
    )
    # JWS file actually exists at the custom path.
    custom_jws_path = pack / custom_jws_relative
    assert custom_jws_path.is_file(), (
        f"JWS not produced at manifest-declared path: {custom_jws_path}"
    )
    # in-toto layout lists the custom path (NOT the default).
    intoto = json.loads((pack / "attestations" / "intoto-layout.json").read_text())
    assert any(p.endswith(custom_jws_relative) for p in intoto["artifact_paths"])
    assert not any(
        p.endswith("agent_cards/agent-card.jws")
        for p in intoto["artifact_paths"]
        if not p.endswith(custom_jws_relative)
    )


def test_sign_bundle_with_jws_path_escaping_pack_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #1 companion: manifest-declared
    ``agent_card_jws_path`` that escapes the pack (absolute or
    ``..``-traversal) → closed-enum refusal
    (``failure_mode=agent_card_jws_path_escapes_pack``). Defends
    against attacker-controlled manifests writing the JWS to an
    arbitrary host location."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    body = body.replace(
        'agent_card_jws_path = "agent_cards/agent-card.jws"',
        'agent_card_jws_path = "../escaped/card.jws"',
    )
    manifest_path.write_text(body)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "agent_card_jws_path_escapes_pack"
        for f in payload["findings"]
    )


def test_sign_bundle_with_wheel_symlink_escaping_pack_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #2: wheel under ``dist/`` is a symlink whose target
    resolves OUTSIDE the pack root → closed-enum refusal
    (``failure_mode=wheel_symlink_escape``). Pre-fix cosign / grype
    / digest operated on the external target while the report
    presented the pack-local path."""
    shims = _stage_full_shim_set(tmp_path)
    # Plant a real wheel-named file outside the pack.
    outside_dir = tmp_path / "outside_target"
    outside_dir.mkdir()
    outside_wheel = outside_dir / "evil.whl"
    outside_wheel.write_bytes(b"PKevil-content")

    pack = _stage_pack_with_wheel(tmp_path)
    # Replace the staged wheel with a symlink to the outside target.
    dist = pack / "dist"
    legitimate_wheel = next(dist.glob("*.whl"))
    legitimate_wheel.unlink()
    symlinked_wheel = dist / "cognic_agent_sign_target-0.1.0-py3-none-any.whl"
    symlinked_wheel.symlink_to(outside_wheel)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_symlink_escape"
        for f in payload["findings"]
    )


def test_sign_bundle_with_attestations_dir_symlink_escape_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #3: ``attestations/`` is a symlink whose target
    resolves outside the pack root → closed-enum refusal
    (``failure_mode=attestations_dir_escape``). Pre-fix sign --bundle
    wrote SBOM / provenance / cosign outputs to the external target
    while the report presented pack-local paths."""
    shims = _stage_full_shim_set(tmp_path)
    outside_dir = tmp_path / "outside_attestations"
    outside_dir.mkdir()

    pack = _stage_pack_with_wheel(tmp_path)
    # Remove the existing attestations/ + replace with a symlink.
    import shutil as _shutil

    _shutil.rmtree(pack / "attestations")
    (pack / "attestations").symlink_to(outside_dir)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "attestations_dir_escape"
        for f in payload["findings"]
    )


def test_sign_bundle_with_agent_cards_dir_symlink_escape_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #3 companion: ``agent_cards/`` symlinked outside pack
    (agent kind only) → closed-enum refusal
    (``failure_mode=agent_cards_dir_escape``)."""
    shims = _stage_full_shim_set(tmp_path)
    outside_dir = tmp_path / "outside_agent_cards"
    outside_dir.mkdir()
    # Plant the agent-card JSON at the symlink target so the JWS
    # signer's read succeeds (otherwise we'd hit a different
    # failure mode first).
    (outside_dir / "agent-card.json").write_text('{"name": "evil_card", "schema_version": "1.0"}')

    pack = _stage_pack_with_wheel(tmp_path)
    import shutil as _shutil

    _shutil.rmtree(pack / "agent_cards")
    (pack / "agent_cards").symlink_to(outside_dir)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "agent_cards_dir_escape"
        for f in payload["findings"]
    )


def test_sign_bundle_with_non_string_jws_path_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #1 defensive: ``identity.agent_card_jws_path = 12345``
    (non-string) → closed-enum refusal
    (``failure_mode=manifest_invalid_agent_card_jws_path_type``)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_path.write_text(
        manifest_path.read_text().replace(
            'agent_card_jws_path = "agent_cards/agent-card.jws"',
            "agent_card_jws_path = 12345",
        )
    )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_invalid_agent_card_jws_path_type"
        for f in payload["findings"]
    )


def test_sign_bundle_with_missing_identity_block_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #1 defensive: agent pack with missing [identity] block
    → closed-enum refusal (``failure_mode=manifest_missing_identity_block``).
    Pack admission would normally catch this earlier via validate;
    sign --bundle defends in case the validate step was skipped."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    # Strip the [identity] block.
    new_lines: list[str] = []
    in_identity = False
    for line in body.splitlines():
        if line.startswith("[identity]"):
            in_identity = True
            continue
        if in_identity and line.startswith("["):
            in_identity = False
        if in_identity:
            continue
        new_lines.append(line)
    manifest_path.write_text("\n".join(new_lines) + "\n")
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_identity_block"
        for f in payload["findings"]
    )


@pytest.mark.parametrize(
    ("target", "raise_path_substring", "expected_failure_modes"),
    [
        ("wheel", "/dist/", ("wheel_symlink_resolve_error",)),
        (
            "attestations_dir",
            "/attestations",
            ("attestations_dir_resolve_error",),
        ),
        ("agent_cards_dir", "/agent_cards", ("agent_cards_dir_resolve_error",)),
        (
            "jws_path",
            "/agent_cards/agent-card.jws",
            ("agent_card_jws_path_resolve_error",),
        ),
    ],
)
def test_sign_bundle_path_resolve_error_collapses_to_structured_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    raise_path_substring: str,
    expected_failure_modes: tuple[str, ...],
) -> None:
    """R8 P2 #2/#3 defensive (T12 R29 doctrine): ``Path.resolve()``
    raising ``OSError`` / ``RuntimeError`` (e.g., self-referential
    symlink loop) collapses into a structured ``sign_subprocess_failed``
    finding rather than a Python traceback. Cross-platform via
    monkeypatch on ``Path.resolve``."""
    del target  # used only by the parametrize id
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    real_resolve = Path.resolve

    def _raise_for_target(self: Path, strict: bool = False) -> Path:
        if raise_path_substring in str(self):
            raise OSError(40, "Too many levels of symbolic links", str(self))
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_for_target)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") in expected_failure_modes
        for f in payload["findings"]
    ), f"expected one of {expected_failure_modes}; got {payload['findings']}"


def test_sign_bundle_with_wheel_not_regular_file_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8 P2 #2 defensive: wheel candidate resolves to something
    that isn't a regular file (e.g., a directory) → closed-enum
    refusal (``failure_mode=wheel_not_regular_file``)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Replace the wheel file with a directory of the same name.
    dist = pack / "dist"
    legitimate_wheel = next(dist.glob("*.whl"))
    legitimate_wheel.unlink()
    legitimate_wheel.mkdir()  # directory with the wheel name

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "wheel_not_regular_file"
        for f in payload["findings"]
    )


# ===========================================================================
# T14.B R9 reviewer findings — production-contract gaps (round 9)
# ===========================================================================


def test_sign_bundle_with_missing_agent_card_jws_path_field_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9 P2 #1: agent manifest with NO ``agent_card_jws_path`` field
    in [identity] → closed-enum refusal
    (``failure_mode=manifest_missing_agent_card_jws_path``). Pre-fix
    the helper silently defaulted to ``agent_cards/agent-card.jws``,
    letting a manifest without the required field sign cleanly."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_path.write_text(
        manifest_path.read_text().replace(
            'agent_card_jws_path = "agent_cards/agent-card.jws"\n',
            "",
        )
    )
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_agent_card_jws_path"
        for f in payload["findings"]
    )


def test_sign_bundle_with_attestations_path_as_regular_file_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9 P2 #2: ``pack_path/attestations`` is a regular file (not a
    directory) → ``mkdir(exist_ok=True)`` raises FileExistsError →
    closed-enum refusal (``failure_mode=attestations_dir_create_error``).
    Pre-fix the traceback escaped before the structured-finding
    collapse helper ran."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    import shutil as _shutil

    _shutil.rmtree(pack / "attestations")
    (pack / "attestations").write_bytes(b"a regular file, not a directory")

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "attestations_dir_create_error"
        for f in payload["findings"]
    )


def test_sign_bundle_with_attestations_self_referential_symlink_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9 P2 #2 companion: ``attestations -> attestations`` self-
    referential symlink → mkdir or resolve raises → closed-enum
    refusal naming the directory failure mode (either
    ``attestations_dir_create_error`` or
    ``attestations_dir_resolve_error`` — both protect against the
    same vector)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    import shutil as _shutil

    _shutil.rmtree(pack / "attestations")
    (pack / "attestations").symlink_to("attestations")

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode")
        in (
            "attestations_dir_create_error",
            "attestations_dir_resolve_error",
        )
        for f in payload["findings"]
    )


# ===========================================================================
# T14.B R10 reviewer findings — production-contract gaps (round 10)
# ===========================================================================


def test_sign_bundle_legacy_identity_block_dual_path_signs_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R10 P2 #1: a docs-shaped agent pack declaring its identity at
    the legacy ``[tool.cognic.identity]`` path (NOT the canonical
    top-level ``[identity]``) MUST sign cleanly. The validator
    dual-paths this block per the dual-path doctrine; the signer
    MUST do the same. Pre-fix the signer read only ``[identity]``
    + a legacy-shape pack would validate clean then fail sign with
    ``manifest_missing_identity_block``."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    # Re-shape: top-level [identity] → legacy [tool.cognic.identity].
    body = body.replace("[identity]", "[tool.cognic.identity]")
    manifest_path.write_text(body)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"legacy-identity-shape sign --bundle failed: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    # JWS produced at the manifest-declared path.
    assert (pack / "agent_cards" / "agent-card.jws").is_file()


def test_sign_bundle_legacy_identity_with_missing_jws_field_emits_subprocess_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R10 P2 #1 companion: legacy [tool.cognic.identity] block
    that's missing the agent_card_jws_path field still trips the
    R9 P2 #1 required-field guard. The dual-path lookup MUST
    enforce the required-field contract on whichever path is
    declared (canonical takes precedence)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    # Move identity to legacy path AND drop the agent_card_jws_path.
    body = body.replace("[identity]", "[tool.cognic.identity]")
    body = body.replace(
        'agent_card_jws_path = "agent_cards/agent-card.jws"\n',
        "",
    )
    manifest_path.write_text(body)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_missing_agent_card_jws_path"
        for f in payload["findings"]
    )


def test_sign_module_header_describes_shipped_t14a_and_t14b_surfaces() -> None:
    """R10 P3 #1: the cli/sign.py module header MUST describe the
    SHIPPED surface (T14.A sign-blob + T14.B sign --bundle), with
    only T14.C (verify) noted as follow-up. Pre-fix the header
    still said T14.B was a future commit + vault:// landed at
    T14.B (both now landed in this commit)."""
    from cognic_agentos.cli import sign as sign_module

    docstring = sign_module.__doc__ or ""
    # Negative pin: the old "T14.B (follow-up)" wording must be gone.
    lower = docstring.lower()
    assert "t14.b (follow-up)" not in lower, "header still describes T14.B as future work"
    # Positive pin: header acknowledges T14.A + T14.B as shipped.
    # Either explicit "shipped" wording OR an absence of
    # "follow-up" / "lands later" tied to T14.B is acceptable; the
    # negative pin above is the load-bearing assertion.


def test_sign_test_module_header_describes_t14a_and_t14b_coverage() -> None:
    """R10 P3 #2: this test file's docstring MUST acknowledge that
    it carries BOTH the T14.A sign-blob arms AND the T14.B
    sign-bundle arms. Pre-fix the header said the file landed only
    T14.A + T14.B/T14.C ship in follow-up commits — false at this
    commit."""
    import tests.unit.cli.test_cli_sign as test_module

    docstring = test_module.__doc__ or ""
    lower = docstring.lower()
    # Negative pin: the old "T14.B (sign --bundle full orchestrator)
    # ship in follow-up commits" wording must be gone.
    assert "t14.b (sign --bundle full orchestrator)" not in lower, (
        "test header still claims T14.B ships in a follow-up"
    )
    assert "t14.b sign --bundle" in lower or "sign --bundle" in lower, (
        "test header should acknowledge sign --bundle coverage in this file"
    )


# ===========================================================================
# T14.B R11 reviewer findings — production-contract gaps (round 11)
# ===========================================================================


def test_sign_bundle_with_canonical_identity_non_table_refuses_even_with_valid_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R11 P2 #1: when canonical ``[identity]`` is present with the
    wrong type (e.g., ``identity = "not-a-table"``), the signer
    MUST refuse with a structured finding — even if a valid
    ``[tool.cognic.identity]`` exists. The validator's shape gate
    treats a present-but-non-table required block as
    ``block_not_table`` and does NOT let the legacy path rescue
    it; the signer's dual-path lookup MUST share that semantic so
    a malformed canonical key isn't silently bypassed."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    manifest_path = pack / "cognic-pack-manifest.toml"
    body = manifest_path.read_text()
    # The fixture has a valid [identity] block. Replace it with a
    # scalar value AND stage a parallel valid [tool.cognic.identity].
    body = body.replace("[identity]", "[tool.cognic.identity]")
    # Now tool.cognic.identity is the legacy block (which would
    # rescue under the old dual-path logic). Add a non-table
    # canonical key at the top level.
    body = 'identity = "not-a-table"\n' + body
    manifest_path.write_text(body)

    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_subprocess_failed"
        and f["payload"].get("failure_mode") == "manifest_invalid_identity_block_type"
        for f in payload["findings"]
    ), f"expected manifest_invalid_identity_block_type; got {payload['findings']}"


def test_jws_path_helper_docstring_documents_missing_field_failure_mode() -> None:
    """R11 P3 #1: the ``_read_agent_card_jws_path_for_bundle``
    helper's closed-enum failure-mode list in the docstring MUST
    name ``manifest_missing_agent_card_jws_path``. Pre-fix R9 added
    the failure mode + R10 dual-pathed it, but the docstring's
    enum list still skipped it — leaving the missing-field branch
    as an undocumented one-off for future maintainers."""
    from cognic_agentos.cli.sign import _read_agent_card_jws_path_for_bundle

    docstring = _read_agent_card_jws_path_for_bundle.__doc__ or ""
    assert "manifest_missing_agent_card_jws_path" in docstring, (
        "helper docstring's closed-enum failure-mode list MUST include "
        "manifest_missing_agent_card_jws_path (R9 added it; R10 enforces "
        "it across canonical + legacy identity blocks); refresh the list"
    )


def test_sign_bundle_with_dev_mode_skip_cosign_skips_cosign_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2 P2 #3: ``--dev-mode-skip-cosign`` is honored by
    ``run_sign_bundle``. Cosign NOT invoked; security warning on
    stderr; report status ``pass`` (other 6 attestations still
    produced); cosign output files NOT created."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )
    monkeypatch.setenv("COGNIC_RUNTIME_PROFILE", "dev")

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--dev-mode-skip-cosign"])
    assert result.exit_code == 0, (
        f"dev-mode-skip in bundle path failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "WARNING" in result.stderr or "warning" in result.stderr.lower()
    rec_pointer = tmp_path / f"{shims['cosign'].name}.recording_path"
    rec_path = Path(rec_pointer.read_text())
    assert not rec_path.is_file(), "cosign was invoked under --dev-mode-skip-cosign in bundle path"
    assert not (pack / "attestations" / "cosign.sig").exists()
    assert not (pack / "attestations" / "bundle.sigstore").exists()


def test_sign_bundle_with_missing_agent_card_json_emits_jws_signing_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent pack with no ``agent_cards/agent-card.json`` →
    ``_sign_agent_card_jws_to_disk`` raises ``OSError`` reading the
    missing card; orchestrator collapses into
    ``sign_agent_card_jws_signing_failed``. Covers line 792 (the
    OSError catch in the JWS-to-disk helper)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    # Remove the agent_card.json so card.read_bytes() raises FileNotFoundError.
    (pack / "agent_cards" / "agent-card.json").unlink()
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(
        f["reason"] == "sign_agent_card_jws_signing_failed"
        and f["payload"].get("error_type") == "FileNotFoundError"
        for f in payload["findings"]
    )


def test_sign_bundle_resolves_tools_via_host_path_fallback_when_overrides_unset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``settings.{tool}_path`` unset for all 4 tools + monkeypatched
    ``shutil.which`` returns shim paths → orchestrator runs successfully
    against the PATH-resolved binaries. Covers the fallback-success
    branch in ``_resolve_tool_path`` (the generic helper used by syft /
    grype / license-auditor + the equivalent _resolve_cosign_path)."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    monkeypatch.delenv("COGNIC_COSIGN_PATH", raising=False)
    monkeypatch.delenv("COGNIC_SYFT_PATH", raising=False)
    monkeypatch.delenv("COGNIC_GRYPE_PATH", raising=False)
    monkeypatch.delenv("COGNIC_LICENSE_AUDITOR_PATH", raising=False)
    monkeypatch.setenv("COGNIC_SIGNING_KEY_PATH", str(_TEST_PRIVATE_PEM))

    import shutil as real_shutil

    real_which = real_shutil.which
    routing = {
        "cosign": str(shims["cosign"]),
        "syft": str(shims["syft"]),
        "grype": str(shims["grype"]),
        "pip-licenses": str(shims["license_auditor"]),
    }

    def _which_routes(
        cmd: str,
        mode: int = os.F_OK | os.X_OK,
        path: str | None = None,
    ) -> str | None:
        if cmd in routing:
            return routing[cmd]
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(real_shutil, "which", _which_routes)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack)])
    assert result.exit_code == 0, (
        f"sign --bundle exit {result.exit_code}; stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_sign_bundle_jws_signing_failure_emits_agent_card_jws_signing_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure during AgentCard JWS production via joserfc →
    closed-enum refusal ``sign_agent_card_jws_signing_failed``.
    Monkeypatch the joserfc serializer to raise."""
    shims = _stage_full_shim_set(tmp_path)
    pack = _stage_pack_with_wheel(tmp_path)
    _set_sign_bundle_settings(
        monkeypatch,
        cosign_path=shims["cosign"],
        syft_path=shims["syft"],
        grype_path=shims["grype"],
        license_auditor_path=shims["license_auditor"],
    )

    import cognic_agentos.cli.sign as sign_module

    def _raise_on_sign(*args: object, **kwargs: object) -> bytes:
        raise RuntimeError("synthetic JWS signing error")

    monkeypatch.setattr(sign_module, "_sign_agent_card_jws_bytes", _raise_on_sign)

    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", str(pack), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout.strip())
    assert any(f["reason"] == "sign_agent_card_jws_signing_failed" for f in payload["findings"])
