"""Sprint-7A T14 — `agentos sign` regressions.

T14 is split into three commits per the Sprint-7A 3-commit-split
decision (T14.A sign-blob, T14.B sign --bundle, T14.C verify). This
file lands T14.A — the narrow ``sign-blob`` path:

  - Real ``asyncio.create_subprocess_exec`` against a Python cosign-
    shim (mirrors the Sprint-4 ``test_trust_gate.py::_make_cosign_shim``
    pattern). The shim records argv + env + cwd to JSON; tests assert
    against that recording.
  - Closed-enum refusals: ``sign_cosign_not_installed`` (shutil.which
    returns None), ``sign_signing_key_unavailable`` (signing_key_path
    unset / file missing / vault returns None),
    ``sign_subprocess_failed`` (cosign exits non-zero).
  - ``--dev-mode-skip-cosign`` flag prints a security warning to
    stderr + skips the cosign exec; the prod profile rejects the
    flag at Settings construction time (per Doctrine F + the
    config.py:1035 prod-profile guard).

T14.B (sign --bundle full orchestrator) + T14.C (verify offline trust
gate) ship in follow-up commits.

Halt-before-commit per Doctrine Decision G — ``cli/sign.py`` is on the
critical-controls floor at 95% line / 90% branch.
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
