"""Remediation pins for the M8.5-C live-proof review (2026-07-12).

TWO adversarial rounds against the M8.5-C proof tree, before any live run.

ROUND 1 (F1-F11) found eleven defects — a self-authorizing browser TLS trust, a
Bar D that never actually replayed an approval (so the whole HP-4 actor-binding
claim went unexercised), a BFF that could not read its own TLS key, secrets
leaking through ``kubectl`` argv, a missing four-eyes TTL override, and several
bars that could pass without their claimed evidence.

ROUND 2 (R1-R9) rejected that packet and found nine more. The load-bearing one:
Bar A had delegated S4 / S6 / S10, and Bar B the expired-token case, to unit and
conformance suites — while the RATIFIED spec (§5.2) requires all ten session
cases and the expired-token refusal LIVE on kind. A README disclosure cannot
lower a ratified contract, and all four proved perfectly liveable; the delegation
had been convenience, not infeasibility. Round 2 also found S5 vacuous (it never
reached the one-time-state check at all), S9 able to pass with no restart, S7
satisfied by any driver error, Bar C unable to show a *visible* refusal, and Bar
E accepting any non-empty transcript.

This suite is the "permanent runner-structure tests and mutation checks" the
review required: every test pins ONE fix so tightly that reverting the fix flips
the assertion. These are structural (text-shape) pins over the proof scripts —
the live bars themselves are the behavioural proof; these stop a silent
regression from reaching the live run. They complement (never replace) the
``test_proof_m85c_structure.py`` invariants and the reference-binder unit suite.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_PROOF = _REPO / "infra" / "proof-m85c"
_RUNNER = _PROOF / "run-proof-m85c.sh"
_DRIVER = _PROOF / "playwright" / "driver.py"
_STAGE = _PROOF / "stage-packs.sh"
_SEED = _PROOF / "seed-db.sh"
_KERNEL_SEED = _PROOF / "kernel-seed.sql"
_BFF_YAML = _PROOF / "manifests" / "bff.yaml"
_DOCKERIGNORE = _PROOF / ".dockerignore"
_PKCE = _PROOF / "keycloak" / "pkce_login.py"
_BINDER = _PROOF / "overlay_reference" / "binder.py"
_README = _PROOF / "README.md"

_RUNNER_TEXT = _RUNNER.read_text()
_DRIVER_TEXT = _DRIVER.read_text()
_STAGE_TEXT = _STAGE.read_text()
_README_TEXT = _README.read_text()


# =========================================================================== #
# Shared machinery for the ROUND-4 MUTATION tests.                            #
#                                                                             #
# These tests execute the RUNNER'S OWN function text, extracted from the      #
# production script at test time. They never re-type a copy of it: a          #
# test-local duplicate passes happily while production drifts away underneath #
# it, which is the vacuous-proof class this repo has an explicit doctrine     #
# against. If an extraction finds nothing (the function was renamed or        #
# moved), the helper FAILS LOUD rather than silently testing an empty string. #
# =========================================================================== #


def _extract_shell_function(name: str, *, text: str = _RUNNER_TEXT) -> str:
    """The REAL production text of a shell function (`sed -n '/^name()/,/^}/p'`).

    Fails loud when the function is absent, when the closing brace is missing, or when
    the extracted text does not parse — any of which would otherwise leave a mutation
    test asserting confidently against nothing at all."""
    lines = text.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if re.match(rf"^{re.escape(name)}\(\)", ln)), None
    )
    assert start is not None, (
        f"{name}() is not defined at the start of a line in run-proof-m85c.sh — it was "
        "renamed or moved. This mutation test would otherwise pass VACUOUSLY, asserting "
        "against an empty string, so it fails loudly instead."
    )
    end = next((j for j in range(start + 1, len(lines)) if lines[j] == "}"), None)
    assert end is not None, f"{name}() has no closing brace at column 0"
    body = "\n".join(lines[start : end + 1])
    # A `}` at column 0 INSIDE the body would silently truncate the sed range above —
    # so prove the extraction is a complete, parseable function before anyone relies on
    # it. (This bit once: an in-pod `|| { … }` block put a brace at column 0.)
    probe = subprocess.run(["bash", "-n"], input=body, capture_output=True, text=True)
    assert probe.returncode == 0, (
        f"the extracted {name}() does not parse — the sed range was truncated by a `}}` at "
        f"column 0 inside the body:\n{probe.stderr}"
    )
    return body


#: A stand-in kubectl driven by FAKE_MODE.
#:
#: ``read_fail`` — the API call itself fails: an API blip, a dead port-forward, a pod
#: churning under a rollout. This is precisely the case the pre-review helpers turned
#: silently into the count ``0``.
#:
#: Otherwise ``logs`` prints the fixture, and ``exec`` RUNS THE IN-POD SCRIPT LOCALLY
#: (everything after ``--``) so the ledger test exercises the REAL in-pod three-state
#: logic rather than a re-typed imitation of it.
_FAKE_KUBECTL = """#!/bin/sh
if [ "$FAKE_MODE" = "read_fail" ]; then
  echo "error: unable to connect to the server" >&2
  exit 1
fi
for a in "$@"; do
  if [ "$a" = "logs" ]; then
    cat "$FAKE_LOG_FIXTURE"
    exit 0
  fi
done
while [ "$1" != "--" ]; do shift; done
shift
exec "$@"
"""


def _bash_probe(
    *,
    functions: tuple[str, ...],
    call: str,
    fake_mode: str = "ok",
    log_lines: str = "",
    ledger_path: str = "/nonexistent",
    preamble: str = "",
) -> subprocess.CompletedProcess[str]:
    """Run the REAL extracted runner functions in a bash subshell with a fake kubectl.

    `die` / `bar_fail` are stubbed to exit non-zero (production's bar_fail also writes a
    diagnostics dump, which needs a live cluster; the exit is the part under test)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "kubectl").write_text(_FAKE_KUBECTL)
        (bin_dir / "kubectl").chmod(0o755)
        (tmp / "logs.txt").write_text(log_lines)
        (tmp / "qc").mkdir()
        script = "\n".join(
            [
                "set -euo pipefail",
                f'export PATH="{bin_dir}:$PATH"',
                f'export FAKE_MODE="{fake_mode}"',
                f'export FAKE_LOG_FIXTURE="{tmp / "logs.txt"}"',
                'NS="proof-m85c"',
                f'QC_TMP="{tmp / "qc"}"',
                '_REFUSAL_LOG_WINDOW="1800s"',
                f'PROBE_LEDGER_PATH="{ledger_path}"',
                'die() { echo "DIE: $*" >&2; exit 90; }',
                'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
                preamble,
                *(_extract_shell_function(fn) for fn in functions),
                call,
            ]
        )
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# F1 — the browser TLS trust is no longer self-authorizing.                    #
# --------------------------------------------------------------------------- #


def test_f1_driver_never_ignores_https_errors() -> None:
    # The blanket bypass (any cert accepted) must appear NOWHERE — not even as a
    # disclosed fallback. A computation failure now fails closed instead.
    assert "ignore_https_errors" not in _DRIVER_TEXT


def test_f1_driver_dropped_the_unverified_leaf_fetch_and_bypass_flags() -> None:
    # The function that opened a CERT_NONE socket and pinned whatever leaf it was
    # handed is gone, as are the flags that bypassed pinning entirely.
    for forbidden in ("_spki_pin_from_served_leaf", "--pin-url", "--tls-insecure", "tls_insecure"):
        assert forbidden not in _DRIVER_TEXT, forbidden


def test_f1_driver_pins_on_disk_leaves_and_fails_closed() -> None:
    # Pins come from the runner-minted on-disk leaf certs (--leaf), and an empty
    # pin set raises rather than degrading to a blanket bypass.
    assert "--leaf" in _DRIVER_TEXT
    assert "spki_pins_unavailable" in _DRIVER_TEXT


def test_f1_runner_passes_on_disk_leaves_not_pin_url() -> None:
    assert "--pin-url" not in _RUNNER_TEXT
    assert '--leaf "$PKI_TMP/harness.crt"' in _RUNNER_TEXT
    assert '--leaf "$PKI_TMP/keycloak.crt"' in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F2 — Bar D actually replays the approval (HP-4 exercised for real).          #
# --------------------------------------------------------------------------- #


def test_f2_mint_probe_request_returns_id_and_nonce() -> None:
    # The nonce is the bound argument every replay must re-send; discarding it
    # (the pre-review defect) made every recall mint a FRESH request. The shell
    # literal is: printf '%s\t%s\n' "$rid" "$nonce"  (\t / \n are literal in the
    # single-quoted format string).
    assert 'printf \'%s\\t%s\\n\' "$rid" "$nonce"' in _RUNNER_TEXT


def test_f2_recall_probe_threads_the_approval_request_id() -> None:
    # recall_probe now takes (role, request_id, nonce) and sends approval_request_id
    # in the body so the kernel matches the SAME request, not a fresh one.
    assert 'local role="$1" rid="$2" nonce="$3"' in _RUNNER_TEXT
    assert '"approval_request_id":sys.argv[1]' in _RUNNER_TEXT


def test_f2_bar_d_recalls_pass_both_request_id_and_nonce() -> None:
    # Every recall in Bar D must carry the captured request-id + nonce pair. The
    # pre-review calls passed a bare fresh nonce string (e.g. "denied-recall-1").
    assert 'recall_probe amir "$D_REQ1" "$D_NONCE1"' in _RUNNER_TEXT
    assert 'recall_probe amir "$D_REQ2" "$D_NONCE2"' in _RUNNER_TEXT
    assert 'recall_probe sara "$D_REQ2" "$D_NONCE2"' in _RUNNER_TEXT
    for stale in ('"denied-recall-1"', '"still-pending-1"', '"$D_NONCE2"' + ")"):
        assert f"recall_probe amir {stale}" not in _RUNNER_TEXT


def test_f2_bar_d_pins_the_exact_replay_reasons() -> None:
    # The denied / pending / originator-mismatch legs assert the EXACT wire reason,
    # not just a status code.
    for reason in (
        "tool_approval_denied",
        "tool_approval_pending",
        "tool_approval_originator_mismatch",
    ):
        assert reason in _RUNNER_TEXT, reason


# --------------------------------------------------------------------------- #
# F3 — the probe pack is admitted on the boot allow-list.                      #
# --------------------------------------------------------------------------- #


def test_f3_probe_is_added_to_the_plugin_allowlist_when_released() -> None:
    assert 'COGNIC_PROOF_M85C_PROBE_RELEASED:-0}" = "1"' in _STAGE_TEXT
    assert '_ALLOWLIST_PACKS+=("$PROBE_PACK_ID")' in _STAGE_TEXT


# --------------------------------------------------------------------------- #
# F4 — the BFF can read its own TLS key (fsGroup) and the runner pins it.      #
# --------------------------------------------------------------------------- #


def test_f4_bff_pod_has_fsgroup_and_runs_nonroot() -> None:
    text = _BFF_YAML.read_text()
    assert "fsGroup: 10001" in text
    assert "runAsNonRoot: true" in text
    assert "runAsUser: 10001" in text


def test_f4_runner_pins_the_tls_key_readability_from_inside_the_pod() -> None:
    assert "test -r /etc/harness-tls/tls.key" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F5 — Bar A implements S5/S7 correctly and discloses S4/S6/S10.               #
# --------------------------------------------------------------------------- #


def test_f5_s7_uses_a_fail_closed_login_capture_not_a_bar_failing_login() -> None:
    # drive_login_capture NEVER bar_fails on a non-zero rc, so the CORRECT
    # fail-closed login during the Redis outage does not abort the whole proof.
    # Pinned on the CONTRACT (the outage login goes through the capturing helper),
    # not on which identity it happens to use — Codex round 2 moved the outage
    # login to a different identity because `sara` now serves S7's control session.
    assert "drive_login_capture()" in _RUNNER_TEXT
    assert 'A_OUTAGE="$(drive_login_capture ' in _RUNNER_TEXT
    assert 'A_OUTAGE="$(drive_login ' not in _RUNNER_TEXT


def test_f5_s5_replays_the_consumed_oidc_callback() -> None:
    assert "replay-callback" in _DRIVER_TEXT
    assert "callback_url" in _DRIVER_TEXT
    # The callback URL is a CREDENTIAL (it carries a one-time authz code), so it
    # rides the child's environment now — the flag that used to carry it is deleted.
    assert 'drive_replay_callback "$A_CB" "$A_PRE"' in _RUNNER_TEXT


def test_f5_cross_replica_uses_per_pod_port_forward() -> None:
    # The session is proven against EACH named replica, not just "deployed twice".
    assert "bff_pf_pod()" in _RUNNER_TEXT
    assert "session authenticated against replica" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F6 — Bar B pins the exact binder gate and proves kernel RBAC + human binding. #
# --------------------------------------------------------------------------- #


def test_f6_bar_b_asserts_the_specific_binder_refusal_reasons() -> None:
    assert "assert_binder_refusal()" in _RUNNER_TEXT
    for reason in ("typ_not_at_jwt", "token_malformed", "kid_unknown", "audience_not_exact"):
        assert f"assert_binder_refusal {reason}" in _RUNNER_TEXT, reason


def test_f6_human_binding_uses_a_human_gated_action_not_a_scope_only_read() -> None:
    # A queue GET needs only tool.approve.observe; proving human binding requires a
    # human-gated action (deny).
    assert "human-binding probe" in _RUNNER_TEXT
    assert "actor_type=human" in _RUNNER_TEXT


def test_f6_manipulated_post_targets_a_real_request_and_demands_exactly_403() -> None:
    # The pre-review probe targeted a nonexistent id and accepted 404 (proves
    # nothing about RBAC). It now targets a real request and demands the kernel 403.
    assert '"/approvals/$B_THROW/grant"' in _RUNNER_TEXT
    assert "/approvals/does-not-exist/grant" not in _RUNNER_TEXT


def test_f6_pkce_login_accepts_an_optional_scope_for_wrong_audience() -> None:
    text = _PKCE.read_text()
    assert "len(argv) not in (6, 7)" in text
    assert "openid wrong-audience" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F7 — the remaining bars cannot pass without their claimed evidence.          #
# --------------------------------------------------------------------------- #


def test_f7_xss_requires_the_hostile_markup_to_actually_render() -> None:
    # script_executed=false is vacuous if nothing rendered; require the markup to
    # be present as inert escaped text.
    assert "rendered_text_contains_markup" in _RUNNER_TEXT


def test_f7_csrf_demands_the_exact_governed_reason() -> None:
    assert 'A_CSRF_REASON" = "csrf_invalid"' in _RUNNER_TEXT


def test_f7_pagination_asserts_exact_id_set_equality_and_link_posture() -> None:
    assert "set(ids) == set(minted)" in _RUNNER_TEXT
    assert 'doc["link_on_first_page"] is True' in _RUNNER_TEXT
    assert 'doc["link_on_last_page"] is False' in _RUNNER_TEXT


def test_f7_evidence_reconciles_digests_not_just_the_run_id() -> None:
    assert "question_sha256" in _RUNNER_TEXT
    assert "answer_sha256" in _RUNNER_TEXT
    assert "conv_turn_chain_field" in _RUNNER_TEXT


def test_f7_bar_f_pins_screen_set_and_forbids_actor_header_paths() -> None:
    assert "_EXPECTED_ROUTES=" in _RUNNER_TEXT
    assert "x-proof-role|x-actor" in _RUNNER_TEXT
    # htmx: assert absent (no un-pinned vendored asset) until a checksum pin lands.
    assert "htmx is vendored" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F8 — the four-eyes TTL is raised above the browser-workflow duration.        #
# --------------------------------------------------------------------------- #


def test_f8_runner_overrides_the_four_eyes_ttl() -> None:
    # The 60s ADR-014 default is shorter than the Playwright-paced grant sequence.
    assert "COGNIC_APPROVAL_FOUR_EYES_TTL_S=1800" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F9 — new secrets never ride the kubectl argument vector.                     #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "leaked",
    [
        "--from-literal=oidc-client-secret",
        "--from-literal=session-hmac-secret",
        "--from-literal=redis-url",
    ],
)
def test_f9_harness_secrets_are_not_passed_via_from_literal(leaked: str) -> None:
    assert leaked not in _RUNNER_TEXT


def test_f9_harness_secrets_and_admin_password_use_from_file() -> None:
    assert "--from-file=oidc-client-secret=" in _RUNNER_TEXT
    assert "--from-file=session-hmac-secret=" in _RUNNER_TEXT
    assert "--from-file=redis-url=" in _RUNNER_TEXT
    # the keycloak admin password too (was --from-literal=password="$(openssl ...)")
    assert '--from-literal=password="$(openssl' not in _RUNNER_TEXT
    assert "--from-file=password=" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F10 — provenance / supply-chain tightening.                                  #
# --------------------------------------------------------------------------- #


def test_f10_harness_image_is_built_with_its_git_sha() -> None:
    assert '--build-arg BUILD_SHA="$HARNESS_GIT_SHA"' in _RUNNER_TEXT


def _run_resign_probe(
    tmp_path: Path, *, verify_failure: bool = False
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Execute the production re-sign function against a strict fake cosign."""
    pack_id = "cognic-tool-oracle-schema"
    version = "0.3.0"
    wheel = "oracle.whl"
    staging = tmp_path / "staging"
    attestations = staging / "pack-attestations" / pack_id / version
    release_pubs = staging / "release-pubs"
    approve_key = tmp_path / "approve-key"
    attestations.mkdir(parents=True)
    release_pubs.mkdir(parents=True)
    approve_key.mkdir()
    (attestations / wheel).write_bytes(b"digest-pinned-wheel")
    signature = attestations / "cosign.sig"
    signature.write_text("release-signature")
    (release_pubs / f"{pack_id}.pub").write_text("release-public-key")
    (approve_key / "cosign.key").write_text("proof-private-key")
    calls = tmp_path / "cosign-calls"
    fail = "1" if verify_failure else "0"
    preamble = f"""
STAGING_DST={shlex.quote(str(staging))}
APPROVE_KEY_TMP={shlex.quote(str(approve_key))}
COSIGN_CALLS={shlex.quote(str(calls))}
ORIGINAL_SIG={shlex.quote(str(signature))}
FAKE_VERIFY_FAILURE={fail}
cosign() {{
  printf '%s\\n' "$*" >> "$COSIGN_CALLS"
  case "$1" in
    verify-blob)
      case " $* " in
        *" --insecure-ignore-tlog=true "*) ;;
        *) echo "unexpected Rekor-dependent verification" >&2; return 42 ;;
      esac
      [ "$(cat "$ORIGINAL_SIG")" = "release-signature" ] || return 43
      if [ "$FAKE_VERIFY_FAILURE" = "1" ]; then
        echo "offline signature mismatch sentinel" >&2
        return 44
      fi
      return 0
      ;;
    sign-blob)
      while [ "$#" -gt 0 ]; do
        if [ "$1" = "--output-signature" ]; then
          shift
          printf 'proof-signature' > "$1"
          return 0
        fi
        shift
      done
      return 45
      ;;
    *) return 46 ;;
  esac
}}
"""
    result = _bash_probe(
        functions=("_resign_tools_pack",),
        call=f'_resign_tools_pack "{pack_id}" "{version}" "{wheel}"',
        preamble=preamble,
    )
    return result, signature, calls


def test_f10_resign_verifies_the_release_signature_offline_before_overwriting(
    tmp_path: Path,
) -> None:
    # Releases are deliberately signed with --tlog-upload=false. This test goes RED
    # if the runner regrows a Rekor lookup or signs before authenticating the bytes.
    result, signature, calls = _run_resign_probe(tmp_path)
    assert result.returncode == 0, result.stderr
    assert signature.read_text() == "proof-signature"
    call_lines = calls.read_text().splitlines()
    assert call_lines[0].startswith("verify-blob --insecure-ignore-tlog=true --key ")
    assert call_lines[1].startswith("sign-blob --key ")
    assert "release-pubs" in _STAGE_TEXT


def test_f10_resign_failure_is_diagnostic_and_never_overwrites(
    tmp_path: Path,
) -> None:
    result, signature, calls = _run_resign_probe(tmp_path, verify_failure=True)
    assert result.returncode == 90
    assert "offline signature mismatch sentinel" in result.stderr
    assert signature.read_text() == "release-signature"
    assert len(calls.read_text().splitlines()) == 1


def test_f10_proof_build_context_has_a_dockerignore_excluding_pycache() -> None:
    assert _DOCKERIGNORE.exists(), "the proof build context needs a .dockerignore"
    text = _DOCKERIGNORE.read_text()
    assert "__pycache__/" in text


def test_f10_loaded_tag_is_asserted_equal_to_the_verified_digest() -> None:
    assert "_H_TAG_ID" in _RUNNER_TEXT and "_H_REF_ID" in _RUNNER_TEXT


# --------------------------------------------------------------------------- #
# F11 — the reference binder binds a STABLE subject; the seed is coupled to it. #
# --------------------------------------------------------------------------- #


def test_f11_binder_binds_the_issuer_qualified_sub() -> None:
    text = _BINDER.read_text()
    # subject = f"{config.issuer}#{sub}" — issuer-qualified, non-reassignable.
    assert 'subject = f"{config.issuer}#{sub}"' in text
    # and the mutable claim no longer determines the subject.
    assert "subject = username if" not in text


def test_f11_binder_logs_a_value_free_refusal_marker() -> None:
    text = _BINDER.read_text()
    assert "reference_binder.refused reason=" in text


def test_f11_seed_is_keyed_by_the_bound_subject_not_the_login_name() -> None:
    seed = _KERNEL_SEED.read_text()
    assert "__SUBJECT_ANALYST_AMIR__" in seed
    assert "__SUBJECT_ANALYST_SARA__" in seed
    # the runner renders the seed from realm-subjects.env and resolves subjects
    # through bound_subject for every out-of-band DB operation.
    assert "COGNIC_PROOF_M85C_REALM_SUBJECTS=" in _RUNNER_TEXT
    assert "bound_subject()" in _RUNNER_TEXT
    assert 'entitlement_delete "$C_AMIR_SUB" financials' in _RUNNER_TEXT


def test_f11_seed_db_fails_loud_on_unsubstituted_placeholders() -> None:
    seed_db = _SEED.read_text()
    assert "COGNIC_PROOF_M85C_REALM_SUBJECTS" in seed_db
    assert "__SUBJECT_" in seed_db  # the placeholder pattern the renderer guards on


# =========================================================================== #
# ROUND 2 (2026-07-12) — the reviewer rejected the round-1 packet.            #
#                                                                             #
# Nine further findings. The load-bearing one: Bar A delegated S4 / S6 / S10  #
# and Bar B delegated the expired-token case to unit / conformance suites,    #
# while the RATIFIED spec (§5.2) requires all ten session cases and the       #
# expired-token refusal LIVE on kind. A README disclosure cannot lower a      #
# ratified contract, and all four turned out to be perfectly liveable — the   #
# delegation was convenience, not infeasibility. These pins make the live     #
# legs structural so they cannot quietly regress back into a disclosure.      #
# =========================================================================== #

_REDIS_BFF_YAML = _PROOF / "manifests" / "redis-bff.yaml"
_GEN_REALM = _PROOF / "keycloak" / "gen_realm.py"


# --- R1: S4 / S6 / S10 / expired are LIVE, not delegated -------------------- #


def test_r1_no_conformance_or_unit_delegation_remains_in_the_bars() -> None:
    """The exact inversion of the round-1 posture: the runner must no longer
    claim any S-case or the expired-token case is 'covered elsewhere'."""
    for ducked in (
        "conformance-suite-covered",
        "NOT re-run in the live kind bar",
        "not re-run live",
        "disclosed — not re-run live",
    ):
        assert ducked not in _RUNNER_TEXT, f"a live case is still delegated away: {ducked!r}"


def test_r1_s4_proves_idle_and_absolute_ttls_independently_live() -> None:
    # Both legs, and the operator-surface lever that makes them observable.
    assert "bff_set_ttls()" in _RUNNER_TEXT
    assert "COGNIC_HARNESS_SESSION_IDLE_TTL_S=$1" in _RUNNER_TEXT
    assert "COGNIC_HARNESS_SESSION_ABSOLUTE_TTL_S=$2" in _RUNNER_TEXT
    # The shrunken TTLs are now named constants. Their VALUES are not pinned here —
    # test_f2_the_committed_s4_constants_satisfy_the_exclusion re-derives the
    # arithmetic instead, so the numbers can be tuned for headroom without a
    # rubber-stamp edit here, but can never be tuned into a false positive.
    assert "_S4_IDLE_TTL_S=" in _RUNNER_TEXT
    assert "_S4_ABSOLUTE_TTL_S=" in _RUNNER_TEXT
    assert 'bff_set_ttls "$_S4_IDLE_TTL_S" "$_S4_ABSOLUTE_TTL_S"' in _RUNNER_TEXT  # shrink
    assert "bff_set_ttls 900 28800" in _RUNNER_TEXT  # and RESTORE
    # leg 1: idle bites while the absolute window is still open
    assert "an IDLE session survived past the ${_S4_IDLE_TTL_S}s idle TTL" in _RUNNER_TEXT
    # leg 2: absolute bites a CONTINUOUSLY ACTIVE session (the independence proof)
    assert "bff_touch " in _RUNNER_TEXT
    assert (
        "survived past the ${_S4_ABSOLUTE_TTL_S}s ABSOLUTE TTL despite continuous activity"
        in _RUNNER_TEXT
    )


def test_r1_s6_races_both_replicas_and_counts_refreshes_at_keycloak() -> None:
    # A genuine CROSS-REPLICA race needs two simultaneous forwards — a burst at
    # the Service could land every request on one pod.
    assert "bff_pf_dual()" in _RUNNER_TEXT
    assert "$BFF_POD_A_URL/" in _RUNNER_TEXT
    assert "$BFF_POD_B_URL/" in _RUNNER_TEXT
    # The observer is KEYCLOAK's event log, not the BFF's own report.
    assert "kc_refresh_event_count()" in _RUNNER_TEXT
    assert 'A_S6_REFRESHES" = "1"' in _RUNNER_TEXT  # exactly one winner
    assert 'A_S6_ERRS" = "0"' in _RUNNER_TEXT  # no spent-token reuse


def test_r1_s10_is_a_single_variable_schema_version_experiment() -> None:
    # The runner addresses ONE record by deriving its real key, and changes ONLY
    # the version field — so the refusal cannot be explained by anything else.
    assert "session_redis_key()" in _RUNNER_TEXT
    # THE MUTATION IS A BYTE REPLACEMENT, NOT A RE-SERIALISATION (round 5, F3 — this
    # assertion was SUPERSEDED: it pinned `record["v"] = 999`, i.e. the dict mutation whose
    # `json.dumps(..., separators=(",", ":"))` round trip changed EVERY SEPARATOR BYTE in
    # the record while the leg claimed "same bytes". The claim is now literally true, and
    # the pin has to be too — see TestRound5F3S10ByteExactMutation for the behavioural
    # proof against a record serialised the way the BFF actually serialises it.)
    # Both re-serialisation shapes must be gone from every EXECUTABLE line OF THE S10 LEG.
    # Scoped to the leg, not the whole runner: Bar B's kid_unknown probe legitimately
    # re-encodes a JWT HEADER with compact separators, which has nothing to do with the
    # session record. Comments may still NAME the shapes — the note explaining what was
    # replaced, and why, is what stops someone reinstating it.
    s10 = _RUNNER_TEXT.split("# S10 — an unknown session-record schema version REFUSES", 1)[
        1
    ].split("# S4 — idle and absolute TTLs behave INDEPENDENTLY", 1)[0]
    reserialised = [
        ln.strip()
        for ln in s10.splitlines()
        if not ln.lstrip().startswith("#")
        and ('record["v"] = 999' in ln or 'separators=(",", ":")' in ln)
    ]
    assert not reserialised, (
        "S10 is re-serialising the record again. A json.dumps round trip rewrites EVERY "
        "separator byte (the harness stores with the DEFAULT separators; a compact re-encode "
        f"changes all of them), so the leg's single-variable claim would be false: {reserialised}"
    )
    assert 'raw[:start] + b"999" + raw[end:]' in s10
    # THE DEADLINE IS PRESERVED EXACTLY, AND ATOMICALLY (round 4, F4 — this assertion
    # was INVERTED before: it pinned the very PTTL-then-PSETEX pattern that broke the
    # single-variable claim). The old write read PTTL at T_r, did client-side work, and
    # wrote `PSETEX <key> <that stale ttl> <value>` at T_w — so the new deadline was
    # T_w + PTTL while the original was T_r + PTTL, EXTENDING the record's life by
    # (T_w - T_r). Measured live on redis:7.4-alpine: PTTL 4932 -> 4866 after a 1s
    # gap, where a preserving write yields ~3950. S10 was changing TWO variables.
    #
    # The rewrite is now ONE server-side EVAL: read the TTL, refuse a dead/eternal key,
    # and `SET … KEEPTTL` — no client-side window at all.
    assert "_S10_REWRITE_LUA=" in _RUNNER_TEXT
    assert 'redis.call("SET", KEYS[1], ARGV[1], "KEEPTTL")' in _RUNNER_TEXT
    assert 'redis_bff_cli_stdin EVAL "$_S10_REWRITE_LUA" 1 "$A_S10_KEY"' in _RUNNER_TEXT
    # the live-record precondition is evaluated INSIDE the script, so it cannot be raced
    assert 'redis.error_reply("s10_key_gone")' in _RUNNER_TEXT  # -2
    assert 'redis.error_reply("s10_no_expiry")' in _RUNNER_TEXT  # -1
    # ... and the old non-atomic pattern is GONE from every EXECUTABLE line (the
    # comments still name PSETEX to explain what was replaced, and must stay free to).
    for line in _RUNNER_TEXT.splitlines():
        if line.strip().startswith("#"):
            continue
        assert "PSETEX" not in line, f"the non-atomic PSETEX write survives: {line.strip()!r}"
        assert "redis_bff_cli PTTL" not in line, (
            f"a client-side PTTL re-read survives — the read/write window is back: {line.strip()!r}"
        )
    assert 'redis_bff_cli SET "$A_S10_KEY"' not in _RUNNER_TEXT
    assert "control failed: the throwaway session does not authenticate BEFORE the mutation" in (
        _RUNNER_TEXT
    )
    assert "STILL authenticated with an UNKNOWN schema version" in _RUNNER_TEXT
    # The observer needs VERIFIED TLS into the store — the session Redis is
    # TLS-only with the plaintext port disabled, and the observer must not
    # downgrade to reach it. (Scoped to the redis client: `cosign verify
    # --insecure-ignore-tlog` elsewhere in the runner is an offline-tlog flag,
    # not a TLS bypass.)
    assert "--tls --cacert /etc/proof-ca/proof-ca.pem" in _RUNNER_TEXT
    redis_cli_lines = [ln for ln in _RUNNER_TEXT.splitlines() if "redis-cli" in ln]
    assert redis_cli_lines, "the S10 observer's redis-cli invocation is gone"
    for line in redis_cli_lines:
        assert "--insecure" not in line, f"the redis observer downgraded TLS: {line.strip()!r}"
    assert "/etc/proof-ca" in _REDIS_BFF_YAML.read_text()


def test_r1_expired_token_is_proven_live_at_the_binder_exp_gate() -> None:
    assert "kc_set_access_token_lifespan 10" in _RUNNER_TEXT
    assert "assert_binder_refusal token_expired" in _RUNNER_TEXT
    # and the leg refuses to be vacuous: it proves the token really IS short-lived
    # before spending the wait, and really HAS expired after it.
    assert "the access.token.lifespan override did not take effect" in _RUNNER_TEXT
    assert "has NOT expired after the wait" in _RUNNER_TEXT


def test_r1_realm_ships_the_two_levers_the_live_cases_need() -> None:
    realm = _GEN_REALM.read_text()
    assert '"access.token.lifespan"' in realm  # the per-client override home
    assert '"eventsEnabled": True' in realm  # the independent refresh observer
    assert "REFRESH_TOKEN_ERROR" in realm


# --- R2: S5 reaches consume_oidc() (it did not before) ---------------------- #


def test_r2_s5_replays_the_callback_with_the_pre_auth_cookie() -> None:
    """Without the pre-auth cookie the BFF refuses `no_login_session` BEFORE
    consume_oidc() is reached, so a BFF that never consumed state/nonce would
    pass. The cookie is what makes S5 mean anything."""
    # Both the callback URL and the cookie are CREDENTIALS, so they ride the child's
    # environment (F1) — the wrapper is the only way in, and it REFUSES an empty
    # cookie, which is what keeps the cookieless (vacuous) shape unreachable here.
    assert 'drive_replay_callback "$A_CB" "$A_PRE"' in _RUNNER_TEXT
    assert "drive_replay_callback() {" in _RUNNER_TEXT
    assert 'COGNIC_PROOF_COOKIE_VALUE="$cookie"' in _RUNNER_TEXT
    assert "a cookieless replay is refused at the BFF's session gate" in _RUNNER_TEXT
    # and the observable must name the SINGLE-USE gate, not merely "it refused"
    assert "assert_bff_refusal login_state_already_consumed" in _RUNNER_TEXT
    assert "assert_bff_refusal()" in _RUNNER_TEXT
    assert "auth.callback.refused reason=" in _RUNNER_TEXT
    # the pre-auth id is required, never silently skipped
    assert "the rotation (S1) and single-use-state (S5) cases cannot be judged" in _RUNNER_TEXT


# --- R3: S7 / S9 / S3 cannot pass without their event ----------------------- #


def test_r3_s7_demands_the_exact_503_on_a_live_session() -> None:
    # A control (200 with the store up) then the EXACT governed 503 with it down.
    # 'any driver failure' no longer satisfies the leg.
    assert 'A_S7_UP" = "200"' in _RUNNER_TEXT
    assert 'A_S7_DOWN" = "503"' in _RUNNER_TEXT
    assert "the BFF continued from memory (FORBIDDEN)" in _RUNNER_TEXT


def test_r3_s9_proves_a_pod_actually_died() -> None:
    # The pre-review leg swallowed a failed delete with `|| true`, so a no-op
    # restart passed. The UID check is what makes the restart real.
    assert "A_POD_A_UID" in _RUNNER_TEXT
    assert "the victim pod delete FAILED" in _RUNNER_TEXT
    assert "is STILL running — nothing actually restarted" in _RUNNER_TEXT
    assert 'kubectl -n "$NS" delete "$A_POD_A" --wait=true >/dev/null 2>&1 || true' not in (
        _RUNNER_TEXT
    )


def test_r3_s2_and_s3_require_two_distinct_replicas() -> None:
    # `continue`-ing past a missing replica while reporting "BOTH" is gone.
    assert "cross-replica revocation cannot be judged against one pod" in _RUNNER_TEXT
    assert "a single-replica check cannot prove the session is shared" in _RUNNER_TEXT
    assert '[ -n "$_pod" ] || continue' not in _RUNNER_TEXT


# --- R4: Bar C proves a VISIBLE refusal, not merely a non-empty answer ------ #


def test_r4_bar_c_requires_the_refusal_to_render_on_the_evidence_screen() -> None:
    """The pre-review leg asserted only a non-empty answer + a DB refusal row, so a
    model that hallucinated a plausible figure while the dispatch was refused
    underneath would have passed, and nothing tied the rendered page to the chain."""
    assert 'drive evidence --conversation-id "$C_CID" --seq 2' in _RUNNER_TEXT
    # the rendered dispatch must carry the refusal AND the scope it was refused for
    assert 'd.get("refusal_reason") == "agent_scope_not_entitled"' in _RUNNER_TEXT
    assert 'd.get("scope_id") == "financials"' in _RUNNER_TEXT
    # ... and no OK financials read may be rendered
    assert "renders an OK financials dispatch after revocation" in _RUNNER_TEXT
    # ... correlated by exact id + chain-row sequence + BOTH digests (turn 2, which
    # the pre-review bar never coupled — it coupled turn 1 only).
    assert "conv_turn_chain_sequence()" in _RUNNER_TEXT
    assert 'tc["agent_run_id"] == run_id' in _RUNNER_TEXT
    assert 'q == tc["question_sha256"]' in _RUNNER_TEXT
    assert 'a == tc["answer_sha256"]' in _RUNNER_TEXT


def test_r4_scope_column_is_rendered_by_the_harness_and_surfaced_by_the_driver() -> None:
    """Turn 2 dispatches the SAME capability twice (retail ok, financials refused).
    Without the scope column those are two identical rows and the refusal cannot be
    attributed. The driver reads the LIVE ``<thead>``, so if the harness ever drops
    the column again ``scope_id`` VANISHES from the emitted rows (it is never
    fabricated as ``None``) and the runner fails loud.

    OWNERSHIP (review 2026-07-12, F5). This test pins only what THIS repo owns: the
    driver surfaces the scope column, and the runner refuses to trust a scope the
    screen does not render. The ``evidence_chain.html`` TEMPLATE is owned by the
    ``cognic-harness`` repo and is guarded there — by that repo's own CI, and live by
    Bar C, whose ``"scope_id" in cols`` assertion fails loud the moment the column
    regresses. An earlier version of this test reached into an ABSOLUTE workstation
    path (a developer home directory holding a ``cognic-harness`` checkout) inside an
    ``if template.exists():`` — on any CI runner that path is absent, so the template
    assertions silently vanished and the test became a vacuous gate. A test in repo A
    reading repo B's working tree at an absolute path is neither reproducible nor
    CI-valid; the guard below makes the anti-pattern unrepresentable."""
    assert '"scope": "scope_id"' in _DRIVER_TEXT
    assert 'DISPATCH_HEADERS_RENDERED_TODAY = ("step", "kind", "capability", "scope"' in (
        _DRIVER_TEXT
    )
    # the runner refuses to trust a scope value the screen does not actually render
    assert '"scope_id" in cols' in _RUNNER_TEXT
    assert "the evidence screen renders no scope column" in _RUNNER_TEXT


def test_f5_no_test_in_this_package_reaches_an_absolute_workstation_path() -> None:
    """No test under ``tests/unit/infra/`` may reach an absolute workstation path.

    Such a path is absent on every CI runner, so any assertion behind it silently
    disappears — the exact vacuous-gate defect found in the scope-column test above
    (F5). This guard makes the anti-pattern impossible to reintroduce anywhere in the
    package, not just in the one test that had it.

    The needle is assembled at runtime precisely so this guard does not match its own
    source."""
    needle = "/" + "Users" + "/"  # deliberately not a literal — see the docstring
    offenders: list[str] = []
    for path in sorted(Path(__file__).parent.rglob("*.py")):
        if needle in path.read_text():
            offenders.append(str(path.relative_to(_REPO)))
    assert not offenders, (
        f"absolute workstation path ({needle}…) in: {offenders}. A test that reads a path "
        "outside this repo is not reproducible and silently no-ops on CI — assert on what "
        "this repo owns, and let the other repo's own CI (and the live bar) guard the rest."
    )


# --- R5: Bar E validates the RENDERED transcript, not just its emptiness ---- #


def test_r5_bar_e_rehashes_the_rendered_transcript_against_the_chain() -> None:
    """Comparing the chain screen's digests to the DB is the kernel's numbers
    against the kernel's numbers. Hashing the WORDS ON THE PAGE is what binds the
    screen to the chain — a stale or wrong transcript now fails."""
    assert "assert_rendered_transcript_matches_chain()" in _RUNNER_TEXT
    assert 'assert_rendered_transcript_matches_chain "$E_EVID" "$C_CID"' in _RUNNER_TEXT
    assert 'hashlib.sha256(turn["question_text"].encode()).hexdigest()' in _RUNNER_TEXT
    assert 'hashlib.sha256(turn["answer_text"].encode()).hexdigest()' in _RUNNER_TEXT
    assert "the transcript is not the governed text" in _RUNNER_TEXT
    # bound to the run id rendered on BOTH screens, so the hashed text provably
    # belongs to the turn whose digests it matched
    assert "the hashed text is not bound to the turn whose digests it matched" in _RUNNER_TEXT
    # the driver must emit the VERBATIM rendered text (no strip/normalise), or the
    # re-hash would be meaningless.
    assert "question_text" in _DRIVER_TEXT
    assert "answer_text" in _DRIVER_TEXT


# --- R7: the approval queue's ORDER, not just its membership ---------------- #


def test_r7_pagination_asserts_the_kernel_keyset_order() -> None:
    # Set equality passes on a reversed walk; the spec requires correct ordering.
    assert "approval_queue_order()" in _RUNNER_TEXT
    assert "ORDER BY created_at ASC, request_id ASC" in _RUNNER_TEXT
    assert "paginated ORDER != the kernel keyset order" in _RUNNER_TEXT


# --- R8: the probe's trust pins are maintainer-locked, not operator-supplied - #


def test_r8_probe_digests_are_committed_literals_not_env_reads() -> None:
    """An env-supplied digest is not a pin: whoever runs the proof could swap the
    release and export the matching value.

    v0.1.0 released 2026-07-13 (tag at 03a7058): the FILL_AT_RELEASE sentinels
    were replaced by the maintainer-committed digests of the published assets,
    independently recomputed from fresh public downloads at review time. Pinning
    the exact literals here makes this test a tamper-detector: a swapped release
    cannot ride an unreviewed stage-packs.sh edit."""
    assert "COGNIC_PROOF_M85C_PROBE_WHEEL_SHA256" not in _STAGE_TEXT
    assert "COGNIC_PROOF_M85C_PROBE_PUB_SHA256" not in _STAGE_TEXT
    assert (
        'PROBE_WHEEL_SHA256="e670616ee6d89d70ef364c0b100c6f08d5af64fdd21faf0ea1551ba753946d26"'
        in _STAGE_TEXT
    )
    assert (
        'PROBE_PUB_SHA256="b1ab8c2fe3342004e79b04e9c0873334087e9cea8400ede86fd3bd2f4479154a"'
        in _STAGE_TEXT
    )
    # ... and the arm still refuses to run against an unreplaced sentinel.
    assert 'PROBE_WHEEL_SHA256" != "FILL_AT_RELEASE"' in _STAGE_TEXT


# --------------------------------------------------------------------------- #
# F4 (round 3) — the probe-pin conversion is FINISHED, not half-done.          #
#                                                                             #
# R8 above converted stage-packs.sh to committed literals — but the RUNNER     #
# still hard-required the retired env digests and exited 1 without them, and   #
# the README still told operators to export them. So the operator was forced   #
# to export values that were then ignored, and the docs were wrong.            #
# --------------------------------------------------------------------------- #

_README = _PROOF / "README.md"
_README_TEXT = _README.read_text()


@pytest.mark.parametrize("retired", ["PROBE_WHEEL_SHA256", "PROBE_PUB_SHA256"])
def test_f4_the_retired_probe_env_digests_are_gone_from_runner_and_readme(retired: str) -> None:
    """The env gate is DELETED everywhere — script and docs. Requiring an operator to
    export a value that is then ignored is worse than not asking for it: it reads as
    a trust control while enforcing nothing."""
    env_name = f"COGNIC_PROOF_M85C_{retired}"
    assert env_name not in _RUNNER_TEXT, f"the runner still reads the retired {env_name}"
    assert env_name not in _README_TEXT, f"the README still tells operators to export {env_name}"


def test_f4_runner_preflights_the_committed_literals_and_derives_released() -> None:
    """The runner reads the two MAINTAINER-COMMITTED literals out of stage-packs.sh
    and fails loud while either is the sentinel — and `released` is DERIVED from the
    pins being real, never from an operator-exported flag."""
    assert "_probe_pin()" in _RUNNER_TEXT
    assert 'PROBE_WHEEL_PIN="$(_probe_pin PROBE_WHEEL_SHA256)"' in _RUNNER_TEXT
    assert 'PROBE_PUB_PIN="$(_probe_pin PROBE_PUB_SHA256)"' in _RUNNER_TEXT
    assert '"$_pin_value" = "FILL_AT_RELEASE"' in _RUNNER_TEXT
    assert "the live-run prerequisite is a MAINTAINER COMMIT" in _RUNNER_TEXT.replace(
        "The live-run prerequisite is a MAINTAINER COMMIT",
        "the live-run prerequisite is a MAINTAINER COMMIT",
    )
    # `released` is ASSIGNED (derived), never read from the environment.
    assert "export COGNIC_PROOF_M85C_PROBE_RELEASED=1" in _RUNNER_TEXT
    assert "${COGNIC_PROOF_M85C_PROBE_RELEASED" not in _RUNNER_TEXT


def test_f4_readme_prerequisite_names_the_maintainer_commit() -> None:
    """The README must not instruct the operator to export a pin — the prerequisite
    is a maintainer COMMIT of the two released digests."""
    assert "MAINTAINER" in _README_TEXT
    # the old copy-paste reproduce block must not carry the retired exports
    assert "COGNIC_PROOF_M85C_PROBE_WHEEL_SHA256=<from release.sh>" not in _README_TEXT


# --- R9: provenance + documentation pins ------------------------------------ #


def test_r9_cleanliness_guard_covers_every_proof_input_suite() -> None:
    guard_line = next(
        line for line in _RUNNER_TEXT.splitlines() if line.startswith("PROOF_INPUT_DIRTY=")
    )
    for suite in (
        "test_proof_m85c_structure.py",
        "test_proof_m85c_reference_binder.py",
        "test_proof_m85c_remediation.py",
    ):
        assert suite in guard_line, f"{suite} is not covered by the proof-input cleanliness guard"


def test_r9_playwright_readme_documents_no_deleted_flags() -> None:
    """The README must not INSTRUCT an operator to reach for a flag the driver no
    longer has (they would hit an argparse error, or worse, assume a TLS bypass is
    still available). Naming them to say they are GONE is allowed and useful — the
    note is what stops someone re-adding them — so the pin forbids every mention
    EXCEPT on a line that marks them deleted."""
    readme = (_PROOF / "playwright" / "README.md").read_text()
    for gone in ("--pin-url", "--tls-insecure"):
        for line in readme.splitlines():
            if gone not in line:
                continue
            assert "deleted" in line.lower() or "removed" in line.lower(), (
                f"the README still presents the DELETED {gone} flag as usable: {line.strip()!r}"
            )
    assert "--leaf" in readme


# --- secret custody: the new admin plumbing keeps secrets off argv ---------- #


def test_round2_keycloak_admin_secrets_never_ride_argv() -> None:
    """The admin password and the admin bearer are secrets. `ps` on a shared host
    would expose either if it rode the argument vector."""
    assert '-H "Authorization: Bearer' not in _RUNNER_TEXT  # the standing pin
    assert "kc_admin_get()" in _RUNNER_TEXT  # bearer via curl -K - on stdin
    assert '--data-urlencode "password=' not in _RUNNER_TEXT
    assert "grant_type=password&client_id=admin-cli&username=admin&password=%s" in _RUNNER_TEXT


# =========================================================================== #
# ROUND 3 (2026-07-12) — six more findings.                                   #
#                                                                             #
# The load-bearing one (F1): the runner states its own custody rule ("the     #
# client secret + the user password ride the ENVIRONMENT of the child — never #
# argv; a `ps` snapshot would expose an argv secret") and a standing pin      #
# enforces it for the Authorization bearer — yet FOUR other credential        #
# classes still rode argv. A process's argument vector is world-readable;     #
# its environment is not. That is the whole basis of the rule.                #
# =========================================================================== #


# --- F1: NO credential class rides a process argument vector ---------------- #
#
# The four classes the review found, each pinned below:
#   1. access JWTs            (token_has_life passed the token as python3 argv)
#   2. session cookies        (bff_status/bff_touch on curl argv; session_redis_key
#                              on python argv; the driver's --cookie-value flag)
#   3. authz-code callback URLs  (the driver's --callback-url flag — `?code=…` is
#                              exchangeable for tokens)
#   4. whole session records  (S10's `SET key <record> KEEPTTL` put the record —
#                              which carries the OAuth access + refresh + id tokens —
#                              on the operator's kubectl argv AND the pod's redis-cli
#                              argv)


def test_f1_jwts_never_ride_argv_token_has_life_reads_stdin() -> None:
    """Class 1 — access JWTs. The token is a live bearer credential; only the numeric
    floor (not a secret) may stay on argv."""
    assert "printf '%s' \"$1\" | python3 -c '" in _RUNNER_TEXT
    assert "tok, floor = sys.stdin.read(), int(sys.argv[1])" in _RUNNER_TEXT
    # the pre-review shape read BOTH from argv
    assert "tok, floor = sys.argv[1], int(sys.argv[2])" not in _RUNNER_TEXT


def test_f1_session_cookies_never_ride_curl_argv() -> None:
    """Class 2a — the session cookie on curl's argv. Possession of the `__Host-`
    value IS the session: it is a bearer credential exactly like a token, and it must
    go through curl's stdin config (-K -) like the Authorization bearer already does."""
    assert '-H "Cookie:' not in _RUNNER_TEXT, "a session cookie must not ride curl -H argv"
    assert 'printf \'header = "Cookie: %s=%s"\\n" "$BFF_COOKIE_NAME" "$1"'.replace(
        '"\\n"', "'\\n'"
    ) in _RUNNER_TEXT or 'printf \'header = "Cookie: %s=%s"\\n\' "$BFF_COOKIE_NAME" "$1"' in (
        _RUNNER_TEXT
    )
    # both cookie-bearing curl helpers feed the header on stdin
    assert _RUNNER_TEXT.count("printf 'header = \"Cookie: %s=%s\"\\n'") >= 2


def test_f1_session_cookies_never_ride_python_argv() -> None:
    """Class 2b — the session cookie on python's argv (session_redis_key). The
    HMAC-secret PATH may stay on argv: a path is not a credential."""
    assert "session_id = sys.stdin.read()" in _RUNNER_TEXT
    assert "hmac.new(secret, sys.argv[2].encode(), hashlib.sha256)" not in _RUNNER_TEXT


@pytest.mark.parametrize("deleted_flag", ["--cookie-value", "--callback-url"])
def test_f1_the_credential_bearing_driver_flags_are_deleted(deleted_flag: str) -> None:
    """Classes 2c + 3 — the driver's own flags. DELETED, not merely optional: a flag
    that still accepts a credential invites a call site that passes one. They are
    replaced by the environment channel the password already uses."""
    assert deleted_flag not in _RUNNER_TEXT, f"the runner still passes {deleted_flag} on argv"
    # In the driver the flag may only be NAMED on a line that says it is gone (the
    # note is what stops someone re-adding it) — never declared via add_argument.
    for line in _DRIVER_TEXT.splitlines():
        if deleted_flag in line and "add_argument" in line:
            raise AssertionError(f"the driver still DECLARES the deleted flag: {line.strip()!r}")


def test_f1_the_driver_reads_both_credentials_from_the_environment() -> None:
    assert 'COOKIE_VALUE_ENV = "COGNIC_PROOF_COOKIE_VALUE"' in _DRIVER_TEXT
    assert 'CALLBACK_URL_ENV = "COGNIC_PROOF_CALLBACK_URL"' in _DRIVER_TEXT
    assert "def _cookie_value_from_env(" in _DRIVER_TEXT
    assert "def _callback_url_from_env(" in _DRIVER_TEXT
    # a SET-but-EMPTY cookie must fail closed (a shell var that expanded to nothing
    # would inject a valueless cookie and make the replay probes vacuous)
    assert "cookie_value_empty" in _DRIVER_TEXT
    # the runner passes them ONLY through the child's environment
    assert 'COGNIC_PROOF_COOKIE_VALUE="$value" uv run' in _RUNNER_TEXT
    assert 'COGNIC_PROOF_CALLBACK_URL="$url" COGNIC_PROOF_COOKIE_VALUE="$cookie"' in _RUNNER_TEXT


def test_f1_the_session_record_never_rides_kubectl_or_redis_cli_argv() -> None:
    """Class 4 — the whole session record. It carries the OAuth access, refresh and
    id tokens (that custody is the whole point of Bar A). `redis-cli -x` reads the
    command's LAST argument from stdin, and for `EVAL <script> 1 <key>` that lands it
    in ARGV[1] — so it appears on NEITHER the host's kubectl argv nor the pod's
    redis-cli argv. `kubectl exec -i` is what forwards the operator's stdin into the
    pod. (Round 4 moved the write from PSETEX to an atomic EVAL for F4; the custody
    shape — value on stdin, everything else on argv — is unchanged, and the SCRIPT and
    the KEY are legitimately on argv: code and a derived HMAC address, not secrets.)

    Verified live on redis:7.4-alpine: with the record piped through `docker exec -i`
    and redis-cli blocked mid-write, the in-container process table contains the Lua
    script and the key but NO trace of the record — while the record is nonetheless
    applied, proving it arrived as ARGV[1] over stdin."""
    assert "redis_bff_cli_stdin()" in _RUNNER_TEXT
    assert 'kubectl -n "$NS" exec -i deploy/redis-bff' in _RUNNER_TEXT
    assert "exec redis-cli -x --tls" in _RUNNER_TEXT
    assert "printf '%s' \"$A_S10_MUT\" \\\n  | redis_bff_cli_stdin EVAL" in _RUNNER_TEXT
    # the record must never be interpolated into an argv-carrying invocation
    assert 'redis_bff_cli SET "$A_S10_KEY" "$A_S10_MUT"' not in _RUNNER_TEXT
    for line in _RUNNER_TEXT.splitlines():
        if line.strip().startswith("#"):
            continue
        assert not ("redis_bff_cli" in line and "$A_S10_MUT" in line and "|" not in line), (
            f"the session record is being passed on an argument vector: {line.strip()!r}"
        )


def test_f1_the_redis_key_may_stay_on_argv_and_says_why() -> None:
    """The Redis KEY is a derived HMAC-SHA256 digest — an address, not a credential.
    It authenticates nothing and is not the cookie. The distinction is stated so a
    future reader does not "fix" it into a needless stdin dance."""
    assert 'redis_bff_cli GET "$A_S10_KEY"' in _RUNNER_TEXT  # key on argv: fine
    assert "an address, not a credential" in _RUNNER_TEXT


# --- F2: S4's absolute-TTL leg cannot pass via IDLE expiry ------------------ #


def test_f2_bff_touch_requires_http_200_and_never_swallows_a_failure() -> None:
    """The pre-review helper ended in `|| true` and never checked the status — so
    touches that silently stopped landing would let the session die of IDLE expiry at
    45s while the final probe at ~165s credited the death to the ABSOLUTE TTL."""
    touch = _RUNNER_TEXT.split("bff_touch() {", 1)[1].split("\n}", 1)[0]
    assert "|| true" not in touch, "bff_touch must not swallow a failed touch"
    assert '[ "$code" = "200" ]' in touch, "bff_touch must REQUIRE HTTP 200"
    assert "bar_fail" in touch
    # and the failure message must say WHY an unverified touch is fatal to the leg
    assert "destroys the leg's timing argument" in touch


def test_f2_the_timing_guard_recomputes_the_idle_exclusion_arithmetic() -> None:
    """The in-script guard fails loud if a future TTL/cadence edit ever breaks the
    exclusion. A silent regression here turns the bar back into a false positive,
    which is the defect being fixed — so the arithmetic is asserted, not assumed."""
    assert "_s4_assert_timing_plan()" in _RUNNER_TEXT
    assert "_s4_assert_timing_plan\n" in _RUNNER_TEXT  # and it is actually CALLED
    guard = _RUNNER_TEXT.split("_s4_assert_timing_plan() {", 1)[1].split("\n}", 1)[0]
    # leg 1: idle < sleep < absolute
    assert '[ "$_S4_IDLE_TTL_S" -lt "$_S4_LEG1_SLEEP_S" ]' in guard
    assert '[ "$_S4_LEG1_SLEEP_S" -lt "$_S4_ABSOLUTE_TTL_S" ]' in guard
    # leg 2: last_touch < absolute < final_probe, and (final_probe - last_touch) < idle
    assert '[ "$_S4_LAST_TOUCH_S" -lt "$_S4_ABSOLUTE_TTL_S" ]' in guard
    assert '[ "$_S4_FINAL_PROBE_S" -gt "$_S4_ABSOLUTE_TTL_S" ]' in guard
    assert '[ "$((_S4_FINAL_PROBE_S - _S4_LAST_TOUCH_S))" -lt "$_S4_IDLE_TTL_S" ]' in guard
    # the cadence must keep the session inside the idle window
    assert '[ "$_S4_TOUCH_EVERY_S" -lt "$_S4_IDLE_TTL_S" ]' in guard


def test_f2_the_committed_s4_constants_satisfy_the_exclusion() -> None:
    """The guard is only worth having if the SHIPPED constants pass it. Re-derive the
    arithmetic here so a bad edit fails in CI, not 20 minutes into a live run."""
    import re

    def const(name: str) -> int:
        m = re.search(rf"^{name}=(\d+)", _RUNNER_TEXT, re.M)
        assert m, f"{name} is not defined in the runner"
        return int(m.group(1))

    idle = const("_S4_IDLE_TTL_S")
    absolute = const("_S4_ABSOLUTE_TTL_S")
    leg1_sleep = const("_S4_LEG1_SLEEP_S")
    every = const("_S4_TOUCH_EVERY_S")
    mid = const("_S4_MID_CHECK_S")
    last_touch = const("_S4_LAST_TOUCH_S")
    probe = const("_S4_FINAL_PROBE_S")

    assert idle < leg1_sleep < absolute, "leg 1 cannot attribute the death to the idle TTL"
    assert every < idle, "the keep-alive cadence would let the session idle out mid-loop"
    assert idle < mid < last_touch, "the mid-flight liveness checkpoint proves nothing"
    assert last_touch < absolute, "the last touch is not inside the absolute window"
    assert probe > absolute, "the final probe never crosses the absolute window"
    assert probe - last_touch < idle, (
        "IDLE expiry is NOT excluded: the session is idle for >= the idle TTL before the "
        "final probe, so idle expiry explains the death just as well as absolute expiry"
    )


def test_f2_leg2_stops_touching_and_measures_the_realized_timings() -> None:
    """The plan is checked against the constants; the REALIZED instants are checked
    against the wall clock (a slow browser launch or a stalled rollout could push the
    real timings past the plan). Both directions are the safe ones: the probe is
    judged to have STARTED after the absolute deadline, and to have FINISHED inside
    the idle window from the last touch."""
    assert "_s4_elapsed()" in _RUNNER_TEXT
    assert "_s4_sleep_until()" in _RUNNER_TEXT
    # THE TOUCH IS STAMPED AT SEND, NOT AT RESPONSE (round 4, F3a — this assertion was
    # INVERTED before: it pinned `A_S4_LAST_TOUCH_AT="$(_s4_elapsed)"`, i.e. the stamp
    # taken AFTER bff_touch returned, which is the unsound side. last_seen_at >=
    # touch_SENT, so only (probe_done - touch_sent) is an UPPER bound on the true idle
    # interval; measuring from the RESPONSE yields a lower bound and excludes nothing.
    assert 'A_S4_TOUCH_SENT_AT="$(_s4_elapsed)"' in _RUNNER_TEXT
    assert 'A_S4_LAST_TOUCH_AT="$A_S4_TOUCH_SENT_AT"' in _RUNNER_TEXT
    assert 'A_S4_LAST_TOUCH_AT="$(_s4_elapsed)"' not in _RUNNER_TEXT, (
        "the touch is stamped AFTER the response again — a slow touch would SHRINK the "
        "computed idle interval instead of growing it, and the exclusion would be unsound"
    )
    assert 'A_S4_PROBE_AT="$(_s4_elapsed)"' in _RUNNER_TEXT
    assert 'A_S4_PROBE_DONE_AT="$(_s4_elapsed)"' in _RUNNER_TEXT
    assert '[ "$A_S4_LAST_TOUCH_AT" -lt "$_S4_ABSOLUTE_TTL_S" ]' in _RUNNER_TEXT
    assert '[ "$A_S4_PROBE_AT" -gt "$_S4_ABSOLUTE_TTL_S" ]' in _RUNNER_TEXT
    assert (
        '[ "$(( A_S4_PROBE_DONE_AT - A_S4_LAST_TOUCH_AT ))" -lt "$_S4_IDLE_TTL_S" ]' in _RUNNER_TEXT
    )
    # the mid-flight checkpoint must actually have run (a mis-scheduled loop that
    # skipped it would leave the "touching held idle off" claim unproven)
    assert '[ "$A_S4_MID_DONE" -eq 1 ]' in _RUNNER_TEXT


# --- F6: Bar E validates the COMPLETE turn set, not whatever rendered ------- #


def test_f6_bar_e_requires_the_rendered_transcript_to_be_the_complete_turn_set() -> None:
    """`n >= 1` + per-turn checks accepts ANY non-empty subset: a transcript that
    silently dropped turn 1 passed every per-turn digest check, because those only
    inspect the turns that WERE rendered. The rendered sequence list must EQUAL the
    kernel's complete stored turn list, exactly and in order."""
    assert "conv_turn_seqs()" in _RUNNER_TEXT
    # the DB derivation is tenant-scoped through the JOIN (conversation_turns has no
    # tenant column) and reads the kernel's real table/column names (migration 0015)
    assert (
        "SELECT t.seq FROM conversation_turns t JOIN conversations c "
        "ON c.conversation_id = t.conversation_id WHERE c.tenant_id='$TENANT'" in _RUNNER_TEXT
    )
    assert "ORDER BY t.seq ASC" in _RUNNER_TEXT
    assert 'expected_seqs="$(conv_turn_seqs "$cid"' in _RUNNER_TEXT
    assert '[ "$rendered_seqs" = "$expected_seqs" ]' in _RUNNER_TEXT
    assert "is not the kernel's complete turn list" in _RUNNER_TEXT
    # ... with the expected-vs-rendered diff in the failure message
    assert "rendered=[$rendered_seqs] expected=[$expected_seqs]" in _RUNNER_TEXT


def test_f6_bar_e_fails_loud_if_the_transcript_ever_paginates() -> None:
    """If a future conversation exceeds one transcript page, `transcript_turns` is a
    PAGE, not the transcript — and the completeness comparison would be against a
    truncated list. That day must fail loud (with the fix named), never pass."""
    # The evidence document now rides STDIN (round 4, F1 — uniform with jq_get /
    # json_assert), so the read is `printf … | python3 -c …` rather than argv.
    assert 'next_page="$(printf \'%s\' "$evid" | python3 -c ' in _RUNNER_TEXT
    assert '[ "$next_page" = "False" ]' in _RUNNER_TEXT
    assert "The driver must walk the pagination" in _RUNNER_TEXT


# --- F8: per-step replica attribution (the ratified Bar A contract) --------- #


def test_f8_every_bff_port_forward_targets_a_named_pod_never_the_service() -> None:
    """The spec's Bar A contract ends: "Value-free proof logs record which pod served
    each step." A Service forward hands the choice to kube-proxy and leaves the
    runner GUESSING; `kubectl port-forward pod/<name>` bypasses the Service, so the
    serving replica is a fact the runner ESTABLISHED."""
    assert "svc/$HARNESS_HOST" not in _RUNNER_TEXT, (
        "a Service-targeted BFF forward makes per-step replica attribution an inference"
    )
    assert "bff_resolve_pods()" in _RUNNER_TEXT
    assert "bff_pf_pod()" in _RUNNER_TEXT
    # bff_pf_start delegates to the named-pod forward and ALTERNATES the replicas
    start = _RUNNER_TEXT.split("bff_pf_start() {", 1)[1].split("\n}", 1)[0]
    assert "bff_resolve_pods" in start
    assert "bff_pf_pod" in start
    assert 'next="$BFF_POD_2"' in start, "the forward must alternate so BOTH replicas serve"


def test_f8_the_runner_records_served_by_for_each_bar_a_step() -> None:
    assert "bff_served_by()" in _RUNNER_TEXT
    assert 'echo "  step=$step served_by=${pod#pod/}"' in _RUNNER_TEXT
    # every Bar A step that is served by the BFF announces its replica
    for step in (
        "A.S1",
        "A.S5",
        "A.S8",
        "A.S2",
        "A.S9",
        "A.CSRF",
        "A.XSS",
        "A.S3",
        "A.S7",
        "A.S6-burst",
        "A.S10",
        "A.S4-leg1",
        "A.S4-leg2",
    ):
        assert f'bff_served_by "{step}"' in _RUNNER_TEXT, f"no served_by line for step {step}"


def test_f8_pods_are_reresolved_after_anything_that_replaces_them() -> None:
    """A rollout (bff_set_ttls) and the S9 pod kill both REPLACE pods. A stale name
    would attribute a step to a pod that no longer exists."""
    ttls = _RUNNER_TEXT.split("bff_set_ttls() {", 1)[1].split("\n}", 1)[0]
    assert 'BFF_CURRENT_POD=""' in ttls, "the rollout must drop the stale pod binding"
    assert "bff_pf_start" in ttls
    # S9: the killed pod may be the one the forward was targeting
    assert "The pod the forward was targeting may be the one just KILLED" in _RUNNER_TEXT
    # S3/S6 re-resolve rather than reusing the pre-kill names
    assert "pod names CHANGED in the S9 kill" in _RUNNER_TEXT


def test_f8_readme_no_longer_claims_served_by_is_empty_for_the_bar() -> None:
    """The proof README said `served_by` is `[]` and that only some steps attribute a
    replica — i.e. it documented the ratified contract as unmet. Attribution is now
    established for every step, and the README must say HOW (the runner CHOOSES the
    pod, so it is a fact, not an inference about kube-proxy)."""
    assert "`served_by` is `[]`" not in _README_TEXT
    assert "served_by=" in _README_TEXT  # the per-step line is documented
    assert "CHOOSES" in _README_TEXT or "chooses" in _README_TEXT
    assert "kube-proxy" in _README_TEXT


# --- F9: refusal markers are COUNT DELTAS, never existence checks ----------- #


def test_f9_the_refusal_asserts_compare_counts_not_existence() -> None:
    """`grep -q "<marker>"` over a multi-minute window passes if ANY matching line
    exists — including one an EARLIER step left behind. The step's own request need
    never have refused, or even reached the server. (Concretely: any earlier request
    carrying a lapsed bearer plants a `token_expired` marker that Bar B's deliberate
    expired-token leg could then free-ride on.) The technique is the one S6 already
    uses for Keycloak's refresh events: snapshot, act, require a strict increase."""
    assert "bff_refusal_count()" in _RUNNER_TEXT
    assert "binder_refusal_count()" in _RUNNER_TEXT
    for fn in ("assert_bff_refusal() {", "assert_binder_refusal() {"):
        body = _RUNNER_TEXT.split(fn, 1)[1].split("\n}", 1)[0]
        assert 'post="$(' in body and '-gt "$pre"' in body, f"{fn} must compare COUNTS"
        assert "grep -q" not in body, f"{fn} still uses an existence check"
        # a missing pre-count is a programming error, not a silent fallback
        assert 'pre="${2:-}"' in body and "die " in body
        assert "did NOT increase" in body
    # THE COUNTERS FAIL LOUD ON A FAILED READ (round 4, F2 — this assertion was
    # INVERTED before: it REQUIRED the `|| true` + `${n:-0}` swallow that IS the bug).
    #
    # The old body was `kubectl … 2>/dev/null | grep -c "$marker" || true` normalised to
    # `${n:-0}`. If the kubectl read FAILED, stderr was hidden, grep saw empty input,
    # and the helper returned 0 — byte-identical to a legitimate "I looked, and found
    # none". A failed pre-read then yields 0, a STALE marker already in the window is
    # later counted as 1, the delta is +1, and the assert passes although the step's own
    # request never refused (or never even reached the server).
    #
    # Now: the read's exit status is checked EXPLICITLY and a failure bar_fails. Only
    # `grep -c`'s documented exit-1 ("zero matches") normalises to 0 — by exit code, so
    # it can never again be conflated with the read failure it used to be lumped with.
    for fn in ("bff_refusal_count() {", "binder_refusal_count() {"):
        body = _RUNNER_TEXT.split(fn, 1)[1].split("\n}", 1)[0]
        assert "grep -c" in body
        assert "|| true" not in body, (
            f"{fn} swallows a failed read again — a kubectl failure would silently "
            "become the count 0, and the refusal delta could free-ride on a stale marker"
        )
        assert "${n:-0}" not in body, (
            f"{fn} defaults an EMPTY read to 0 again — an unobserved zero is not a zero"
        )
        assert "kubectl_capture" in body, f"{fn} must read through the fail-loud capture"
        assert "rc=$?" in body and '[ "$rc" -eq 0 ]' in body, (
            f"{fn} must check the read's exit status EXPLICITLY"
        )
        assert "bar_fail" in body and "REFUSING to report a count" in body
        # the ONE legitimate non-zero exit is normalised by CODE, not by a catch-all
        assert "1) n=0 ;;" in body, (
            f"{fn} must normalise grep's zero-matches exit (1) to 0 explicitly, by code"
        )


def test_f9_every_refusal_call_site_passes_a_pre_count() -> None:
    """All six: the S5 BFF marker and the five Bar B binder gates."""
    expected = {
        'assert_bff_refusal login_state_already_consumed "$A_S5_PRE"',
        'assert_binder_refusal typ_not_at_jwt "$B_TYP_PRE"',
        'assert_binder_refusal token_malformed "$B_MAL_PRE"',
        'assert_binder_refusal kid_unknown "$B_KID_PRE"',
        'assert_binder_refusal audience_not_exact "$B_AUD_PRE"',
        'assert_binder_refusal token_expired "$B_EXP_PRE"',
    }
    for call in sorted(expected):
        assert call in _RUNNER_TEXT, f"missing pre-count at call site: {call}"
    # and each pre-count is SNAPSHOT BEFORE the action it judges
    for snapshot in (
        'A_S5_PRE="$(bff_refusal_count login_state_already_consumed)"',
        'B_TYP_PRE="$(binder_refusal_count typ_not_at_jwt)"',
        'B_MAL_PRE="$(binder_refusal_count token_malformed)"',
        'B_KID_PRE="$(binder_refusal_count kid_unknown)"',
        'B_AUD_PRE="$(binder_refusal_count audience_not_exact)"',
        'B_EXP_PRE="$(binder_refusal_count token_expired)"',
    ):
        assert snapshot in _RUNNER_TEXT, f"missing pre-count snapshot: {snapshot}"


def test_f9_no_bare_existence_grep_survives_for_either_marker() -> None:
    """The whole point: neither marker may be judged by mere presence anywhere."""
    for marker in ("auth.callback.refused reason=", "reference_binder.refused reason="):
        for line in _RUNNER_TEXT.splitlines():
            if marker in line and "grep -q" in line:
                raise AssertionError(
                    f"an existence check survives for {marker!r}: {line.strip()!r}"
                )


def test_f9_the_pre_and_post_reads_share_one_wide_window() -> None:
    """A window that AGED between the pre-read and the post-read could under-count and
    produce a spurious FAIL. One wide window, used by both counters."""
    assert '_REFUSAL_LOG_WINDOW="1800s"' in _RUNNER_TEXT
    assert _RUNNER_TEXT.count('"--since=$_REFUSAL_LOG_WINDOW"') == 2
    assert "--since=300s" not in _RUNNER_TEXT
    assert "--since=180s" not in _RUNNER_TEXT


# =========================================================================== #
# ROUND 4 (2026-07-12) — the reviewer rejected the round-3 packet.            #
#                                                                             #
# Four findings (F1-F4), a fifth found while sweeping for more of F2's bug    #
# class (F2-b), and a sixth found by smoke-testing the F1 fix (the JSON       #
# boolean spelling). The unifying theme of F2 / F2-b is the most dangerous    #
# shape in the whole runner: A FAILED READ THAT IS INDISTINGUISHABLE FROM A   #
# LEGITIMATE ZERO. The proof's strongest claims are its NEGATIVE ones — "the  #
# marker count rose because of THIS request", "the ledger is still 0, so the  #
# denied tool did NOT execute" — and a fabricated zero hands every one of     #
# them a free pass.                                                           #
#                                                                             #
# The tests below EXECUTE the runner's own function text (see                 #
# `_extract_shell_function`); they never re-type it.                          #
# =========================================================================== #


# --- F1: no credential rides argv, and none is printed into the log --------- #


def test_r4_f1_the_json_readers_take_the_document_on_stdin() -> None:
    """The three readers the reviewer named — plus `_e_field`, kept uniform.

    Each used to take the JSON DOCUMENT on python3's argument vector, which is
    world-readable (`ps`). The documents they are handed are the most sensitive objects
    in the proof: the LOGIN JSON (both session ids + the callback URL, whose `?code=` is
    exchangeable for tokens) and the COOKIE DUMP (the live `__Host-` cookie VALUE)."""
    for fn in ("jq_get", "json_field", "_e_field"):
        body = _extract_shell_function(fn)
        assert "sys.stdin.read()" in body or "$_JSON_GET_PY" in body, (
            f"{fn} no longer reads the document from stdin"
        )
        assert "json.loads(sys.argv" not in body, f"{fn} reads the JSON document from argv"
    # json_assert takes the document as argument 3 and pipes it in.
    body = _extract_shell_function("json_assert")
    assert 'local label="$1" src="$2" doc="$3"' in body
    assert 'printf \'%s\' "$doc" | python3 -c "$src"' in body


def test_r4_f1_no_json_assert_predicate_reads_its_document_from_argv() -> None:
    """Every predicate must read `json.loads(sys.stdin.read())`. The ONLY documents
    still permitted on argv anywhere in the runner are the responses of
    `/api/v1/system/plugins` — an endpoint that requires no authentication at all, so
    its body is not a credential by construction."""
    offenders = [
        ln.strip()
        for ln in _RUNNER_TEXT.splitlines()
        if "json.loads(sys.argv" in ln or "json.load(sys.argv" in ln
    ]
    # the permitted readers of the PUBLIC plugins body
    assert len(offenders) == 2, (
        f"a JSON document is being read from argv at an unexpected site: {offenders}"
    )
    public_readers = _RUNNER_TEXT.count("system/plugins")
    assert public_readers >= 2
    assert _RUNNER_TEXT.count("json.loads(sys.stdin.read())") >= 9, (
        "the json_assert predicates must read their document from stdin"
    )


#: Every shell variable in the runner that holds CREDENTIAL-BEARING material: a login
#: JSON (both session ids + the `?code=` callback URL, exchangeable for tokens), a
#: cookie dump (the live `__Host-` cookie VALUE), a raw session id, a stored session
#: RECORD (the OAuth access/refresh/id tokens), or a password.
_CREDENTIAL_VARS = (
    "A_LOGIN",
    "A_S10_LOGIN",
    "A_S4A",
    "A_S4B",
    "A_S7",
    "A_OUTAGE",
    "A_COOKIES",
    "A_PRE",
    "A_POST",
    "A_CB",
    "A_S10_C",
    "A_S10_REC",
    "A_S10_MUT",
    "A_S4A_C",
    "A_S4B_C",
    "A_S6_C",
    "A_S7_C",
    "KC_CLIENT_SECRET",
    "REDIS_BFF_PW",
    "B_DANA_PW",
    "B_AMIR_PW",
)


def test_r4_f1_no_credential_variable_ever_reaches_a_python_argv() -> None:
    """The invariant the idiom-count above only PROXIES — stated directly.

    The previous pin counted occurrences of the `json.loads(sys.argv` spelling and
    required exactly two. That bounds one IDIOM, not the actual hazard: a future reader
    written `doc = sys.argv[1]` / `json.loads(doc)` reads a document off the argument
    vector while matching nothing the count looks for, and would join the permitted
    readers in silence. (Three call sites already pass a document on argv; only two use
    that spelling — so the count was already looser than it read.)

    The hazard is not an idiom. It is a CREDENTIAL on a world-readable argument vector.
    So: no variable holding credential material may appear on a `python3` argv at all.
    The three documents that legitimately ride argv are all the response body of the
    UNAUTHENTICATED `/api/v1/system/plugins` — not a credential by construction."""
    offenders: list[str] = []
    for ln in _RUNNER_TEXT.splitlines():
        stripped = ln.strip()
        if stripped.startswith("#") or "python3" not in stripped:
            continue
        # the argv portion: everything after the python3 invocation, minus any heredoc
        # body (which is stdin, not argv) and minus `-c '<script>'` (the script itself).
        argv_part = stripped.split("python3", 1)[1].split("<<", 1)[0]
        for var in _CREDENTIAL_VARS:
            if f'"${var}"' in argv_part or f'"${{{var}}}"' in argv_part:
                offenders.append(f"${var} on python3 argv: {stripped}")
    assert not offenders, (
        "a credential-bearing value is on a python3 argument vector — a `ps` snapshot "
        "captures argv for the whole life of the process, so this discloses it to every "
        "local user. Pipe the value in on STDIN instead.\n  " + "\n  ".join(offenders)
    )


def test_r4_f1_the_s8_predicate_never_prints_a_cookie_value() -> None:
    """S8 hands json_assert the live cookie dump. Its assertion messages used to end
    `, sess` — so a failure printed the whole cookie dict, VALUE INCLUDED, into the
    proof log via bar_fail. A custody proof whose FAILURE path discloses the session is
    not a custody proof. The messages now carry cookie NAMES and shape facts only."""
    block = _RUNNER_TEXT.split('json_assert "BAR A S8 cookie content"', 1)[1].split(
        '\' "$A_COOKIES"', 1
    )[0]
    assert 'assert sess["secure"] and sess["httpOnly"], sess' not in block, (
        "the S8 predicate prints the whole cookie dict (value included) on failure"
    )
    assert 'assert sess["path"] == "/" and not sess.get("domain"), sess' not in block
    # the value is INSPECTED but only the NAME is ever reported
    assert 'f"__Host-cognic_session flags wrong' in block
    assert 'c[\\"name\\"]' in block


def test_r4_f1_the_login_json_and_session_ids_are_never_printed() -> None:
    """S1's two messages interpolated the login JSON (session ids + the callback URL
    with its one-time authz code) and both session ids in plaintext. They now carry a
    non-reversible fingerprint, and state the FACT the assertion is about."""
    assert "redact()" in _RUNNER_TEXT
    assert 'bar_fail "BAR A S1 login did not complete (body: $A_LOGIN)"' not in _RUNNER_TEXT
    assert "($A_PRE == $A_POST)" not in _RUNNER_TEXT
    assert 'body $(redact "$A_LOGIN")' in _RUNNER_TEXT
    assert 'both $(redact "$A_PRE")' in _RUNNER_TEXT

    # THE SWEEP. No bar_fail / die / echo MESSAGE may interpolate a credential-bearing
    # variable in the clear. Only the message string itself is inspected — a credential
    # appearing in the *test* that guards the message (e.g. `[ -n "$A_POST" ] ||
    # bar_fail "no post-auth session id"`) is not a disclosure; the message is what is
    # printed into the proof log.
    #
    # THE REFERENCE IS MATCHED ON A WORD BOUNDARY, IN BOTH SHELL SPELLINGS (round 5). The
    # round-4 sweep tested `cred in msg` against the literal `"$A_S10_MUT"`, which is wrong
    # in both directions:
    #   * FALSE POSITIVE — `$A_S10_MUT` is a PREFIX of `$A_S10_MUT_RC`, an exit code that
    #     is not a credential at all. (This fired for real: round 5 added exactly such a
    #     variable, and the guard called an integer a session record.)
    #   * FALSE NEGATIVE — the braced form `${A_S10_MUT}` does NOT contain the substring
    #     `$A_S10_MUT` (the `{` sits between the `$` and the name), so the guard would have
    #     waved a genuine disclosure straight through. That is the more dangerous half.
    # Both are closed by matching `$NAME` / `${NAME}` with a trailing word boundary.
    creds = ("A_LOGIN", "A_PRE", "A_POST", "A_COOKIES", "A_S10_REC", "A_S10_MUT")
    message = re.compile(r'(?:bar_fail|die|echo)\s+"((?:[^"\\]|\\.)*)"')
    for line in _RUNNER_TEXT.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for msg in message.findall(stripped):
            for cred in creds:
                reference = re.compile(r"\$\{?" + re.escape(cred) + r"\}?(?![0-9A-Za-z_])")
                if reference.search(msg):
                    assert "redact" in msg, (
                        f"a credential (${cred}) is printed into the proof log in the clear: "
                        f"{msg!r}"
                    )


def test_r4_f1_redact_is_non_reversible_and_stable() -> None:
    """Behavioural, against the REAL helper: it must fingerprint, not echo — and equal
    inputs must fingerprint equally, or "are these two session ids the same?" (the S1
    rotation question) could not be answered from the log at all."""
    fn = _extract_shell_function("redact")
    script = "\n".join(
        [
            fn,
            'redact "SUPER-SECRET-SESSION-ID"',
            'redact "SUPER-SECRET-SESSION-ID"',
            'redact "other"',
            'redact ""',
        ]
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    a, b, c, empty = out.stdout.split("\n")[:4]
    assert "SUPER-SECRET-SESSION-ID" not in out.stdout, "redact echoed the credential"
    assert a.startswith("sha256:") and "/len=23" in a  # len("SUPER-SECRET-SESSION-ID")
    assert a == b, "equal values must fingerprint equally (the S1 rotation check needs this)"
    assert a != c, "different values must fingerprint differently"
    assert empty == "<empty>"


def test_r4_f1_the_driver_pops_every_credential_env_var() -> None:
    """The env is the right channel INTO the driver; the problem is what the driver
    then LAUNCHES. `sync_playwright()` starts a Node process and `chromium.launch()` a
    browser that forks renderer / GPU / utility children — every one inheriting
    `os.environ` verbatim. Merely READING left the live session cookie, the one-time
    authorization code and the user's password sitting in the environment of the whole
    browser process tree."""
    assert 'PASSWORD_ENV = "HARNESS_USER_PASSWORD"' in _DRIVER_TEXT
    assert "CREDENTIAL_ENV_VARS" in _DRIVER_TEXT
    for env_const in ("COOKIE_VALUE_ENV", "CALLBACK_URL_ENV", "PASSWORD_ENV"):
        assert f"os.environ.pop({env_const}, None)" in _DRIVER_TEXT, (
            f"{env_const} is not POPPED — a child process would inherit it"
        )
    assert 'os.environ.get("HARNESS_USER_PASSWORD")' not in _DRIVER_TEXT
    assert "os.environ.get(COOKIE_VALUE_ENV)" not in _DRIVER_TEXT
    assert "os.environ.get(CALLBACK_URL_ENV)" not in _DRIVER_TEXT


def test_r4_f1_the_driver_guards_the_env_before_any_child_launch() -> None:
    """ORDER IS THE CONTRACT: the guard must run before the Node driver and the browser
    exist. A guard placed after either would be inspecting an environment the children
    had already inherited. (The driver's own selftest re-derives this from
    `inspect.getsource`, so it is pinned behaviourally too.)"""
    assert "def _assert_credential_env_cleared()" in _DRIVER_TEXT
    body = _DRIVER_TEXT.split("def _run_in_browser(", 1)[1].split("\ndef ", 1)[0]
    guard = body.find("_assert_credential_env_cleared()")
    node = body.find("with sync_playwright()")
    launch = body.find("pw.chromium.launch(")
    assert guard >= 0, "_run_in_browser does not assert the credential env is clear"
    assert guard < node < launch, (
        "the credential-env guard must run BEFORE sync_playwright() and chromium.launch()"
    )


def test_r4_f1_the_driver_redacts_credential_urls_in_diagnostics() -> None:
    """Driver diagnostics go to stderr, and the runner interpolates that stderr straight
    into a bar_fail message in the proof log. A failing login is very often parked on
    `…/auth/callback?code=<one-time authz code>` — and ~20 diagnostics carry
    `url=page.url`. Redacting inside `_fail`, the single funnel, covers every present
    AND future call site."""
    assert "def _redact_url(" in _DRIVER_TEXT
    assert "_CREDENTIAL_QUERY_PARAMS" in _DRIVER_TEXT
    fail_body = _DRIVER_TEXT.split("def _fail(", 1)[1].split("\ndef ", 1)[0]
    assert 'diagnostics["url"] = _redact_url(diagnostics["url"])' in fail_body, (
        "_fail must redact the url diagnostic — it is the single funnel every "
        "`url=page.url` call site passes through"
    )


# --- F2: a failed log read can no longer masquerade as a legitimate zero ----- #

_BFF_MARKER = "auth.callback.refused reason=login_state_already_consumed"
_BINDER_MARKER = "reference_binder.refused reason=token_expired"


@pytest.mark.parametrize(
    "fn,reason,marker",
    [
        ("bff_refusal_count", "login_state_already_consumed", _BFF_MARKER),
        ("binder_refusal_count", "token_expired", _BINDER_MARKER),
    ],
)
def test_r4_f2_a_failed_log_read_dies_instead_of_returning_zero(
    fn: str, reason: str, marker: str
) -> None:
    """THE MUTATION TEST the review demanded, against the REAL function text.

    The reviewer reproduced the false pass end to end: the pre-read FAILS -> the helper
    returns 0 -> a STALE marker already sitting in the (30-minute) window is later
    counted -> 1 -> delta +1 -> the assert passes, although the step's own request never
    refused, and may never have reached the server at all.

    Three cases, and the first is the whole point: a read failure must DIE, not decay
    into a number. `grep -c` legitimately exits 1 on zero matches, and that case must
    still normalise to 0 — but it must be told apart from the read failure it used to be
    lumped in with."""
    fns = ("kubectl_capture", "_kubectl_capture_err", fn)

    # (i) the read FAILS -> dies loudly, and reports NO count.
    failed = _bash_probe(
        functions=fns,
        fake_mode="read_fail",
        call=f'N="$({fn} {reason})"; echo "RETURNED=[$N]"',
    )
    assert failed.returncode != 0, "a failed log read did not abort the run"
    assert "RETURNED=" not in failed.stdout, (
        f"{fn} RETURNED a value after a failed read — a fabricated count is exactly what "
        "lets a refusal delta free-ride on a stale marker"
    )
    assert "BAR_FAIL" in failed.stderr
    assert "REFUSING to report a count" in failed.stderr

    # (ii) a SUCCESSFUL read with zero matches is a REAL zero.
    zero = _bash_probe(
        functions=fns,
        log_lines="some unrelated line\nanother\n",
        call=f'N="$({fn} {reason})"; echo "RETURNED=[$N]"',
    )
    assert zero.returncode == 0, zero.stderr
    assert "RETURNED=[0]" in zero.stdout

    # (iii) a SUCCESSFUL read with N matches counts N.
    three = _bash_probe(
        functions=fns,
        log_lines=f"noise\n{marker}\nnoise\n{marker}\n{marker}\n",
        call=f'N="$({fn} {reason})"; echo "RETURNED=[$N]"',
    )
    assert three.returncode == 0, three.stderr
    assert "RETURNED=[3]" in three.stdout


def test_r4_f2_the_stale_marker_free_ride_is_now_impossible() -> None:
    """The reviewer's false-positive, reconstructed in the PRODUCTION call shape.

    `A_S5_PRE="$(bff_refusal_count …)"` is how the pre-count is taken. Before the fix a
    failed read yielded `pre=0` and execution sailed on to the delta assert, which a
    stale marker then satisfied. Now the run aborts at the pre-read — the delta can never
    be computed from a count nobody actually observed."""
    probe = _bash_probe(
        functions=("kubectl_capture", "_kubectl_capture_err", "bff_refusal_count"),
        fake_mode="read_fail",
        call=(
            'A_S5_PRE="$(bff_refusal_count login_state_already_consumed)"\n'
            'echo "REACHED_THE_DELTA_ASSERT pre=[$A_S5_PRE]"'
        ),
    )
    assert probe.returncode != 0
    assert "REACHED_THE_DELTA_ASSERT" not in probe.stdout, (
        "the runner reached the delta assertion with a FABRICATED pre-count of 0 — a "
        "stale marker in the log window would now satisfy it for free"
    )


def test_r4_f2_kubectl_capture_returns_status_and_does_not_bar_fail_itself() -> None:
    """A bash 3.2 semantic that would otherwise have made the whole F2 fix a no-op.

    `set -e` is IGNORED inside the subshell of a command substitution that is part of an
    assignment. So a bar_fail raised INSIDE kubectl_capture — which the callers invoke as
    `logs="$(kubectl_capture …)"`, themselves already inside `$( … )` — ends only
    kubectl_capture's own subshell. The caller sails on past the failed assignment with
    `logs` empty, counts zero matches, and returns a clean "0". The fabricated zero comes
    straight back, now wearing a bar_fail message as camouflage.

    Hence: kubectl_capture RETURNS the status; the callers check it and raise their own
    bar_fail, which sits directly in the substituted function and does end the run."""
    body = _extract_shell_function("kubectl_capture")
    assert "bar_fail" not in body, (
        "kubectl_capture must NOT bar_fail: one substitution level deeper, bash 3.2 "
        "swallows the exit and the caller returns a fabricated 0 anyway"
    )
    assert 'return "$rc"' in body
    for caller in ("bff_refusal_count", "binder_refusal_count", "probe_ledger_count"):
        cbody = _extract_shell_function(caller)
        assert "rc=$?" in cbody and '[ "$rc" -eq 0 ]' in cbody and "bar_fail" in cbody, (
            f"{caller} must check kubectl_capture's status explicitly and bar_fail itself"
        )


# --- F2-b: the probe ledger — the proof's load-bearing NEGATIVE observable --- #


def test_r4_f2b_probe_ledger_distinguishes_absent_from_unreadable() -> None:
    """Every `= "0"` assertion in Bars B and D claims a DENIED / PENDING / under-approved
    high-risk tool did NOT execute. The pre-review in-pod command was
    `wc -l < $LEDGER 2>/dev/null || echo 0`, which collapsed three states onto 0:

      * the file is ABSENT        — a legitimate zero (the probe creates it on first run);
      * the file has zero lines   — a legitimate zero;
      * the file EXISTS BUT THE READ FAILED — not an observation at all, yet reported as
        "zero execution", handing every one of those assertions a free pass while an
        executed tool sits unread in a file nobody could open.

    The fake kubectl runs the REAL in-pod script locally, so this drives the actual
    three-state logic. "Unreadable" is exercised by pointing the ledger at a DIRECTORY:
    `wc -l < dir` genuinely fails on every platform, and (unlike chmod 000) it fails for
    root too, so the test cannot go vacuous under a root CI runner."""
    fns = ("kubectl_capture", "_kubectl_capture_err", "probe_ledger_count")
    tmp = Path(tempfile.mkdtemp())
    try:
        ledger = tmp / "ledger"
        ledger.write_text("exec-1\nexec-2\nexec-3\n")
        as_dir = tmp / "ledger_dir"
        as_dir.mkdir()

        # (i) the in-pod READ FAILS -> dies. It must NOT report 0.
        unreadable = _bash_probe(
            functions=fns,
            ledger_path=str(as_dir),
            call='N="$(probe_ledger_count)"; echo "RETURNED=[$N]"',
        )
        assert unreadable.returncode != 0, "an unreadable ledger did not abort the run"
        assert "RETURNED=" not in unreadable.stdout, (
            "probe_ledger_count reported a count for a ledger it could not read — every "
            "'the ledger stayed 0' assertion would pass on an execution nobody looked for"
        )
        assert "REFUSING to report a count" in unreadable.stderr

        # (ii) the ledger is ABSENT -> an AFFIRMATIVE zero (nothing has executed).
        absent = _bash_probe(
            functions=fns,
            ledger_path=str(tmp / "nope"),
            call='N="$(probe_ledger_count)"; echo "RETURNED=[$N]"',
        )
        assert absent.returncode == 0, absent.stderr
        assert "RETURNED=[0]" in absent.stdout

        # (iii) N lines -> N.
        counted = _bash_probe(
            functions=fns,
            ledger_path=str(ledger),
            call='N="$(probe_ledger_count)"; echo "RETURNED=[$N]"',
        )
        assert counted.returncode == 0, counted.stderr
        assert "RETURNED=[3]" in counted.stdout

        # (iv) the kubectl exec itself fails -> dies.
        exec_failed = _bash_probe(
            functions=fns,
            fake_mode="read_fail",
            ledger_path=str(ledger),
            call='N="$(probe_ledger_count)"; echo "RETURNED=[$N]"',
        )
        assert exec_failed.returncode != 0
        assert "RETURNED=" not in exec_failed.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_r4_f2b_an_unreadable_ledger_cannot_satisfy_a_ledger_stays_zero_assertion() -> None:
    """The production call shape, `[ "$(probe_ledger_count)" = "0" ] || bar_fail`, is what
    Bars B and D.1-D.3 use to prove a high-risk tool did NOT run. With an unreadable
    ledger it must be impossible for that assertion to PASS."""
    tmp = Path(tempfile.mkdtemp())
    try:
        as_dir = tmp / "ledger_dir"
        as_dir.mkdir()
        probe = _bash_probe(
            functions=("kubectl_capture", "_kubectl_capture_err", "probe_ledger_count"),
            ledger_path=str(as_dir),
            call='[ "$(probe_ledger_count)" = "0" ] && echo "LEDGER_ZERO_ASSERT_PASSED"',
        )
        assert probe.returncode != 0
        assert "LEDGER_ZERO_ASSERT_PASSED" not in probe.stdout, (
            "an UNREADABLE ledger satisfied a 'the ledger stayed 0' assertion — the proof "
            "would claim a denied tool did not execute without ever having looked"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_r4_f2b_the_in_pod_script_has_no_silent_catch_all() -> None:
    body = _extract_shell_function("probe_ledger_count")
    assert "|| echo 0" not in body, (
        "the in-pod read swallows every failure into 0 again — an unreadable ledger would "
        "read as 'nothing executed'"
    )
    assert "2>/dev/null" not in body, "the in-pod read hides its own errors again"
    assert "probe_ledger_unreadable" in body and "probe_ledger_read_failed" in body
    assert "if [ ! -e " in body, "the ABSENT case must be an affirmative, deliberate zero"


# --- F3: S4 can now exclude the wrong expiry clock -------------------------- #


def test_r4_f3_leg1_bounds_the_absolute_age_from_before_the_login() -> None:
    """Leg 1 claims the session died of IDLE while the ABSOLUTE window was still open —
    but never checked the second half of that sentence against the wall clock. A slow
    run (a Chromium launch + an OIDC round trip + two more browser drives, all inside a
    150s absolute TTL) could push the true absolute age past the deadline, at which point
    an ABSOLUTE death is credited to the IDLE clock and the leg proves the opposite of
    what it claims.

    Stamping BEFORE the login is what makes the bound an UPPER bound (created_at >=
    pre_login), and only an upper bound below the TTL proves the window had not elapsed."""
    assert '_S4_L1_PRE_LOGIN_AT="$(date +%s)"' in _RUNNER_TEXT
    assert '_S4_L1_PROBE_DONE_AT="$(date +%s)"' in _RUNNER_TEXT
    assert '[ "$_S4_L1_ABS_AGE_MAX" -lt "$_S4_ABSOLUTE_TTL_S" ]' in _RUNNER_TEXT
    # the stamp must PRECEDE the login, or it understates the age and proves nothing
    leg1 = _RUNNER_TEXT.split('bff_served_by "A.S4-leg1"', 1)[1].split("Bar A S4 leg 1 OK", 1)[0]
    stamp = leg1.find('_S4_L1_PRE_LOGIN_AT="$(date +%s)"')
    login = leg1.find("drive_login sara")
    probe_done = leg1.find('_S4_L1_PROBE_DONE_AT="$(date +%s)"')
    final_probe = leg1.find('A_S4A_FINAL="$(drive_replay_cookie')
    assert 0 <= stamp < login, "the pre-login instant is stamped AFTER the login"
    assert 0 <= final_probe < probe_done, "the probe-done instant is stamped BEFORE the probe"


def test_r4_f3_leg2_stamps_the_touch_before_the_request_leaves() -> None:
    """BEHAVIOURAL, against the REAL touch loop.

    The idle interval must be bounded from the touch's SEND instant: the BFF refreshes
    `last_seen_at` while it PROCESSES the request, i.e. at some instant >= send. So
    (probe_done - touch_sent) is an UPPER bound and (probe_done - touch_responded) is a
    LOWER bound — and asserting that a LOWER bound is under the TTL constrains nothing.

    This drives the extracted loop with a deliberately SLOW `bff_touch` (4s). With the
    stamp at SEND the recorded instant stays ~0 (so a slow response GROWS the computed
    idle interval — it fails safe). Stamped after the response it would be ~4."""
    lines = _RUNNER_TEXT.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith('while [ "$A_S4_NEXT" -le ')), None
    )
    assert start is not None, (
        "the S4 leg-2 touch loop is gone (renamed?) — this test cannot pass vacuously"
    )
    end = next((j for j in range(start + 1, len(lines)) if lines[j] == "done"), None)
    assert end is not None
    loop = "\n".join(lines[start : end + 1])

    script = "\n".join(
        [
            "set -euo pipefail",
            "_S4_TOUCH_EVERY_S=15",
            "_S4_LAST_TOUCH_S=15",  # exactly ONE iteration
            "_S4_MID_CHECK_S=15",  # ... in which the mid-check also fires
            "_S4_IDLE_TTL_S=60",
            "_S4_ABSOLUTE_TTL_S=150",
            '_S4_T0="$(date +%s)"',
            "_s4_elapsed() { echo $(( $(date +%s) - _S4_T0 )); }",
            "_s4_sleep_until() { :; }",  # no real waiting
            "bff_touch() { sleep 4; }",  # A SLOW TOUCH RESPONSE
            "drive_replay_cookie() { echo '{}'; }",
            "jq_get() { echo true; }",
            'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
            'A_S4B_C="cookie"',
            'A_S4_NEXT="$_S4_TOUCH_EVERY_S"',
            "A_S4_LAST_TOUCH_AT=-1",
            "A_S4_MID_DONE=0",
            loop,
            'echo "LAST_TOUCH_AT=$A_S4_LAST_TOUCH_AT"',
        ]
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    recorded = int(out.stdout.split("LAST_TOUCH_AT=")[1].split("\n")[0])
    assert recorded <= 2, (
        f"the touch was stamped at {recorded}s — i.e. AFTER the (4s) response, not before the "
        "request. A slow touch would then SHRINK the computed idle interval instead of "
        "growing it, and the idle-exclusion assertion would be unsound (it would be "
        "asserting a LOWER bound is below the TTL, which proves nothing)."
    )


def test_r4_f3_the_committed_s4_constants_satisfy_the_new_exclusions() -> None:
    """The guard is only worth having if the SHIPPED constants pass it — including the
    two browser budgets the round-4 bounds added."""

    def const(name: str) -> int:
        m = re.search(rf"^{name}=(\d+)", _RUNNER_TEXT, re.M)
        assert m, f"{name} is not defined in the runner"
        return int(m.group(1))

    idle = const("_S4_IDLE_TTL_S")
    absolute = const("_S4_ABSOLUTE_TTL_S")
    leg1_sleep = const("_S4_LEG1_SLEEP_S")
    last_touch = const("_S4_LAST_TOUCH_S")
    probe = const("_S4_FINAL_PROBE_S")
    leg1_browser = const("_S4_LEG1_BROWSER_BUDGET_S")
    probe_budget = const("_S4_PROBE_BUDGET_S")

    # leg 1: the WHOLE leg must fit inside the absolute window, browser cost included.
    assert leg1_sleep + leg1_browser < absolute, (
        "leg 1 can overrun the absolute window: an ABSOLUTE death would be credited to the IDLE TTL"
    )
    # leg 2: the probe's OWN duration counts against the idle window, because the
    # interval is measured from the touch's SEND instant to the probe's END.
    assert probe + probe_budget - last_touch < idle, (
        "leg 2's realized idle interval can reach the idle TTL: IDLE expiry would explain "
        "the death just as well as ABSOLUTE expiry"
    )


def test_r4_f3_the_plan_guard_checks_the_new_budgeted_exclusions() -> None:
    guard = _extract_shell_function("_s4_assert_timing_plan")
    assert (
        '[ "$((_S4_LEG1_SLEEP_S + _S4_LEG1_BROWSER_BUDGET_S))" -lt "$_S4_ABSOLUTE_TTL_S" ]' in guard
    )
    assert (
        '[ "$((_S4_FINAL_PROBE_S + _S4_PROBE_BUDGET_S - _S4_LAST_TOUCH_S))" -lt "$_S4_IDLE_TTL_S" ]'
        in guard
    )


def test_r4_f3_s4_never_reads_the_bff_clock_domain_for_an_interval() -> None:
    """The session record's created_at / last_seen_at live in the BFF POD's clock domain
    while `date +%s` is the runner host's. Any interval spanning both is silently
    corrupted by clock skew — so S4 bounds every interval inside ONE clock domain, using
    request-start / response-end instants it observes directly. (A reviewer suggested
    reading the record; this is the reasoned alternative they also offered, and the
    reasoning is written into the script so it is not "simplified" away.)"""
    s4 = _RUNNER_TEXT.split("# S4 — idle and absolute TTLs behave INDEPENDENTLY", 1)[1].split(
        "PROOF M8.5-C (BAR A) PASS", 1
    )[0]
    for forbidden in ("last_seen_at", "created_at"):
        for line in s4.splitlines():
            if line.strip().startswith("#"):
                continue
            assert forbidden not in line, (
                f"S4 reads {forbidden} from the session record — that is the BFF POD's clock "
                "domain, and an interval spanning it and the runner host's is corrupted by skew"
            )
    assert "CLOCK DOMAIN" in _RUNNER_TEXT


# --- F4: the S10 rewrite is atomic and preserves the deadline EXACTLY -------- #


def _extract_s10_lua() -> str:
    m = re.search(r"^_S10_REWRITE_LUA='(.*?)'\n", _RUNNER_TEXT, re.S | re.M)
    assert m, (
        "the S10 rewrite Lua script is gone from the runner (renamed or moved) — this "
        "test would otherwise pass vacuously against nothing"
    )
    return m.group(1)


def test_r4_f4_s10_uses_the_atomic_keepttl_path_and_not_psetex() -> None:
    """S10 is billed as a controlled SINGLE-variable experiment, and its comment claimed
    PTTL/PSETEX preserved the deadline "to the millisecond". That was FALSE: it read PTTL
    at T_r, did client-side work (a python3 spawn + a JSON mutation), then wrote
    `PSETEX <key> <that stale ttl> <value>` at T_w — so the new deadline was T_w + PTTL
    while the original was T_r + PTTL. The record's life was EXTENDED by (T_w - T_r).
    Measured live: PTTL 4932 -> 4866 across a 1s gap, where a preserving write yields
    ~3950. Two variables changed, not one."""
    lua = _extract_s10_lua()
    assert 'redis.call("SET", KEYS[1], ARGV[1], "KEEPTTL")' in lua
    assert 'redis.call("PTTL", KEYS[1])' in lua
    # the precondition is evaluated INSIDE the script, so there is no client-side window
    assert 'error_reply("s10_key_gone")' in lua
    assert 'error_reply("s10_no_expiry")' in lua
    # the record rides stdin: `redis-cli -x EVAL <script> 1 <key>` puts it at ARGV[1]
    assert 'redis_bff_cli_stdin EVAL "$_S10_REWRITE_LUA" 1 "$A_S10_KEY"' in _RUNNER_TEXT
    # ... and the non-atomic pattern is gone from every EXECUTABLE line
    for line in _RUNNER_TEXT.splitlines():
        if line.strip().startswith("#"):
            continue
        assert "PSETEX" not in line
        assert "redis_bff_cli PTTL" not in line


def test_r4_f4_the_false_comment_is_gone() -> None:
    """The old comment bragged that "PTTL/PSETEX preserve it to the millisecond, so the
    ONLY intentional difference in the rewritten record stays the schema version". It was
    not true, and a comment that asserts a property the code does not have is worse than
    no comment: it is what stopped anyone from checking."""
    assert "PTTL/PSETEX preserve it to the millisecond" not in _RUNNER_TEXT
    assert "KEEPTTL` retains the existing deadline EXACTLY" in _RUNNER_TEXT


_REDIS_GATE = "COGNIC_RUN_REDIS_KEEPTTL_INTEGRATION"


@pytest.mark.skipif(
    os.environ.get(_REDIS_GATE) != "1",
    reason=f"live redis behavioural proof — set {_REDIS_GATE}=1 (needs docker)",
)
def test_r4_f4_live_the_rewrite_preserves_the_deadline_against_real_redis() -> None:
    """THE LIVE BEHAVIOURAL PROOF (env-gated, `COGNIC_RUN_*_INTEGRATION=1` convention).

    Runs the runner's OWN extracted Lua against a real redis:7.4-alpine and reproduces
    the reviewer's measurement both ways:

      * CONTROL — the pre-review pattern (read PTTL, do work, PSETEX the stale value)
        EXTENDS the record's life. If this leg ever stops reproducing, the test below is
        vacuous and we would never know.
      * FIX — the atomic EVAL + `SET … KEEPTTL` leaves the deadline DECAYING with the
        wall clock, exactly as an untouched key would.

    When the gate is ON the suite fails LOUD (never skips) on a missing docker, per this
    repo's Z2 doctrine."""
    assert shutil.which("docker"), (
        f"{_REDIS_GATE}=1 but docker is not on PATH — refusing to skip a proof that was "
        "explicitly requested"
    )
    lua = _extract_s10_lua()
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "redis:7.4-alpine"],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    ).stdout.strip()
    try:

        def r(*args: str) -> str:
            return subprocess.run(
                ["docker", "exec", cid, "redis-cli", *args],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            ).stdout.strip()

        def rx(value: str, *args: str) -> str:
            return subprocess.run(
                ["docker", "exec", "-i", cid, "redis-cli", "-x", *args],
                input=value,
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            ).stdout.strip()

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                if r("PING") == "PONG":
                    break
            except subprocess.CalledProcessError:
                pass
            time.sleep(1)
        else:
            raise AssertionError("redis:7.4-alpine did not become ready")

        # CONTROL — the pre-review pattern. Read PTTL, do the client-side work, then
        # write the STALE ttl back. This is what the reviewer measured.
        r("SET", "sess:old", '{"v":1}', "PX", "5000")
        stale = int(r("PTTL", "sess:old"))
        time.sleep(1.0)  # the client-side window (a python3 spawn + a JSON mutation)
        rx('{"v":999}', "PSETEX", "sess:old", str(stale))
        after_old = int(r("PTTL", "sess:old"))
        assert after_old > stale - 300, (
            f"the CONTROL no longer reproduces the bug (PTTL {stale} -> {after_old}); without "
            "it the assertion below cannot be trusted to detect a regression"
        )

        # THE FIX — one atomic server-side evaluation, the record on STDIN.
        r("SET", "sess:new", '{"v":1,"access_token":"AT"}', "PX", "5000")
        before = int(r("PTTL", "sess:new"))
        time.sleep(1.0)
        returned = int(rx('{"v":999,"access_token":"AT"}', "EVAL", lua, "1", "sess:new"))
        after = int(r("PTTL", "sess:new"))

        assert after < before - 900, (
            f"the deadline was NOT preserved: PTTL {before} -> {after} across a 1s gap. It "
            "should have DECAYED with the wall clock (~{before - 1000}), not been reset — "
            "the record's life is being extended and S10 is changing two variables."
        )
        assert after > 0
        assert 0 < returned <= before, "the script must return the PRESERVED ttl"
        assert r("GET", "sess:new") == '{"v":999,"access_token":"AT"}', (
            "the version-mutated record was not applied — so it did not arrive as ARGV[1]"
        )

        # the in-script preconditions refuse, and refuse as NON-NUMERIC text (which is
        # what the runner keys its bar_fail on — redis-cli's exit code is not relied on).
        r("SET", "sess:noexp", '{"v":1}')  # deliberately no expiry
        no_exp = subprocess.run(
            ["docker", "exec", "-i", cid, "redis-cli", "-x", "EVAL", lua, "1", "sess:noexp"],
            input='{"v":999}',
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert "s10_no_expiry" in (no_exp.stdout + no_exp.stderr)
        assert not (no_exp.stdout.strip().isdigit()), "a refusal must not look like a ttl"
        gone = subprocess.run(
            ["docker", "exec", "-i", cid, "redis-cli", "-x", "EVAL", lua, "1", "sess:gone"],
            input='{"v":999}',
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert "s10_key_gone" in (gone.stdout + gone.stderr)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=120)


# --- the bonus P1 found while smoke-testing the F1 stdin conversion --------- #


def test_r4_jq_get_emits_json_booleans_not_python_repr() -> None:
    """A LIVE-RUN-FATAL bug that had never fired, because the proof has not yet been run
    end to end.

    `jq_get` printed Python's `True` / `False`, while EIGHTEEN call sites compare the
    result against the lowercase JSON spelling. Seventeen of them (`[ "$(jq_get
    authenticated …)" = "false" ]`) would have bar_failed on a perfectly healthy BFF —
    Bar A would have died on its very first assertion. The eighteenth is worse: S7 reads
    `[ "$A_OUTAGE_OK" != "true" ]`, and `"True" != "true"` is TRUE, so the assertion that
    the BFF must NOT fall back to memory during a Redis outage would have passed
    VACUOUSLY — even if a login had succeeded with the store down.

    Behavioural, against the REAL helper."""
    fn = "\n".join(
        [
            _RUNNER_TEXT.split("_JSON_GET_PY='", 1)[0].rsplit("\n", 1)[0][:0],  # (no-op anchor)
            "_JSON_GET_PY='" + _RUNNER_TEXT.split("_JSON_GET_PY='", 1)[1].split("'\n", 1)[0] + "'",
            _extract_shell_function("jq_get"),
        ]
    )
    doc = '{"ok":true,"authenticated":false,"sid":"abc","n":7,"rows":[1,2],"nil":null}'
    script = f"""
{fn}
echo "ok=[$(jq_get ok '{doc}')]"
echo "authenticated=[$(jq_get authenticated '{doc}')]"
echo "sid=[$(jq_get sid '{doc}')]"
echo "n=[$(jq_get n '{doc}')]"
echo "rows=[$(jq_get rows '{doc}')]"
echo "nil=[$(jq_get nil '{doc}')]"
"""
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    body = out.stdout
    assert "ok=[true]" in body, f"jq_get must emit JSON booleans, got: {body!r}"
    assert "authenticated=[false]" in body, f"jq_get must emit JSON booleans, got: {body!r}"
    assert "True" not in body and "False" not in body, (
        'jq_get is emitting Python\'s bool repr again — every `= "true"` / `= "false"` '
        'comparison in Bar A would fail, and S7\'s `!= "true"` would pass vacuously'
    )
    # strings and numbers stay BARE (session ids must remain usable as shell values)
    assert "sid=[abc]" in body and "n=[7]" in body
    assert "nil=[]" in body
    # containers stay JSON
    assert "rows=[[1, 2]]" in body


def test_r4_the_boolean_call_sites_all_use_the_json_spelling() -> None:
    """Nothing may go back to comparing against Python's repr."""
    for line in _RUNNER_TEXT.splitlines():
        if "jq_get" not in line or line.strip().startswith("#"):
            continue
        assert '= "True"' not in line and '= "False"' not in line, (
            f"a jq_get result is compared against Python's bool repr: {line.strip()!r}"
        )


# =========================================================================== #
# ROUND 5 (2026-07-12) — the reviewer rejected the round-4 packet.            #
#                                                                             #
# Four findings, and every one is the SAME doctrine in a new place:           #
#                                                                             #
#     A FAILED READ IS NOT AN OBSERVATION. An assertion may be satisfied ONLY #
#     by an observation of the event it claims. Any read, probe or drive that #
#     can FAIL must surface its failure — never collapse it into a benign     #
#     default. The fabricated default is always the SAFE-LOOKING value, so    #
#     the bug is invisible on a green run and shows up only as a false PASS.  #
#                                                                             #
# Round 4 closed this INSIDE the readers (jq_get, the refusal counters, the   #
# probe ledger). Round 5 found it one level UP, in the things that FEED them: #
#                                                                             #
#   F1  S7 awarded "the BFF refused a fresh login" for ANY driver failure —   #
#       drive_login_capture synthesised {"ok": false} for every non-zero exit,#
#       so a Chromium crash MANUFACTURED the evidence that the BFF failed     #
#       closed. Round 4's fix (demand an OBSERVED `false`) closed the         #
#       fabrication in jq_get and left this one untouched.                    #
#   F2  The disabled-grant legs were the runner's ONLY unguarded negative     #
#       assertions. `[ "$CODE" != "200" ]` is TRUE for curl's `000` — so a    #
#       TOTAL FAILURE TO CONTACT KEYCLOAK "proved" the grants are disabled.   #
#   F3  S10's "same bytes" claim was FALSE: the record was round-tripped      #
#       through a JSON encoder with different separators than the BFF used.   #
#   F5  Bar F's |safe gate was a grep for one spelling, wearing a `|| true`   #
#       that made a failed scan read as a clean bundle.                       #
#                                                                             #
# These tests EXECUTE the runner's own text. They never re-type it.           #
# =========================================================================== #


def _extract_shell_single_quoted_var(name: str, *, text: str = _RUNNER_TEXT) -> str:
    """The REAL production text of a single-quoted shell variable, assignment included.

    Returns ``NAME='…'`` ready to inject into a probe script. Fails loud when the variable
    is gone, or when its body has grown a single quote (which would silently truncate the
    extraction and leave a mutation test asserting against a fragment)."""
    match = re.search(rf"^({re.escape(name)}='[^']*')$", text, re.M)
    assert match, (
        f"{name} is not defined as a single-quoted shell variable in run-proof-m85c.sh — it "
        "was renamed, moved, or its body grew a single quote. This mutation test would "
        "otherwise assert against nothing at all, so it fails loudly instead."
    )
    return match.group(1)


def _extract_runner_block(start: str, end: str, *, text: str = _RUNNER_TEXT) -> str:
    """The REAL production text of a contiguous runner block, from the first line
    containing ``start`` through the first line at-or-after it containing ``end``.

    Proves the extraction parses before anyone relies on it, exactly as
    ``_extract_shell_function`` does."""
    lines = text.splitlines()
    first = next((i for i, ln in enumerate(lines) if start in ln), None)
    assert first is not None, (
        f"the runner block starting {start!r} is gone (renamed or moved) — this test would "
        "otherwise pass VACUOUSLY against an empty string"
    )
    last = next((j for j in range(first, len(lines)) if end in lines[j]), None)
    assert last is not None, f"the runner block starting {start!r} has no line containing {end!r}"
    block = "\n".join(lines[first : last + 1])
    probe = subprocess.run(["bash", "-n"], input=block, capture_output=True, text=True)
    assert probe.returncode == 0, f"the extracted block does not parse:\n{probe.stderr}"
    return block


def _run_bash(
    script: str, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a probe script with stdin closed, so a fake tool that reads stdin cannot hang."""
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=90,
        env=full_env,
        stdin=subprocess.DEVNULL,
    )


# --------------------------------------------------------------------------- #
# F1 — S7 may be awarded ONLY by an observation of the BFF's own refusal.      #
# --------------------------------------------------------------------------- #

#: A stand-in for `uv run … python driver.py login …`, driven by FAKE_DRIVER_MODE. It
#: reproduces every way the real invocation can end: the driver CRASHES; it writes
#: garbage; it writes a TRUNCATED document; it emits the pre-review fabricated shape; it
#: reports an OBSERVED BFF refusal; it authenticates. Only ONE of those is evidence that
#: the BFF refused, and this is what proves the runner can tell them apart.
_FAKE_UV = """#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--out" ]; then out="$a"; fi
  prev="$a"
done
[ -n "$out" ] || { echo "fake uv: no --out on the driver argv" >&2; exit 90; }
case "$FAKE_DRIVER_MODE" in
  crash)
    echo '{"error": "browser_launch_failed", "detail": "Chromium exited unexpectedly"}' >&2
    exit 3 ;;
  garbage)
    printf 'Traceback (most recent call last):\\n  File "driver.py", line 1\\n' > "$out"
    exit 3 ;;
  partial)
    printf '{"ok": false, "outcome": "ref' > "$out"
    exit 5 ;;
  legacy_ok_false)
    printf '{"ok": false, "login_failed": true, "rc": 3}' > "$out"
    exit 3 ;;
  refused_503)
    printf '{"ok": false, "outcome": "refused", "http_status": 503, "stage": "nav"}' > "$out"
    exit 5 ;;
  refused_500)
    printf '{"ok": false, "outcome": "refused", "http_status": 500, "stage": "nav"}' > "$out"
    exit 5 ;;
  refused_no_status)
    printf '{"ok": false, "outcome": "refused"}' > "$out"
    exit 5 ;;
  refused_but_exited_zero)
    printf '{"ok": false, "outcome": "refused", "http_status": 503}' > "$out"
    exit 0 ;;
  refused_but_exited_driver_error)
    printf '{"ok": false, "outcome": "refused", "http_status": 503}' > "$out"
    exit 3 ;;
  authenticated)
    printf '{"ok": true, "outcome": "authenticated", "http_status": 200, ' > "$out"
    printf '"post_auth_session_id": "sid"}' >> "$out"
    exit 0 ;;
  authenticated_but_exited_nonzero)
    printf '{"ok": true, "outcome": "authenticated", "http_status": 200}' > "$out"
    exit 3 ;;
  *) echo "fake uv: unknown FAKE_DRIVER_MODE=$FAKE_DRIVER_MODE" >&2; exit 91 ;;
esac
"""


def _s7_browser_probe(mode: str) -> subprocess.CompletedProcess[str]:
    """Drive the REAL drive_login_capture + the REAL S7 assertion lines against a fake
    driver ending in `mode`. Prints S7_PASSED only if S7 would award the leg."""
    tmp = Path(tempfile.mkdtemp())
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "uv").write_text(_FAKE_UV)
        (bin_dir / "uv").chmod(0o755)
        (tmp / "qc").mkdir()
        (tmp / "driver").mkdir()
        (tmp / "creds").mkdir()
        (tmp / "creds" / "realm-credentials.env").write_text("KC_PW_PROBE_USER=hunter2\n")

        outcome_assert = next(
            (ln for ln in _RUNNER_TEXT.splitlines() if ln.startswith('[ "$A_OUTAGE_OUTCOME" = ')),
            None,
        )
        status_assert = next(
            (ln for ln in _RUNNER_TEXT.splitlines() if ln.startswith('[ "$A_OUTAGE_STATUS" = ')),
            None,
        )
        assert outcome_assert and status_assert, (
            "S7's outcome/status assertion lines were renamed — this test would assert "
            "against nothing at all"
        )

        script = "\n".join(
            [
                "set -euo pipefail",
                f'export PATH="{bin_dir}:$PATH"',
                f'export FAKE_DRIVER_MODE="{mode}"',
                f'QC_TMP="{tmp / "qc"}"',
                f'DRIVER_DIR="{tmp / "driver"}"',
                f'KC_CRED_TMP="{tmp / "creds"}"',
                'HARNESS_BASE_URL="https://127.0.0.1:8444"',
                'PROOF_CA="/dev/null"',
                'PKI_TMP="/dev/null"',
                # The production script declares `declare -A IDENTITY_USER`, which bash 3.2
                # (the macOS system bash, and what `bash` resolves to here) does not have.
                # The role->user MAP is not what is under test — the outcome CLASSIFICATION
                # is — so the same name is declared as a plain indexed array and the probe
                # passes the numeric key 0. Every other line of drive_login_capture is the
                # REAL production text.
                'IDENTITY_USER=("probe.user")',
                'die() { echo "DIE: $*" >&2; exit 90; }',
                'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
                _extract_shell_single_quoted_var("_JSON_GET_PY"),
                _extract_shell_single_quoted_var("_LOGIN_OUTCOME_PY"),
                _extract_shell_function("jq_get"),
                _extract_shell_function("drive_login_capture"),
                'A_OUTAGE="$(drive_login_capture 0)"',
                'A_OUTAGE_OUTCOME="$(jq_get outcome "$A_OUTAGE")"',
                'A_OUTAGE_STATUS="$(jq_get http_status "$A_OUTAGE")"',
                'echo "OBSERVED_OUTCOME=[$A_OUTAGE_OUTCOME]"',
                outcome_assert.rstrip(" \\") + " || bar_fail S7_OUTCOME_NOT_REFUSED",
                status_assert.rstrip(" \\") + " || bar_fail S7_STATUS_NOT_503",
                'echo "S7_PASSED outcome=$A_OUTAGE_OUTCOME status=$A_OUTAGE_STATUS"',
            ]
        )
        return _run_bash(script)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestRound5F1S7CannotBeAwardedByABrokenHarness:
    """S7's claim is "the BFF refused a fresh login while its session store was
    destroyed". ONLY an observation of the BFF's own refusal may award it.

    The pre-review drive_login_capture synthesised ``{"ok": false, "login_failed": true}``
    for EVERY non-zero driver exit and every empty ``--out``. So a Chromium crash, a
    selector typo, a ``uv`` resolution failure, an OOM or a password missing from the
    credentials file each MANUFACTURED the exact evidence the bar was looking for. Round 4
    tightened the assertion from ``!= "true"`` to an observed ``= "false"``, which closed
    the fabrication inside ``jq_get`` — and left this one, one level up, untouched."""

    @pytest.mark.parametrize(
        ("mode", "why"),
        [
            ("crash", "the driver CRASHED — a Chromium launch failure is not a BFF refusal"),
            ("garbage", "the driver wrote a traceback to --out, not a result document"),
            ("partial", "the driver died mid-write, leaving TRUNCATED JSON"),
            (
                "legacy_ok_false",
                "the PRE-REVIEW FABRICATED SHAPE ({ok:false, login_failed:true}) — the very "
                "document the old helper synthesised out of a crash. It must no longer "
                "satisfy the bar, or the fix is cosmetic",
            ),
            ("refused_no_status", "a refusal with NO observed http_status is not an observation"),
            (
                "refused_but_exited_zero",
                "the document and the exit code CONTRADICT each other, so neither is trusted",
            ),
            (
                "refused_but_exited_driver_error",
                "only LOGIN_REFUSED_EXIT may authenticate a refusal-shaped document; a generic "
                "driver-error exit must never be laundered into governed evidence",
            ),
            (
                "authenticated_but_exited_nonzero",
                "the document and the exit code CONTRADICT each other",
            ),
        ],
    )
    def test_a_broken_harness_can_never_award_s7(self, mode: str, why: str) -> None:
        probe = _s7_browser_probe(mode)
        assert "S7_PASSED" not in probe.stdout, (
            f"S7 was AWARDED by a broken proof harness: {why}.\n"
            f"stdout={probe.stdout!r}\nstderr={probe.stderr!r}"
        )
        assert probe.returncode != 0, "a broken harness must ABORT the run, not continue"
        assert "OBSERVED_OUTCOME=[driver_error]" in probe.stdout, (
            "a harness failure must classify as driver_error — the one outcome that is NOT "
            f"an observation of anything about the BFF. stdout={probe.stdout!r}"
        )

    def test_the_bff_authenticating_with_the_store_down_fails_the_bar(self) -> None:
        """The FORBIDDEN behaviour: a memory continuation. It must fail LOUD, and it must
        NOT be confused with a driver error."""
        probe = _s7_browser_probe("authenticated")
        assert "S7_PASSED" not in probe.stdout
        assert probe.returncode != 0
        assert "OBSERVED_OUTCOME=[authenticated]" in probe.stdout, (
            "a BFF that authenticated a login with its store destroyed must be reported as "
            "AUTHENTICATED — not laundered into a driver error"
        )

    def test_a_refusal_with_the_wrong_status_fails_the_bar(self) -> None:
        """An OBSERVED refusal, but not the GOVERNED one. A 500 means the BFF fell over;
        the spec names 503."""
        probe = _s7_browser_probe("refused_500")
        assert "S7_PASSED" not in probe.stdout
        assert "OBSERVED_OUTCOME=[refused]" in probe.stdout
        assert probe.returncode != 0

    def test_only_an_observed_governed_refusal_awards_s7(self) -> None:
        """The ONE case that may pass: the driver OBSERVED the BFF refuse the /login
        navigation with the governed 503."""
        probe = _s7_browser_probe("refused_503")
        assert probe.returncode == 0, f"stdout={probe.stdout!r} stderr={probe.stderr!r}"
        assert "S7_PASSED outcome=refused status=503" in probe.stdout


#: A stand-in for curl, driven by FAKE_CURL_{CODE,BODY,RC}. It honours `-o <file>` and
#: prints the code on stdout exactly as `-w '%{http_code}'` does — including curl's real
#: behaviour of printing `000` when the connection never happened.
_FAKE_CURL = """#!/bin/sh
has_data=0
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  if [ "$a" = "-d" ]; then has_data=1; fi
  prev="$a"
done
[ "$has_data" = "1" ] && cat > /dev/null
[ -n "$out" ] && printf '%s' "${FAKE_CURL_BODY:-}" > "$out"
printf '%s' "${FAKE_CURL_CODE:-000}"
exit "${FAKE_CURL_RC:-0}"
"""


def _s7_direct_probe(code: str, rc: str) -> subprocess.CompletedProcess[str]:
    """Drive the REAL bff_fresh_login_status + the REAL S7 direct-probe assertions."""
    tmp = Path(tempfile.mkdtemp())
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(_FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        block = _extract_runner_block(
            "# (1) THE DIRECT, DRIVER-FREE PROBE", 'A_S7_FRESH_DOWN" = "503"'
        )
        # the assertion's own `|| bar_fail …` continuation line
        lines = _RUNNER_TEXT.splitlines()
        idx = next(
            i for i, ln in enumerate(lines) if ln.startswith('[ "$A_S7_FRESH_DOWN" = "503" ]')
        )
        block = block + "\n" + lines[idx + 1]
        script = "\n".join(
            [
                "set -euo pipefail",
                f'export PATH="{bin_dir}:$PATH"',
                f'export FAKE_CURL_CODE="{code}"',
                f'export FAKE_CURL_RC="{rc}"',
                'PROOF_CA="/dev/null"',
                'HARNESS_BASE_URL="https://127.0.0.1:8444"',
                'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
                _extract_shell_function("bff_fresh_login_status"),
                block,
                'echo "S7_DIRECT_PASSED status=$A_S7_FRESH_DOWN"',
            ]
        )
        return _run_bash(script)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestRound5F1S7DirectLoginProbe:
    """The driver-free half of the F1 fix — a cookie-less, CA-verified ``GET /login``.

    With Redis scaled to zero the BFF's ``create_pre_auth()`` (the FIRST store touch in the
    login flow) raises SessionStoreUnavailable, and the harness's registered handler returns
    EXACTLY 503. So a plain HTTP GET is a DIRECT observation of the very claim S7 makes —
    with no browser in the loop and therefore no fabrication surface at all."""

    @pytest.mark.parametrize(
        ("code", "rc", "why"),
        [
            (
                "000",
                "7",
                "TRANSPORT FAILURE — curl never reached the BFF. `000` must never "
                "be mistaken for a refusal: a tool that could not run has observed "
                "nothing",
            ),
            ("200", "0", "the BFF served the login page with its store destroyed"),
            (
                "302",
                "0",
                "the BFF REDIRECTED to Keycloak — it minted pre-auth state with no "
                "store to mint it into (a memory continuation, FORBIDDEN)",
            ),
            ("500", "0", "the BFF fell over; the spec names the governed 503"),
            ("404", "0", "a typo'd endpoint observes nothing about the store outage"),
            (
                "503",
                "28",
                "THE ISOLATION CASE for the exit-status gate: curl reports the status it "
                "SAW and still FAILS (a --max-time timeout after the status line exits 28 "
                "with %{http_code} populated). The status and the body look perfect, but "
                "the tool did not run to completion, so it observed nothing. Without the "
                "explicit rc check the status gate alone would wave this through",
            ),
        ],
    )
    def test_only_an_observed_503_may_pass(self, code: str, rc: str, why: str) -> None:
        probe = _s7_direct_probe(code, rc)
        assert "S7_DIRECT_PASSED" not in probe.stdout, (
            f"the direct /login probe passed on HTTP {code} (curl rc={rc}): {why}"
        )
        assert probe.returncode != 0

    def test_an_observed_503_passes(self) -> None:
        probe = _s7_direct_probe("503", "0")
        assert probe.returncode == 0, f"stderr={probe.stderr!r}"
        assert "S7_DIRECT_PASSED status=503" in probe.stdout


def test_r5_f1_the_login_capture_helper_never_fabricates_a_refusal() -> None:
    """The pre-review synthesis is GONE from the source, not merely out-competed. A helper
    that can still mint ``{"ok": false, "login_failed": true}`` invites a call site that
    trusts it."""
    body = _extract_shell_function("drive_login_capture")
    assert "login_failed" not in body, (
        "drive_login_capture still synthesises a login_failed document — it must classify "
        "the drive, never invent its outcome"
    )
    assert '"$_LOGIN_OUTCOME_PY"' in body, (
        "drive_login_capture must classify the driver's --out through the closed 3-value "
        "outcome vocabulary"
    )
    # The classifier reads the (credential-bearing) result document on STDIN; only the exit
    # code and the stderr PATH ride argv.
    assert '"$rc" "$err_file" < "$out_file"' in body


def test_r5_f1_driver_error_is_minted_by_the_runner_and_never_by_the_driver() -> None:
    """`driver_error` means "the proof harness broke". The driver cannot report that —
    precisely because it broke — so only the runner's capturing wrapper may mint it.

    Comments may NAME the value (the note is what stops someone wiring it up); only
    EXECUTABLE code is forbidden from producing it."""
    offenders = [
        ln.strip()
        for ln in _DRIVER_TEXT.splitlines()
        if "driver_error" in ln and not ln.lstrip().startswith("#")
    ]
    assert not offenders, (
        "the driver EMITS driver_error from executable code. A crashed process cannot "
        "report its own crash, so a driver that mints the value only invites the runner "
        f"to trust it: {offenders}"
    )
    assert "driver_error" in _RUNNER_TEXT


def test_r5_f1_s7_asserts_on_the_discriminator_and_the_governed_status() -> None:
    """Affirmative, both halves: an OBSERVED `refused`, and the governed 503."""
    assert '[ "$A_OUTAGE_OUTCOME" = "refused" ]' in _RUNNER_TEXT
    assert '[ "$A_OUTAGE_STATUS" = "503" ]' in _RUNNER_TEXT
    # The round-4 boolean, which a fabricated `driver_error` could still satisfy, is gone
    # from every EXECUTABLE line. Comments may still name it — the note explaining WHY it
    # was insufficient is what stops someone reinstating it.
    revived = [
        ln.strip()
        for ln in _RUNNER_TEXT.splitlines()
        if "A_OUTAGE_OK" in ln and not ln.lstrip().startswith("#")
    ]
    assert not revived, (
        "S7 is reading the `ok` boolean again. `ok: false` cannot tell a BFF refusal apart "
        f"from a broken proof harness, which is the whole of finding F1: {revived}"
    )
    # ... and the direct, driver-free probe is wired into the leg
    assert 'A_S7_FRESH_DOWN="$(bff_fresh_login_status)"' in _RUNNER_TEXT
    assert '[ "$A_S7_FRESH_DOWN_RC" -eq 0 ]' in _RUNNER_TEXT


def test_r5_f1_no_fail_open_boolean_assertion_survives_anywhere() -> None:
    """Carried forward from round 4 (it was never S7-specific): every boolean bar assertion
    must NAME the value it requires. `!=` against a bool passes on everything else,
    including a non-observation."""
    offenders = [
        ln.strip()
        for ln in _RUNNER_TEXT.splitlines()
        if re.search(r'\[ "\$[A-Z_]+" != "(true|false)" \]', ln) and not ln.lstrip().startswith("#")
    ]
    assert not offenders, f"fail-open boolean assertion(s) reintroduced: {offenders}"


# --------------------------------------------------------------------------- #
# F2 — the disabled-grant claim needs an OAuth refusal that NAMES the grant.   #
# --------------------------------------------------------------------------- #


def _grant_probe(code: str, body: str, rc: str = "0") -> subprocess.CompletedProcess[str]:
    """Drive the REAL kc_token_probe + the REAL assert_grant_disabled against a fake
    Keycloak. Prints GRANT_ASSERT_PASSED only if the bar would award the leg."""
    tmp = Path(tempfile.mkdtemp())
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(_FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        (tmp / "qc").mkdir()
        script = "\n".join(
            [
                "set -euo pipefail",
                f'export PATH="{bin_dir}:$PATH"',
                f"export FAKE_CURL_CODE={shlex.quote(code)}",
                f"export FAKE_CURL_BODY={shlex.quote(body)}",
                f"export FAKE_CURL_RC={shlex.quote(rc)}",
                f'QC_TMP="{tmp / "qc"}"',
                'PROOF_CA="/dev/null"',
                'KC_ISSUER="https://kc.invalid/realms/proof"',
                'die() { echo "DIE: $*" >&2; exit 90; }',
                'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
                _extract_shell_single_quoted_var("_OAUTH_ERROR_PY"),
                _extract_shell_function("kc_token_probe"),
                'GRANT_OBSERVED_ERROR=""',
                _extract_shell_function("assert_grant_disabled"),
                "set +e",
                "CODE=\"$(printf 'grant_type=client_credentials&client_id=c&client_secret=s' "
                '| kc_token_probe "$QC_TMP/body.json")"',
                "RC=$?",
                "set -e",
                'assert_grant_disabled "probe grant" "$QC_TMP/body.json" "$RC" "$CODE"',
                'echo "GRANT_ASSERT_PASSED code=$CODE error=$GRANT_OBSERVED_ERROR"',
            ]
        )
        return _run_bash(script)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestRound5F2DisabledGrantNeedsAnObservedGrantTypeRefusal:
    """The two disabled-grant legs were the ONLY unguarded negative assertions in the
    whole runner: ``[ "$CODE" != "200" ] || bar_fail``.

    That is fail-open four ways. It passes on 404 (a typo'd endpoint), on 500 (Keycloak
    itself broke), and — worst — on curl's ``000``, which is what ``%{http_code}`` prints
    when the connection NEVER HAPPENED. A total failure to contact Keycloak "proved" the
    grants were disabled. And even a legitimate 400 does not carry the claim: a password
    grant that is ENABLED refuses a WRONG PASSWORD with 400 ``invalid_grant``, so the
    status alone cannot tell "this client may not use this grant type" apart from "your
    credentials were wrong".

    RFC 6749 §5.2 names the one code that IS the claim: ``unauthorized_client`` — "the
    authenticated client is not authorized to use this authorization grant type"."""

    @pytest.mark.parametrize(
        ("code", "body", "rc", "why"),
        [
            (
                "000",
                "",
                "7",
                "TRANSPORT FAILURE — curl never reached Keycloak. This is the reviewer's "
                "headline case: `[ 000 != 200 ]` is TRUE, so the pre-review assertion "
                "PASSED without the request ever reaching the server",
            ),
            (
                "200",
                '{"access_token":"AT"}',
                "0",
                "the grant SUCCEEDED — the locked profile does NOT hold",
            ),
            ("404", "<html>Not Found</html>", "0", "a typo'd token endpoint observes nothing"),
            (
                "500",
                '{"error":"internal_error"}',
                "0",
                "Keycloak BROKE. A 5xx is not a refusal, and it is not evidence of anything "
                "about the grant profile",
            ),
            (
                "400",
                '{"error":"invalid_grant"}',
                "0",
                "THE SUBTLE ONE: direct-access grants may be ENABLED and the PASSWORD simply "
                "wrong. Accepting this would let the leg pass while direct access is live",
            ),
            (
                "400",
                '{"error":"invalid_client"}',
                "0",
                "the client SECRET was wrong, so client authentication failed — the grant-type "
                "check was never reached",
            ),
            (
                "400",
                '{"error":"invalid_request"}',
                "0",
                "the probe itself was malformed",
            ),
            ("400", "<html>oops</html>", "0", "a non-JSON body: the REASON was never observed"),
            ("400", "{}", "0", "a JSON body with no error field: the reason was never observed"),
            ("401", '{"error":"unauthorized_client"}', "0", "not the 400 Keycloak documents"),
            (
                "400",
                '{"error":"unauthorized_client"}',
                "28",
                "THE ISOLATION CASE for the exit-status gate: a PERFECT-LOOKING refusal from "
                "a curl that FAILED (a --max-time timeout after the status line exits 28 with "
                "%{http_code} populated). The tool did not run to completion, so nothing it "
                "printed is a trustworthy observation. Without the explicit rc check the "
                "status and error-code gates would both wave this through",
            ),
        ],
    )
    def test_only_an_observed_unauthorized_client_may_pass(
        self, code: str, body: str, rc: str, why: str
    ) -> None:
        probe = _grant_probe(code, body, rc)
        assert "GRANT_ASSERT_PASSED" not in probe.stdout, (
            f"the disabled-grant leg PASSED on HTTP {code} / body {body!r} / curl rc={rc}: {why}"
        )
        assert probe.returncode != 0, "the leg must ABORT the run"

    def test_an_observed_unauthorized_client_refusal_passes(self) -> None:
        """The ONE case that carries the claim."""
        probe = _grant_probe("400", '{"error":"unauthorized_client"}')
        assert probe.returncode == 0, f"stdout={probe.stdout!r} stderr={probe.stderr!r}"
        assert "GRANT_ASSERT_PASSED code=400 error=unauthorized_client" in probe.stdout


def test_r5_f2_no_unguarded_negative_status_assertion_survives() -> None:
    """The bug class, stated directly: an HTTP status compared with `!=` passes on every
    value the author did not anticipate — including curl's `000`, which means the request
    never happened at all. Every status assertion in the runner must NAME the status it
    requires."""
    offenders = [
        ln.strip()
        for ln in _RUNNER_TEXT.splitlines()
        if re.search(r'\[ "\$[A-Z_0-9]+" != "[0-9]{3}" \]', ln) and not ln.lstrip().startswith("#")
    ]
    # S7's `A_S7_DOWN != 200` is PAIRED with an affirmative `= "503"` on the very next
    # assertion, so it is a defence-in-depth restatement, not the load-bearing gate.
    allowed = {'[ "$A_S7_DOWN" != "200" ] \\'}
    unguarded = [ln for ln in offenders if ln not in allowed]
    assert not unguarded, (
        "an HTTP status is asserted with `!=`, which passes on curl's 000 (the request "
        f"never reached the server) and on every unanticipated value: {unguarded}"
    )


def test_r5_f2_the_grant_probe_captures_status_body_and_curl_exit_status() -> None:
    """All three, or the claim cannot be made: the STATUS (was it a refusal?), the BODY
    (was it refused for the GRANT TYPE?) and curl's EXIT STATUS (did the request happen at
    all?). The pre-review probe discarded the body with `-o /dev/null` and never looked at
    curl's exit status."""
    body = _extract_shell_function("kc_token_probe")
    assert "-o /dev/null" not in body, "the probe discards the response body again"
    assert 'return "$rc"' in body, (
        "kc_token_probe must RETURN curl's exit status — the kubectl_capture contract. A "
        "bar_fail here would be swallowed by bash 3.2 one substitution level deeper."
    )
    assert "bar_fail" not in body, (
        "kc_token_probe must not bar_fail: callers invoke it inside `$( … )`, where bash 3.2 "
        "ignores `set -e` and would hand back a clean fabricated value anyway"
    )
    # the caller checks it, and the secrets stay off argv
    assert "B_CC_RC=$?" in _RUNNER_TEXT and "B_DAG_RC=$?" in _RUNNER_TEXT
    assert "-d @-" in body, "the client secret / password must ride STDIN, never argv"
    assert 'assert_grant_disabled "client-credentials grant"' in _RUNNER_TEXT
    assert 'assert_grant_disabled "direct-access (password) grant"' in _RUNNER_TEXT


def test_r5_f2_the_grant_assertion_demands_the_rfc6749_grant_type_reason() -> None:
    body = _extract_shell_function("assert_grant_disabled")
    assert '[ "$err" = "unauthorized_client" ]' in body, (
        "the leg must demand RFC 6749 §5.2's unauthorized_client — the ONLY code that means "
        "'this client may not use this GRANT TYPE'"
    )
    assert '[ "$code" = "400" ]' in body, "the leg must demand an OBSERVED refusal status"
    assert '[ "$rc" -eq 0 ]' in body, "the leg must reject a transport failure explicitly"


# --------------------------------------------------------------------------- #
# F3 — S10's "same bytes" claim is now TRUE, and proven at both levels.        #
# --------------------------------------------------------------------------- #


def _s10_mutate(record: bytes) -> subprocess.CompletedProcess[bytes]:
    """Drive the REAL _S10_MUTATE_PY over a record."""
    source = _extract_shell_single_quoted_var("_S10_MUTATE_PY")
    program = source.split("='", 1)[1][:-1]  # strip `_S10_MUTATE_PY='` … `'`
    return subprocess.run(["python3", "-c", program], input=record, capture_output=True, timeout=60)


#: EXACTLY how the harness serialises a session record: ``json.dumps(record.to_wire())``
#: — Python's DEFAULT separators (``", "`` and ``": "``), NOT the compact ones the
#: pre-review rewrite used. That difference IS the finding.
def _bff_serialised(record: dict[str, object]) -> bytes:
    import json

    return json.dumps(record).encode()


class TestRound5F3S10ByteExactMutation:
    """S10 is billed as a controlled SINGLE-VARIABLE experiment — same key, same bytes,
    same deadline, only ``v`` changes — so the refusal cannot be explained by anything else.

    The claim was FALSE. The record was round-tripped through Python's JSON encoder with
    COMPACT separators while the harness writes it with the DEFAULT ones, so EVERY
    SEPARATOR BYTE in the record changed. The conclusion still held (the semantic fields
    were untouched), but the CLAIM did not — and this document's entire value is that its
    claims are exactly true. Worse, the round trip was a HIDDEN SECOND VARIABLE: the day
    ``to_wire()`` grows a field whose json round trip is not byte-faithful, "only v changed"
    silently becomes false in a way that DOES matter, and nothing would catch it."""

    def test_the_mutation_differs_only_in_the_version_span(self) -> None:
        import json

        record = {
            "v": 1,
            "session_id": "sess-abc",
            "access_token": "AT",
            "refresh_token": "RT",
            "id_token": "IT",
            "created_at": 1700000000.5,
            "last_seen_at": 1700000042.25,
            "claims": {"sub": "kc#u1", "scopes": ["a", "b"]},
        }
        raw = _bff_serialised(record)
        out = _s10_mutate(raw)
        assert out.returncode == 0, out.stderr.decode()
        mutated = out.stdout

        # (a) BYTE LEVEL — the two strings differ in exactly ONE contiguous span, and that
        #     span is the version value.
        # zip is deliberately NON-strict: the mutated record is exactly 2 bytes LONGER
        # (b"1" -> b"999"), which is itself part of what is being asserted below.
        divergence = next(i for i, (a, b) in enumerate(zip(raw, mutated, strict=False)) if a != b)
        assert raw[:divergence] == mutated[:divergence], "the bytes BEFORE the span changed"
        assert raw[divergence : divergence + 1] == b"1"
        assert mutated[divergence : divergence + 3] == b"999"
        assert raw[divergence + 1 :] == mutated[divergence + 3 :], (
            "the bytes AFTER the version span changed — this is exactly the separator "
            "rewrite the pre-review re-serialisation performed"
        )
        assert len(mutated) == len(raw) + 2

        # (b) SEMANTIC LEVEL — every other key and value survives, IN ORDER.
        after = json.loads(mutated)
        assert after["v"] == 999
        assert [(k, v) for k, v in after.items() if k != "v"] == [
            (k, v) for k, v in record.items() if k != "v"
        ]

        # (c) and the separator style the harness actually uses is PRESERVED — the thing
        #     the pre-review rewrite destroyed.
        assert b'", "' in mutated and b'": "' in mutated, (
            "the record was re-serialised with compact separators — the 'same bytes' claim "
            "is false again"
        )

    def test_a_compact_record_is_handled_too_without_assuming_a_style(self) -> None:
        """Nothing about the harness's separator style is HARD-CODED: the token is derived
        from the record actually read. A compact record mutates byte-exactly as well."""
        import json

        raw = json.dumps({"v": 1, "session_id": "s"}, separators=(",", ":")).encode()
        out = _s10_mutate(raw)
        assert out.returncode == 0, out.stderr.decode()
        assert out.stdout == b'{"v":999,"session_id":"s"}'

    @pytest.mark.parametrize(
        ("record", "reason", "why"),
        [
            (
                b'{"v": 1, "nested": {"v": 1}, "s": "x"}',
                "s10_version_token_not_unique",
                'THE DECOY: a NESTED object carrying its own `"v": 1` puts a SECOND '
                "identical token in the raw bytes. A blind str.replace would have hit "
                "whichever came first; the mutation REFUSES an ambiguous record rather "
                "than guessing which span is the real one",
            ),
            (
                b'{"v": 2, "session_id": "s"}',
                "s10_unexpected_stored_schema_version",
                "the leg's precondition is that the STORED version is 1; anything else means "
                "the schema moved and the experiment is not the one being claimed",
            ),
            (b"not json at all", "s10_record_unparseable", "an unreadable record is refused"),
            (b'[{"v": 1}]', "s10_record_is_not_a_json_object", "a non-object is refused"),
            (
                b'{"session_id": "s"}',
                "s10_unexpected_stored_schema_version",
                "a record with NO version field cannot have its version mutated",
            ),
        ],
    )
    def test_an_ambiguous_or_unexpected_record_is_refused_loudly(
        self, record: bytes, reason: str, why: str
    ) -> None:
        out = _s10_mutate(record)
        assert out.returncode != 0, f"the mutation must REFUSE: {why}"
        assert reason.encode() in out.stderr, (
            f"expected the closed refusal {reason!r}, got {out.stderr!r}"
        )
        assert out.stdout == b"", (
            "a REFUSED mutation printed a record anyway — the runner would go on to write "
            "it, and the single-variable claim would rest on bytes nobody verified"
        )

    def test_a_version_token_inside_a_string_value_cannot_forge_a_span(self) -> None:
        """A string VALUE that contains the text `"v": 1` cannot create a false candidate:
        JSON escapes the quotes (`\\"v\\": 1`), so the literal `"v"` never appears in the
        raw bytes. Pinned so the uniqueness guard is understood to rest on JSON's own
        escaping, not on luck."""
        import json

        raw = _bff_serialised({"v": 1, "note": 'the text "v": 1 appears in this string'})
        assert raw.count(b'"v"') == 1, "JSON did not escape the decoy — the premise is wrong"
        out = _s10_mutate(raw)
        assert out.returncode == 0, out.stderr.decode()
        after = json.loads(out.stdout)
        assert after["v"] == 999
        assert after["note"] == 'the text "v": 1 appears in this string', (
            "the string value was corrupted by the byte replacement"
        )

    def test_a_nested_version_that_is_not_a_bare_one_does_not_confuse_the_token(self) -> None:
        """The negative lookahead earns its keep: a nested ``"v": 10`` is not a candidate
        span, so the record is not spuriously rejected as ambiguous."""
        import json

        raw = _bff_serialised({"v": 1, "meta": {"v": 10}, "s": "x"})
        out = _s10_mutate(raw)
        assert out.returncode == 0, out.stderr.decode()
        after = json.loads(out.stdout)
        assert after["v"] == 999
        assert after["meta"] == {"v": 10}, "the nested version was mutated — wrong span"


def test_r5_f3_the_runner_proves_its_copy_is_the_stored_bytes() -> None:
    """The byte-level check can only compare the runner's COPY of the record. A command
    substitution strips trailing newlines, so the copy could already differ from the stored
    bytes — and "only v changed" would be false before the mutation even ran. Redis hashes
    its OWN bytes; the runner hashes its copy; they must agree."""
    assert "_S10_SHA1_LUA=" in _RUNNER_TEXT
    assert "redis.sha1hex(v)" in _RUNNER_TEXT
    assert '[ "$A_S10_STORED_SHA1" = "$A_S10_LOCAL_SHA1" ]' in _RUNNER_TEXT
    assert "is NOT byte-identical to the record redis stores" in _RUNNER_TEXT


def test_r5_f3_the_success_line_no_longer_overclaims() -> None:
    """The old line said "same cookie, same record, same deadline … the ONLY difference is
    the schema version" while every separator byte had in fact been rewritten. The line must
    now say only what is actually guaranteed."""
    line = next(
        (ln for ln in _RUNNER_TEXT.splitlines() if "Bar A S10 OK:" in ln),
        None,
    )
    assert line, "S10's success line is gone"
    assert "BYTE-IDENTICAL apart from the 1 byte that encoded the schema version" in line
    assert "same cookie, same record, same deadline" not in line, (
        "S10's success line still makes the pre-review claim verbatim"
    )


# --------------------------------------------------------------------------- #
# F5 (Bar F half) — the |safe gate is SEMANTIC, and fails loud if it cannot    #
# actually scan.                                                               #
# --------------------------------------------------------------------------- #


def _template_scan(root: Path) -> subprocess.CompletedProcess[str]:
    """Drive the REAL embedded scanner (`_F_TEMPLATE_SCAN_PY`) over a directory."""
    source = _extract_shell_single_quoted_var("_F_TEMPLATE_SCAN_PY")
    program = source.split("='", 1)[1][:-1]
    return subprocess.run(
        ["python3", "-c", program, str(root)], capture_output=True, text=True, timeout=60
    )


def _template_tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp()) / "cognic_harness" / "web" / "templates"
    root.mkdir(parents=True)
    for name, source in files.items():
        (root / name).write_text(source)
    return root.parents[1]


#: The 8 templates the harness actually ships, in clean (autoescaped) form.
_HARNESS_TEMPLATE_NAMES = (
    "approval_detail.html",
    "approvals.html",
    "base.html",
    "chat.html",
    "evidence_chain.html",
    "evidence_list.html",
    "evidence_transcript.html",
    "login.html",
)


class TestRound5F5TemplateAutoescapeGateIsSemantic:
    """The deployed-image ``|safe`` gate carried Bar F's strongest claim — no XSS escape
    hatch — and was its WEAKEST check: ``grep -rl '|safe'``.

    A grep for one spelling is evaded by rewording. And it wore a ``|| true``, so a grep
    that could not run AT ALL yielded the empty string and ``[ -z "" ]`` PASSED — finding
    F2's bug class living inside finding F5. A failed scan is not an observation of a clean
    bundle.

    The gate now parses every shipped template with the image's own jinja2 and walks the
    AST, so it reasons about NODES rather than spelling."""

    @pytest.mark.parametrize(
        ("name", "source", "why"),
        [
            ("safe_plain.html", "{{ x|safe }}", "the literal the old grep caught"),
            ("safe_space_r.html", "{{ x| safe }}", "ONE SPACE evades a grep for '|safe'"),
            ("safe_space_rr.html", "{{ x|  safe }}", "two spaces"),
            ("safe_space_l.html", "{{ x |safe }}", "a space on the left"),
            ("safe_space_both.html", "{{ x | safe }}", "spaces on both sides"),
            ("safe_chained.html", "{{ x|e|safe }}", "chained after another filter"),
            ("safe_newline.html", "{{ x\n   |\n   safe }}", "split across lines"),
            (
                "filter_block.html",
                "{% filter safe %}{{ x }}{% endfilter %}",
                "the filter BLOCK form",
            ),
            (
                "autoescape_false.html",
                "{% autoescape false %}{{ x }}{% endautoescape %}",
                "disables escaping for a WHOLE BLOCK and contains no `safe` filter at all — "
                "the grep could never have caught it",
            ),
            (
                "autoescape_true.html",
                "{% autoescape true %}{{ x }}{% endautoescape %}",
                "BANNED OUTRIGHT: permitting the node means a later edit flips it to false "
                "without tripping the gate",
            ),
            (
                "unparseable.html",
                "{% if x %}",
                "a template that will not PARSE cannot be cleared — it must not be skipped "
                "into a pass",
            ),
        ],
    )
    def test_every_bypass_shape_is_rejected(self, name: str, source: str, why: str) -> None:
        root = _template_tree({name: source, "clean.html": "<p>{{ x }}</p>"})
        try:
            scan = _template_scan(root)
            assert scan.returncode != 0, (
                f"the autoescape gate PASSED a template that bypasses escaping ({name}): "
                f"{why}\nstdout={scan.stdout!r}"
            )
            assert "OFFENDER" in scan.stdout
            assert name in scan.stdout
        finally:
            shutil.rmtree(root.parents[0], ignore_errors=True)

    def test_the_real_harness_template_set_passes(self) -> None:
        """The 8 shipped templates, in clean autoescaped form, must CLEAR the gate — or the
        scanner is not usable and would be weakened back out."""
        clean = (
            "{% extends 'base.html' %}\n"
            "{% block content %}\n"
            "  <h1>{{ title }}</h1>\n"
            "  <p>{{ user_text }}</p>\n"
            "  <p>{{ maybe_none|default('—') }}</p>\n"
            "  {% for row in rows %}<td>{{ row.id|e }}</td>{% endfor %}\n"
            "  {% if x %}<span>{{ x }}</span>{% endif %}\n"
            "{% endblock %}\n"
        )
        root = _template_tree({name: clean for name in _HARNESS_TEMPLATE_NAMES})
        try:
            scan = _template_scan(root)
            assert scan.returncode == 0, (
                f"the gate REJECTED the clean harness template set: {scan.stdout!r}"
            )
            assert "TEMPLATES_SCANNED=8" in scan.stdout
            assert "OFFENDERS=0" in scan.stdout
        finally:
            shutil.rmtree(root.parents[0], ignore_errors=True)

    @pytest.mark.parametrize("name", ["bypass.tpl", "bypass.xml", "bypass.txt"])
    def test_unknown_template_extension_cannot_escape_the_census(self, name: str) -> None:
        """Jinja loads filenames, not a fixed extension vocabulary. The former suffix
        allow-list ignored an added ``.tpl`` entirely, so eight clean HTML files plus an
        unsafe ninth file still satisfied the pinned count and passed. Every file under
        the template root is now observed and any name outside the exact reviewed set
        fails loud."""
        clean = "<p>{{ x }}</p>"
        files = {template: clean for template in _HARNESS_TEMPLATE_NAMES}
        files[name] = "{{ x|safe }}"
        root = _template_tree(files)
        try:
            scan = _template_scan(root)
            assert scan.returncode != 0, (
                f"the deployed-image scanner ignored {name!r} and reported the exact-eight "
                f"census clean: stdout={scan.stdout!r}"
            )
            assert name in scan.stdout
            assert "census mismatch" in scan.stdout
        finally:
            shutil.rmtree(root.parents[0], ignore_errors=True)

    def test_zero_templates_is_a_hard_failure_not_a_pass(self) -> None:
        """THE DOCTRINE, applied to the scanner itself. If the glob is wrong or the exec
        broke, the scan has observed NOTHING — and "no offenders found" is exactly the
        fabricated safe-looking default. It must FAIL."""
        root = _template_tree({})
        try:
            scan = _template_scan(root)
            assert scan.returncode != 0, (
                "the gate PASSED having scanned ZERO templates. A scan that observed nothing "
                "is not evidence of a clean bundle — this is the `|| true` bug in a new coat."
            )
            assert "ZERO templates were scanned" in scan.stdout
        finally:
            shutil.rmtree(root.parents[0], ignore_errors=True)

    def test_a_missing_package_directory_is_a_hard_failure(self) -> None:
        scan = _template_scan(Path("/nonexistent/python*/site-packages/cognic_harness"))
        assert scan.returncode != 0
        assert "SCANNER_ERROR" in scan.stdout
        assert "was not found" in scan.stdout

    def test_the_glob_is_resolved_and_a_real_python_glob_is_used(self) -> None:
        """`kubectl exec` runs NO shell, so `$F_PKG`'s `python*` reaches the scanner
        un-expanded. Python must do the globbing, or the scan finds nothing — and "nothing"
        would have been reported as clean."""
        tmp = Path(tempfile.mkdtemp())
        try:
            pkg = tmp / "opt" / "venv" / "lib" / "python3.12" / "site-packages" / "cognic_harness"
            template_root = pkg / "web" / "templates"
            template_root.mkdir(parents=True)
            for name in _HARNESS_TEMPLATE_NAMES:
                (template_root / name).write_text("<p>{{ x }}</p>")
            glob = tmp / "opt" / "venv" / "lib" / "python*" / "site-packages" / "cognic_harness"
            scan = _template_scan(Path(str(glob)))
            assert scan.returncode == 0, scan.stdout
            assert "TEMPLATES_SCANNED=8" in scan.stdout
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def test_r5_f5_the_textual_safe_grep_is_gone_from_bar_f() -> None:
    """The evadable check must be DELETED, not merely supplemented — a grep that still runs
    invites a reader to believe it is the gate."""
    executable = [ln for ln in _RUNNER_TEXT.splitlines() if not ln.lstrip().startswith("#")]
    for line in executable:
        assert "grep -rl '|safe'" not in line, (
            f"the textual |safe grep survives — every spacing variant evades it: {line.strip()!r}"
        )
    assert "F_SAFE=" not in _RUNNER_TEXT
    assert "_F_TEMPLATE_SCAN_PY=" in _RUNNER_TEXT


def test_r5_f5_the_template_scan_is_read_through_the_fail_loud_capture() -> None:
    """A scan that could not run must ABORT, never report a clean bundle."""
    assert 'F_TPL="$(kubectl_capture -n "$NS" exec "$F_POD" -- python -c' in _RUNNER_TEXT
    assert "F_TPL_RC=$?" in _RUNNER_TEXT
    assert '[ "$F_TPL_RC" -eq 0 ]' in _RUNNER_TEXT
    # The exact census is asserted: zero, missing, renamed, and newly added unknown-suffix
    # files all fail. A merely-positive count let eight clean files hide an unsafe ninth.
    assert "TEMPLATES_SCANNED=\\([0-9][0-9]*\\)" in _RUNNER_TEXT
    assert '[ "$F_TPL_N" = "8" ]' in _RUNNER_TEXT
    assert "exact 8-file template census" in _RUNNER_TEXT


def test_r5_f5_no_bar_f_scan_swallows_its_own_failure_any_more() -> None:
    """The sibling gates carried the SAME `|| true` swallow: a grep/find that could not run
    yielded "" and `[ -z "" ]` PASSED. All three now check the tool's exit status."""
    for var, rc in (("F_ACTORHDR", "F_ACTORHDR_RC"), ("F_HTMX", "F_HTMX_RC")):
        assignment = next(
            (ln for ln in _RUNNER_TEXT.splitlines() if ln.startswith(f'{var}="$(')), None
        )
        assert assignment, f"Bar F's {var} scan is gone"
        assert "|| true" not in assignment, (
            f"Bar F's {var} scan swallows its own failure again — a scan that could not run "
            f"would read as a clean bundle: {assignment.strip()!r}"
        )
        assert "kubectl_capture" in assignment, f"{var} must read through the fail-loud capture"
        assert f"{rc}=$?" in _RUNNER_TEXT, f"{var}'s exit status is never checked"
    # grep's THREE states are told apart by exit CODE, never collapsed onto ""
    assert 'case "$F_ACTORHDR_RC" in' in _RUNNER_TEXT
    assert "could not RUN" in _RUNNER_TEXT


def test_r5_f1_the_driver_raises_the_refusal_FROM_the_observed_status() -> None:
    """AST, not text — and the distinction is the round-4 lesson, relearned.

    The driver's selftest checks that ``raise ObservedRefusal(`` APPEARS in ``cmd_login``.
    A threat-model revert proved that pin VACUOUS: neutering the guard to ``if False:``
    leaves the string right where it is, so the refusal becomes unreachable and the
    selftest never notices. The driver would then classify a genuine 503 as
    ``keycloak_login_form_absent`` — a harness error — and S7 would fail closed for the
    WRONG reason, which is a different (and quieter) bug than the one being fixed.

    So this walks the AST and requires the raise to be GUARDED BY A COMPARISON ON THE
    OBSERVED STATUS. `if False:` is a Constant, not a Compare against ``login_status``, and
    fails."""
    import ast

    tree = ast.parse(_DRIVER_TEXT)
    cmd_login = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "cmd_login"),
        None,
    )
    assert cmd_login is not None, "cmd_login is gone from the driver"

    # the status is READ from the navigation response, not invented
    reads_status = [
        n
        for n in ast.walk(cmd_login)
        if isinstance(n, ast.Attribute)
        and n.attr == "status"
        and isinstance(n.value, ast.Name)
        and n.value.id == "login_response"
    ]
    assert reads_status, (
        "cmd_login does not read the /login navigation's HTTP status. page.goto() RETURNS "
        "the Response on a non-2xx, which is the ONLY way the driver can observe the BFF's "
        "own refusal rather than merely failing somewhere downstream of it."
    )

    guarded_raises = []
    for node in ast.walk(cmd_login):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if "login_status" not in names:
            continue
        for stmt in ast.walk(node):
            if (
                isinstance(stmt, ast.Raise)
                and isinstance(stmt.exc, ast.Call)
                and isinstance(stmt.exc.func, ast.Name)
                and stmt.exc.func.id == "ObservedRefusal"
            ):
                guarded_raises.append(node)

    assert guarded_raises, (
        "cmd_login does not raise ObservedRefusal from a comparison on the OBSERVED login "
        "status. The raise must be REACHABLE and driven by what the BFF actually returned — "
        "a neutered guard (`if False:`) leaves the raise in the source, unreachable, and a "
        "text-matching pin would happily wave it through."
    )
    # ... and the refusal must carry the observed status out to the runner, or S7 cannot
    # tell the governed 503 from any other refusal.
    call = next(
        stmt.exc
        for node in guarded_raises
        for stmt in ast.walk(node)
        if isinstance(stmt, ast.Raise)
        and isinstance(stmt.exc, ast.Call)
        and isinstance(stmt.exc.func, ast.Name)
        and stmt.exc.func.id == "ObservedRefusal"
    )
    kwargs = {kw.arg for kw in call.keywords}
    assert "http_status" in kwargs, (
        "the refusal does not carry the observed http_status — S7 could not then demand the "
        "GOVERNED 503 rather than any refusal at all"
    )


# --------------------------------------------------------------------------- #
# The LIVE-RUN-FATAL bug found while building the round-5 mutation tests.      #
# --------------------------------------------------------------------------- #


def test_r6_runner_refuses_unsupported_bash_before_any_provider_call() -> None:
    """The documented executable resolves to macOS Bash 3.2 on the proof host, while
    the runner uses ``declare -A``. Before this guard it validated the provider key and
    then died at the first identity map. Execute the REAL guard under the current Bash,
    assert its result matches that shell's major version, and pin its placement before
    both the provider probe and the first associative declaration."""
    block = _extract_runner_block(
        'if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]',
        "fi",
    )
    probe = _run_bash(block)
    version = subprocess.run(
        ["bash", "-c", 'printf "%s" "${BASH_VERSINFO[0]}"'],
        capture_output=True,
        text=True,
        check=True,
    )
    major = int(version.stdout)
    assert probe.returncode == (0 if major >= 4 else 1), (
        f"the production Bash-version guard disagrees with Bash {major}: "
        f"stdout={probe.stdout!r} stderr={probe.stderr!r}"
    )
    if major < 4:
        assert "requires Bash 4.0+" in probe.stderr

    guard = _RUNNER_TEXT.index('if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]')
    provider = _RUNNER_TEXT.index("KEY_PROBE_CODE=")
    arrays = _RUNNER_TEXT.index("declare -A IDENTITY_TENANT")
    assert guard < provider < arrays, (
        "the Bash compatibility refusal must fire before the zero-spend provider probe "
        "and before declare -A can abort cryptically"
    )
    assert "Bash 4.0 or newer" in _README_TEXT
    assert "macOS `/bin/bash` 3.2 is unsupported" in _README_TEXT


def test_r6_driver_module_contract_names_the_distinct_refusal_exit() -> None:
    """The module contract formerly promised exit 0 for governed refusals while main
    deliberately returns ``LOGIN_REFUSED_EXIT``. Keep the public description aligned
    with the discriminator the runner consumes."""
    module_doc = _DRIVER_TEXT.split('"""', 2)[1]
    assert "LOGIN_REFUSED_EXIT" in module_doc
    assert "even when the observed" not in module_doc
    assert "a governed refusal" not in module_doc or "exits ``0``" not in module_doc


def test_r6_runner_consumes_the_driver_refusal_exit_contract() -> None:
    """The dedicated driver exit is not ornamental: only that exact status may
    authenticate a refusal-shaped document. Pin the two language surfaces together."""
    match = re.search(r"^LOGIN_REFUSED_EXIT\s*=\s*(\d+)\s*$", _DRIVER_TEXT, re.MULTILINE)
    assert match is not None, "driver.py no longer defines LOGIN_REFUSED_EXIT"
    refusal_exit = int(match.group(1))
    classifier = _extract_shell_single_quoted_var("_LOGIN_OUTCOME_PY")
    assert f"if rc != {refusal_exit}:" in classifier, (
        "the runner does not consume the driver's dedicated refusal exit; any non-zero "
        "driver failure could authenticate a refusal-shaped document"
    )


@pytest.mark.parametrize("fn", ["drive_login", "drive_login_capture"])
def test_r5_the_role_lookup_resolves_under_set_u_on_every_bash(fn: str) -> None:
    """`local role="$1" user="${IDENTITY_USER[$role]:-}"` DOES NOT WORK.

    Bash word-expands EVERY argument of the `local` builtin BEFORE the builtin assigns any
    of them, so the `$role` inside the second argument is the OUTER (unset) `role`, never
    the one being assigned beside it. Under the `set -u` this script runs with, that is a
    hard `role: unbound variable` abort. Reproduced on bash 3.2.57, 4.4 AND 5.2.

    Bar A's very first action is `drive_login amir`, so THE ENTIRE PROOF DIED ON ITS FIRST
    LOGIN, on every bash version. It had never fired because the proof has never been run
    end to end — which is exactly the class of bug an unrun script hides, and exactly why
    the round-5 mutation tests (which execute the REAL function text) surfaced it.

    This drives the REAL function against a fake driver: the role must RESOLVE, the
    password must be looked up, and the login JSON must come back."""
    tmp = Path(tempfile.mkdtemp())
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "uv").write_text(_FAKE_UV)
        (bin_dir / "uv").chmod(0o755)
        (tmp / "qc").mkdir()
        (tmp / "driver").mkdir()
        (tmp / "creds").mkdir()
        (tmp / "creds" / "realm-credentials.env").write_text("KC_PW_ANALYST_AMIR=hunter2\n")

        script = "\n".join(
            [
                "set -euo pipefail",
                f'export PATH="{bin_dir}:$PATH"',
                'export FAKE_DRIVER_MODE="authenticated"',
                f'QC_TMP="{tmp / "qc"}"',
                f'DRIVER_DIR="{tmp / "driver"}"',
                f'KC_CRED_TMP="{tmp / "creds"}"',
                'HARNESS_BASE_URL="https://127.0.0.1:8444"',
                'PROOF_CA="/dev/null"',
                'PKI_TMP="/dev/null"',
                # A numeric key: bash 3.2 (the macOS system bash) has no associative arrays,
                # and the role->user MAP is not what is under test — the LOOKUP is.
                'IDENTITY_USER=("analyst.amir")',
                'die() { echo "DIE: $*" >&2; exit 90; }',
                'bar_fail() { echo "BAR_FAIL: $*" >&2; exit 91; }',
                _extract_shell_single_quoted_var("_LOGIN_OUTCOME_PY"),
                _extract_shell_function(fn),
                f'OUT="$({fn} 0)"',
                'echo "LOOKUP_RESOLVED out=$OUT"',
            ]
        )
        probe = _run_bash(script)
        assert "unbound variable" not in probe.stderr, (
            f"{fn}() aborts with `role: unbound variable` under `set -u`. "
            '`local a="$1" b="${MAP[$a]}"` expands the second argument BEFORE assigning the '
            "first, so the lookup reads an UNSET variable. Split the `local` into two "
            f"statements. As written this kills the proof on its first login.\n"
            f"stderr={probe.stderr!r}"
        )
        assert probe.returncode == 0, f"stdout={probe.stdout!r} stderr={probe.stderr!r}"
        assert "LOOKUP_RESOLVED" in probe.stdout
        # the role RESOLVED to a user, and that user's password was found and threaded on
        assert '"outcome": "authenticated"' in probe.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
