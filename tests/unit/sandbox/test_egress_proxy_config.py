"""Sprint 8A T7 — egress proxy config rendering + ProxyAccessRecord shape
+ proxy_log → chain-row materialisation.

Per spec §10.2 (proxy implementation) + §10.3 (audit emission shape) +
§10.4 (proxy-observed vs network-blocked refusal classes).

`sandbox/proxy.py` is the substantive egress enforcement decision point
(spec §17 critical-controls promotion). Tests in this file are organised
into 10 sections:

* TestRenderProxyConfig — happy-path env rendering + scheme-strip
* TestRenderProxyConfigDefenceInDepth — defence-in-depth scheme + host
  refusals (the substantive guard the module exists to provide)
* TestEgressProxyConfigShape — frozen-dataclass + immutability guard
* TestProxyAccessRecordShape — 6-field shape + Literal closed-enums
* TestProxyAccessRecordImmutability — frozen-dataclass guard
* TestProxyAccessRefusalReasonClosedEnum — drift detector for the
  proxy-side refusal vocabulary (per spec §10.4)
* TestProxyLogToChainPayload — chain-row materialisation contract
* TestProxyLogEvidenceBoundaryInvariants — round-9 P1 (naive timestamp
  bypass) + P2 (joint-invariant bypass) regressions; the materialiser
  is the single seam where (outcome, refusal_reason) joint contracts
  + the aware-timestamp contract can be enforced
* TestSandboxExecResultUsesExpandedRecord — typecompat with T3's
  SandboxExecResult.proxy_log tuple
* TestModulePublicSurface — pins the exported symbol set so a
  reviewer-driven re-export change does not silently drop a member
"""

from __future__ import annotations

import dataclasses
import json
import typing
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

from cognic_agentos.sandbox import SandboxLifecycleRefused
from cognic_agentos.sandbox.protocol import SandboxExecResult
from cognic_agentos.sandbox.proxy import (
    EgressProxyConfig,
    ProxyAccessOutcome,
    ProxyAccessRecord,
    ProxyAccessRefusalReason,
    proxy_log_to_chain_payload,
    render_proxy_config,
)


# A tzinfo subclass whose ``utcoffset()`` returns None — Python treats
# such datetimes as "effectively naive" (their ``isoformat()`` emits
# no offset suffix). Used by R10 P1 regression to prove the timestamp
# guard catches more than just ``tzinfo is None``.
class _NullOffsetTz(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return None

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return None


# ---------------------------------------------------------------------------
# render_proxy_config — happy-path env rendering
# ---------------------------------------------------------------------------


class TestRenderProxyConfig:
    """Spec §10.2 — `render_proxy_config` projects the per-call allow-list
    onto the env-var contract the sidecar parses on start."""

    def test_renders_allow_list_to_env_vars_for_sidecar(self) -> None:
        config = render_proxy_config(
            egress_allow_list=("api.example.com", "data.example.com"),
            session_id="sess-1",
        )
        assert isinstance(config, EgressProxyConfig)
        env = config.to_env()
        # ALLOW_LIST is a JSON array — the sidecar parses on start per
        # spec §10.2 ("Reads the per-call allow-list from env at start
        # (`ALLOW_LIST` JSON-encoded)").
        assert json.loads(env["ALLOW_LIST"]) == ["api.example.com", "data.example.com"]
        assert env["SESSION_ID"] == "sess-1"

    def test_empty_allow_list_renders_no_external_egress_allowed(self) -> None:
        """Zero-entry allow-list ⇒ the sidecar refuses everything. The
        env rendering must still be well-formed JSON so the sidecar's
        `json.loads(os.environ["ALLOW_LIST"])` does not error."""
        config = render_proxy_config(egress_allow_list=(), session_id="sess-2")
        assert json.loads(config.to_env()["ALLOW_LIST"]) == []

    def test_https_scheme_stripped_to_hostname_only(self) -> None:
        """Allow-list entries may carry `https://` scheme; sidecar wants
        hostnames only (the sidecar enforces https-CONNECT itself)."""
        config = render_proxy_config(
            egress_allow_list=("https://api.example.com",),
            session_id="s",
        )
        assert json.loads(config.to_env()["ALLOW_LIST"]) == ["api.example.com"]

    def test_http_scheme_stripped_to_hostname_only(self) -> None:
        """Symmetric case to `test_https_scheme_stripped_to_hostname_only`
        — `http://` entries also collapse to bare hostname."""
        config = render_proxy_config(
            egress_allow_list=("http://api.example.com",),
            session_id="s",
        )
        assert json.loads(config.to_env()["ALLOW_LIST"]) == ["api.example.com"]

    def test_mixed_scheme_and_bare_hostnames_collapse_to_bare_list(self) -> None:
        """Mixed input ⇒ all collapse to hostnames; sidecar receives a
        homogeneous list."""
        config = render_proxy_config(
            egress_allow_list=(
                "https://a.example.com",
                "b.example.com",
                "http://c.example.com",
            ),
            session_id="s",
        )
        assert json.loads(config.to_env()["ALLOW_LIST"]) == [
            "a.example.com",
            "b.example.com",
            "c.example.com",
        ]

    def test_input_order_preserved_in_rendered_list(self) -> None:
        """Examiner-readability: the sidecar logs ALLOW_LIST at start;
        preserving input order makes operator diff'ing trivial. Stable
        ordering also lets future canonical_bytes hashing (Sprint 8.5
        checkpoint) be deterministic."""
        config = render_proxy_config(
            egress_allow_list=("z.example.com", "a.example.com", "m.example.com"),
            session_id="s",
        )
        # NOT sorted alphabetically — input order preserved.
        assert json.loads(config.to_env()["ALLOW_LIST"]) == [
            "z.example.com",
            "a.example.com",
            "m.example.com",
        ]


# ---------------------------------------------------------------------------
# render_proxy_config — defence-in-depth (the substantive CC guard)
# ---------------------------------------------------------------------------


class TestRenderProxyConfigDefenceInDepth:
    """Spec §17 critical-controls promotion — `render_proxy_config` is
    the second-layer scheme guard. Stage-1 `validate_policy_shape` runs
    first in the admission pipeline, but proxy.py must refuse INDEPENDENTLY
    so that a future code path that bypasses Stage-1 cannot smuggle a
    non-HTTP allow-list entry through to the sidecar (which would then
    silently allow arbitrary-protocol traffic to that host)."""

    def test_ftp_scheme_refused_via_egress_protocol_not_http(self) -> None:
        """Defence-in-depth: `ftp://` entry refuses with the same closed-
        enum reason Stage-1 emits — `sandbox_policy_egress_protocol_not_http`."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            render_proxy_config(
                egress_allow_list=("ftp://files.example.com",),
                session_id="s",
            )
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"

    def test_redis_scheme_refused_via_egress_protocol_not_http(self) -> None:
        """Symmetric: arbitrary non-HTTP schemes (`redis://`, `mysql://`,
        `mongodb://`) all refuse with the same closed-enum reason."""
        for scheme in ("redis", "mysql", "mongodb", "smtp", "ftp"):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                render_proxy_config(
                    egress_allow_list=(f"{scheme}://host.example.com",),
                    session_id="s",
                )
            assert exc.value.reason == "sandbox_policy_egress_protocol_not_http", (
                f"scheme {scheme}:// should refuse but didn't"
            )

    def test_malformed_host_refused_via_egress_host_invalid(self) -> None:
        """Defence-in-depth: `-bad.example.com` (leading hyphen, RFC 1123
        violation) refuses with `sandbox_policy_egress_host_invalid`."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            render_proxy_config(
                egress_allow_list=("-bad.example.com",),
                session_id="s",
            )
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"

    def test_empty_host_refused_via_egress_host_invalid(self) -> None:
        """Empty entry refuses (would otherwise collapse to a wildcard
        match-anything ACL inside the sidecar)."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            render_proxy_config(egress_allow_list=("",), session_id="s")
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"

    def test_first_failing_entry_raises_immediately(self) -> None:
        """If a list mixes valid + invalid entries, the FIRST invalid
        entry refuses — short-circuit semantics matching Stage-1."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            render_proxy_config(
                egress_allow_list=("api.example.com", "ftp://bad.example.com"),
                session_id="s",
            )
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"


# ---------------------------------------------------------------------------
# EgressProxyConfig dataclass shape
# ---------------------------------------------------------------------------


class TestEgressProxyConfigShape:
    """Pin the frozen-dataclass invariant. EgressProxyConfig is the
    return type of render_proxy_config + the input to the sidecar
    launch path (T10 docker_sibling.create); accidental mutation
    after rendering would silently change what the sidecar receives."""

    def test_dataclass_is_frozen(self) -> None:
        config = render_proxy_config(
            egress_allow_list=("api.example.com",),
            session_id="s",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.session_id = "different"  # type: ignore[misc]

    def test_to_env_returns_dict_with_required_keys(self) -> None:
        config = render_proxy_config(
            egress_allow_list=("api.example.com",),
            session_id="s",
        )
        env = config.to_env()
        assert isinstance(env, dict)
        assert set(env.keys()) == {"ALLOW_LIST", "SESSION_ID"}
        for k, v in env.items():
            assert isinstance(k, str)
            assert isinstance(v, str)


# ---------------------------------------------------------------------------
# ProxyAccessRecord — 6-field shape per spec §10.3
# ---------------------------------------------------------------------------


class TestProxyAccessRecordShape:
    """Spec §10.3 — `ProxyAccessRecord` carries 6 fields. T3 placeholder
    in `protocol.py` was a 4-field stub explicitly tagged 'Fields are
    placeholders until T7' (line 120 docstring); T7 expands the same
    type to the spec shape. SandboxExecResult.proxy_log references the
    same type — see TestSandboxExecResultUsesExpandedRecord."""

    def test_record_shape_carries_required_fields(self) -> None:
        rec = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="allowed",
            refusal_reason=None,
        )
        assert rec.host == "api.example.com"
        assert rec.method == "GET"
        assert rec.timestamp == datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
        assert rec.policy_id == "pol-1"
        assert rec.outcome == "allowed"
        assert rec.refusal_reason is None

    def test_refusal_record_carries_closed_enum_reason_not_in_allow_list(self) -> None:
        rec = ProxyAccessRecord(
            host="evil.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="refused",
            refusal_reason="not_in_allow_list",
        )
        assert rec.outcome == "refused"
        assert rec.refusal_reason == "not_in_allow_list"

    def test_refusal_record_carries_closed_enum_reason_non_http_connect_target(self) -> None:
        """Spec §10.4 — `egress_protocol_not_http` proxy-observed path
        emits `refusal_reason="non_http_connect_target"`."""
        rec = ProxyAccessRecord(
            host="redis.example.com",
            method="CONNECT",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="refused",
            refusal_reason="non_http_connect_target",
        )
        assert rec.refusal_reason == "non_http_connect_target"


class TestProxyAccessRecordImmutability:
    """Frozen-dataclass guard — chain-row payload must NOT silently
    mutate after the record enters the proxy_log tuple."""

    def test_record_is_frozen(self) -> None:
        rec = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="allowed",
            refusal_reason=None,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.host = "different"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Closed-enum drift detectors
# ---------------------------------------------------------------------------


class TestProxyAccessRefusalReasonClosedEnum:
    """Spec §10.4 — the proxy-side refusal vocabulary is a closed-enum
    pinned to TWO values for Wave-1:

    * `not_in_allow_list` — host not on the per-call allow-list
    * `non_http_connect_target` — HTTP CONNECT to non-443 / non-HTTP
       method (spec §10.4 proxy-observed class)

    Wave-2 may add network-level telemetry that surfaces new reasons
    (e.g. `raw_tcp_attempt`); those are deliberately NOT in the Wave-1
    vocabulary per spec §10.4 'no per-attempt audit record in Wave 1'.
    Drift between this Literal and the chain-row consumer (Sprint 8B
    audit composers / examiner readers) is a wire-protocol regression."""

    def test_vocabulary_has_exactly_two_values(self) -> None:
        values = set(typing.get_args(ProxyAccessRefusalReason))
        assert values == {"not_in_allow_list", "non_http_connect_target"}, (
            f"ProxyAccessRefusalReason vocabulary drift: {values}"
        )

    def test_outcome_vocabulary_has_exactly_two_values(self) -> None:
        """Spec §10.3 — ``outcome`` is a 2-value closed-enum:
        ``"allowed"`` / ``"refused"``. Wave-2 may add additional
        outcomes (e.g. ``"upstream_error"`` for sidecar-side network
        errors); those are deliberately NOT in the Wave-1 vocabulary
        per spec §10.4. Drift between this Literal and the chain-row
        consumer is a wire-protocol regression."""
        values = set(typing.get_args(ProxyAccessOutcome))
        assert values == {"allowed", "refused"}, f"ProxyAccessOutcome vocabulary drift: {values}"


# ---------------------------------------------------------------------------
# proxy_log → chain row materialisation
# ---------------------------------------------------------------------------


class TestProxyLogToChainPayload:
    """Spec §10.3 — proxy_log materialisation contract. The chain row's
    `payload.proxy_log` carries `list[dict]` not `tuple[dataclass]`
    because `core.canonical.canonical_bytes` rejects tuples (silent
    list/tuple ambiguity bug class). Timestamps must serialise as ISO-
    8601 strings (UTC `+00:00` suffix preserved; no naive timestamps)."""

    def test_renders_single_record_to_canonical_json_friendly_dict(self) -> None:
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        payload = proxy_log_to_chain_payload(records)
        assert payload == [
            {
                "host": "api.example.com",
                "method": "GET",
                "timestamp": "2026-05-16T12:00:00+00:00",
                "policy_id": "pol-1",
                "outcome": "allowed",
                "refusal_reason": None,
            }
        ]

    def test_empty_tuple_renders_to_empty_list(self) -> None:
        """No outbound calls during a sandbox session ⇒ empty proxy_log
        ⇒ the chain row carries `payload.proxy_log = []`. Distinct from
        absence-of-key (which would mean 'proxy did not run')."""
        assert proxy_log_to_chain_payload(()) == []

    def test_multiple_records_preserve_input_order(self) -> None:
        """Examiner reads the chain payload in attempt-order to
        reconstruct what the sandbox did. Re-ordering would break the
        evidence-pack export readers."""
        records = (
            ProxyAccessRecord(
                host="first.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
            ProxyAccessRecord(
                host="second.example.com",
                method="POST",
                timestamp=datetime(2026, 5, 16, 12, 0, 1, tzinfo=UTC),
                policy_id="pol-1",
                outcome="refused",
                refusal_reason="not_in_allow_list",
            ),
            ProxyAccessRecord(
                host="third.example.com",
                method="CONNECT",
                timestamp=datetime(2026, 5, 16, 12, 0, 2, tzinfo=UTC),
                policy_id="pol-1",
                outcome="refused",
                refusal_reason="non_http_connect_target",
            ),
        )
        payload = proxy_log_to_chain_payload(records)
        assert [r["host"] for r in payload] == [
            "first.example.com",
            "second.example.com",
            "third.example.com",
        ]
        assert payload[1]["refusal_reason"] == "not_in_allow_list"
        assert payload[2]["refusal_reason"] == "non_http_connect_target"

    def test_returns_list_not_tuple_for_canonical_bytes_compat(self) -> None:
        """`core.canonical.canonical_bytes` rejects tuples in chain
        payloads to prevent the silent list/tuple ambiguity bug class.
        proxy_log_to_chain_payload MUST return a list (mutable container
        type at the top level)."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        payload = proxy_log_to_chain_payload(records)
        assert isinstance(payload, list)
        # Each inner record must be a plain dict, not a dataclass /
        # tuple / namedtuple — canonical_bytes requires dicts.
        for entry in payload:
            assert isinstance(entry, dict)


# ---------------------------------------------------------------------------
# Evidence-boundary invariants on the materialiser (round-9 P1+P2 fix)
# ---------------------------------------------------------------------------


class TestProxyLogEvidenceBoundaryInvariants:
    """Spec §10.3 + canonical-form contract — the materialiser is the
    single seam where (outcome, refusal_reason) joint invariants AND
    the aware-timestamp contract are enforced. ProxyAccessRecord lives
    in ``protocol.py`` and types ``refusal_reason`` as ``str | None``
    to keep protocol.py free of an import on ``sandbox.proxy``; that
    architectural compromise makes this materialiser the ONLY runtime
    seam where the spec invariants can be checked.

    Violations raise :exc:`ValueError` fail-loud (programmer-error
    states from buggy upstream construction paths — NOT
    ``SandboxLifecycleRefused`` which is for admission-class refusals
    on external input).

    Reviewer-flagged at round-9 P1 (naive timestamp bypass) + P2
    (joint-invariant bypass); without these guards an examiner reading
    a chain payload could see ``outcome="allowed", refusal_reason="x"``
    or a stringified naive datetime with no offset.
    """

    # -- Timestamp-awareness invariant (P1) --

    def test_naive_timestamp_raises_value_error(self) -> None:
        """Naive datetime stringified via isoformat() yields
        ``"2026-05-16T12:00:00"`` with NO offset — bypassing
        core.canonical's aware-datetime guard. Refuse at the
        materialiser."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0),  # naive
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        with pytest.raises(ValueError, match="must be timezone-aware"):
            proxy_log_to_chain_payload(records)

    def test_naive_timestamp_error_carries_host_for_diagnosis(self) -> None:
        """The error must name the offending record's host so a T10
        author debugging a buggy capture path can find the source."""
        records = (
            ProxyAccessRecord(
                host="specific-host.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0),  # naive
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        with pytest.raises(ValueError) as exc:
            proxy_log_to_chain_payload(records)
        assert "specific-host.example.com" in str(exc.value)

    def test_effectively_naive_tzinfo_with_null_utcoffset_raises_value_error(self) -> None:
        """Round-10 P1 — Python's actual aware/naive contract is BOTH
        ``tzinfo is not None`` AND ``utcoffset() is not None``. A
        ``tzinfo`` subclass returning ``None`` from ``utcoffset()`` is
        "effectively naive" — its ``isoformat()`` emits NO offset
        suffix, bypassing the canonical-form guard the R9 check was
        meant to mirror. The R10 fix uses the Pythonic
        ``utcoffset() is None`` check (NOT only ``tzinfo is None``)
        to catch this class.

        Pin: without the ``or rec.timestamp.utcoffset() is None``
        clause, this test fails — the materialiser accepts the
        record + stringifies it as ``"2026-05-16T12:00:00"`` (no
        offset)."""
        null_tz = _NullOffsetTz()
        ts = datetime(2026, 5, 16, 12, 0, 0, tzinfo=null_tz)
        # Sanity guard on the test scaffolding: the constructed
        # datetime IS effectively-naive by Python's definition.
        assert ts.tzinfo is not None
        assert ts.utcoffset() is None
        # And its isoformat would silently lose the offset — proving
        # this is the exact attack class P1 R10 flagged.
        assert ts.isoformat() == "2026-05-16T12:00:00"

        records = (
            ProxyAccessRecord(
                host="effectively-naive.example.com",
                method="GET",
                timestamp=ts,
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        with pytest.raises(ValueError, match="must be timezone-aware"):
            proxy_log_to_chain_payload(records)

    def test_non_utc_aware_timestamp_passes(self) -> None:
        """The contract is 'aware', NOT 'UTC-only' — a fixed-offset
        aware datetime (e.g. New York summer time) must materialise
        successfully with its offset preserved in the ISO string.
        Pins the design choice that the materialiser does not coerce
        timestamps; the upstream capture path owns timezone discipline
        and the materialiser only enforces presence-of-tzinfo."""
        ny_summer = timezone(timedelta(hours=-4))
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=ny_summer),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        payload = proxy_log_to_chain_payload(records)
        assert payload[0]["timestamp"] == "2026-05-16T12:00:00-04:00"

    # -- (outcome, refusal_reason) joint invariants (P2) --

    def test_allowed_with_non_none_refusal_reason_raises_value_error(self) -> None:
        """Allowed records cannot carry a refusal_reason — physically
        impossible state."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason="not_in_allow_list",  # invariant violation
            ),
        )
        with pytest.raises(ValueError, match="outcome='allowed' must have refusal_reason=None"):
            proxy_log_to_chain_payload(records)

    def test_refused_with_none_refusal_reason_raises_value_error(self) -> None:
        """Refused records must carry a refusal_reason — otherwise the
        chain payload says 'something was refused but we won't say
        why', which is unreadable evidence."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="refused",
                refusal_reason=None,  # invariant violation
            ),
        )
        with pytest.raises(
            ValueError, match="outcome='refused' must carry a non-None refusal_reason"
        ):
            proxy_log_to_chain_payload(records)

    def test_refused_with_unknown_reason_raises_value_error(self) -> None:
        """Refused records must carry one of the closed-enum
        :data:`ProxyAccessRefusalReason` values — a typo or a Wave-2
        reason that escaped the type-check at construction time is
        caught here at the evidence boundary."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="refused",
                refusal_reason="raw_tcp_attempt",  # Wave-2 reason; not Wave-1
            ),
        )
        with pytest.raises(
            ValueError,
            match="refusal_reason must be one of",
        ):
            proxy_log_to_chain_payload(records)

    def test_refused_with_each_valid_reason_passes(self) -> None:
        """Positive coverage: both closed-enum values are accepted by
        the materialiser (pins the invariant doesn't accidentally
        reject a valid reason)."""
        for reason in ("not_in_allow_list", "non_http_connect_target"):
            records = (
                ProxyAccessRecord(
                    host="api.example.com",
                    method="GET",
                    timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                    policy_id="pol-1",
                    outcome="refused",
                    refusal_reason=reason,
                ),
            )
            payload = proxy_log_to_chain_payload(records)
            assert payload[0]["refusal_reason"] == reason, (
                f"reason {reason!r} should serialise unchanged"
            )

    # -- Outcome closed-set invariant (R10 P2) --

    def test_unknown_outcome_raises_value_error(self) -> None:
        """Round-10 P2 — Python does not enforce ``Literal`` values at
        runtime, so ``ProxyAccessRecord(outcome="maybe", ...)`` is
        constructible. Without an explicit closed-set check, the
        materialiser's joint-invariant block would dispatch on neither
        ``"allowed"`` nor ``"refused"`` branch + land the record
        unchanged in the chain payload. The R10 fix closed-checks
        ``outcome`` against :data:`_VALID_OUTCOMES` BEFORE the joint
        block.

        T10's sidecar-log parser will build records from dynamic input
        (proxy log lines) — exactly the construction class this guard
        is meant to catch."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="maybe",  # type: ignore[arg-type]
                refusal_reason="not_in_allow_list",
            ),
        )
        with pytest.raises(
            ValueError,
            match=r"outcome must be one of",
        ):
            proxy_log_to_chain_payload(records)

    def test_unknown_outcome_check_fires_before_joint_invariants(self) -> None:
        """Defensive ordering: an unknown ``outcome`` paired with an
        invalid ``refusal_reason`` raises the OUTCOME closed-set error,
        not the refusal_reason error. Pins the spec'd check order so a
        future refactor cannot accidentally re-order them (which would
        produce confusing error messages naming the wrong invariant)."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="error",  # type: ignore[arg-type]
                refusal_reason="not_a_real_reason",
            ),
        )
        with pytest.raises(ValueError) as exc:
            proxy_log_to_chain_payload(records)
        # The OUTCOME closed-set error fires first, not the
        # refusal_reason one.
        assert "outcome must be one of" in str(exc.value)
        assert "refusal_reason must be one of" not in str(exc.value)

    def test_outcome_unknown_falsy_string_raises_value_error(self) -> None:
        """Edge case: empty-string outcome is also not in the closed
        set; would silently fall through both branches without the
        guard."""
        records = (
            ProxyAccessRecord(
                host="api.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="",  # type: ignore[arg-type]
                refusal_reason=None,
            ),
        )
        with pytest.raises(ValueError, match=r"outcome must be one of"):
            proxy_log_to_chain_payload(records)

    # -- Short-circuit + batch-integrity invariants --

    def test_validation_short_circuits_on_first_bad_record(self) -> None:
        """A batch with a bad record at index 1 raises before index 2
        is processed — the in-flight payload list is discarded on the
        exception path so the chain row never sees a partial batch."""
        records = (
            ProxyAccessRecord(
                host="good-first.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
            ProxyAccessRecord(
                host="bad-second.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 1, tzinfo=UTC),
                policy_id="pol-1",
                outcome="refused",
                refusal_reason=None,  # invariant violation
            ),
            ProxyAccessRecord(
                host="unreached-third.example.com",
                method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 2, tzinfo=UTC),
                policy_id="pol-1",
                outcome="allowed",
                refusal_reason=None,
            ),
        )
        with pytest.raises(ValueError) as exc:
            proxy_log_to_chain_payload(records)
        # The bad record is the one named, not the good record before
        # it or the unreached record after.
        assert "bad-second.example.com" in str(exc.value)
        assert "good-first.example.com" not in str(exc.value)
        assert "unreached-third.example.com" not in str(exc.value)

    # -- Closed-set-of-valid-reasons lockstep with the Literal --

    def test_valid_refusal_reasons_set_matches_literal_via_get_args(self) -> None:
        """Intra-module drift detector: the runtime
        ``_VALID_REFUSAL_REASONS`` frozenset must equal
        ``frozenset(get_args(ProxyAccessRefusalReason))``. Derivation
        at module load (via ``typing.get_args``) gives us this for
        free; the test pins that the derivation pattern is still in
        place so a future refactor cannot silently swap in a stale
        hand-maintained copy."""
        from cognic_agentos.sandbox.proxy import _VALID_REFUSAL_REASONS

        assert frozenset(typing.get_args(ProxyAccessRefusalReason)) == _VALID_REFUSAL_REASONS

    def test_valid_outcomes_set_matches_literal_via_get_args(self) -> None:
        """Intra-module drift detector for ``_VALID_OUTCOMES``.
        Symmetric with the refusal-reason drift detector above;
        derivation at module load via ``typing.get_args`` keeps
        the runtime closed-set in lockstep with the
        :data:`ProxyAccessOutcome` Literal."""
        from cognic_agentos.sandbox.proxy import _VALID_OUTCOMES

        assert frozenset(typing.get_args(ProxyAccessOutcome)) == _VALID_OUTCOMES


# ---------------------------------------------------------------------------
# SandboxExecResult typecompat — the expanded record must be assignable
# to the existing `proxy_log: tuple[ProxyAccessRecord, ...]` field.
# ---------------------------------------------------------------------------


class TestSandboxExecResultUsesExpandedRecord:
    """Round-trip the expanded ProxyAccessRecord through SandboxExecResult
    to prove T3's `proxy_log` field references the SAME (now-expanded)
    type — not a stale 4-field forward declaration."""

    def test_exec_result_accepts_tuple_of_expanded_records(self) -> None:
        rec = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="allowed",
            refusal_reason=None,
        )
        result = SandboxExecResult(
            stdout=b"",
            stderr=b"",
            exit_code=0,
            proxy_log=(rec,),
        )
        assert len(result.proxy_log) == 1
        # Access the spec-§10.3 fields through the tuple to prove the
        # type binding is the expanded one.
        assert result.proxy_log[0].timestamp == datetime(
            2026,
            5,
            16,
            12,
            0,
            0,
            tzinfo=UTC,
        )
        assert result.proxy_log[0].policy_id == "pol-1"


# ---------------------------------------------------------------------------
# Module public surface — pin the exported symbol set
# ---------------------------------------------------------------------------


class TestModulePublicSurface:
    """Pin the exact public surface so a reviewer-driven re-export
    refactor cannot silently drop a member or rename a closed-enum
    without test failure."""

    def test_proxy_module_exports_expected_symbols(self) -> None:
        from cognic_agentos.sandbox import proxy as proxy_mod

        # The exports the rest of AgentOS (T10 docker_sibling backend,
        # the chain-row composer) actually depend on. Adding a new
        # export is fine; removing one is wire-protocol regression.
        for name in (
            "EgressProxyConfig",
            "ProxyAccessOutcome",
            "ProxyAccessRecord",
            "ProxyAccessRefusalReason",
            "render_proxy_config",
            "proxy_log_to_chain_payload",
        ):
            assert hasattr(proxy_mod, name), f"sandbox.proxy missing required export {name!r}"

    def test_sandbox_init_re_exports_proxy_public_surface(self) -> None:
        """The 7B-era public-API pattern: sandbox/__init__.py re-exports
        sub-module symbols so callers import from `cognic_agentos.sandbox`
        without learning the internal module layout. T7 adds 5 new
        re-exports (ProxyAccessRecord + ProxyAccessOutcome live in
        protocol; the other 3 live in proxy)."""
        import cognic_agentos.sandbox as sb_mod

        for name in (
            "EgressProxyConfig",
            "ProxyAccessOutcome",
            "ProxyAccessRecord",
            "ProxyAccessRefusalReason",
            "render_proxy_config",
            "proxy_log_to_chain_payload",
        ):
            assert hasattr(sb_mod, name), f"cognic_agentos.sandbox missing re-export {name!r}"
            assert name in sb_mod.__all__, f"cognic_agentos.sandbox.__all__ missing {name!r}"
