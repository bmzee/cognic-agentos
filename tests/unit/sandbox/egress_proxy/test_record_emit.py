"""T5a — tinyproxy ``LogLevel Info`` log → ProxyAccessRecord mapper.

Two behavioural classes plus a schema round-trip:

* ``TestNormalFixturesMapExactly`` — the verbatim T1 Info-level capture maps to
  exactly 5 records, in order, with the expected
  ``(host, method, outcome, refusal_reason)`` tuples; the single host-less
  port-refusal pairs to its ONE pending same-port CONNECT (unambiguous ⇒ real
  host).
* ``TestAmbiguousPortRefusalSentinel`` — two pending same-port CONNECTs before a
  port-refusal ⇒ fail-closed ``AMBIGUOUS_HOST_SENTINEL`` (never guess a host).
* ``TestSchemaRoundTrip`` — the emitted dicts, serialised as JSONL, round-trip
  through the REAL backend parser ``_parse_proxy_log_jsonl`` (the wire oracle).

``cognic_egress_shim`` is image content under ``infra/sandbox/egress-proxy/`` (a
hyphenated, non-importable dir put on sys.path by ``conftest.py``); mypy cannot
resolve it because ``infra/`` is outside the ``src``/``tests`` type-check roots.
"""

import json
from datetime import datetime

from cognic_egress_shim import (  # type: ignore[import-not-found]
    AMBIGUOUS_HOST_SENTINEL,
    UNKNOWN_METHOD_SENTINEL,
    parse_tinyproxy_log,
)

# Verbatim T1 Info-level capture (GET allowed, CONNECT allowed, GET filtered,
# CONNECT filtered, CONNECT bad-port). Interleaved with NOTICE/INFO noise lines.
# Built as a joined line list (NOT a triple-quoted literal): the byte-exact
# tinyproxy lines that exceed the 100-col limit must NOT be reflowed, so they
# carry a per-line E501 suppression that a string literal could not.
_T1_INFO_LINES = [
    "CONNECT   May 28 15:08:52.926 [3814]: Request (file descriptor 2): GET http://allowed.test/ HTTP/1.1",  # noqa: E501
    'CONNECT   May 28 15:08:52.928 [3814]: Established connection to host "allowed.test" using file descriptor 3.',  # noqa: E501
    "CONNECT   May 28 15:08:52.936 [3814]: Request (file descriptor 2): CONNECT allowed.test:443 HTTP/1.1",  # noqa: E501
    'CONNECT   May 28 15:08:52.938 [3814]: Established connection to host "allowed.test" using file descriptor 3.',  # noqa: E501
    "CONNECT   May 28 15:08:52.946 [3814]: Request (file descriptor 2): GET http://denied.test/ HTTP/1.1",  # noqa: E501
    'NOTICE    May 28 15:08:52.946 [3814]: Proxying refused on filtered domain "denied.test"',
    "CONNECT   May 28 15:08:52.952 [3814]: Request (file descriptor 2): CONNECT denied.test:443 HTTP/1.1",  # noqa: E501
    'NOTICE    May 28 15:08:52.952 [3814]: Proxying refused on filtered domain "denied.test"',
    "CONNECT   May 28 15:08:52.957 [3814]: Request (file descriptor 2): CONNECT allowed.test:22 HTTP/1.1",  # noqa: E501
    "INFO      May 28 15:08:52.957 [3814]: Refused CONNECT method on port 22",
]
_T1_INFO_LOG = "\n".join(_T1_INFO_LINES)

# Expected (host, method, outcome, refusal_reason) tuples in log order.
_EXPECTED_T1 = [
    ("allowed.test", "GET", "allowed", None),
    ("allowed.test", "CONNECT", "allowed", None),
    ("denied.test", "GET", "refused", "not_in_allow_list"),
    ("denied.test", "CONNECT", "refused", "not_in_allow_list"),
    ("allowed.test", "CONNECT", "refused", "non_http_connect_target"),
]


class TestNormalFixturesMapExactly:
    def test_yields_exactly_five_records(self):
        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        assert len(records) == 5

    def test_record_tuples_match_in_order(self):
        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        got = [(r["host"], r["method"], r["outcome"], r["refusal_reason"]) for r in records]
        assert got == _EXPECTED_T1

    def test_unambiguous_single_pending_port_refusal_gets_real_host(self):
        # Exactly ONE pending :22 CONNECT ⇒ unambiguous ⇒ real host, NOT sentinel.
        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        port_refusal = records[-1]
        assert port_refusal["refusal_reason"] == "non_http_connect_target"
        assert port_refusal["host"] == "allowed.test"
        assert port_refusal["host"] != AMBIGUOUS_HOST_SENTINEL

    def test_policy_id_threaded_onto_every_record(self):
        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        assert all(r["policy_id"] == "sess-xyz" for r in records)

    def test_every_timestamp_is_tz_aware_iso8601(self):
        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        for r in records:
            parsed = datetime.fromisoformat(r["timestamp"])
            assert parsed.tzinfo is not None and parsed.utcoffset() is not None

    def test_noise_lines_produce_no_records(self):
        # opensock / getaddrinfo / No upstream proxy / Closed connection / NOTICE
        # shutdown — none of these are Request/outcome lines ⇒ zero records.
        noise = """\
CONNECT   May 28 15:08:52.926 [3814]: opensock: opening connection to allowed.test:80
CONNECT   May 28 15:08:52.927 [3814]: getaddrinfo returned for allowed.test:80
INFO      May 28 15:08:52.927 [3814]: No upstream proxy for allowed.test
CONNECT   May 28 15:08:52.999 [3814]: Closed connection between local client and remote.
NOTICE    May 28 15:08:53.000 [3814]: Initiating shutdown."""
        assert parse_tinyproxy_log(noise, policy_id="sess-xyz", year=2026) == []


class TestAmbiguousPortRefusalSentinel:
    # Two pending same-port CONNECTs before the refusal ⇒ cannot attribute a
    # single host ⇒ fail-closed sentinel.
    _AMBIGUOUS_LOG = """\
CONNECT   May 28 15:09:00.100 [9001]: Request (file descriptor 2): CONNECT host-a.test:22 HTTP/1.1
CONNECT   May 28 15:09:00.110 [9001]: Request (file descriptor 5): CONNECT host-b.test:22 HTTP/1.1
INFO      May 28 15:09:00.120 [9001]: Refused CONNECT method on port 22"""

    def test_two_pending_same_port_yield_sentinel_host(self):
        records = parse_tinyproxy_log(self._AMBIGUOUS_LOG, policy_id="sess-amb", year=2026)
        # Only the refusal line resolves to a record; the two pending :22
        # CONNECTs are FLUSHED on the ambiguous refusal (P1) so they can't
        # mis-pair against a later host-bearing outcome.
        refusals = [r for r in records if r["refusal_reason"] == "non_http_connect_target"]
        assert len(refusals) == 1
        rec = refusals[0]
        assert rec["host"] == AMBIGUOUS_HOST_SENTINEL
        assert rec["host"] not in ("host-a.test", "host-b.test")
        assert rec["method"] == "CONNECT"
        assert rec["outcome"] == "refused"
        assert rec["refusal_reason"] == "non_http_connect_target"

    def test_zero_pending_same_port_also_yields_sentinel(self):
        # No matching pending CONNECT at all ⇒ still fail-closed sentinel.
        log = "INFO      May 28 15:09:00.120 [9001]: Refused CONNECT method on port 22"
        records = parse_tinyproxy_log(log, policy_id="sess-amb", year=2026)
        assert len(records) == 1
        assert records[0]["host"] == AMBIGUOUS_HOST_SENTINEL
        assert records[0]["refusal_reason"] == "non_http_connect_target"

    def test_ambiguous_refusal_flushes_pending_no_stale_reuse(self):
        # P1 regression: after an ambiguous same-port refusal flushes the tainted
        # pending CONNECTs, a LATER host-bearing outcome must NOT reuse a stale
        # entry. Without the flush, the filtered host-a line below would pop the
        # stale host-a.test:22 CONNECT and report method="CONNECT" + a stale ts.
        log = "\n".join(
            [
                "CONNECT   May 28 15:09:00.100 [9001]: Request (file descriptor 2): CONNECT host-a.test:22 HTTP/1.1",  # noqa: E501
                "CONNECT   May 28 15:09:00.110 [9001]: Request (file descriptor 5): CONNECT host-b.test:22 HTTP/1.1",  # noqa: E501
                "INFO      May 28 15:09:00.120 [9001]: Refused CONNECT method on port 22",
                'NOTICE    May 28 15:09:00.200 [9001]: Proxying refused on filtered domain "host-a.test"',  # noqa: E501
            ]
        )
        records = parse_tinyproxy_log(log, policy_id="sess-amb", year=2026)
        assert len(records) == 2
        # 1) the ambiguous port-refusal -> sentinel host.
        assert records[0]["host"] == AMBIGUOUS_HOST_SENTINEL
        assert records[0]["refusal_reason"] == "non_http_connect_target"
        # 2) the later host-a filtered refusal -> real host, but ORPHAN (the
        # stale host-a.test:22 CONNECT was flushed), so method is the unknown
        # sentinel, NOT "CONNECT" reused from the stale pending entry.
        assert records[1]["host"] == "host-a.test"
        assert records[1]["refusal_reason"] == "not_in_allow_list"
        assert records[1]["method"] == UNKNOWN_METHOD_SENTINEL
        assert records[1]["method"] != "CONNECT"


class TestOrphanOutcomeMethodSentinel:
    # P2: a host-bearing outcome line with no paired Request (log-tail restart /
    # truncation) emits the host + outcome with an explicit method sentinel,
    # never a silent "".
    def test_orphan_established_uses_method_sentinel(self):
        log = 'CONNECT   May 28 15:10:00.000 [1]: Established connection to host "x.test" using file descriptor 3.'  # noqa: E501
        records = parse_tinyproxy_log(log, policy_id="p", year=2026)
        assert len(records) == 1
        assert records[0]["host"] == "x.test"
        assert records[0]["outcome"] == "allowed"
        assert records[0]["method"] == UNKNOWN_METHOD_SENTINEL

    def test_orphan_filtered_uses_method_sentinel(self):
        log = 'NOTICE    May 28 15:10:00.000 [1]: Proxying refused on filtered domain "y.test"'
        records = parse_tinyproxy_log(log, policy_id="p", year=2026)
        assert len(records) == 1
        assert records[0]["host"] == "y.test"
        assert records[0]["refusal_reason"] == "not_in_allow_list"
        assert records[0]["method"] == UNKNOWN_METHOD_SENTINEL


class TestSchemaRoundTrip:
    def test_emitted_dicts_roundtrip_through_backend_parser(self):
        # The emitted shape must satisfy the REAL backend parser (the wire
        # oracle) — this pins host/method/outcome/refusal_reason against the
        # ProxyAccessRecord wire-contract consumers actually use.
        from cognic_agentos.sandbox.backends.docker_sibling import _parse_proxy_log_jsonl

        records = parse_tinyproxy_log(_T1_INFO_LOG, policy_id="sess-xyz", year=2026)
        jsonl = "\n".join(json.dumps(r) for r in records)
        parsed = _parse_proxy_log_jsonl(jsonl)

        assert len(parsed) == 5
        got = [(p.host, p.method, p.outcome, p.refusal_reason) for p in parsed]
        assert got == _EXPECTED_T1
