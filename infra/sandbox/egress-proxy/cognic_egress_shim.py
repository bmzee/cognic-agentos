"""Canonical egress-proxy PID1 shim — tinyproxy Filter renderer + host validator.

This module is IMAGE CONTENT: it runs INSIDE the cognic egress-proxy Docker
container as part of the entrypoint, not inside the AgentOS Python package. It
therefore uses ONLY the Python standard library and MUST NOT import from
``cognic_agentos`` (the package is not present in the proxy image).

tinyproxy runs with ``FilterDefaultDeny Yes`` (whitelist mode). The Filter file
is a list of regexes, one per line, each an anchored exact-match for an allowed
hostname. An EMPTY filter file therefore means DENY ALL egress — which is the
fail-closed posture this renderer falls back to on any malformed input.

Security note: ``re.escape`` alone is NOT sufficient to keep the
one-pattern-per-line invariant. ``re.escape("a\\nb")`` preserves the literal
newline, which would split one host into two filter lines and could widen
access. The real control is :func:`_is_valid_host`, which rejects any host
containing control characters or whitespace (among other RFC-1123 violations);
``re.escape`` is defense-in-depth on regex metacharacters only.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

# RFC-1123 label: 1-63 chars, alphanumeric start/end, hyphens allowed in the
# middle only. No underscore, no leading/trailing hyphen, no empty label.
# End-anchor is ``\Z`` (absolute end), NOT ``$``: in Python ``$`` also matches
# just before a trailing newline, so ``$`` would let a host ending in ``\n``
# validate and inject a literal newline into the one-pattern-per-line Filter
# file. ``\Z`` closes that hole — do NOT "simplify" back to ``$``.
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\Z")

# RFC-1123 total hostname length cap.
_MAX_HOST_LEN = 253

# RFC-1123 label length cap.
_MAX_LABEL_LEN = 63


def _is_valid_host(h: str) -> bool:
    """Return True iff ``h`` is a syntactically valid RFC-1123 hostname.

    Rejects (returns False for): empty string; total length > 253; any empty
    label (e.g. ``a..b``); any label > 63 chars; any label with a
    leading/trailing hyphen; underscores; schemes (``://``); paths (``/``);
    wildcards (``*``); whitespace; and control characters — because none of
    those match the per-label regex. The whitespace/control-char reject is the
    load-bearing control that stops a newline-embedded host from breaking the
    one-pattern-per-line Filter invariant.
    """
    if not h or len(h) > _MAX_HOST_LEN:
        return False
    labels = h.split(".")
    for label in labels:
        if len(label) > _MAX_LABEL_LEN:
            return False
        if _LABEL_RE.match(label) is None:
            return False
    return True


def render_filter_file(allow_list_json: str) -> str:
    """Render a tinyproxy Filter file from a JSON array of allowed hostnames.

    Fail-closed contract: returns ``""`` (an empty filter ⇒ deny-all under
    ``FilterDefaultDeny Yes``) on ANY malformed input — invalid JSON, a
    non-list top level, a non-string element, or a single host that fails
    :func:`_is_valid_host`. One bad entry poisons the whole list: a tampered
    ``ALLOW_LIST`` must never widen access by silently dropping the bad entry
    and keeping the good ones.

    On valid input, renders one anchored exact-match regex per host
    (``^`` + ``re.escape(host)`` + ``$``), de-duplicated preserving first-seen
    order, joined by newlines.
    """
    try:
        parsed = json.loads(allow_list_json)
    except (json.JSONDecodeError, ValueError):
        # Invalid JSON ⇒ deny-all. Never raise into an allow-all posture.
        return ""

    if not isinstance(parsed, list):
        # Non-list top level (object, string, number, …) ⇒ deny-all.
        return ""

    lines: list[str] = []
    seen: set[str] = set()
    for element in parsed:
        if not isinstance(element, str) or not _is_valid_host(element):
            # One bad entry poisons the whole list ⇒ deny-all.
            return ""
        if element in seen:
            continue
        seen.add(element)
        lines.append(f"^{re.escape(element)}$")

    return "\n".join(lines)


class ShimStartupError(Exception):
    """Raised when the shim cannot start safely (e.g. SESSION_ID absent/empty).

    The entrypoint treats this as refuse-startup — the proxy must NOT run and
    emit audit records it cannot correlate to a session.
    """


def resolve_policy_id(env: dict[str, str]) -> str:
    """Resolve the ProxyAccessRecord ``policy_id`` from the launch env.

    ``policy_id = SESSION_ID`` (the per-session id the backend passes). Raises
    :class:`ShimStartupError` if ``SESSION_ID`` is absent or empty — fail-closed:
    never emit audit records with a missing/uncorrelatable policy_id.
    """
    session_id = env.get("SESSION_ID")
    if not session_id:  # None or "" -> refuse startup
        raise ShimStartupError(
            "SESSION_ID env var is required (policy_id = SESSION_ID); refusing "
            "to start rather than emit audit records with no session correlation."
        )
    return session_id


def render_tinyproxy_conf(*, filter_path: str, log_path: str, port: int = 3128) -> str:
    """Render the tinyproxy config for the canonical egress proxy.

    Emits exactly the security-relevant directives (operational/hardening
    directives like User/Timeout/Listen/Allow are added when the conf is wired
    into the running image, a later task):

    - ``Port <port>`` — the proxy listen port (default 3128, the backend's
      _PROXY_PORT).
    - ``FilterDefaultDeny Yes`` — whitelist mode: only hosts in the Filter file
      are allowed; an empty Filter ⇒ deny-all.
    - ``Filter "<filter_path>"`` — the anchored-host whitelist (rendered by
      :func:`render_filter_file`).
    - ``ConnectPort 443`` — HTTPS tunnels (CONNECT) restricted to port 443.
    - ``LogFile "<log_path>"`` — where tinyproxy writes its access log.
    - ``LogLevel Info`` — MANDATORY. At ``LogLevel Connect`` tinyproxy does NOT
      log the ConnectPort denial, so the audit layer could not derive the
      ``non_http_connect_target`` outcome. Do NOT lower this to Connect.

    NEVER emits ``FilterURLs`` — URL-mode filtering is HTTPS-blind (HTTPS
    encrypts the URL); the proxy relies on default domain-mode filtering, which
    gates the plaintext CONNECT host. Do NOT add FilterURLs.

    ``filter_path`` / ``log_path`` are AgentOS-internal constants set by the
    entrypoint (not workload-controlled), so no path escaping is performed here.
    """
    return (
        "\n".join(
            [
                f"Port {port}",
                "FilterDefaultDeny Yes",
                f'Filter "{filter_path}"',
                "ConnectPort 443",
                f'LogFile "{log_path}"',
                "LogLevel Info",
            ]
        )
        + "\n"
    )


#: Sentinel host emitted when a host-less port-refusal cannot be unambiguously
#: attributed to a single pending same-port CONNECT (fail-closed: never guess a
#: host). Machine-detectable; tests pin this exact constant.
AMBIGUOUS_HOST_SENTINEL = "__cognic_ambiguous_host__"

#: Sentinel method emitted when a host-bearing outcome line (Established /
#: filtered-domain) has no paired Request — e.g. a log-tail restart or truncated
#: input. The host + outcome are known but the method is not; an explicit
#: sentinel keeps the audit value machine-detectable rather than a silent "".
UNKNOWN_METHOD_SENTINEL = "__cognic_unknown_method__"

# tinyproxy LogLevel Info line prefix: ``<LEVEL>   <Mon DD HH:MM:SS.mmm> [<pid>]: <message>``.
# The four relevant message bodies are matched against ``<message>`` (the text
# after ``]: ``). We capture the timestamp segment for tz-aware rendering and the
# message tail for per-type dispatch. Non-matching lines (opensock, getaddrinfo,
# No upstream proxy, Closed connection, NOTICE shutdown, …) are noise: ignored.
_LINE_RE = re.compile(
    r"^\S+\s+(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"\[\d+\]: (?P<msg>.*)$"
)

# Request (file descriptor N): <METHOD> <TARGET> HTTP/1.1
_REQUEST_RE = re.compile(
    r"^Request \(file descriptor \d+\): (?P<method>\S+) (?P<target>\S+) HTTP/[\d.]+$"
)

# Established connection to host "<host>" using file descriptor M.
_ESTABLISHED_RE = re.compile(r'^Established connection to host "(?P<host>[^"]*)" using ')

# Proxying refused on filtered domain "<host>"
_FILTERED_RE = re.compile(r'^Proxying refused on filtered domain "(?P<host>[^"]*)"$')

# Refused CONNECT method on port <port>  (NO host on this line)
_BAD_PORT_RE = re.compile(r"^Refused CONNECT method on port (?P<port>\d+)$")

# tinyproxy omits the year from its timestamp; %b parses the abbreviated month.
_TS_FORMAT = "%b %d %H:%M:%S.%f"


def _parse_ts(ts: str, *, year: int) -> str:
    """Parse a tinyproxy ``Mon DD HH:MM:SS.mmm`` prefix into a tz-aware UTC
    ISO 8601 string (tinyproxy omits the year — supplied by the caller)."""
    return datetime.strptime(ts, _TS_FORMAT).replace(year=year, tzinfo=UTC).isoformat()


def _extract_host_port(method: str, target: str) -> tuple[str | None, int | None]:
    """Extract ``(host, port)`` from a Request line's ``<METHOD> <TARGET>``.

    * CONNECT targets are ``host:port`` (split on the LAST ``:`` so IPv6/odd
      hosts keep their port boundary) — ``port`` is the int.
    * Everything else (GET/POST/…) is an ``http://host/…`` URL — ``host`` via
      ``urlsplit().hostname``; ``port`` is ``None`` (only CONNECT port-refusals
      need port pairing).

    Returns ``(None, None)`` if the target shape can't be parsed (defence: a
    malformed Request line must not crash the mapper)."""
    if method == "CONNECT":
        host, sep, port_str = target.rpartition(":")
        if not sep or not host:
            return None, None
        try:
            return host, int(port_str)
        except ValueError:
            return None, None
    host = urlsplit(target).hostname
    return host, None


class _LogParser:
    """Stateful tinyproxy ``LogLevel Info`` → ProxyAccessRecord-dict parser.

    Retains pending-Request state ACROSS :meth:`feed` calls so a ``Request`` line
    and its outcome line that land in DIFFERENT poll reads still pair correctly.
    This is the load-bearing reason the parser is a class and not a free
    function: the T6 incremental tailer feeds only the newly-appended complete
    lines on each poll, and a straddling request (Request in poll N, Established
    in poll N+1) must NOT be orphaned. Re-parsing the whole growing log each poll
    is forbidden (O(n²) + duplicate records); :meth:`feed` is the only public seam
    and it is purely additive over the persistent ``self._pending`` state.

    Correlation model (single pass per feed; tinyproxy has no per-request id):
      * Track pending Requests parsed from ``Request (...)`` lines in
        ``self._pending``.
      * ``Established connection to host "<h>"`` -> ALLOWED. The host is in the
        line; pair to the most-recent pending Request whose host == <h> (for the
        method + request timestamp); remove it.
      * ``Proxying refused on filtered domain "<h>"`` -> REFUSED /
        ``not_in_allow_list``. Same host-in-line pairing.
      * ``Refused CONNECT method on port <p>`` -> REFUSED /
        ``non_http_connect_target``, method="CONNECT". This line has NO host.
        Look at pending CONNECT Requests whose port == <p>:
          - exactly ONE  -> host = that pending's host; remove it.
          - zero OR >1   -> host = AMBIGUOUS_HOST_SENTINEL (fail-closed; do NOT
                            pick one of the pending hosts).
      * timestamp: parse the line's ``Mon DD HH:MM:SS.mmm`` prefix into a
        tz-aware UTC datetime (tinyproxy omits the year -> use ``year`` if given,
        else the current UTC year), rendered via ``.isoformat()``. Use the paired
        Request's timestamp for paired records; the refusal line's timestamp for
        an unpaired (sentinel) port-refusal.
    """

    def __init__(self, *, policy_id: str, year: int | None = None) -> None:
        self._policy_id = policy_id
        # tinyproxy omits the year from its timestamp; resolve ONCE at
        # construction so every feed in this parser's lifetime stamps the same
        # year (matches the free-function semantics of a single resolved year).
        self._year = year if year is not None else datetime.now(UTC).year
        # Pending Requests not yet paired to an outcome line, PERSISTED across
        # feeds. Each entry carries the parsed host / method / port /
        # request-timestamp so a later outcome line (even in a future feed) can
        # adopt the Request's timestamp (the connection attempt's own clock).
        self._pending: list[dict] = []

    def _pop_pending_by_host(self, host: str) -> dict | None:
        """Remove + return the MOST-RECENT pending Request whose host == host
        (LIFO over the host match), else None."""
        for i in range(len(self._pending) - 1, -1, -1):
            if self._pending[i]["host"] == host:
                return self._pending.pop(i)
        return None

    def _resolve_pending_connect_by_port(self, port: int) -> dict | None:
        """Resolve a host-less ``Refused CONNECT method on port`` line.

        If EXACTLY ONE pending CONNECT has port == port, remove + return it
        (unambiguous ⇒ real host). Otherwise (zero OR >1) FLUSH every same-port
        pending CONNECT and return None — the caller emits the sentinel.

        Flushing is load-bearing (P1): a pending CONNECT to a ConnectPort-denied
        port can ONLY ever produce more port-refusals, never an Established /
        allowed line. Leaving ambiguous entries in ``self._pending`` would both
        leak in a long-running tailer AND let a later host-bearing outcome
        mis-pair against the stale CONNECT. Fail-closed: never guess among
        multiple."""
        matches = [
            i for i, p in enumerate(self._pending) if p["method"] == "CONNECT" and p["port"] == port
        ]
        if len(matches) == 1:
            return self._pending.pop(matches[0])
        # 0 or >1 -> sentinel; flush all same-port matches (reverse index order
        # so earlier pops don't shift later indices) — tainted entries removed.
        for i in reversed(matches):
            self._pending.pop(i)
        return None

    def feed(self, text: str) -> list[dict]:
        """Process the complete lines in ``text``, updating persistent pending
        state, and return the records resolved by THIS feed (in order).

        Returns one dict per request resolved by this feed, each with keys
        host / method / timestamp (tz-aware ISO 8601 str) / policy_id / outcome /
        refusal_reason. A Request line with no outcome yet stays in
        ``self._pending`` and contributes ZERO records to this feed's return
        (it will resolve in a later feed when its outcome line arrives)."""
        resolved_year = self._year
        records: list[dict] = []

        for raw_line in text.splitlines():
            line_match = _LINE_RE.match(raw_line)
            if line_match is None:
                continue  # not a tinyproxy Info line -> noise
            ts_segment = line_match.group("ts")
            message = line_match.group("msg")

            req_match = _REQUEST_RE.match(message)
            if req_match is not None:
                method = req_match.group("method")
                host, port = _extract_host_port(method, req_match.group("target"))
                if host is None:
                    continue  # unparseable target -> drop the Request, do not pend
                self._pending.append(
                    {
                        "host": host,
                        "method": method,
                        "port": port,
                        "timestamp": _parse_ts(ts_segment, year=resolved_year),
                    }
                )
                continue

            est_match = _ESTABLISHED_RE.match(message)
            if est_match is not None:
                host = est_match.group("host")
                paired = self._pop_pending_by_host(host)
                method = paired["method"] if paired is not None else UNKNOWN_METHOD_SENTINEL
                timestamp = (
                    paired["timestamp"]
                    if paired is not None
                    else _parse_ts(ts_segment, year=resolved_year)
                )
                records.append(
                    {
                        "host": host,
                        "method": method,
                        "timestamp": timestamp,
                        "policy_id": self._policy_id,
                        "outcome": "allowed",
                        "refusal_reason": None,
                    }
                )
                continue

            filt_match = _FILTERED_RE.match(message)
            if filt_match is not None:
                host = filt_match.group("host")
                paired = self._pop_pending_by_host(host)
                method = paired["method"] if paired is not None else UNKNOWN_METHOD_SENTINEL
                timestamp = (
                    paired["timestamp"]
                    if paired is not None
                    else _parse_ts(ts_segment, year=resolved_year)
                )
                records.append(
                    {
                        "host": host,
                        "method": method,
                        "timestamp": timestamp,
                        "policy_id": self._policy_id,
                        "outcome": "refused",
                        "refusal_reason": "not_in_allow_list",
                    }
                )
                continue

            port_match = _BAD_PORT_RE.match(message)
            if port_match is not None:
                port = int(port_match.group("port"))
                paired = self._resolve_pending_connect_by_port(port)
                if paired is not None:
                    host = paired["host"]
                    timestamp = paired["timestamp"]
                else:
                    # Zero OR >1 pending same-port CONNECT -> fail-closed sentinel;
                    # the refusal line carries no host, so use its own timestamp.
                    host = AMBIGUOUS_HOST_SENTINEL
                    timestamp = _parse_ts(ts_segment, year=resolved_year)
                records.append(
                    {
                        "host": host,
                        "method": "CONNECT",
                        "timestamp": timestamp,
                        "policy_id": self._policy_id,
                        "outcome": "refused",
                        "refusal_reason": "non_http_connect_target",
                    }
                )
                continue

            # Matched the Info-line prefix but none of the four relevant messages
            # (e.g. "No upstream proxy for ...") -> noise.

        return records


def parse_tinyproxy_log(log_text: str, *, policy_id: str, year: int | None = None) -> list[dict]:
    """Map tinyproxy ``LogLevel Info`` output to ProxyAccessRecord-shaped dicts.

    Stateless one-shot wrapper over :class:`_LogParser`: constructs a fresh
    parser and feeds the whole ``log_text`` in a single call, so a Request and
    its outcome must both be present in ``log_text`` to pair. The stateful
    cross-feed pairing the T6 tailer relies on lives in :class:`_LogParser`;
    this function's signature + behaviour are PRESERVED exactly for the existing
    callers (the T5a record-emit tests + the backend wire oracle).

    Returns one dict per resolved request, in log order, each with keys
    host / method / timestamp (tz-aware ISO 8601 str) / policy_id / outcome /
    refusal_reason.
    """
    return _LogParser(policy_id=policy_id, year=year).feed(log_text)
