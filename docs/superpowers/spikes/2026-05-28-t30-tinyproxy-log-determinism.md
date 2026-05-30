# T30 Spike — tinyproxy log determinism (plan Task 1)

**Date:** 2026-05-28
**Question (spec §8 / plan T1):** can the egress-proxy shim derive the `ProxyAccessRecord` fields — specifically `outcome ∈ {allowed, refused}` and `refusal_reason ∈ {not_in_allow_list, non_http_connect_target}` — by **tailing tinyproxy's native log** (Path 1), or must it become an **in-path decision shim** (Path 2)?

## Decision

**Path 1 (log-tail) — viable, at `LogLevel Info`.** tinyproxy's log distinguishes all four outcomes with distinct, stable strings. T5 = **T5a** (log-tail mapper). Path 2 is NOT needed.

**Hard requirement surfaced:** the canonical proxy MUST run **`LogLevel Info`** (not `Connect`) — at `Connect` level the ConnectPort denial is **not logged at all**, so `non_http_connect_target` would be invisible. This refines plan **T4** (the `tinyproxy.conf` renderer pins `LogLevel Info`).

## Environment

- Image base: `debian:bookworm-slim`; **tinyproxy `1.11.1-2.1+deb12u1`** (apt). Pin this version (or the canonical image's pinned build) — the mapping below is version-coupled.
- Config: `Port 8888`, `Listen 127.0.0.1`, `Allow 127.0.0.1`, `FilterDefaultDeny Yes`, `Filter` = single line `^allowed\.test$`, `ConnectPort 443`, `LogLevel {Connect|Info}`.
- Upstreams: local `allowed.test` (HTTP :80 + a **dummy TCP :443 listener — NOT a TLS-terminating echo**); `denied.test` aliased but unserved (filtered before connect). **The dummy TCP listener is sufficient for this spike** because tinyproxy logs the CONNECT *tunnel establishment* at TCP-connect time, before any TLS handshake — the spike measures tinyproxy's **log shape**, not TLS enforcement. curl's TLS handshake over the tunnel fails against the dummy listener (irrelevant to the captured log line). The real allowed-HTTPS path (a TLS-terminating echo, plus actual forward/deny enforcement) is exercised by the **T13 enforcement proof**, NOT here — do not mistake T1 for that proof.
- 5 cases driven via `curl -x`: allowed-HTTP, allowed-HTTPS-CONNECT, denied-HTTP, denied-HTTPS-CONNECT, CONNECT-to-:22 (non-443).

## Evidence (key lines)

Each request emits a **`Request` line** then (contiguously) an **outcome line**:

- `Request (file descriptor N): <METHOD> <TARGET> HTTP/1.1` — `<TARGET>` is `http://host/…` (GET) or `host:port` (CONNECT). Source of `method` + `host` (+ port).
- **allowed** (both HTTP GET and HTTPS CONNECT): `CONNECT  … Established connection to host "<host>" using file descriptor M.`
- **filtered host** (HTTP + CONNECT): `NOTICE   … Proxying refused on filtered domain "<host>"`
- **bad CONNECT port**: `INFO     … Refused CONNECT method on port <port>` — **Info-level only**.

`LogLevel Connect` vs `Info`:
- **Connect** logs the allowed (`Established…`) and filter-denied (`Proxying refused on filtered domain…`) cases, but the **CONNECT-:22 case produced no outcome line at all** (only the `Request` line). → `non_http_connect_target` indistinguishable at Connect.
- **Info** logs all four, adding `Refused CONNECT method on port 22` for case 5 (plus a lot of benign noise — `opensock`, `getaddrinfo`, `No upstream proxy`, `Closed connection between…` — which the shim ignores).

## Shim mapping table (T5a)

Filter to these four patterns; ignore all other lines. Pair each `Request` line with its immediately-following outcome line:

| tinyproxy log pattern | `outcome` | `refusal_reason` |
|---|---|---|
| `Request (...): <M> <target> HTTP/1.1` | — | (carries `method` + `host`/`port`) |
| `Established connection to host "<h>"` | `allowed` | `None` |
| `Proxying refused on filtered domain "<h>"` | `refused` | `not_in_allow_list` |
| `Refused CONNECT method on port <p>` | `refused` | `non_http_connect_target` |

`timestamp` = parse tinyproxy's `Mon DD HH:MM:SS.mmm` prefix → tz-aware (stamp UTC). `policy_id` = `SESSION_ID` (per spec §4.2). `host` from the `Request` target (the `refused`/`Established` lines also echo the host; the port-refusal line carries only the port, so correlate it to its preceding CONNECT `Request`).

## Residual risks (carry into T5a)

1. **Multi-line correlation — a T5a acceptance gate, NOT a free pass.** The outcome is on a separate line from `Request`, tinyproxy carries no per-request correlation ID, and critically the **port-refusal line (`Refused CONNECT method on port <p>`) carries only the port — no host**. So under concurrent same-port load, naive sequence-pairing can attribute the **wrong host** to a `non_http_connect_target` record — that is a *wrong* record, not merely degraded fidelity, so it must NOT be called "individually accurate." T5a MUST do **one** of:
   - **(a) prove** deterministic correlation under a concurrent duplicate-target / same-port test; OR
   - **(b) detect ambiguity and skip/refuse** the record (fail-closed on the audit line) rather than emit a possibly-wrong host; OR
   - **(c) constrain** tinyproxy/shim operation so `Request`→outcome is always contiguous (e.g. serialize, or run tinyproxy single-connection).

   Enforcement itself is tinyproxy's (allow/deny is NOT log-derived), so this is an **audit-record-correctness** gate, not an enforcement gate — but wrong host attribution is unacceptable and **blocks shipping the log-tail path**. This is spec §8's ship/no-ship line applied to T5a.
2. **Version coupling.** The four strings are tinyproxy 1.11.1 wording. Pin the version in the Dockerfile (T7) and add a regression that re-runs this spike's case matrix and re-verifies the strings if the version bumps.
3. **Log volume at Info.** Info is verbose (several lines/request). Bounded by request count; fine for a per-sandbox egress sidecar. The shim reads incrementally (tail), not whole-file.

## Raw capture (T5a fixtures — verbatim)

Reproduced via `docker run --rm -i debian:bookworm-slim bash -s < /tmp/t1_spike.sh` (throwaway; not committed). The lines below are the actual `1.11.1-2.1+deb12u1` output and are the **fixture corpus T5a parses** (timestamp prefix + level + `[pid]` + message preserved exactly).

### `LogLevel Info` — the canonical level (per-case `Request` + outcome)

```text
# case 1 — allowed HTTP
CONNECT   May 28 15:08:52.926 [3814]: Request (file descriptor 2): GET http://allowed.test/ HTTP/1.1
CONNECT   May 28 15:08:52.928 [3814]: Established connection to host "allowed.test" using file descriptor 3.

# case 2 — allowed HTTPS CONNECT
CONNECT   May 28 15:08:52.936 [3814]: Request (file descriptor 2): CONNECT allowed.test:443 HTTP/1.1
CONNECT   May 28 15:08:52.938 [3814]: Established connection to host "allowed.test" using file descriptor 3.

# case 3 — denied HTTP (filtered)
CONNECT   May 28 15:08:52.946 [3814]: Request (file descriptor 2): GET http://denied.test/ HTTP/1.1
NOTICE    May 28 15:08:52.946 [3814]: Proxying refused on filtered domain "denied.test"

# case 4 — denied HTTPS CONNECT (filtered)
CONNECT   May 28 15:08:52.952 [3814]: Request (file descriptor 2): CONNECT denied.test:443 HTTP/1.1
NOTICE    May 28 15:08:52.952 [3814]: Proxying refused on filtered domain "denied.test"

# case 5 — CONNECT to non-443 port (ConnectPort denial); NOTE: outcome line has NO host
CONNECT   May 28 15:08:52.957 [3814]: Request (file descriptor 2): CONNECT allowed.test:22 HTTP/1.1
INFO      May 28 15:08:52.957 [3814]: Refused CONNECT method on port 22
```

Benign Info-level noise the shim MUST ignore (example, between case-1 `Request` and `Established`):

```text
INFO      May 28 15:08:52.926 [3814]: No upstream proxy for allowed.test
INFO      May 28 15:08:52.927 [3814]: opensock: opening connection to allowed.test:80
INFO      May 28 15:08:52.927 [3814]: opensock: getaddrinfo returned for allowed.test:80
INFO      May 28 15:08:52.929 [3814]: Closed connection between local client (fd:2) and remote client (fd:3)
```

### `LogLevel Connect` — negative evidence for case 5 (why Info is mandatory)

At `Connect`, the `CONNECT :22` `Request` line is followed directly by shutdown — **no outcome line at all**, so `non_http_connect_target` is invisible:

```text
CONNECT   May 28 15:08:49.884 [3794]: Request (file descriptor 2): CONNECT allowed.test:22 HTTP/1.1
NOTICE    May 28 15:08:50.891 [3794]: Shutting down.
```

(Cases 1–4 at `Connect` are identical in shape to the Info lines above — `Established connection to host …` / `Proxying refused on filtered domain …`.)
