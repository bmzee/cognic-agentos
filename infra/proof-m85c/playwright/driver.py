#!/usr/bin/env python3
"""Playwright browser driver for the Cognic AgentOS M8.5-C live proof.

This CLI DRIVES and OBSERVES the Cognic Harness v1 BFF (a same-origin FastAPI +
Jinja2 + plain-CSS + progressively-enhanced-HTML product with exactly three
screens: chat, approvals inbox, evidence viewer). It is invoked as a subprocess
by the proof runner (``infra/proof-m85c/run-proof-m85c.sh`` — NOT part of this
file's ownership). Each subcommand prints a single JSON object to stdout. A
completed ordinary interaction exits ``0``; a login navigation that directly
observes a governed BFF refusal writes its discriminated result and exits
``LOGIN_REFUSED_EXIT``; an interaction failure exits with a separate non-zero
diagnostic (page never loaded, expected control absent, etc.).

    THE DRIVER NEVER ASSERTS A BAR OUTCOME. The runner reads the JSON keys and
    makes every pass/fail judgement. Keeping that boundary strict means a driver
    bug cannot hide a proof failure.

TLS — SPKI pinning (design decision, §"TLS" of the task)
--------------------------------------------------------
The proof CA is self-signed. Rather than a blanket "accept any certificate"
bypass (which would trust whatever it is handed), the driver pins EXACTLY the
public keys we minted. The proof runner
mints every leaf certificate itself, on disk, in a private per-run directory,
each signed by the one per-run proof CA passed as ``--ca``. Those are trusted
bytes we produced — the driver reads them from disk and NEVER fetches a leaf
over an unverified socket to decide what to trust.

The driver computes the base64 SHA-256 of the SubjectPublicKeyInfo (SPKI) of
every certificate in ``--ca`` PLUS every certificate in every ``--leaf`` file,
and passes the de-duplicated set to Chromium via
``--ignore-certificate-errors-spki-list=<pin,pin,...>``. Chromium matches the
SPKI of ANY certificate in the presented chain; our servers present only their
leaf and the CA is NOT in the presented chain, which is exactly why the on-disk
leaf pins are required. That pins EXACTLY our CA/leaf public keys and still
rejects every other bad certificate — strictly stronger than the blanket
bypass. The SPKI computation is proven byte-identical to the canonical
``openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst
-sha256 -binary | openssl enc -base64`` recipe.

    FAIL CLOSED: if the resulting pin set is empty (no readable ``--ca`` certs
    and no readable ``--leaf`` files), the driver raises
    ``DriverFailure("spki_pins_unavailable", ...)`` and refuses to run. A TLS-pin
    computation failure must NEVER degrade to a blanket certificate bypass — there
    is no such fallback anywhere in this driver. Playwright's request API is a
    SEPARATE Node HTTP stack that does not honour the Chromium launch flag, so
    ``NODE_EXTRA_CA_CERTS`` is pointed at ``--ca`` — that makes Node trust EXACTLY
    our CA (again, not a blanket bypass).

Invocation (documented in README.md)
------------------------------------
    uv run --with-requirements requirements.txt python driver.py <subcommand> \
        --base-url https://127.0.0.1:8444 --ca /run/proof/ca.pem \
        --state-file /run/proof/amir.state.json --out /run/proof/out.json [flags]

    # one-time, in the driver's environment:
    playwright install chromium

Credentials are NEVER read from argv — only from the environment. A process's
argument vector is world-readable (``ps``); its environment is not. THREE values
ride the env for exactly that reason:

===============================  ==========================================
``HARNESS_USER_PASSWORD``        ``login`` — the Keycloak user password.
``COGNIC_PROOF_COOKIE_VALUE``    ``replay-cookie`` (required) /
                                 ``replay-callback`` (optional) — the
                                 ``__Host-`` session cookie value.
                                 **Possession of it IS the session**: it is a
                                 bearer credential exactly like a token.
``COGNIC_PROOF_CALLBACK_URL``    ``replay-callback`` — the captured
                                 ``…/auth/callback?code=…&state=…`` URL. The
                                 ``code`` is a one-time authorization code,
                                 **exchangeable for tokens**.
===============================  ==========================================

The corresponding ``--cookie-value`` / ``--callback-url`` flags are **deleted**,
not merely optional — a flag that still accepts a credential invites a call site
that passes one.

All three are **POPPED**, never merely read (review 2026-07-12 round 4). The
environment is the right channel INTO this process, but this process then LAUNCHES
OTHERS — the Playwright Node driver, Chromium, and Chromium's own renderer / GPU /
utility children — every one of which inherits ``os.environ`` verbatim. Reading a
variable leaves it there; popping it into a local before any child exists means the
browser process tree simply never sees it. ``_assert_credential_env_cleared()``
enforces that immediately before the first launch, so a subcommand that forgets to
pop fails closed instead of leaking. For the same reason the ``url`` field of every
failure diagnostic is fingerprinted (``_redact_url``): the runner pipes driver
stderr straight into the proof log, and a failing login is usually parked on
``…/auth/callback?code=…``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, cast

# Types only — the runtime import is lazy (inside functions) so ``import driver``
# and ``--selftest`` need no playwright installed.
if TYPE_CHECKING:
    from playwright.sync_api import (
        APIResponse,
        BrowserContext,
        Dialog,
        Locator,
        Page,
        Request,
        Response,
    )

# --------------------------------------------------------------------------- #
# Constants — the wire/DOM contract, every selector traced to a template line. #
# --------------------------------------------------------------------------- #

#: The one session cookie (cognic_harness/auth/cookies.py:15). Opaque value only.
COOKIE_NAME = "__Host-cognic_session"

#: Synchronizer CSRF field (cognic_harness/auth/csrf.py:16) + header (csrf.py:17).
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

# Keycloak default login-theme selectors. Confirmed live-used by the harness's
# own e2e lane at tests/e2e/test_authenticated_screens_e2e.py:37-39.
KC_USERNAME = "#username"
KC_PASSWORD = "#password"
KC_SUBMIT = "#kc-login"
# Keycloak renders a bad-credential error into these (default login.ftl).
KC_ERROR = "#input-error, .alert-error, .kc-feedback-text, #input-error-username"

# Harness DOM selectors — base.html / chat.html / approvals.html /
# approval_detail.html / evidence_*.html (cognic_harness/web/templates/).
SEL_ACTOR = "header.topbar .actor"  # base.html:18 — present only when authenticated
SEL_LOGOUT_FORM = "form.logout-form"  # base.html:21
SEL_LOGOUT_BUTTON = "form.logout-form button[type=submit]"  # base.html:23 ("Sign out")
SEL_NEWCONVO_FORM = "form.new-convo"  # chat.html:6
SEL_NEWCONVO_AGENT = "form.new-convo input[name=agent_id]"  # chat.html:9
SEL_NEWCONVO_SUBMIT = "form.new-convo button[type=submit]"  # chat.html:10
SEL_COMPOSER_FORM = "form.composer"  # chat.html:48
SEL_COMPOSER_TEXTAREA = "form.composer textarea[name=user_message]"  # chat.html:50
SEL_COMPOSER_SUBMIT = "form.composer button[type=submit]"  # chat.html:52 ("Send")
SEL_CHAT_TURNS = "section.transcript ol.turns li.turn"  # chat.html:33-35
SEL_TURN_USER_PRE = ".msg.user pre"  # chat.html:37-38
SEL_TURN_AGENT_PRE = ".msg.agent pre"  # chat.html:41-42
SEL_CHAT_REFUSAL = "section.transcript .refusal code"  # chat.html:29
SEL_APPROVALS_SECTION = "section.approvals"  # approvals.html:4
SEL_APPROVALS_FORBIDDEN = "section.approvals .refusal code"  # approvals.html:8
SEL_APPROVALS_ROWS = "section.approvals table.queue tbody tr"  # approvals.html:11,16
SEL_APPROVALS_NEXT = "section.approvals a.next-page"  # approvals.html:34
SEL_DETAIL_SECTION = "section.approval-detail"  # approval_detail.html:4
SEL_DETAIL_DL = "section.approval-detail dl.detail"  # approval_detail.html:10
SEL_DETAIL_ACTION_REFUSAL = "section.approval-detail .refusal code"  # approval_detail.html:8
SEL_EV_TRANSCRIPT_TURNS = (
    "section.evidence-transcript ol.turns li.turn"  # evidence_transcript.html:9-11
)
SEL_EV_TRANSCRIPT_NEXT = "section.evidence-transcript a.next-page"  # evidence_transcript.html:22
SEL_EV_TURN_RUN_ID = "p.turn-head span.mono"  # evidence_transcript.html:12 — the agent_run_id
SEL_EV_TURN_CHAIN_LINK = "a[href*='/turns/']"  # evidence_transcript.html:17 (scoped to a li.turn)
SEL_EV_CHAIN_SECTION = "section.evidence-chain"  # evidence_chain.html:4
SEL_EV_CHAIN_HEADING = "section.evidence-chain h1"  # evidence_chain.html:6 — "Turn chain — seq N"
SEL_EV_CHAIN_DISPATCH_ROWS = (
    "section.evidence-chain table.queue tbody tr"  # evidence_chain.html:40-52
)
SEL_EV_CHAIN_DISPATCH_HEADERS = (
    "section.evidence-chain table.queue thead th"  # evidence_chain.html:41
)

#: The dispatch table's RENDERED column headers (evidence_chain.html:41) → the JSON
#: keys the runner reads. The driver reads the LIVE ``<thead>`` and maps through
#: this table; a rendered header that is NOT in the map is still emitted (under its
#: snake_cased header text) — the driver never silently drops a rendered column, and
#: never invents one that is not rendered.
#:
#:     ``scope`` is LOAD-BEARING. Two dispatches of the same tool (retail-ok +
#:     financials-refused) render an IDENTICAL ``capability_ref``, so the scope is
#:     the only rendered field that says WHICH one was refused. The pipeline always
#:     carried it — the kernel stamps it on the chain row (core/agent/dispatch.py:644
#:     ``"scope_id": scope_id``), the read API publishes it
#:     (portal/api/conversations/dto.py:183), the harness parses it into
#:     ``DispatchBlock.scope_id`` (application/models.py:140) — but
#:     ``evidence_chain.html``'s table used to DROP it at the last inch. The round-2
#:     review found that harness gap and it is now closed (the thead renders six
#:     columns). The driver still reads the LIVE ``<thead>`` rather than assuming it:
#:     if the column were ever removed again, ``scope_id`` would simply VANISH from
#:     the emitted rows — never fabricated as ``None`` — and a runner that needs it
#:     must check ``chain.dispatch_columns`` and fail loudly.
DISPATCH_HEADER_KEYS: dict[str, str] = {
    "step": "step_index",
    "kind": "capability_kind",
    "capability": "capability_ref",
    "outcome": "outcome",
    "refusal": "refusal_reason",
    "scope": "scope_id",
    "scope id": "scope_id",
    "scope_id": "scope_id",
}

#: The dispatch columns the harness renders TODAY (evidence_chain.html:41), read off
#: the template. The driver does NOT hardcode these at runtime — it reads the live
#: ``<thead>``. The tuple exists so the selftest pins the header→key map against the
#: template we actually read.
DISPATCH_HEADERS_RENDERED_TODAY = ("step", "kind", "capability", "scope", "outcome", "refusal")

#: Response headers that COULD identify which BFF *replica/pod* served a step.
#: The harness exposes NONE of these today (see README "served_by"): pod
#: attribution for Bar A is a runner-side ``kubectl logs`` concern. Listed so
#: that if the proof deployment later injects one (downward-API POD_NAME env →
#: middleware), it is surfaced automatically without a driver change. The generic
#: ``Server`` header is DELIBERATELY EXCLUDED — it identifies the server software
#: (e.g. ``uvicorn``), not the replica instance, so surfacing it would fabricate a
#: per-pod marker that reads identically on every replica.
REPLICA_HEADER_CANDIDATES = (
    "x-served-by",
    "x-pod",
    "x-pod-name",
    "x-replica",
    "x-replica-id",
    "x-instance",
    "x-instance-id",
    "x-backend",
    "x-upstream",
    "x-hostname",
)

DEFAULT_TIMEOUT_MS = 30_000
# A chat turn drives a real server-side LLM call; give it a wide budget so a
# slow turn never times out mid live-run.
CHAT_TIMEOUT_MS = 180_000
# Hard cap so a broken pagination cursor cannot spin forever.
MAX_PAGES = 500


# --------------------------------------------------------------------------- #
# Failure handling — the driver/runner boundary.                              #
# --------------------------------------------------------------------------- #


class DriverFailure(Exception):
    """The browser interaction itself failed (not a governed refusal, which is a
    valid observation). Carries a diagnostic payload written to stderr; the
    process exits non-zero so a live-run failure is diagnosable without a re-run."""

    def __init__(self, message: str, **diagnostics: Any) -> None:
        super().__init__(message)
        self.message = message
        self.diagnostics = diagnostics


#: The closed outcome vocabulary of ``login`` (review 2026-07-12 round 5, F1).
#:
#: ``authenticated`` and ``refused`` are the driver's OWN observations; ``driver_error``
#: is minted by the RUNNER's capturing wrapper and never by this file — the driver
#: cannot report that it broke, precisely because it broke.
LOGIN_OUTCOME_AUTHENTICATED = "authenticated"
LOGIN_OUTCOME_REFUSED = "refused"
#: The exit status ``main`` returns for an OBSERVED BFF refusal. NON-ZERO (so a caller
#: that requires a successful login — ``drive_login`` — still fails loud), but distinct
#: from the harness-failure codes 3 / 4 so a reader of the exit code alone can tell them
#: apart. The observation is written to ``--out`` BEFORE the process exits.
LOGIN_REFUSED_EXIT = 5


class ObservedRefusal(Exception):
    """THE BFF ITSELF REFUSED — a governed observation, not a harness failure.

    The distinction is the whole point (review 2026-07-12 round 5, F1). ``S7`` claims
    "the BFF refuses a fresh login while its session store is destroyed". Before this
    class existed, the runner synthesised that very claim out of ANY non-zero driver
    exit — so a Chromium crash, a selector typo, a ``uv`` resolution failure or a
    missing password each MANUFACTURED the evidence that the BFF failed closed. A failed
    drive is not an observation of a refusal.

    ``page.goto()`` RETURNS the ``Response`` on a non-2xx (it raises only on a
    network-level failure), so the driver can OBSERVE the BFF's actual HTTP status on the
    login navigation — and that observation, carried here, is what the runner asserts on.
    ``main`` writes ``result`` to ``--out`` and then exits ``LOGIN_REFUSED_EXIT``."""

    def __init__(self, **result: Any) -> None:
        super().__init__(str(result.get("outcome", LOGIN_OUTCOME_REFUSED)))
        self.result: dict[str, Any] = {"ok": False, "outcome": LOGIN_OUTCOME_REFUSED, **result}


#: Query parameters that ARE CREDENTIALS in an OIDC flow: ``code`` is the one-time
#: authorization code — exchangeable for tokens — and ``state`` / ``session_state``
#: are the one-time transaction handles the BFF consumes exactly once.
_CREDENTIAL_QUERY_PARAMS: frozenset[str] = frozenset({"code", "state", "session_state"})


def _redact_url(url: str | None) -> str | None:
    """A URL with every credential-bearing query parameter replaced by a
    NON-REVERSIBLE fingerprint (``sha256(value)[:8]``).

    WHY (review 2026-07-12 round 4, F1). Driver failure diagnostics go to STDERR, and
    the runner interpolates that stderr straight into a ``bar_fail`` message that is
    appended to the proof log (``drive``/``drive_login``/``drive_replay_*`` all do
    ``head -c 800 "$err_file"``). Several diagnostics carry ``url=page.url`` — and at
    the moment a login fails the page is very often sitting on
    ``…/auth/callback?code=<one-time authz code>&state=…``. That is a credential in a
    world-readable log. Host, path and every non-credential parameter survive, so the
    diagnostic stays just as useful for debugging; only the exchangeable material is
    fingerprinted.

    NOT applied to the captured ``callback_url`` the login RESULT returns: the runner
    must replay that verbatim (S5), and it never reaches a log — it rides the child's
    environment into ``replay-callback``."""
    if not url:
        return url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    if not parts.query:
        return url
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not any(key in _CREDENTIAL_QUERY_PARAMS and value for key, value in pairs):
        return url
    redacted = [
        (
            key,
            f"sha256:{hashlib.sha256(value.encode()).hexdigest()[:8]}"
            if key in _CREDENTIAL_QUERY_PARAMS and value
            else value,
        )
        for key, value in pairs
    ]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(redacted, safe=":")))


def _fail(message: str, **diagnostics: Any) -> DriverFailure:
    """Build the diagnostic exception, REDACTING the ``url`` payload on the way out.

    ``_fail`` is the single funnel every diagnostic passes through, so redacting here
    covers every present call site AND every future one — a new ``url=page.url``
    cannot reintroduce the leak."""
    if "url" in diagnostics:
        diagnostics["url"] = _redact_url(diagnostics["url"])
    return DriverFailure(message, **diagnostics)


# --------------------------------------------------------------------------- #
# SPKI pinning helpers (pure — offline-testable).                             #
# --------------------------------------------------------------------------- #


def _split_pem_certs(pem_text: str) -> list[str]:
    """Split a (possibly multi-cert) PEM bundle into individual certificate PEMs."""
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    out: list[str] = []
    idx = 0
    while True:
        start = pem_text.find(marker, idx)
        if start == -1:
            break
        stop = pem_text.find(end, start)
        if stop == -1:
            break
        out.append(pem_text[start : stop + len(end)] + "\n")
        idx = stop + len(end)
    return out


def _spki_pin_from_cert_pem(cert_pem: str) -> str | None:
    """base64(SHA-256(DER SubjectPublicKeyInfo)) for one certificate PEM.

    Prefers ``cryptography`` (clean, in-process); falls back to the canonical
    ``openssl`` pipeline; returns ``None`` if neither is available. The two paths
    are proven byte-identical."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        spki_der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(hashlib.sha256(spki_der).digest()).decode()
    except ImportError:
        return _spki_pin_via_openssl(cert_pem)
    except Exception:
        return None


def _spki_pin_via_openssl(cert_pem: str) -> str | None:
    """Fallback SPKI pin via the openssl CLI (identical output to cryptography)."""
    try:
        pub = subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout"],
            input=cert_pem.encode(),
            capture_output=True,
            check=True,
        ).stdout
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "der"],
            input=pub,
            capture_output=True,
            check=True,
        ).stdout
        return base64.b64encode(hashlib.sha256(der).digest()).decode()
    except (OSError, subprocess.CalledProcessError):
        return None


def _spki_pins_from_ca_bundle(ca_path: str) -> list[str]:
    """SPKI pins for every certificate in the ``--ca`` bundle."""
    try:
        text = _read_text(ca_path)
    except OSError as exc:
        raise _fail("ca_unreadable", ca=ca_path, error=str(exc)) from exc
    pins: list[str] = []
    for cert_pem in _split_pem_certs(text):
        pin = _spki_pin_from_cert_pem(cert_pem)
        if pin is not None:
            pins.append(pin)
    return pins


def _spki_pins_from_leaf_file(leaf_path: str) -> list[str]:
    """SPKI pins for every certificate in an on-disk ``--leaf`` PEM file.

    These are certificates the proof runner MINTED and wrote to disk under the
    per-run PKI dir — trusted bytes. An unreadable ``--leaf`` path is a
    configuration error and fails closed (the operator asked us to pin it)."""
    try:
        text = _read_text(leaf_path)
    except OSError as exc:
        raise _fail("leaf_unreadable", leaf=leaf_path, error=str(exc)) from exc
    pins: list[str] = []
    for cert_pem in _split_pem_certs(text):
        pin = _spki_pin_from_cert_pem(cert_pem)
        if pin is not None:
            pins.append(pin)
    return pins


def _collect_spki_pins(ca_path: str, leaf_paths: list[str]) -> list[str]:
    """SPKI pins of every cert in the ``--ca`` bundle PLUS every cert in every
    ``--leaf`` file. De-duplicated, order-stable.

    Chromium's ``--ignore-certificate-errors-spki-list`` matches the SPKI of any
    cert in the *presented* chain; our servers present only their leaf and the CA
    is not in the presented chain — which is exactly why the on-disk leaf pins
    are needed. Every certificate here is one WE minted (the CA + the per-run
    leaves the runner wrote to disk); nothing is fetched over an unverified
    socket.

    FAILS CLOSED: an empty result raises ``DriverFailure`` — a pin-computation
    failure must never degrade to a blanket TLS bypass."""
    pins: list[str] = list(_spki_pins_from_ca_bundle(ca_path))
    for leaf_path in leaf_paths:
        pins.extend(_spki_pins_from_leaf_file(leaf_path))
    seen: set[str] = set()
    unique: list[str] = []
    for pin in pins:
        if pin not in seen:
            seen.add(pin)
            unique.append(pin)
    if not unique:
        raise _fail(
            "spki_pins_unavailable",
            ca=ca_path,
            leaves=list(leaf_paths),
            hint=(
                "no SPKI pins computed from --ca or any --leaf; refusing to fall back to a "
                "blanket TLS bypass. Is a crypto backend (cryptography or openssl) present, "
                "and do --ca / --leaf point at real certificate PEMs?"
            ),
        )
    return unique


# --------------------------------------------------------------------------- #
# Small pure helpers (offline-testable).                                       #
# --------------------------------------------------------------------------- #


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _parse_fields(raw_fields: list[str] | None) -> dict[str, str]:
    """``["k=v", "a=b=c"]`` → ``{"k": "v", "a": "b=c"}`` (split on the first ``=``)."""
    result: dict[str, str] = {}
    for item in raw_fields or []:
        if "=" not in item:
            raise _fail("field_missing_equals", field=item)
        key, value = item.split("=", 1)
        result[key] = value
    return result


def _seq_from_chain_href(href: str | None) -> int | None:
    """``/evidence/<cid>/turns/<seq>`` → ``<seq>`` (int) or ``None``."""
    if not href:
        return None
    match = re.search(r"/turns/(\d+)", href)
    return int(match.group(1)) if match else None


def _seq_from_chain_heading(text: str | None) -> int | None:
    """``"Turn chain — seq 3"`` → ``3`` (evidence_chain.html:6) or ``None``."""
    if not text:
        return None
    match = re.search(r"seq\s+(\d+)\s*$", text.strip())
    return int(match.group(1)) if match else None


def _dispatch_key(header: str) -> str:
    """One RENDERED dispatch-table header → the JSON key the runner reads.

    Case/whitespace-insensitive (``.queue th`` is CSS-uppercased at app.css:503, so
    the visible label and the DOM text differ in case). An UNMAPPED header is NOT
    dropped — it is snake_cased and emitted under that name, so a harness template
    that grows a column surfaces it here without a driver change."""
    normalized = " ".join(header.split()).lower()
    mapped = DISPATCH_HEADER_KEYS.get(normalized)
    if mapped is not None:
        return mapped
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_") or "column"


def _transcript_turn_record(
    *, sequence: int, agent_run_id: str, question_text: str, answer_text: str
) -> dict[str, Any]:
    """Project ONE rendered transcript turn onto the runner's contract.

    ``question_text`` / ``answer_text`` are the VERBATIM rendered text — never
    stripped, never normalised — because the runner sha256s them and compares the
    digest against the chain screen's ``question_sha256`` / ``answer_sha256`` (Bar
    E). ``agent_run_id`` is the ONLY identifier rendered on BOTH the transcript
    (evidence_transcript.html:12) and the chain screen (evidence_chain.html:13), so
    it is the binding that lets the runner prove the hashed text belongs to the turn
    whose digests it is comparing — a stale/wrong transcript cannot pass.

    ``seq`` / ``user_message`` / ``answer`` are the pre-existing key names, kept so
    the runner's current reads keep working; they carry the SAME values."""
    return {
        "sequence": sequence,
        "seq": sequence,
        "agent_run_id": agent_run_id,
        "question_text": question_text,
        "answer_text": answer_text,
        "user_message": question_text,
        "answer": answer_text,
    }


def _conversation_id_from_action(action: str | None) -> str | None:
    """``/conversations/<cid>/turns`` → ``<cid>``."""
    if not action:
        return None
    match = re.search(r"/conversations/([^/]+)/turns", action)
    return match.group(1) if match else None


def _extract_reason(status: int, content_type: str, body: str) -> str | None:
    """Best-effort governed-reason extraction across the harness's refusal shapes:

    * plaintext ``"AgentOS error: <reason>"`` (web/__init__.py:71,84);
    * JSON ``{"detail": {"reason": <r>}}`` or ``{"reason": <r>}`` (CSRF 403,
      web/dependencies.py:73);
    * an HTML page carrying a ``.refusal`` block ``<code><r></code>`` (chat /
      approvals / detail governed refusal renders).
    """
    body = body or ""
    prefix = "AgentOS error: "
    if prefix in body:
        tail = body.split(prefix, 1)[1].strip()
        first_line = tail.splitlines()[0].strip() if tail else ""
        if first_line:
            return first_line
    if "json" in content_type.lower() or body.lstrip().startswith("{"):
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            detail = parsed.get("detail")
            if isinstance(detail, dict):
                nested = detail.get("reason")
                if isinstance(nested, str):
                    return nested
            if isinstance(detail, str) and detail:
                return detail
            top = parsed.get("reason")
            if isinstance(top, str):
                return top
    match = re.search(r'class="refusal".*?<code>(.*?)</code>', body, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _cookie_to_dict(cookie: dict[str, Any]) -> dict[str, Any]:
    """Project a Playwright cookie onto the S8 contract shape."""
    return {
        "name": cookie.get("name"),
        "value": cookie.get("value"),
        "secure": bool(cookie.get("secure", False)),
        "httpOnly": bool(cookie.get("httpOnly", False)),
        "sameSite": cookie.get("sameSite"),
        "path": cookie.get("path"),
        "domain": cookie.get("domain"),
    }


#: The three credential-bearing values that ride the ENVIRONMENT, never argv (see the
#: module docstring). A session cookie value IS the session, a callback URL carries a
#: one-time authorization code exchangeable for tokens, and the password is a
#: password — all three are bearer credentials, and a ``ps`` snapshot captures argv
#: for the whole process lifetime.
COOKIE_VALUE_ENV = "COGNIC_PROOF_COOKIE_VALUE"
CALLBACK_URL_ENV = "COGNIC_PROOF_CALLBACK_URL"
PASSWORD_ENV = "HARNESS_USER_PASSWORD"

#: Every credential the driver takes from its environment. They are **POPPED** at
#: read time — never merely read (review 2026-07-12 round 4, F1).
#:
#: WHY POP AND NOT GET. The environment is the RIGHT channel into *this* process (it
#: is not world-readable, unlike argv). But this process then LAUNCHES OTHERS: the
#: Playwright Node driver (``sync_playwright()``) and Chromium (``chromium.launch``),
#: and Chromium in turn forks a renderer, a GPU process, utility processes… Every one
#: of them inherits ``os.environ`` verbatim. Merely READING a variable leaves it in
#: the environment, so the live session cookie, the one-time authorization code and
#: the user's password were being handed to the whole browser process tree — and a
#: browser is precisely the process you least want holding them. Popping the value
#: into a local BEFORE any child is launched means the children inherit an
#: environment from which the credentials are simply absent.
CREDENTIAL_ENV_VARS: tuple[str, ...] = (COOKIE_VALUE_ENV, CALLBACK_URL_ENV, PASSWORD_ENV)


def _assert_credential_env_cleared() -> None:
    """FAIL CLOSED if any credential env var would be inherited by a child process.

    Defence in depth behind the pops in the three ``_*_from_env`` readers: this runs
    immediately before ``sync_playwright()`` (i.e. before the Node driver and Chromium
    exist), so a future subcommand that forgets to pop — or an operator with one of
    these exported in their interactive shell — is refused loudly instead of silently
    leaking the credential into the browser process tree."""
    leaked = sorted(name for name in CREDENTIAL_ENV_VARS if name in os.environ)
    if leaked:
        raise _fail(
            "credential_env_not_cleared",
            detail=",".join(leaked),
            hint=(
                "these credential variables would be INHERITED by the Node driver and by "
                "Chromium (and every Chromium child). Read them with the driver's "
                "_*_from_env helpers, which POP them, or unset them before invoking the "
                "driver — never leave them in the environment across a browser launch"
            ),
        )


def _cookie_value_from_env(*, required: bool) -> str | None:
    """The ``__Host-`` session cookie value — POPPED out of the environment.

    Three states, deliberately distinct:

    * **unset** — no cookie. Legal only where the cookieless shape is meaningful
      (``replay-callback``, whose ``cookie_injected: false`` result tells the
      runner it hit the session gate rather than the OIDC gate). Where a cookie is
      REQUIRED (``replay-cookie``) an unset variable fails closed.
    * **set but empty** — ALWAYS fails closed. This is the shell variable that
      silently expanded to nothing; injecting a valueless cookie would make the
      replay probe report ``authenticated: false`` for the wrong reason, and the
      runner would read that VACUOUS observation as a real "the stale cookie is
      dead" pass.
    * **set and non-empty** — the cookie value.

    The variable is POPPED in every one of those states (see ``CREDENTIAL_ENV_VARS``):
    the value is returned to the caller as a local and no longer exists in the
    environment the browser is about to inherit.
    """
    raw = os.environ.pop(COOKIE_VALUE_ENV, None)
    if raw is None:
        if required:
            raise _fail(
                "missing_cookie_env",
                hint=(
                    f"set {COOKIE_VALUE_ENV} in the child's environment (never argv — the "
                    "session cookie value IS the session, a bearer credential a `ps` "
                    "snapshot would capture)"
                ),
            )
        return None
    if not raw:
        raise _fail(
            "cookie_value_empty",
            hint=(
                f"{COOKIE_VALUE_ENV} is set but EMPTY; refusing to inject a valueless "
                "session cookie, which would make the replay probe vacuously 'fail to "
                "authenticate'"
            ),
        )
    return raw


def _callback_url_from_env() -> str:
    """The captured ``…/auth/callback?code=…&state=…`` URL — POPPED out of the env.

    The ``code`` query parameter is a one-time authorization code that is
    EXCHANGEABLE FOR TOKENS — the URL is a credential, so it rides the env exactly
    as the cookie and the password do, and is popped so no browser child inherits it.
    Fails closed when unset or empty."""
    raw = os.environ.pop(CALLBACK_URL_ENV, None)
    if not raw:
        raise _fail(
            "missing_callback_env",
            hint=(
                f"set {CALLBACK_URL_ENV} in the child's environment (never argv — the "
                "callback URL carries a one-time authorization code, exchangeable for "
                "tokens)"
            ),
        )
    return raw


def _password_from_env() -> str:
    """The Keycloak user password — POPPED out of the environment.

    Unset and set-but-empty both fail closed with the SAME ``missing_password_env``
    reason the pre-pop reader used (``if not password``), so the wire contract the
    runner reads is byte-for-byte unchanged; only the custody improves."""
    raw = os.environ.pop(PASSWORD_ENV, None)
    if not raw:
        raise _fail("missing_password_env", hint=f"set {PASSWORD_ENV} (never argv)")
    return raw


def _session_cookie(base_url: str, value: str) -> dict[str, Any]:
    """The one BFF session cookie, shaped for ``BrowserContext.add_cookies``.

    With ``url`` set, Playwright derives a host-only domain + ``Path=/`` (the
    ``__Host-`` shape) — passing ``path`` too is rejected ("either url or path").

    FAILS CLOSED on an empty value (defence in depth behind
    ``_cookie_value_from_env``, which fails closed on a set-but-empty variable). An
    empty cookie value would inject a valueless cookie, the BFF would refuse it, and
    the driver would report ``authenticated: false`` — a VACUOUS observation the
    runner would read as a real 'the stale cookie is dead' / 'the replayed callback
    did not authenticate' pass."""
    if not value:
        raise _fail(
            "cookie_value_empty",
            hint=(
                "the session cookie value is empty; refusing to inject a valueless session "
                "cookie, which would make the replay probe vacuously 'fail to authenticate'"
            ),
        )
    return {
        "name": COOKIE_NAME,
        "value": value,
        "url": base_url,
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
    }


# --------------------------------------------------------------------------- #
# Browser plumbing.                                                            #
# --------------------------------------------------------------------------- #


def _chromium_launch_args(args: argparse.Namespace, pins: list[str]) -> list[str]:
    launch_args: list[str] = ["--disable-dev-shm-usage"]
    # Chromium's own setuid sandbox routinely blocks a root/container run; this is
    # unrelated to our TLS SPKI pin. Enabled when running as root or on request.
    if args.no_sandbox or (hasattr(os, "geteuid") and os.geteuid() == 0):
        launch_args.append("--no-sandbox")
    if pins:
        # Pin EXACTLY our CA/leaf public keys; every other bad cert still rejected.
        # ``pins`` is guaranteed non-empty here — ``_collect_spki_pins`` fails
        # closed before we reach a browser launch — so this is never skipped.
        launch_args.append("--ignore-certificate-errors-spki-list=" + ",".join(pins))
    return launch_args


class _Session:
    """A live Playwright browser + context + page for one subcommand run."""

    def __init__(self, page: Page, context: BrowserContext, base_url: str) -> None:
        self.page = page
        self.context = context
        self.base_url = base_url
        #: distinct replica markers observed across the run's main-frame responses.
        self.served_by: list[str] = []
        self._seen_served: set[str] = set()

    def observe_response(self, response: Response) -> None:
        try:
            headers = response.headers
        except Exception:
            return
        for name in REPLICA_HEADER_CANDIDATES:
            value = headers.get(name)
            if value:
                marker = f"{name}={value}"
                if marker not in self._seen_served:
                    self._seen_served.add(marker)
                    self.served_by.append(marker)


def _run_in_browser(
    args: argparse.Namespace,
    *,
    load_state: bool,
    persist_state: bool,
    fresh_cookie: dict[str, Any] | None,
    body: Callable[[_Session], dict[str, Any]],
) -> dict[str, Any]:
    """Launch Chromium, build a context (optionally from ``--state-file`` or with a
    single injected cookie), run ``body(session)``, optionally persist state."""
    from playwright.sync_api import Error as PWError
    from playwright.sync_api import TimeoutError as PWTimeout
    from playwright.sync_api import sync_playwright

    # NO CREDENTIAL MAY SURVIVE INTO A CHILD PROCESS (review 2026-07-12 round 4, F1).
    # Everything below this line forks: `sync_playwright()` starts the Node driver and
    # `chromium.launch()` starts a browser that itself forks a renderer, a GPU process
    # and utility processes — all inheriting `os.environ` verbatim. The three
    # credential readers POP their variable, so by the time a subcommand reaches here
    # the environment must be clean; this asserts it rather than trusting it.
    _assert_credential_env_cleared()

    # Fails closed (raises DriverFailure) if it cannot compute at least one pin —
    # a pin-computation failure must never degrade to a blanket TLS bypass.
    pins = _collect_spki_pins(args.ca, args.leaf or [])
    launch_args = _chromium_launch_args(args, pins)

    # Playwright's request API (``context.request``, used by manipulated-post /
    # csrf-probe) is a SEPARATE Node HTTP stack that does NOT honour Chromium's
    # ``--ignore-certificate-errors-spki-list`` launch flag. Point Node at our CA
    # so those POSTs trust EXACTLY our CA — not a blanket bypass. Must be set
    # before the driver's Node process starts (i.e. before ``sync_playwright()``).
    if args.ca and os.path.exists(args.ca):
        os.environ["NODE_EXTRA_CA_CERTS"] = os.path.abspath(args.ca)

    with sync_playwright() as pw:
        try:
            # If the browser binary is missing this raises PWError with a "run
            # `playwright install`" message — surfaced as a clean diagnostic.
            browser = pw.chromium.launch(headless=not args.headed, args=launch_args)
        except PWError as exc:
            raise _fail(
                "browser_launch_failed",
                detail=str(exc).splitlines()[0] if str(exc) else "",
                hint="did you run `playwright install chromium`?",
            ) from exc
        try:
            context_kwargs: dict[str, Any] = {"base_url": args.base_url}
            if load_state and args.state_file and os.path.exists(args.state_file):
                context_kwargs["storage_state"] = args.state_file
            context = browser.new_context(**context_kwargs)
            context.set_default_timeout(args.timeout_ms)
            if fresh_cookie is not None:
                # Playwright's SetCookieParam TypedDict is not re-exported from
                # sync_api; the dict is shaped for it (__Host- form).
                context.add_cookies([cast("Any", fresh_cookie)])
            page = context.new_page()
            session = _Session(page, context, args.base_url)
            page.on("response", session.observe_response)
            try:
                result = body(session)
            finally:
                if persist_state and args.state_file:
                    parent = os.path.dirname(os.path.abspath(args.state_file))
                    os.makedirs(parent, exist_ok=True)
                    context.storage_state(path=args.state_file)
            return result
        except PWTimeout as exc:
            raise _fail(
                "playwright_timeout",
                url=_safe_url(locals().get("page")),
                detail=str(exc).splitlines()[0] if str(exc) else "",
            ) from exc
        except PWError as exc:
            raise _fail(
                "playwright_error",
                url=_safe_url(locals().get("page")),
                detail=str(exc).splitlines()[0] if str(exc) else "",
            ) from exc
        finally:
            browser.close()


def _safe_url(page: Page | None) -> str | None:
    if page is None:
        return None
    try:
        return page.url
    except Exception:
        return None


def _goto(session: _Session, path: str, *, timeout_ms: int | None = None) -> Response:
    page = session.page
    url = path if path.startswith("http") else session.base_url.rstrip("/") + path
    # timeout_ms=None → Playwright uses the context's default timeout.
    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    if response is None:
        raise _fail("navigation_no_response", url=url)
    return response


def _dl_value(dl: Locator, label: str) -> str | None:
    """Return the ``<dd>`` text following the ``<dt>`` whose text == ``label``.

    Harness detail/chain screens render ``<dl class="detail"><dt>Label</dt>
    <dd>value</dd>…``. Absent label → ``None``."""
    locator = dl.locator(
        f"xpath=.//dt[normalize-space()={_xpath_literal(label)}]/following-sibling::dd[1]"
    )
    if locator.count() == 0:
        return None
    return locator.first.inner_text().strip()


def _rendered_text(locator: Locator, *, what: str) -> str:
    """The element's rendered TEXT, VERBATIM — ``Node.textContent``, never HTML.

    ``text_content()`` and NOT ``inner_text()`` is DELIBERATE: the runner sha256s
    what this returns and compares it to the kernel's chain digest, so extraction
    must be byte-faithful to the text the template wrote.

    * ``inner_text()`` is the CSS-RENDERED projection. It applies ``text-transform``
      — app.css uppercases every ``.queue th`` (:503) and ``.detail dt`` (:535), so a
      header reads ``"STEP"`` through ``inner_text()`` and ``"step"`` through
      ``text_content()`` — and it re-normalises line breaks at block boundaries.
    * ``text_content()`` returns the DOM text the browser parsed from the bytes the
      BFF actually sent. That is the string the kernel hashed.

    NOTHING is stripped or normalised here. Callers that want ``.strip()`` (a table
    cell, a heading) do it explicitly; the two HASHED fields (``question_text`` /
    ``answer_text``) are never stripped.

    FAILS CLOSED: a ``None`` textContent (element gone between count and read)
    raises rather than handing the runner an empty string it would happily hash."""
    text = locator.text_content()
    if text is None:
        raise _fail("rendered_text_unavailable", what=what)
    return text


def _xpath_literal(value: str) -> str:
    """Quote a string for safe embedding in an XPath expression."""
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    return "concat(" + ', "\'", '.join(f"'{part}'" for part in parts) + ")"


def _is_authenticated(session: _Session) -> bool:
    """Authenticated screens render the actor chip + logout form (base.html:18-24);
    ``/signin`` (login.html) renders neither."""
    page = session.page
    if "/signin" in page.url:
        return False
    return page.locator(SEL_ACTOR).count() > 0 and page.locator(SEL_LOGOUT_FORM).count() > 0


def _harvest_csrf(session: _Session) -> str:
    """Load an authenticated page and read a real hidden ``csrf_token`` field.

    Every authenticated screen renders the session token into its forms; ``/`` is
    the simplest (logout form always present)."""
    _goto(session, "/")
    field = session.page.locator(f"input[name={CSRF_FIELD}]")
    if field.count() == 0:
        raise _fail(
            "csrf_token_absent",
            url=session.page.url,
            hint="not authenticated? no form with a csrf_token field rendered",
            dom_excerpt=_dom_excerpt(session),
        )
    value = field.first.input_value()
    if not value:
        raise _fail("csrf_token_empty", url=session.page.url)
    return value


def _dom_excerpt(session: _Session, *, limit: int = 1500) -> str:
    try:
        return session.page.content()[:limit]
    except Exception:
        return "<content unavailable>"


# --------------------------------------------------------------------------- #
# Subcommand handlers — each returns the JSON dict the runner reads.           #
# --------------------------------------------------------------------------- #


def cmd_login(args: argparse.Namespace) -> dict[str, Any]:
    username = args.username
    # POPPED, not read (F1): the password is threaded through as a LOCAL that the
    # `body` closure captures, so it never survives into the Node/Chromium children
    # `_run_in_browser` is about to launch. This runs BEFORE `_run_in_browser`, which
    # is what makes the ordering guarantee hold.
    password = _password_from_env()

    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        served_steps: dict[str, list[str]] = {}
        # Capture the OIDC callback URL (…/auth/callback?code=…&state=…) the IdP
        # redirects through on the way back to the BFF — the runner replays it to
        # prove session case S5 (OIDC state/nonce single-use). A server-side 303
        # at /auth/callback may not surface as an intermediate frame navigation,
        # so we observe raw requests (the browser must GET that URL to deliver the
        # code) AND re-check inside the wait_for_url predicate. First BFF-origin
        # /auth/callback URL wins. The driver only RECORDS it; it never judges S5.
        callback: dict[str, str | None] = {"url": None}

        def _note_callback(url: str) -> None:
            if (
                callback["url"] is None
                and url.startswith(session.base_url)
                and "/auth/callback" in url
            ):
                callback["url"] = url

        def _on_request(request: Request) -> None:
            # Best-effort: a stray event-handler exception must never disrupt the
            # navigation the login flow depends on.
            with contextlib.suppress(Exception):
                _note_callback(request.url)

        page.on("request", _on_request)
        # 1) hit /login → 302 to Keycloak; the pre-auth session cookie is set now.
        #
        # THE BFF'S OWN STATUS IS OBSERVED HERE (review 2026-07-12 round 5, F1).
        # `page.goto()` RETURNS the Response on a non-2xx — it raises only on a
        # network-level failure — and it follows redirects, so on the healthy path this
        # is Keycloak's 200 login form. When the BFF REFUSES the login it never redirects
        # at all and this is the BFF's own refusal status. `GET /login` →
        # `AuthService.begin_login()` → `store.create_pre_auth()` is the FIRST store touch
        # in the whole login flow, so a destroyed session store surfaces EXACTLY here, as
        # the governed 503 the harness's SessionStoreUnavailable handler returns (S7).
        #
        # A refusal is an OBSERVATION, and it must never be conflated with the driver
        # BREAKING. Raising ObservedRefusal is what keeps those two events distinct all
        # the way out to the runner: the observation (with its status) is written to
        # --out, and the process still exits non-zero so `drive_login` — which requires a
        # successful login — keeps failing loud.
        login_response = _goto(session, "/login")
        login_status = login_response.status
        served_steps["login"] = list(session.served_by)
        if login_status >= 400:
            raise ObservedRefusal(
                http_status=login_status,
                stage="login_navigation",
                final_url=_redact_url(page.url),
            )
        pre_auth = _cookie_value(session, COOKIE_NAME)
        # 2) the Keycloak login form.
        if page.locator(KC_USERNAME).count() == 0:
            raise _fail(
                "keycloak_login_form_absent",
                url=page.url,
                hint="did /login redirect to Keycloak? expected #username/#password/#kc-login",
                dom_excerpt=_dom_excerpt(session),
            )
        page.fill(KC_USERNAME, username)
        page.fill(KC_PASSWORD, password)
        # 3) submit → back through /auth/callback → the authenticated BFF.
        page.click(KC_SUBMIT)

        def _returned_to_bff(url: str) -> bool:
            _note_callback(url)
            return url.startswith(session.base_url) and "/auth/callback" not in url

        try:
            page.wait_for_url(_returned_to_bff, timeout=args.timeout_ms)
        except Exception as exc:
            # a Keycloak credential error re-renders the form with an error block.
            if page.locator(KC_ERROR).count() > 0:
                raise _fail(
                    "keycloak_login_rejected",
                    url=page.url,
                    error_text=_first_text(page, KC_ERROR),
                ) from exc
            raise _fail(
                "login_did_not_return_to_bff",
                url=page.url,
                dom_excerpt=_dom_excerpt(session),
            ) from exc
        page.wait_for_load_state("domcontentloaded")
        served_steps["post_auth"] = list(session.served_by)
        post_auth = _cookie_value(session, COOKIE_NAME)
        if not _is_authenticated(session):
            raise _fail(
                "not_authenticated_after_login",
                url=page.url,
                dom_excerpt=_dom_excerpt(session),
            )
        cookie_names = [c["name"] for c in _bff_cookies(session)]
        return {
            "ok": True,
            # The DISCRIMINATOR the runner asserts on (F1). `ok` is retained for the
            # existing call sites, but a boolean cannot tell "the BFF refused" apart from
            # "the harness broke" — and S7's entire claim rests on that distinction.
            "outcome": LOGIN_OUTCOME_AUTHENTICATED,
            "http_status": login_status,
            "final_url": page.url,
            "pre_auth_session_id": pre_auth,
            "post_auth_session_id": post_auth,
            "cookie_names": cookie_names,
            "served_by": session.served_by,
            "served_by_steps": served_steps,
            "callback_url": callback["url"],
        }

    return _run_in_browser(args, load_state=False, persist_state=True, fresh_cookie=None, body=body)


def cmd_cookie_dump(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        cookies = [_cookie_to_dict(c) for c in _bff_cookies(session)]
        return {"cookies": cookies}

    return _run_in_browser(args, load_state=True, persist_state=False, fresh_cookie=None, body=body)


def cmd_replay_cookie(args: argparse.Namespace) -> dict[str, Any]:
    """Replay a session cookie in a FRESH context. The cookie value is REQUIRED and
    rides ``COGNIC_PROOF_COOKIE_VALUE`` — never argv."""
    value = _cookie_value_from_env(required=True)
    assert value is not None  # required=True never returns None (it raises)
    cookie = _session_cookie(args.base_url, value)

    def body(session: _Session) -> dict[str, Any]:
        response = _goto(session, "/")
        authenticated = _is_authenticated(session)
        return {
            "status": response.status,
            "authenticated": authenticated,
            "final_url": session.page.url,
        }

    # Fresh context (do NOT load the state-file) with only the injected cookie.
    return _run_in_browser(
        args, load_state=False, persist_state=False, fresh_cookie=cookie, body=body
    )


def cmd_replay_callback(args: argparse.Namespace) -> dict[str, Any]:
    """Replay a captured OIDC callback URL (…/auth/callback?code=…&state=…) in a
    FRESH browser context (no state-file, no persisted state), OPTIONALLY carrying
    the PRE-AUTH session cookie ``login`` captured.

    BOTH inputs ride the ENVIRONMENT, never argv: ``COGNIC_PROOF_CALLBACK_URL``
    (required — the URL's ``code`` is a one-time authorization code, exchangeable
    for tokens) and ``COGNIC_PROOF_COOKIE_VALUE`` (optional — possession of the
    cookie value IS the session).

    WHY THE COOKIE IS THE WHOLE POINT (S5). The BFF's ``complete_callback()`` reads
    the session cookie FIRST: with NO cookie it refuses ``no_login_session`` before
    it ever reaches ``consume_oidc()``. A cookieless replay therefore never
    exercises the one-time state/nonce consumption AT ALL — a BFF that never
    consumed the state would still "not authenticate", and the probe would pass
    vacuously. Injecting the pre-auth session id (the SAME session the successful
    login already spent) drives the replay THROUGH the session gate and INTO the
    OIDC gate, where a correct BFF refuses because the state/nonce is already
    consumed — and the RUNNER greps the BFF pod log for ``login_state_already_
    consumed``. The driver still only REPORTS what it observed in the browser
    (``status`` / ``authenticated`` / ``final_url`` / whether a cookie was
    injected); it judges nothing.

    The cookie stays OPTIONAL (an UNSET ``COGNIC_PROOF_COOKIE_VALUE``) so the
    cookieless shape remains drivable, and ``cookie_injected`` tells the runner which
    of the two gates it actually hit. A SET-but-EMPTY variable still fails closed."""
    value = _cookie_value_from_env(required=False)
    callback_url = _callback_url_from_env()
    cookie = _session_cookie(args.base_url, value) if value is not None else None

    def body(session: _Session) -> dict[str, Any]:
        response = _goto(session, callback_url)
        return {
            "status": response.status,
            "authenticated": _is_authenticated(session),
            "final_url": session.page.url,
            "cookie_injected": cookie is not None,
        }

    # Fresh context: no state-file, no persisted state; ONLY the injected pre-auth
    # cookie (when the caller supplied one).
    return _run_in_browser(
        args, load_state=False, persist_state=False, fresh_cookie=cookie, body=body
    )


def cmd_chat_turn(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        start_path = (
            f"/?conversation_id={urllib.parse.quote(args.conversation_id)}"
            if args.conversation_id
            else "/"
        )
        _goto(session, start_path)
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=page.url, dom_excerpt=_dom_excerpt(session))
        # Ensure an active conversation with a composer.
        if args.create or page.locator(SEL_COMPOSER_FORM).count() == 0:
            _create_conversation(session, args)
        if page.locator(SEL_COMPOSER_FORM).count() == 0:
            raise _fail(
                "no_active_composer",
                url=page.url,
                hint="conversation not active/renderable; cannot post a turn",
                dom_excerpt=_dom_excerpt(session),
            )
        conversation_id = _conversation_id_from_action(
            page.locator(SEL_COMPOSER_FORM).first.get_attribute("action")
        )
        page.fill(SEL_COMPOSER_TEXTAREA, args.message)
        turns_before = page.locator(SEL_CHAT_TURNS).count()
        status = _submit_and_capture_status(
            session,
            click_selector=SEL_COMPOSER_SUBMIT,
            match_path=f"/conversations/{conversation_id}/turns",
            method="POST",
            timeout_ms=CHAT_TIMEOUT_MS,
        )
        page.wait_for_load_state("domcontentloaded", timeout=CHAT_TIMEOUT_MS)
        # A completed turn 303-reloads the transcript; a submit refusal renders
        # inline. Either way the settled DOM is a chat page.
        answer_text = _last_agent_answer(session)
        inline_refusal = _first_text(page, SEL_CHAT_REFUSAL)
        if not answer_text and inline_refusal:
            # a submit-level refusal (no recorded turn) — the governed answer.
            answer_text = inline_refusal
        turn_count = page.locator(SEL_CHAT_TURNS).count()
        return {
            "conversation_id": conversation_id,
            "answer_text": answer_text,
            "turn_count": turn_count,
            "served_by": session.served_by,
            "status": status,
            "refusal_inline": inline_refusal,
            "turns_before": turns_before,
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_approvals_list(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        response = _goto(session, "/approvals")
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=page.url, dom_excerpt=_dom_excerpt(session))
        # A non-observer's governed 403 renders as a refusal view (approvals.html:8).
        forbidden = _first_text(page, SEL_APPROVALS_FORBIDDEN)
        if forbidden is not None:
            return {
                "status": response.status,
                "refusal_rendered": True,
                "refusal_reason": forbidden,
                "rows": [],
            }
        rows = _parse_approval_rows(session)
        return {
            "status": response.status,
            "refusal_rendered": False,
            "rows": rows,
            "next_page_available": page.locator(SEL_APPROVALS_NEXT).count() > 0,
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_approvals_paginate(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        _goto(session, "/approvals")
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=page.url, dom_excerpt=_dom_excerpt(session))
        if page.locator(SEL_APPROVALS_FORBIDDEN).count() > 0:
            raise _fail(
                "approvals_forbidden",
                url=page.url,
                hint="paginate needs an observer; got a rendered 403 refusal",
            )
        request_ids: list[str] = []
        per_page: list[list[str]] = []
        link_present: list[bool] = []
        pages = 0
        seen_cursors: set[str] = set()
        while True:
            pages += 1
            if pages > MAX_PAGES:
                raise _fail("pagination_exceeded_cap", pages=pages, cap=MAX_PAGES)
            ids = [row["request_id"] for row in _parse_approval_rows(session)]
            per_page.append(ids)
            request_ids.extend(ids)
            next_link = page.locator(SEL_APPROVALS_NEXT)
            has_next = next_link.count() > 0
            link_present.append(has_next)
            if not has_next:
                break
            href = next_link.first.get_attribute("href") or ""
            cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query).get("cursor", [""])[0]
            if cursor and cursor in seen_cursors:
                raise _fail("pagination_cursor_loop", cursor=cursor, pages=pages)
            if cursor:
                seen_cursors.add(cursor)
            with page.expect_navigation(wait_until="domcontentloaded"):
                next_link.first.click()
        return {
            "pages": pages,
            "request_ids": request_ids,
            "request_ids_per_page": per_page,
            "link_on_first_page": link_present[0] if link_present else False,
            "link_on_last_page": link_present[-1] if link_present else False,
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_approvals_act(args: argparse.Namespace) -> dict[str, Any]:
    action_paths = {"grant": "/grant", "grant-second": "/grant-second", "deny": "/deny"}
    suffix = action_paths[args.action]

    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        rid = urllib.parse.quote(args.request_id, safe="")
        _goto(session, f"/approvals/{rid}")
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=page.url, dom_excerpt=_dom_excerpt(session))
        form = page.locator(f"{SEL_DETAIL_SECTION} form[action$='{suffix}']")
        if form.count() == 0:
            raise _fail(
                "action_control_absent",
                url=page.url,
                action=args.action,
                hint="the action form is absent (state not pending/awaiting_second?)",
                current_state=_detail_state(session),
                dom_excerpt=_dom_excerpt(session),
            )
        if args.reason is not None:
            reason_field = form.locator("input[name=reason]")  # approval_detail.html:31,37,43
            if reason_field.count() > 0:
                reason_field.first.fill(args.reason)
        status = _submit_and_capture_status(
            session,
            click_selector=f"{SEL_DETAIL_SECTION} form[action$='{suffix}'] button[type=submit]",
            match_path=f"/approvals/{args.request_id}{suffix}",
            method="POST",
            timeout_ms=args.timeout_ms,
        )
        page.wait_for_load_state("domcontentloaded")
        refusal = _first_text(page, SEL_DETAIL_ACTION_REFUSAL)
        return {
            "status": status,
            "resulting_state": _detail_state(session),
            "refusal_reason": refusal,
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_evidence(args: argparse.Namespace) -> dict[str, Any]:
    """Render the evidence transcript (``/evidence/<cid>``) then the per-turn chain
    (``/evidence/<cid>/turns/<seq>``), and emit what BOTH screens ACTUALLY RENDERED.

    ``transcript_turns`` carries, per rendered turn, the VERBATIM rendered question
    and answer TEXT plus the rendered ``agent_run_id`` — so the runner can sha256
    the text it can SEE and compare it to the digests the chain screen shows (Bar E:
    a stale or simply wrong transcript can no longer pass a digests-only check),
    binding the two screens by the one id both render.

    ``chain.dispatches`` carries the per-dispatch rows AS RENDERED — including the
    ``outcome`` and the governed ``refusal_reason`` — so Bar C can prove the refusal
    REACHES THE UI, not just the DB. ``chain.dispatch_columns`` names the columns the
    screen actually has, so a runner asking for a column the harness does not render
    (``scope_id`` today) fails loudly instead of reading a fabricated ``null``.

    The driver judges NOTHING here: every comparison is the runner's."""

    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        cid = urllib.parse.quote(args.conversation_id, safe="")
        _goto(session, f"/evidence/{cid}")
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=page.url, dom_excerpt=_dom_excerpt(session))
        transcript_turns = _parse_evidence_transcript(session)
        # The transcript paginates (evidence_transcript.html:21-25). Report whether a
        # further page exists so "the turn is not in transcript_turns" cannot be
        # misread as "the turn does not exist" — the runner judges.
        next_page = page.locator(SEL_EV_TRANSCRIPT_NEXT).count() > 0
        _goto(session, f"/evidence/{cid}/turns/{int(args.seq)}")
        if page.locator(SEL_EV_CHAIN_SECTION).count() == 0:
            raise _fail(
                "evidence_chain_absent",
                url=page.url,
                dom_excerpt=_dom_excerpt(session),
            )
        chain = _parse_evidence_chain(session)
        return {
            "transcript_turns": transcript_turns,
            "transcript_next_page_available": next_page,
            "chain": chain,
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_manipulated_post(args: argparse.Namespace) -> dict[str, Any]:
    fields = _parse_fields(args.field)

    def body(session: _Session) -> dict[str, Any]:
        token = _harvest_csrf(session)  # valid session + valid CSRF
        form = dict(fields)
        form[CSRF_FIELD] = token
        response = _api_post(session, args.path, form)
        text = _response_text(response)
        reason = _extract_reason(response.status, _content_type(response), text)
        return {"status": response.status, "body_reason": reason}

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_csrf_probe(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        # authenticated context, but a missing/garbage CSRF token — the harness
        # runs require_csrf AFTER require_session, so this reaches the CSRF gate.
        _goto(session, "/")
        if not _is_authenticated(session):
            raise _fail("not_authenticated", url=session.page.url)
        form: dict[str, str] = {}
        if args.csrf_mode == "garbage":
            form[CSRF_FIELD] = "not-a-valid-token"
        # else "missing": omit the field entirely
        response = _api_post(session, args.path, form)
        text = _response_text(response)
        reason = _extract_reason(response.status, _content_type(response), text)
        return {"status": response.status, "body_reason": reason, "csrf_mode": args.csrf_mode}

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_xss_probe(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        context = session.context
        # window flag set to false at every document start (before page scripts);
        # any executed injected script would flip it true. Strict CSP + autoescape
        # should both prevent execution.
        context.add_init_script("window.__XSS_FIRED = false;")
        dialog_fired = {"v": False}

        def _on_dialog(dialog: Dialog) -> None:
            # an alert()/confirm() firing is another execution signal.
            dialog_fired["v"] = True
            dialog.dismiss()

        page.on("dialog", _on_dialog)
        surfaces = _xss_surfaces(args.surface, args.conversation_id)
        executed = False
        contains_markup = False
        checked: list[str] = []
        for path in surfaces:
            _goto(session, path)
            if not _is_authenticated(session):
                raise _fail("not_authenticated", url=page.url)
            checked.append(path)
            fired = bool(page.evaluate("() => window.__XSS_FIRED === true"))
            executed = executed or fired
            if _rendered_text_has_markup(session):
                contains_markup = True
        executed = executed or dialog_fired["v"]
        return {
            "script_executed": executed,
            "rendered_text_contains_markup": contains_markup,
            "surfaces_checked": checked,
            "dialog_fired": dialog_fired["v"],
        }

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


def cmd_logout(args: argparse.Namespace) -> dict[str, Any]:
    def body(session: _Session) -> dict[str, Any]:
        page = session.page
        _goto(session, "/")
        if page.locator(SEL_LOGOUT_BUTTON).count() == 0:
            raise _fail(
                "logout_control_absent",
                url=page.url,
                hint="no logout form — already signed out?",
                dom_excerpt=_dom_excerpt(session),
            )
        status = _submit_and_capture_status(
            session,
            click_selector=SEL_LOGOUT_BUTTON,
            match_path="/logout",
            method="POST",
            timeout_ms=args.timeout_ms,
        )
        page.wait_for_load_state("domcontentloaded")
        cookie_cleared = _cookie_value(session, COOKIE_NAME) is None
        return {"status": status, "cookie_cleared": cookie_cleared, "final_url": page.url}

    return _run_in_browser(args, load_state=True, persist_state=True, fresh_cookie=None, body=body)


# --------------------------------------------------------------------------- #
# Handler helpers.                                                             #
# --------------------------------------------------------------------------- #


def _create_conversation(session: _Session, args: argparse.Namespace) -> None:
    page = session.page
    if page.locator(SEL_NEWCONVO_FORM).count() == 0:
        raise _fail("new_conversation_form_absent", url=page.url, dom_excerpt=_dom_excerpt(session))
    page.fill(SEL_NEWCONVO_AGENT, args.agent_id)
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.click(SEL_NEWCONVO_SUBMIT)


def _submit_and_capture_status(
    session: _Session,
    *,
    click_selector: str,
    match_path: str,
    method: str,
    timeout_ms: int,
) -> int:
    """Click a submit control and capture the *governed* status of the resulting
    request (the 303/403/409/… of the POST itself, not the followed GET)."""
    page = session.page

    def predicate(response: Response) -> bool:
        try:
            return response.request.method == method and match_path in response.url
        except Exception:
            return False

    with page.expect_response(predicate, timeout=timeout_ms) as info:
        page.click(click_selector, timeout=timeout_ms)
    return info.value.status


def _api_post(session: _Session, path: str, form: dict[str, str]) -> APIResponse:
    """POST directly through the context's request API (shares the session cookie),
    bypassing the UI control. ``max_redirects=0`` surfaces the exact governed
    status (mirrors the harness's own ``follow_redirects=False`` discipline)."""
    url = path if path.startswith("http") else session.base_url.rstrip("/") + path
    payload = cast("dict[str, str | float | bool]", form)
    return session.context.request.post(url, form=payload, max_redirects=0)


def _parse_approval_rows(session: _Session) -> list[dict[str, Any]]:
    """Parse the queue table. Columns (approvals.html:13 thead order):
    Request | Tool | Flow | Risk tier | Originator | State | (action)."""
    page = session.page
    rows: list[dict[str, Any]] = []
    row_locator = page.locator(SEL_APPROVALS_ROWS)
    for i in range(row_locator.count()):
        cells = row_locator.nth(i).locator("td")
        texts = [cells.nth(j).inner_text().strip() for j in range(cells.count())]
        # defensive: require at least the six data columns.
        if len(texts) < 6:
            continue
        rows.append(
            {
                "request_id": texts[0],
                "tool_identity": texts[1],
                "flow": texts[2],
                "risk_tier": texts[3],
                "originator": texts[4],
                "state": texts[5],
            }
        )
    return rows


def _detail_state(session: _Session) -> str | None:
    dl = session.page.locator(SEL_DETAIL_DL)
    if dl.count() == 0:
        return None
    return _dl_value(dl.first, "State")


def _parse_evidence_transcript(session: _Session) -> list[dict[str, Any]]:
    """Every RENDERED transcript turn, with its text VERBATIM (evidence_transcript
    .html:9-19).

    FIDELITY. The template writes the turn text as the ONLY child of a ``<pre>``
    with no surrounding whitespace (``<div class="msg user"><pre>{{ turn.user_message
    }}</pre></div>``, :15-16) and ``.msg pre { white-space: pre-wrap }`` (app.css:442)
    preserves it, so ``textContent`` IS the string the kernel hashed. We therefore do
    NOT strip, trim or normalise it — a template that grew indentation inside the
    ``<pre>`` MUST break the runner's sha256 comparison, because that would be a real
    rendering defect, and quietly ``.strip()``ing it here would hide exactly the class
    of bug Bar E exists to catch.

        ONE KNOWN LOSSY EDGE, and it belongs to the HTML PARSER, not to us: a text
        node whose first character is a newline loses that newline, because the HTML
        spec drops a newline immediately following a ``<pre>`` start tag. If a proof
        message ever begins with "\\n" the runner's recomputed digest will MISMATCH.
        That is a genuine harness rendering defect (the fix is the template's, e.g.
        a leading sentinel newline), and re-inserting a newline we did not observe
        would be the driver lying about what the screen showed.

    FAILS CLOSED on any turn that renders without its chain link, its seq, its run id
    or either message — the runner must never be handed a half-observed turn it could
    hash and compare."""
    page = session.page
    turns: list[dict[str, Any]] = []
    li = page.locator(SEL_EV_TRANSCRIPT_TURNS)
    for i in range(li.count()):
        item = li.nth(i)
        link = item.locator(SEL_EV_TURN_CHAIN_LINK)
        if link.count() == 0:
            raise _fail(
                "evidence_transcript_turn_link_absent",
                url=page.url,
                turn_index=i,
                hint="a rendered turn has no /turns/<seq> chain link — cannot name its sequence",
                dom_excerpt=_dom_excerpt(session),
            )
        href = link.first.get_attribute("href")
        seq = _seq_from_chain_href(href)
        if seq is None:
            raise _fail(
                "evidence_transcript_turn_seq_unparseable",
                url=page.url,
                turn_index=i,
                href=href,
            )
        run_id_span = item.locator(SEL_EV_TURN_RUN_ID)
        user_pre = item.locator(SEL_TURN_USER_PRE)
        agent_pre = item.locator(SEL_TURN_AGENT_PRE)
        if run_id_span.count() == 0 or user_pre.count() == 0 or agent_pre.count() == 0:
            raise _fail(
                "evidence_transcript_turn_incomplete",
                url=page.url,
                turn_index=i,
                seq=seq,
                run_id_rendered=run_id_span.count() > 0,
                question_rendered=user_pre.count() > 0,
                answer_rendered=agent_pre.count() > 0,
                dom_excerpt=_dom_excerpt(session),
            )
        turns.append(
            _transcript_turn_record(
                sequence=seq,
                # the run id is an identifier, not hashed text — strip is safe here.
                agent_run_id=_rendered_text(
                    run_id_span.first, what=f"turn {seq} agent_run_id"
                ).strip(),
                question_text=_rendered_text(user_pre.first, what=f"turn {seq} question"),
                answer_text=_rendered_text(agent_pre.first, what=f"turn {seq} answer"),
            )
        )
    return turns


def _parse_evidence_chain(session: _Session) -> dict[str, Any]:
    """Read the chain screen AS RENDERED (evidence_chain.html): the heading's seq, the
    three curated ``<dl>`` blocks, and the dispatch table (rows + the column names the
    screen actually has). The three-block ``<dl>`` reads are label-driven XPath, which
    is CSS-blind — ``.detail dt`` is CSS-uppercased (app.css:535) but the DOM text the
    template wrote is what XPath matches, and ``.detail dd`` carries no
    ``text-transform``, so a rendered digest reads back verbatim."""
    page = session.page

    def block(heading: str, labels: list[str]) -> dict[str, Any]:
        dl = page.locator(
            f"xpath=//h2[normalize-space()={_xpath_literal(heading)}]/following-sibling::dl[1]"
        )
        if dl.count() == 0:
            return {}
        return {label: _dl_value(dl.first, label) for label in labels}

    turn_completed = block(
        "turn_completed",
        [
            "sequence",
            "turn_id",
            "agent_run_id",
            "actor_id",
            "question_sha256",
            "answer_sha256",
            "tokens",
        ],
    )
    started = block(
        "run_started",
        ["run_id", "agent_id", "originator", "prior_context_turns", "prior_context_sha256"],
    )
    terminal = block(
        "run_terminal",
        ["terminal_state", "answer_sha256", "steps_used", "refusal_reason"],
    )
    heading = _first_text(page, SEL_EV_CHAIN_HEADING)
    columns, dispatches = _parse_dispatch_rows(session)
    return {
        # The seq the chain screen SAYS it is showing ("Turn chain — seq N",
        # evidence_chain.html:6). HONESTY: the harness echoes the URL path param into
        # it (use_cases.py:178 `seq=seq`) — it proves the screen is not displaying a
        # DIFFERENT turn's heading; it is NOT independent chain-row evidence. The
        # chain row's OWN turn seq (TurnCompletedBlock.seq, models.py:89) is NOT
        # rendered anywhere — the `<dt>sequence</dt>` below is the DECISION-HISTORY
        # row sequence (TurnCompletedBlock.sequence, :87), NOT the turn number. The
        # transcript↔chain binding that IS observable today is `agent_run_id`.
        "heading_seq": _seq_from_chain_heading(heading),
        "turn_completed": turn_completed,
        "started": started,
        "terminal": terminal,
        "dispatch_columns": columns,
        "dispatches": dispatches,
    }


def _parse_dispatch_rows(session: _Session) -> tuple[list[str], list[dict[str, Any]]]:
    """The RENDERED dispatch table (evidence_chain.html:39-53), parsed BY ITS COLUMN
    HEADERS — never by a hardcoded index.

    Returns ``(column_keys, rows)``. Reading the live ``<thead>`` means the driver
    reports the fields the screen ACTUALLY shows: a harness that adds the missing
    ``scope`` column surfaces it here with no driver change, and a harness that
    reorders columns cannot silently mislabel them. ``column_keys`` goes out on the
    wire as ``chain.dispatch_columns`` so a runner can assert a column EXISTS before
    trusting a per-row value.

    Zero rows with headers present is a VALID observation (a turn with no tool
    calls). FAILS CLOSED when the headers are absent (naming the fields would be a
    guess) or when a row's cell count does not match the header count (the driver
    would have to drop or mis-align a RENDERED cell — precisely how a refusal row
    could go missing from Bar C's view)."""
    page = session.page
    headers = page.locator(SEL_EV_CHAIN_DISPATCH_HEADERS)
    header_count = headers.count()
    if header_count == 0:
        raise _fail(
            "evidence_chain_dispatch_headers_absent",
            url=page.url,
            hint="the dispatch table rendered no <thead> <th> — cannot name its columns",
            dom_excerpt=_dom_excerpt(session),
        )
    column_keys = [
        _dispatch_key(_rendered_text(headers.nth(i), what=f"dispatch header {i}"))
        for i in range(header_count)
    ]
    rows: list[dict[str, Any]] = []
    row_locator = page.locator(SEL_EV_CHAIN_DISPATCH_ROWS)
    for i in range(row_locator.count()):
        cells = row_locator.nth(i).locator("td")
        cell_count = cells.count()
        if cell_count != header_count:
            raise _fail(
                "evidence_chain_dispatch_row_shape",
                url=page.url,
                row_index=i,
                cells=cell_count,
                headers=header_count,
                columns=list(column_keys),
                hint="a rendered dispatch row does not line up with the table headers",
                dom_excerpt=_dom_excerpt(session),
            )
        row: dict[str, Any] = {}
        for j, key in enumerate(column_keys):
            text = _rendered_text(cells.nth(j), what=f"dispatch row {i} cell {key}").strip()
            # The template renders an absent value as the empty string
            # (`{{ d.refusal_reason or "" }}`, evidence_chain.html:49): an empty CELL
            # is "the screen shows nothing here", which is None on the wire.
            row[key] = text or None
        rows.append(row)
    return column_keys, rows


def _last_agent_answer(session: _Session) -> str:
    turns = session.page.locator(SEL_CHAT_TURNS)
    count = turns.count()
    if count == 0:
        return ""
    agent = turns.nth(count - 1).locator(SEL_TURN_AGENT_PRE)
    return agent.first.inner_text() if agent.count() > 0 else ""


def _xss_surfaces(surface: str, conversation_id: str) -> list[str]:
    cid = urllib.parse.quote(conversation_id, safe="")
    chat = f"/?conversation_id={cid}"
    evidence = f"/evidence/{cid}"
    if surface == "chat":
        return [chat]
    if surface == "evidence":
        return [evidence]
    return [chat, evidence]  # "both"


def _rendered_text_has_markup(session: _Session) -> bool:
    """True when hostile markup rendered as inert visible TEXT (the correct,
    escaped outcome) — e.g. the literal ``<script>`` / ``onerror=`` / the XSS
    sentinel appears in the transcript's text content."""
    page = session.page
    pres = page.locator(".transcript pre, .evidence-transcript pre, .msg pre")
    needles = ("<script", "onerror=", "__XSS_FIRED", "<img", "javascript:")
    for i in range(pres.count()):
        text = pres.nth(i).inner_text()
        if any(needle in text for needle in needles):
            return True
    return False


def _first_text(page: Page, selector: str) -> str | None:
    locator = page.locator(selector)
    if locator.count() == 0:
        return None
    return locator.first.inner_text().strip()


def _cookie_value(session: _Session, name: str) -> str | None:
    for cookie in _bff_cookies(session):
        if cookie.get("name") == name:
            value = cookie.get("value")
            return value if isinstance(value, str) else None
    return None


def _bff_cookies(session: _Session) -> list[dict[str, Any]]:
    """Cookies scoped to the BFF origin. Playwright's ``Cookie`` is a TypedDict —
    cast to the plain-dict shape the S8 projection reads."""
    return cast("list[dict[str, Any]]", session.context.cookies([session.base_url]))


def _response_text(response: APIResponse) -> str:
    try:
        return response.text()
    except Exception:
        return ""


def _content_type(response: APIResponse) -> str:
    try:
        return response.headers.get("content-type", "")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Selftest — validates the CLI surface + JSON shapes + pure helpers, no browser.#
# --------------------------------------------------------------------------- #

#: The JSON keys each subcommand is contracted to emit (the runner's contract).
#: Extra diagnostic keys beyond these are allowed and non-breaking.
SUBCOMMAND_CONTRACT: dict[str, list[str]] = {
    "login": [
        "ok",
        # The closed discriminator (round 5, F1) — `authenticated` | `refused`. The
        # runner's S7 leg asserts on THIS, never on a bare exit code, because an exit
        # code cannot distinguish a BFF refusal from a broken proof harness.
        "outcome",
        "http_status",
        "final_url",
        "pre_auth_session_id",
        "post_auth_session_id",
        "cookie_names",
        "served_by",
        "callback_url",
    ],
    "cookie-dump": ["cookies"],
    "replay-cookie": ["status", "authenticated"],
    "replay-callback": ["status", "authenticated", "final_url", "cookie_injected"],
    "chat-turn": ["conversation_id", "answer_text", "turn_count", "served_by"],
    "approvals-list": ["status", "rows"],
    "approvals-paginate": ["pages", "request_ids"],
    "approvals-act": ["status", "resulting_state", "refusal_reason"],
    "evidence": ["transcript_turns", "transcript_next_page_available", "chain"],
    "manipulated-post": ["status", "body_reason"],
    "csrf-probe": ["status"],
    "xss-probe": ["script_executed", "rendered_text_contains_markup"],
    "logout": ["status", "cookie_cleared"],
}

#: The keys ``evidence`` emits for EVERY rendered transcript turn.
#: ``question_text`` / ``answer_text`` are the verbatim rendered text (the runner
#: sha256s them); ``seq`` / ``user_message`` / ``answer`` are the pre-existing names
#: carrying the same values.
EVIDENCE_TURN_KEYS = (
    "sequence",
    "seq",
    "agent_run_id",
    "question_text",
    "answer_text",
    "user_message",
    "answer",
)

#: The keys ``evidence`` emits under ``chain``.
EVIDENCE_CHAIN_KEYS = (
    "heading_seq",
    "turn_completed",
    "started",
    "terminal",
    "dispatch_columns",
    "dispatches",
)


def _selftest() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    parser = build_parser()
    # every contracted subcommand must be registered.
    subparsers_action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    registered = set(subparsers_action.choices)
    for name in SUBCOMMAND_CONTRACT:
        check(f"subcommand_registered:{name}", name in registered)
    check(
        "no_extra_subcommands",
        registered == set(SUBCOMMAND_CONTRACT) | {"selftest"},
        detail=str(sorted(registered)),
    )

    # required-arg wiring: these must parse and reject missing required args.
    parse_cases: list[tuple[list[str], bool]] = [
        (["login", "--username", "u", "--base-url", "https://x", "--ca", "c"], True),
        (["login", "--base-url", "https://x", "--ca", "c"], False),  # missing --username
        # SECRET CUSTODY (the load-bearing pair). The value-bearing flags are DELETED:
        # a session cookie IS a bearer credential and a callback URL carries a
        # one-time authorization code, and argv is world-readable via `ps`. Both
        # subcommands now parse with NO credential flag (the values ride the child's
        # environment), and BOTH REJECT the deleted flags — the reject cases fail the
        # moment anyone re-adds a way to put a credential on the argument vector.
        (["replay-cookie", "--base-url", "https://x", "--ca", "c"], True),
        (["replay-cookie", "--cookie-value", "v", "--base-url", "https://x", "--ca", "c"], False),
        (["replay-callback", "--base-url", "https://x", "--ca", "c"], True),
        (
            [
                "replay-callback",
                "--callback-url",
                "https://x/auth/callback?code=c&state=s",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            False,
        ),
        (
            [
                "replay-callback",
                "--cookie-value",
                "pre-auth-session-id",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            False,
        ),
        (["chat-turn", "--message", "hi", "--base-url", "https://x", "--ca", "c"], True),
        (["chat-turn", "--base-url", "https://x", "--ca", "c"], False),
        (
            [
                "approvals-act",
                "--request-id",
                "r",
                "--action",
                "grant",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            True,
        ),
        (
            [
                "approvals-act",
                "--request-id",
                "r",
                "--action",
                "bogus",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            False,
        ),  # bad choice
        (
            [
                "evidence",
                "--conversation-id",
                "c",
                "--seq",
                "1",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            True,
        ),
        (["evidence", "--conversation-id", "c", "--base-url", "https://x", "--ca", "c"], False),
        (
            [
                "manipulated-post",
                "--path",
                "/p",
                "--field",
                "k=v",
                "--base-url",
                "https://x",
                "--ca",
                "c",
            ],
            True,
        ),
        (["csrf-probe", "--path", "/p", "--base-url", "https://x", "--ca", "c"], True),
        (["xss-probe", "--conversation-id", "c", "--base-url", "https://x", "--ca", "c"], True),
        (["cookie-dump", "--base-url", "https://x", "--ca", "c"], True),
        (["approvals-list", "--base-url", "https://x", "--ca", "c"], True),
        (["approvals-paginate", "--base-url", "https://x", "--ca", "c"], True),
        (["logout", "--base-url", "https://x", "--ca", "c"], True),
    ]
    for argv, should_parse in parse_cases:
        ok = _try_parse(parser, argv)
        check(f"parse:{argv[0]}:{'ok' if should_parse else 'reject'}", ok == should_parse)

    # NO subcommand anywhere may declare a credential-bearing flag. The parse cases
    # above cover the two that used to; this sweeps the WHOLE parser so a credential
    # flag cannot reappear on some other subcommand and go unnoticed.
    _forbidden_flags = {"--cookie-value", "--callback-url"}
    _declared_flags: set[str] = set()
    for _sub_parser in subparsers_action.choices.values():
        for _action in _sub_parser._actions:
            _declared_flags.update(_action.option_strings)
    check(
        "no_credential_flags_on_any_subcommand",
        not (_declared_flags & _forbidden_flags),
        detail=str(sorted(_declared_flags & _forbidden_flags)),
    )

    # --- the credential ENV channel (the flags are deleted; argv is `ps`-visible) --
    #
    # Each read gets its OWN _env_scope, because the readers now POP (F1): a second
    # read inside the same scope would — correctly — find the variable already gone.
    with _env_scope({COOKIE_VALUE_ENV: "sess-1"}):
        check("cookie_env_read", _cookie_value_from_env(required=True) == "sess-1")
        # THE POP. The value came back as a LOCAL and no longer exists in the
        # environment that `sync_playwright()` + Chromium (+ every Chromium child)
        # would otherwise inherit verbatim.
        check("cookie_env_popped_not_merely_read", COOKIE_VALUE_ENV not in os.environ)
    with _env_scope({CALLBACK_URL_ENV: "https://x/auth/callback?code=c"}):
        check("callback_env_read", _callback_url_from_env() == "https://x/auth/callback?code=c")
        check("callback_env_popped_not_merely_read", CALLBACK_URL_ENV not in os.environ)
    with _env_scope({PASSWORD_ENV: "pw-1"}):
        check("password_env_read", _password_from_env() == "pw-1")
        check("password_env_popped_not_merely_read", PASSWORD_ENV not in os.environ)

    # SET-but-EMPTY is the shell variable that expanded to nothing: fail closed in
    # BOTH cookie modes, or the replay probe passes vacuously.
    with _env_scope({COOKIE_VALUE_ENV: ""}):
        check(
            "cookie_env_empty_required_fails_closed",
            _raises(lambda: _cookie_value_from_env(required=True)),
        )
    with _env_scope({COOKIE_VALUE_ENV: ""}):
        check(
            "cookie_env_empty_optional_fails_closed",
            _raises(lambda: _cookie_value_from_env(required=False)),
        )
    with _env_scope({CALLBACK_URL_ENV: ""}):
        check("callback_env_empty_fails_closed", _raises(_callback_url_from_env))
    with _env_scope({PASSWORD_ENV: ""}):
        check("password_env_empty_fails_closed", _raises(_password_from_env))
    # ... and a fail-closed read still POPS, so nothing lingers into a child.
    with _env_scope({COOKIE_VALUE_ENV: ""}):
        with contextlib.suppress(DriverFailure):
            _cookie_value_from_env(required=True)
        check("cookie_env_empty_still_popped", COOKIE_VALUE_ENV not in os.environ)

    with _env_scope({COOKIE_VALUE_ENV: None, CALLBACK_URL_ENV: None, PASSWORD_ENV: None}):
        check(
            "cookie_env_unset_required_fails_closed",
            _raises(lambda: _cookie_value_from_env(required=True)),
        )
        # UNSET is the legal cookieless shape (replay-callback only) — never an empty
        # cookie, always an absent one.
        check("cookie_env_unset_optional_is_none", _cookie_value_from_env(required=False) is None)
        check("callback_env_unset_fails_closed", _raises(_callback_url_from_env))
        check("password_env_unset_fails_closed", _raises(_password_from_env))
        # the guard is QUIET on a clean environment — it must not break every
        # subcommand that carries no credential at all.
        check("credential_env_guard_passes_when_clean", not _raises(_assert_credential_env_cleared))

    # THE GUARD (F1). A credential still sitting in the environment must be REFUSED,
    # loudly, before any child process exists to inherit it.
    for _cred_env in CREDENTIAL_ENV_VARS:
        with _env_scope({_cred_env: "leaked"}):
            check(
                f"credential_env_guard_refuses:{_cred_env}",
                _raises(_assert_credential_env_cleared),
            )

    # ORDER IS THE CONTRACT. The guard must run BEFORE the Node driver
    # (`with sync_playwright()`) and BEFORE the browser (`pw.chromium.launch(`) exist:
    # a guard placed after either would be inspecting an environment the children had
    # already inherited, and would prove nothing.
    _browser_src = inspect.getsource(_run_in_browser)
    _guard_at = _browser_src.find("_assert_credential_env_cleared()")
    _node_at = _browser_src.find("with sync_playwright()")
    _launch_at = _browser_src.find("pw.chromium.launch(")
    check(
        "credential_env_guard_runs_before_any_child_launch",
        0 <= _guard_at < _node_at and _guard_at < _launch_at,
        detail=f"guard@{_guard_at} node@{_node_at} chromium@{_launch_at}",
    )

    # --- URL redaction on the diagnostic (stderr -> proof-log) channel ------------
    # The runner interpolates the driver's stderr into a bar_fail message. A failing
    # login very often leaves the page on …/auth/callback?code=<one-time authz code>.
    _cb_url = "https://bff.example/auth/callback?code=SECRET-AUTHZ-CODE&state=SECRET-STATE&x=1"
    _red = _redact_url(_cb_url) or ""
    check("redact_url_drops_the_authz_code", "SECRET-AUTHZ-CODE" not in _red, detail=_red)
    check("redact_url_drops_the_state", "SECRET-STATE" not in _red, detail=_red)
    check("redact_url_keeps_the_path", "/auth/callback" in _red, detail=_red)
    check("redact_url_keeps_benign_params", "x=1" in _red, detail=_red)
    check("redact_url_passthrough_when_clean", _redact_url("https://x/y") == "https://x/y")
    check("redact_url_handles_none", _redact_url(None) is None)
    # _fail is the SINGLE funnel every diagnostic passes through, so no present or
    # future `url=page.url` call site can reintroduce the leak.
    _leaky = _fail("boom", url=_cb_url)
    check(
        "fail_redacts_the_url_diagnostic",
        "SECRET-AUTHZ-CODE" not in str(_leaky.diagnostics.get("url")),
        detail=str(_leaky.diagnostics.get("url")),
    )

    # pure-helper behaviour.
    check("parse_fields", _parse_fields(["k=v", "a=b=c"]) == {"k": "v", "a": "b=c"})
    check("parse_fields_bad", _raises(lambda: _parse_fields(["novalue"])))
    check("seq_from_href", _seq_from_chain_href("/evidence/abc/turns/7") == 7)
    check("seq_from_href_none", _seq_from_chain_href("/evidence/abc") is None)
    check(
        "cid_from_action",
        _conversation_id_from_action("/conversations/conv-1/turns") == "conv-1",
    )
    check(
        "reason_plaintext",
        _extract_reason(403, "text/plain", "AgentOS error: scope_not_held") == "scope_not_held",
    )
    check(
        "reason_json",
        _extract_reason(403, "application/json", '{"detail":{"reason":"csrf_invalid"}}')
        == "csrf_invalid",
    )
    check(
        "reason_html_refusal",
        _extract_reason(
            403, "text/html", '<div class="refusal"><strong>x</strong> <code>denied</code></div>'
        )
        == "denied",
    )
    check("reason_absent", _extract_reason(200, "text/html", "<p>ok</p>") is None)
    check("xpath_literal_plain", _xpath_literal("State") == "'State'")
    check(
        "xpath_literal_apos", "concat(" in _xpath_literal("a'b'c") or '"' in _xpath_literal("a'b")
    )
    check(
        "cookie_project",
        _cookie_to_dict({"name": "n", "value": "v", "secure": True, "httpOnly": True})["httpOnly"]
        is True,
    )
    check("split_pem_two", len(_split_pem_certs(_TWO_CERT_PEM)) == 2)
    check("xss_surfaces_both", _xss_surfaces("both", "c") == ["/?conversation_id=c", "/evidence/c"])
    check("xss_surfaces_chat", _xss_surfaces("chat", "c") == ["/?conversation_id=c"])

    # --- the injected session cookie (replay-cookie AND the S5 replay-callback) ---
    cookie = _session_cookie("https://bff.example", "sess-1")
    check("session_cookie_name", cookie["name"] == COOKIE_NAME)
    check("session_cookie_value", cookie["value"] == "sess-1")
    check(
        "session_cookie_host_shape",
        cookie["url"] == "https://bff.example"
        and "path" not in cookie  # `url` and `path` are mutually exclusive in Playwright
        and cookie["secure"] is True
        and cookie["httpOnly"] is True
        and cookie["sameSite"] == "Lax",
        detail=str(cookie),
    )
    # FAIL CLOSED: an empty --cookie-value would inject a valueless cookie and make
    # the replay probes ("the stale cookie is dead", "the replayed callback did not
    # authenticate") pass VACUOUSLY.
    check("session_cookie_empty_fails_closed", _raises(lambda: _session_cookie("https://x", "")))
    check(
        "replay_callback_reports_cookie_injected",
        "cookie_injected" in SUBCOMMAND_CONTRACT["replay-callback"],
    )

    # --- the rendered evidence contract (Bar C refusal render + Bar E text digests) -
    turn = _transcript_turn_record(
        sequence=2, agent_run_id="run-9", question_text="  q\nline  ", answer_text="a\n"
    )
    check("transcript_turn_keys", set(turn) == set(EVIDENCE_TURN_KEYS), detail=str(sorted(turn)))
    # the hashed fields are VERBATIM — a strip() here would silently change a sha256.
    check("transcript_turn_text_verbatim", turn["question_text"] == "  q\nline  ")
    check("transcript_turn_answer_verbatim", turn["answer_text"] == "a\n")
    check("transcript_turn_sequence_int", turn["sequence"] == 2 and turn["seq"] == 2)
    check(
        "transcript_turn_legacy_aliases",
        turn["user_message"] == turn["question_text"] and turn["answer"] == turn["answer_text"],
    )
    check(
        "evidence_contract_reports_truncation",
        "transcript_next_page_available" in SUBCOMMAND_CONTRACT["evidence"],
    )
    check("chain_contract_keys", "dispatch_columns" in EVIDENCE_CHAIN_KEYS)
    check("chain_heading_seq", _seq_from_chain_heading("Turn chain — seq 3") == 3)
    check("chain_heading_seq_absent", _seq_from_chain_heading("Turn chain") is None)

    # The dispatch table is parsed by its RENDERED headers. `.queue th` is CSS-
    # uppercased (app.css:503), so the mapping must be case-insensitive.
    rendered_today = [_dispatch_key(h) for h in DISPATCH_HEADERS_RENDERED_TODAY]
    check(
        "dispatch_headers_today",
        rendered_today
        == [
            "step_index",
            "capability_kind",
            "capability_ref",
            "scope_id",
            "outcome",
            "refusal_reason",
        ],
        detail=str(rendered_today),
    )
    check("dispatch_key_case_insensitive", _dispatch_key("OUTCOME") == "outcome")
    check("dispatch_key_refusal", _dispatch_key("refusal") == "refusal_reason")
    check("dispatch_key_scope_ready", _dispatch_key("scope") == "scope_id")
    check("dispatch_key_scope_id_ready", _dispatch_key("scope_id") == "scope_id")
    # an unmapped column is snake_cased and EMITTED, never dropped.
    check("dispatch_key_unmapped_kept", _dispatch_key("args sha256") == "args_sha256")
    # The round-2 review found the evidence screen was DROPPING the scope column, so
    # two dispatches of the same tool (retail-ok + financials-refused) rendered as
    # indistinguishable rows. The harness template now renders it, and Bar C depends
    # on it: this pins that the driver surfaces it. (The driver still reads the LIVE
    # <thead>, so removing the column again makes scope_id VANISH from the rows —
    # never fabricated as null — and this check fails loudly.)
    check("dispatch_scope_id_is_rendered", "scope_id" in rendered_today)

    # ---------------------------------------------------------------------- #
    # F1 (round 5) — a BFF REFUSAL and a BROKEN HARNESS are distinct events.  #
    #                                                                         #
    # S7 claims "the BFF refused a fresh login while its session store was    #
    # destroyed". If any driver failure could satisfy that, a Chromium crash  #
    # would MANUFACTURE the evidence. So: the refusal carries the BFF's own   #
    # observed HTTP status, and it is raised through a DEDICATED exception —  #
    # never through the generic DriverFailure path, which is what a harness   #
    # error uses.                                                             #
    # ---------------------------------------------------------------------- #
    refusal = ObservedRefusal(http_status=503, stage="login_navigation")
    check("refusal_carries_the_discriminator", refusal.result["outcome"] == "refused")
    check("refusal_carries_the_observed_status", refusal.result["http_status"] == 503)
    check("refusal_is_not_ok", refusal.result["ok"] is False)
    # DISJOINT from the harness-failure class: a caller must never be able to catch one
    # and get the other, and `main` maps them to DIFFERENT exit codes.
    check("refusal_is_not_a_driver_failure", not issubclass(ObservedRefusal, DriverFailure))
    check("refusal_exit_is_non_zero", LOGIN_REFUSED_EXIT != 0)
    check("refusal_exit_is_distinct", LOGIN_REFUSED_EXIT not in (0, 3, 4))
    # The `login` contract carries the discriminator, and the success path SETS it —
    # re-derived from the handler's own source so a future edit that drops it fails here.
    login_src = inspect.getsource(cmd_login)
    check("login_contract_has_outcome", "outcome" in SUBCOMMAND_CONTRACT["login"])
    check(
        "login_success_sets_authenticated",
        '"outcome": LOGIN_OUTCOME_AUTHENTICATED' in login_src,
    )
    check("login_observes_the_navigation_status", "login_response.status" in login_src)
    check("login_raises_observed_refusal", "raise ObservedRefusal(" in login_src)
    # `main` must write the observation to --out BEFORE returning — the capturing wrapper
    # reads it there, and an unwritten refusal is indistinguishable from a crash.
    main_src = inspect.getsource(main)
    emit = main_src.find("_emit(exc.result")
    refusal_return = main_src.find("return LOGIN_REFUSED_EXIT")
    check("main_emits_the_refusal_to_out", emit >= 0)
    check("main_emits_before_it_exits", 0 <= emit < refusal_return)

    # SPKI computation against a generated self-signed cert (if crypto available).
    spki = _selftest_spki()
    check("spki_computed", spki[0], detail=spki[1])

    # FAIL-CLOSED contract: an empty pin set (nonexistent/empty --ca, no --leaf)
    # must RAISE — never silently degrade to a blanket TLS bypass.
    spki_closed = _selftest_collect_spki_fail_closed()
    check("collect_spki_fail_closed", spki_closed[0], detail=spki_closed[1])

    passed = sum(1 for _, ok, _ in checks if ok)
    failed = [(n, d) for n, ok, d in checks if not ok]
    report = {
        "selftest": "ok" if not failed else "fail",
        "passed": passed,
        "total": len(checks),
        "failures": [{"check": n, "detail": d} for n, d in failed],
        "subcommand_contract": SUBCOMMAND_CONTRACT,
    }
    print(json.dumps(report, indent=2))
    return 0 if not failed else 1


def _try_parse(parser: argparse.ArgumentParser, argv: list[str]) -> bool:
    import io

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(argv)
        return True
    except SystemExit:
        return False


def _raises(fn: Any) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


@contextlib.contextmanager
def _env_scope(values: dict[str, str | None]) -> Iterator[None]:
    """Temporarily set (or, on ``None``, UNSET) environment variables; always restore.

    Selftest-only: it exercises the credential env channel (set / set-but-empty /
    unset) without leaving anything behind in the process environment."""
    saved = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _selftest_spki() -> tuple[bool, str]:
    """Generate a throwaway self-signed cert and verify SPKI pin computation.

    Skips (returns ok) when neither cryptography nor openssl is present."""
    import tempfile

    try:
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                os.devnull if os.name != "nt" else "NUL",
                "-subj",
                "/CN=selftest",
                "-days",
                "1",
            ],
            capture_output=True,
        )
    except OSError:
        return True, "openssl absent — spki path exercised only at live-run"
    if result.returncode != 0:
        return True, "openssl req failed — skipped"
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as handle:
        handle.write(result.stdout)
        ca_path = handle.name
    try:
        pins = _spki_pins_from_ca_bundle(ca_path)
        if not pins:
            return True, "no crypto backend — spki pins empty; the driver FAILS CLOSED (no bypass)"
        canonical = _spki_pin_via_openssl(result.stdout.decode())
        if canonical is not None and pins[0] != canonical:
            return False, f"spki mismatch: {pins[0]} != {canonical}"
        return True, pins[0]
    finally:
        os.unlink(ca_path)


def _selftest_collect_spki_fail_closed() -> tuple[bool, str]:
    """``_collect_spki_pins`` must FAIL CLOSED (raise ``DriverFailure``) when it
    can compute no pins — it must never silently degrade to a blanket TLS bypass.
    Browser-free: only touches the filesystem for a throwaway empty CA file."""
    import tempfile

    # (a) a nonexistent --ca with no --leaf must raise.
    if not _raises(lambda: _collect_spki_pins("/nonexistent/proof-ca.pem", [])):
        return False, "nonexistent --ca did not raise"
    # (b) a present-but-empty --ca (zero certs) with no --leaf must raise the
    # dedicated ``spki_pins_unavailable`` reason (not a crash, not a silent []).
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write("")  # zero certificates
        empty_ca = handle.name
    try:
        try:
            _collect_spki_pins(empty_ca, [])
        except DriverFailure as exc:
            if exc.message != "spki_pins_unavailable":
                return False, f"empty --ca raised {exc.message!r}, want spki_pins_unavailable"
            return True, "raises on nonexistent + empty --ca"
        return False, "present-but-empty --ca did not raise"
    finally:
        os.unlink(empty_ca)


_TWO_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
)


# --------------------------------------------------------------------------- #
# Argument parsing + dispatch.                                                 #
# --------------------------------------------------------------------------- #

HANDLERS: dict[str, Any] = {
    "login": cmd_login,
    "cookie-dump": cmd_cookie_dump,
    "replay-cookie": cmd_replay_cookie,
    "replay-callback": cmd_replay_callback,
    "chat-turn": cmd_chat_turn,
    "approvals-list": cmd_approvals_list,
    "approvals-paginate": cmd_approvals_paginate,
    "approvals-act": cmd_approvals_act,
    "evidence": cmd_evidence,
    "manipulated-post": cmd_manipulated_post,
    "csrf-probe": cmd_csrf_probe,
    "xss-probe": cmd_xss_probe,
    "logout": cmd_logout,
}


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--base-url", required=True, help="the BFF origin, e.g. https://127.0.0.1:8444"
    )
    parser.add_argument("--ca", required=True, help="path to the per-run proof CA PEM bundle")
    parser.add_argument(
        "--state-file",
        default=None,
        help="Playwright storage_state JSON — persists a session across invocations",
    )
    parser.add_argument("--out", default=None, help="also write the JSON result to this path")
    parser.add_argument(
        "--leaf",
        action="append",
        default=None,
        help=(
            "path to an on-disk leaf cert PEM whose SPKI to pin (repeatable; one per TLS "
            "surface — agentos.crt / keycloak.crt / harness.crt, all signed by --ca)"
        ),
    )
    parser.add_argument("--no-sandbox", action="store_true", help="pass Chromium --no-sandbox")
    parser.add_argument("--headed", action="store_true", help="run the browser headed (debug)")
    parser.add_argument(
        "--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS, help="default Playwright timeout (ms)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driver.py",
        description="Playwright browser driver for the Cognic AgentOS M8.5-C live proof.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="drive a real OIDC browser login")
    p.add_argument("--username", required=True, help="Keycloak username (password from env)")
    _add_global_flags(p)

    p = sub.add_parser("cookie-dump", help="emit every cookie with flags (S8)")
    _add_global_flags(p)

    # NOTE (secret custody): `replay-cookie` and `replay-callback` take NO
    # value-bearing flags. The cookie value and the callback URL are BEARER
    # CREDENTIALS (the cookie IS the session; the callback URL carries a one-time
    # authorization code exchangeable for tokens), so they ride the child's
    # ENVIRONMENT — COGNIC_PROOF_COOKIE_VALUE / COGNIC_PROOF_CALLBACK_URL — exactly
    # as the password does. The `--cookie-value` / `--callback-url` flags are
    # DELETED, not merely optional: a flag that still accepts a credential invites a
    # call site that passes one, and argv is world-readable via `ps`.
    p = sub.add_parser(
        "replay-cookie",
        help="inject a cookie value (from COGNIC_PROOF_COOKIE_VALUE) into a fresh context (S1/S3)",
    )
    _add_global_flags(p)

    p = sub.add_parser(
        "replay-callback",
        help=(
            "replay a captured OIDC callback URL (from COGNIC_PROOF_CALLBACK_URL) in a fresh "
            "context, optionally with the pre-auth cookie (COGNIC_PROOF_COOKIE_VALUE) (S5)"
        ),
    )
    _add_global_flags(p)

    p = sub.add_parser("chat-turn", help="submit a chat turn and read the rendered answer")
    p.add_argument("--message", required=True, help="the user message")
    p.add_argument("--conversation-id", default=None, help="target an existing conversation")
    p.add_argument(
        "--agent-id", default="bank-analyst", help="agent id if a conversation must be created"
    )
    p.add_argument("--create", action="store_true", help="force-create a new conversation first")
    _add_global_flags(p)

    p = sub.add_parser("approvals-list", help="render + parse the approvals inbox")
    _add_global_flags(p)

    p = sub.add_parser("approvals-paginate", help="walk the queue's pagination to the end")
    _add_global_flags(p)

    p = sub.add_parser("approvals-act", help="click grant/grant-second/deny")
    p.add_argument("--request-id", required=True)
    p.add_argument("--action", required=True, choices=["grant", "grant-second", "deny"])
    p.add_argument("--reason", default=None)
    _add_global_flags(p)

    p = sub.add_parser("evidence", help="render transcript + per-turn chain")
    p.add_argument("--conversation-id", required=True)
    p.add_argument("--seq", required=True, type=int)
    _add_global_flags(p)

    p = sub.add_parser(
        "manipulated-post", help="valid session + valid CSRF, bypassing the UI control"
    )
    p.add_argument("--path", required=True, help="the BFF path to POST to")
    p.add_argument("--field", action="append", default=None, help="k=v form field (repeatable)")
    _add_global_flags(p)

    p = sub.add_parser("csrf-probe", help="the same POST with a missing/garbage CSRF token")
    p.add_argument("--path", required=True)
    p.add_argument("--field", action="append", default=None, help="k=v form field (repeatable)")
    p.add_argument("--csrf-mode", choices=["garbage", "missing"], default="garbage")
    _add_global_flags(p)

    p = sub.add_parser("xss-probe", help="assert hostile output renders inert")
    p.add_argument("--conversation-id", required=True)
    p.add_argument("--surface", choices=["chat", "evidence", "both"], default="both")
    _add_global_flags(p)

    p = sub.add_parser("logout", help="click the real logout control")
    _add_global_flags(p)

    sub.add_parser("selftest", help="validate the CLI surface + JSON shapes without a browser")
    return parser


def _emit(result: dict[str, Any], out_path: str | None) -> None:
    text = json.dumps(result)
    print(text)
    if out_path:
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "selftest":
        return _selftest()
    handler = HANDLERS[args.command]
    try:
        result = handler(args)
    except ObservedRefusal as exc:
        # THE BFF REFUSED, and the driver OBSERVED it (F1). Write the observation to
        # --out FIRST — the runner's capturing wrapper reads it there and is what makes
        # the refusal assertable — then exit NON-ZERO, so every caller that requires a
        # successful login (drive_login, and its `|| bar_fail`) still fails loud. The
        # observation also goes to stderr so a plain `drive_login` failure names the
        # status it was refused with.
        _emit(exc.result, getattr(args, "out", None))
        print(json.dumps(exc.result, indent=2), file=sys.stderr)
        return LOGIN_REFUSED_EXIT
    except DriverFailure as exc:
        diagnostic = {"error": exc.message, **exc.diagnostics}
        print(json.dumps(diagnostic, indent=2), file=sys.stderr)
        return 3
    except Exception as exc:
        print(
            json.dumps({"error": "unexpected_driver_exception", "detail": repr(exc)}, indent=2),
            file=sys.stderr,
        )
        return 4
    _emit(result, getattr(args, "out", None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
