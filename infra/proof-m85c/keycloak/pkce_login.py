#!/usr/bin/env python3
"""Proof-driver token acquisition — Authorization Code + PKCE (S256), scripted.

PROOF-ONLY (spec §5.1, "Proof driver token acquisition"). The runner's
direct-to-AgentOS and direct-MCP calls happen OUTSIDE the BFF, so they need
their own tokens. They are obtained by driving the **real interactive flow**
against the **same ``cognic-harness`` client** through a proof-only loopback
redirect URI:

  * ``azp`` stays ``cognic-harness`` — the kernel never sees a token minted by
    some other client, so the binder's authorized-party check is exercised
    exactly as it is for a browser login.
  * The LOCKED GRANT PROFILE is preserved. This is NOT a Direct Access Grant
    (resource-owner password) and NOT client credentials — both are DISABLED on
    the client and Bar B proves the attempts fail. What happens here is the
    ordinary Authorization Code flow with the login form submitted
    programmatically instead of by a human hand: same endpoints, same PKCE, same
    code exchange, same token.
  * There is no hidden BFF token endpoint, no Redis scraping, and no token ever
    reaches browser JavaScript.

Custody: the client secret and the user password are read from the ENVIRONMENT
(never argv — a ``ps`` snapshot would expose an argv secret for the process
lifetime). The minted tokens are printed to stdout as JSON for the caller to
capture into the private per-run directory, which the cleanup trap removes.

TLS: every leg dials Keycloak over HTTPS and verifies against the per-run proof
CA. ``verify=False`` appears nowhere; an unverifiable Keycloak is a hard failure,
never a downgrade.

Usage:
    KC_CLIENT_SECRET=... KC_USER_PASSWORD=... \\
    pkce_login.py <issuer> <client-id> <redirect-uri> <username> <ca-pem>

Prints: {"access_token": "...", "id_token": "...", "refresh_token": "..."}
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

#: Keycloak renders the login form with this id; we post to ITS action URL.
_LOGIN_FORM_ACTION = re.compile(
    r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', re.IGNORECASE | re.DOTALL
)
#: Fallback for theme variants that order the attributes differently.
_ANY_FORM_ACTION = re.compile(r'<form[^>]*action="([^"]+)"[^>]*>', re.IGNORECASE)


class LoginFailed(RuntimeError):
    """The scripted Authorization Code flow did not yield a code. Fail loud —
    never fall back to a disabled grant."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop at the 302 so we can read the ``code`` off the Location header
    instead of letting urllib chase the (unroutable) loopback redirect URI."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _opener(ca_pem: str) -> urllib.request.OpenerDirector:
    # Real TLS against the per-run proof CA. Hostname checking ON; no verify=False.
    ctx = ssl.create_default_context(cafile=ca_pem)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        _NoRedirect(),
    )


def _get(opener: urllib.request.OpenerDirector, url: str) -> tuple[int, str, dict[str, str]]:
    try:
        with opener.open(url, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:  # 3xx surfaces here because of _NoRedirect
        return exc.code, exc.read().decode("utf-8", "replace"), dict(exc.headers)


def _post(
    opener: urllib.request.OpenerDirector, url: str, form: dict[str, str]
) -> tuple[int, str, dict[str, str]]:
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with opener.open(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), dict(exc.headers)


def login(
    *,
    issuer: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    username: str,
    password: str,
    ca_pem: str,
    scope: str = "openid",
) -> dict[str, Any]:
    opener = _opener(ca_pem)
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)

    # 1. the authorization request (the real /auth endpoint, PKCE S256). `scope`
    # defaults to "openid"; the proof passes "openid wrong-audience" to mint an
    # OTHERWISE-PERFECT token (correct azp/typ/signature/exp) whose only defect is
    # a second audience, so the reference binder's EXACT-audience gate is the thing
    # under test (Bar B audience_not_exact).
    auth_url = f"{issuer}/protocol/openid-connect/auth?" + urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    status, page, _ = _get(opener, auth_url)
    if status != 200:
        raise LoginFailed(
            f"authorization endpoint returned HTTP {status} (expected the login page)"
        )

    # 2. the login form's action URL (carries session_code / execution / tab_id).
    match = _LOGIN_FORM_ACTION.search(page) or _ANY_FORM_ACTION.search(page)
    if match is None:
        raise LoginFailed(
            "no login form in the authorization response — the realm may not be imported, "
            "or Keycloak rendered an error page instead of the login page"
        )
    action = html.unescape(match.group(1))

    # 3. submit the credentials to the REAL login form (interactive flow).
    status, body, headers = _post(opener, action, {"username": username, "password": password})
    if status not in (302, 303):
        # A 200 here means Keycloak re-rendered the login page => bad credentials
        # or an account condition. Surface the page's error text, never the password.
        hint = (
            "invalid credentials or an account condition" if status == 200 else "unexpected status"
        )
        raise LoginFailed(f"login form POST returned HTTP {status} ({hint}) for user {username!r}")
    location = headers.get("Location") or headers.get("location") or ""
    if not location.startswith(redirect_uri):
        raise LoginFailed(
            f"login redirect did not target the registered redirect_uri for {username!r}"
        )

    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    if query.get("state", [None])[0] != state:
        raise LoginFailed("authorization response state mismatch (CSRF guard)")
    code = query.get("code", [None])[0]
    if not code:
        error = query.get("error", ["<none>"])[0]
        raise LoginFailed(f"no authorization code in the redirect (error={error})")

    # 4. exchange the code (PKCE verifier + confidential-client secret).
    status, body, _ = _post(
        opener,
        f"{issuer}/protocol/openid-connect/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": verifier,
        },
    )
    if status != 200:
        raise LoginFailed(f"token endpoint returned HTTP {status} on the code exchange")
    tokens = json.loads(body)
    for required in ("access_token", "id_token"):
        if not isinstance(tokens.get(required), str) or not tokens[required]:
            raise LoginFailed(f"token response carried no {required}")
    return tokens


def main(argv: list[str]) -> int:
    if len(argv) not in (6, 7):
        print(
            "usage: pkce_login.py <issuer> <client-id> <redirect-uri> <username> <ca-pem> [scope]\n"
            "       (KC_CLIENT_SECRET + KC_USER_PASSWORD come from the environment, never argv)\n"
            "       [scope] defaults to 'openid'; pass 'openid wrong-audience' for the Bar B "
            "exact-audience test",
            file=sys.stderr,
        )
        return 2
    issuer, client_id, redirect_uri, username, ca_pem = argv[1:6]
    scope = argv[6] if len(argv) == 7 else "openid"
    client_secret = os.environ.get("KC_CLIENT_SECRET", "")
    password = os.environ.get("KC_USER_PASSWORD", "")
    if not client_secret or not password:
        print(
            "FAIL: KC_CLIENT_SECRET and KC_USER_PASSWORD must be set in the environment",
            file=sys.stderr,
        )
        return 2
    try:
        tokens = login(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            username=username,
            password=password,
            ca_pem=ca_pem,
            scope=scope,
        )
    except (LoginFailed, urllib.error.URLError, ssl.SSLError) as exc:
        print(f"FAIL: PKCE login for {username!r}: {exc}", file=sys.stderr)
        return 1
    json.dump(
        {
            "access_token": tokens["access_token"],
            "id_token": tokens["id_token"],
            "refresh_token": tokens.get("refresh_token", ""),
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
