# PR-2b-0 — `token_endpoint` issuer-origin binding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bind the OAuth `token_endpoint` to its AS issuer's origin so a compromised-but-allow-listed AS cannot redirect the operator's `client_secret` to an attacker-chosen **public** host (threat-model AS-3b). This is the first, tight slice of PR-2b — `token_endpoint` only; **no** override store, **no** internal-host allow-list, **no** Proof 1b-2.

**Architecture:** A pure module-level `_canonical_origin` helper + a sync `_refuse_token_endpoint_origin_mismatch` check in `MCPAuthzClient._request_token`, placed **after** the PR-2a SSRF guard and **before** any credential material is assembled (preserving the PR-2a pre-credential invariant). Plus `follow_redirects=False` on the token POST (a redirect could bypass the origin check). Reuses `mcp_oauth_as_discovery_invalid` + a `validation_failure` payload field — **Option C: no new public refusal enum, no `plugin_registry` ripple.**

**Tech Stack:** Python, `src/cognic_agentos/protocol/mcp_authz.py` (CC 95/90), pytest + respx, `urllib.parse.urlparse`, `ipaddress`, httpx.

## Global Constraints

- **Single CC module:** `src/cognic_agentos/protocol/mcp_authz.py` ONLY. Do **not** touch `protocol/plugin_registry.py`, `protocol/discovery_status.py`, or add any override/allow-list code (those are PR-2b proper). It is on the durable critical-controls gate (95% line / 90% branch) — core-controls discipline, negative-path tests required, **halt-before-commit on every commit**.
- **Reuse the existing refusal reason:** `mcp_oauth_as_discovery_invalid` + `validation_failure="token_endpoint_issuer_origin_mismatch"` in the payload. Do **not** add a new `AuthzReason` value. An origin mismatch already maps to `discovery_status=refused` (`discovery_status_for_authz_reason` defaults every non-network reason to `refused` — no change needed).
- **Preserve the PR-2a pre-credential invariant:** the origin check runs BEFORE `body` / `headers` / `encoded_id` / `encoded_secret` / `basic_credentials` are assembled. No credential body/header is built or sent on a mismatch.
- **No raw-secret / raw-URL leak:** the refusal payload carries `as_issuer` (the trusted, allow-listed issuer) + the `validation_failure` tag. It does NOT echo the raw `token_endpoint` or the secret.
- **TDD:** failing test first → watch it fail → minimal implementation → watch it pass. Negative-path coverage is mandatory for the CC gate.
- The committed threat-model spec is `docs/superpowers/specs/2026-06-25-pr2b-mcp-internal-host-override-allowlist-design.md` (§7a(ii) + the canonicalization rules are the source of truth for this slice).

## File Structure

- **Modify:** `src/cognic_agentos/protocol/mcp_authz.py` — add `_canonical_origin` (module fn) + `_refuse_token_endpoint_origin_mismatch` (method) + the call site at the Leg-5 guard + `follow_redirects=False` on the token POST.
- **Modify (tests):** `tests/unit/protocol/test_mcp_authz.py` — helper unit tests + the AS-3b / happy-path / redirect / drift-pin tests (mirror `TestOAuthLegSsrfGuard` + `test_leg5_guard_precedes_all_credential_construction`).
- **Modify:** `docs/adrs/ADR-002-mcp-plugin-protocol.md` — a dated amendment recording the PR-2b-0 binding.

`ipaddress` and `urlparse` are already imported in `mcp_authz.py` (used by `_refuse_non_public_discovery_url`).

---

### Task 1: `_canonical_origin` pure helper

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` (a module-level function, place it just above `MCPAuthzClient` or next to the other module helpers).
- Test: `tests/unit/protocol/test_mcp_authz.py`

**Interfaces:**
- Produces: `def _canonical_origin(url: str) -> tuple[str, str, int] | None` — the canonical `(scheme, host, port)` origin of an http(s) URL, or `None` if not http(s) / no host / malformed host or port. Consumed by Task 2's `_refuse_token_endpoint_origin_mismatch`.

- [ ] **Step 1: Write the failing tests**

```python
# in tests/unit/protocol/test_mcp_authz.py — import _canonical_origin from mcp_authz
from cognic_agentos.protocol.mcp_authz import _canonical_origin


class TestCanonicalOrigin:
    def test_default_port_https_equivalence(self) -> None:
        assert _canonical_origin("https://issuer.example") == _canonical_origin(
            "https://issuer.example:443"
        )

    def test_default_port_http_equivalence(self) -> None:
        assert _canonical_origin("http://issuer.example") == _canonical_origin(
            "http://issuer.example:80"
        )

    def test_host_case_insensitive(self) -> None:
        assert _canonical_origin("https://Issuer.EXAMPLE/token") == _canonical_origin(
            "https://issuer.example/path"
        )

    def test_trailing_dot_stripped(self) -> None:
        assert _canonical_origin("https://issuer.example./token") == _canonical_origin(
            "https://issuer.example/token"
        )

    def test_path_query_userinfo_ignored(self) -> None:
        assert _canonical_origin("https://issuer.example/a?b=c") == _canonical_origin(
            "https://issuer.example/d"
        )

    def test_distinct_origins_differ(self) -> None:
        assert _canonical_origin("https://issuer.example") != _canonical_origin(
            "https://evil.example"
        )
        assert _canonical_origin("https://issuer.example") != _canonical_origin(
            "http://issuer.example"
        )  # scheme matters
        assert _canonical_origin("https://issuer.example:8443") != _canonical_origin(
            "https://issuer.example"
        )  # explicit non-default port matters

    def test_ip_literal_canonicalized(self) -> None:
        assert _canonical_origin("https://93.184.216.34/token") == ("https", "93.184.216.34", 443)

    def test_non_http_scheme_is_none(self) -> None:
        assert _canonical_origin("ftp://issuer.example") is None
        assert _canonical_origin("file:///etc/passwd") is None

    def test_no_host_is_none(self) -> None:
        assert _canonical_origin("https:///token") is None
        assert _canonical_origin("not-a-url") is None

    def test_malformed_port_is_none(self) -> None:
        assert _canonical_origin("https://issuer.example:99999/token") is None

    def test_userinfo_rejected(self) -> None:
        # Credential-destination control: a userinfo URL parses to the host AFTER the
        # `@` (the attacker host), which reads as the issuer in logs. Reject outright.
        assert _canonical_origin("https://issuer.example@evil.example/token") is None
        assert _canonical_origin("https://user:pass@evil.example/token") is None

    def test_empty_host_after_trailing_dot_rejected(self) -> None:
        assert _canonical_origin("https://./token") is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestCanonicalOrigin -v`
Expected: FAIL — `ImportError` / `_canonical_origin` is not defined.

- [ ] **Step 3: Implement the helper**

```python
def _canonical_origin(url: str) -> tuple[str, str, int] | None:
    """Canonical ``(scheme, host, port)`` origin of an http(s) URL, or ``None`` if
    the URL is not http(s) / has no host / has a malformed host or port.

    Normalization is identical on both sides of an origin comparison:
    - scheme lowercased (``urlparse`` already lowercases it);
    - host lowercased (``urlparse.hostname`` already lowercases) + trailing dot
      stripped; IP literals normalized to their canonical string; DNS names
      IDNA/punycode-normalized to their A-label (so different encodings of the
      same IDN host compare equal, and a malformed IDN fails closed);
    - port default-normalized (``https``->443, ``http``->80), so
      ``https://h`` == ``https://h:443``;
    - origin is scheme + host + port ONLY (path / query ignored); a URL carrying
      **userinfo** (``user@`` / ``user:pass@``) is REJECTED outright — for a
      credential destination, ``https://issuer.example@evil.example`` (host
      ``evil.example``) must never read as the issuer in logs/reviews.
    """
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = parsed.hostname  # urlparse lowercases the host
    if not host:
        return None
    host = host.rstrip(".")
    if not host:
        return None
    try:
        # IP literals (v4/v6) are not IDN — normalize to the canonical IP string.
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    try:
        port = parsed.port
    except ValueError:
        # Out-of-range port (urlparse raises lazily on .port access).
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestCanonicalOrigin -v`
Expected: PASS (10/10).

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/protocol/mcp_authz.py tests/unit/protocol/test_mcp_authz.py
git commit  # message per the halt-before-commit summary; trailer required
```

---

### Task 2: The issuer-origin-binding check + wiring in `_request_token`

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` — add the `_refuse_token_endpoint_origin_mismatch` method + call it at the Leg-5 guard site (~`:1394`–`1395`).
- Test: `tests/unit/protocol/test_mcp_authz.py`

**Interfaces:**
- Consumes: `_canonical_origin` (Task 1); `as_issuer` (already a `_request_token` parameter, == `candidate_as[0]`).
- Produces: `def _refuse_token_endpoint_origin_mismatch(self, token_endpoint: str, *, as_issuer: str) -> None` — raises `MCPAuthzError("mcp_oauth_as_discovery_invalid", …, as_issuer=…, validation_failure="token_endpoint_issuer_origin_mismatch")` on mismatch / unparseable origin; returns `None` on match. Sync (no I/O).

- [ ] **Step 1: Write the failing tests** (mirror `TestOAuthLegSsrfGuard.test_leg5_credential_exfil_blocked_both_auth_methods`; here both hosts resolve PUBLIC so the SSRF guard passes and the origin check is the gate)

```python
class TestTokenEndpointIssuerOriginBinding:
    @respx.mock
    @pytest.mark.parametrize("auth_method", ["client_secret_post", "client_secret_basic"])
    async def test_public_non_issuer_token_endpoint_refused_no_secret_sent(
        self,
        authz_strict: MCPAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        auth_method: str,
    ) -> None:
        """AS-3b: a public, allow-listed AS returns a token_endpoint at a different
        PUBLIC origin. The SSRF guard passes (public host); the issuer-origin binding
        refuses BEFORE any credential material is built — no POST, no secret sent."""
        as_issuer = "https://as.public.example"  # public, allow-listed
        server = "https://server.example/mcp"
        evil_token_endpoint = "https://evil.public.example/token"  # public BUT not the issuer origin
        secret = "VAULT-CLIENT-SECRET-DO-NOT-LEAK"
        vault_client.read.side_effect = _vault_dispatch(
            allowlist=[as_issuer],
            creds={"client_id": "cid", "client_secret": secret, "auth_method": auth_method},
        )

        async def _resolve(host: str) -> list[str]:
            return ["93.184.216.34"]  # ALL hosts public -> SSRF guard passes everywhere

        monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": "Bearer resource_metadata="
                    '"https://server.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": [as_issuer], "scopes_supported": ["mcp:tools"]}
            )
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": evil_token_endpoint})
        )
        token_route = respx.post(evil_token_endpoint).mock(
            return_value=httpx.Response(200, json={"access_token": "x", "expires_in": 3600})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz_strict.acquire_token(
                server_url=server, manifest_scopes=("mcp:tools",), request_id="r", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_oauth_as_discovery_invalid"
        assert exc.value.payload.get("validation_failure") == "token_endpoint_issuer_origin_mismatch"
        assert not token_route.called  # NO POST -> no secret sent
        for call in respx.calls:
            assert call.request.url.host != "evil.public.example"
            body = (call.request.content or b"").decode("utf-8", "ignore")
            assert secret not in body
            assert secret not in str(dict(call.request.headers))

    @respx.mock
    async def test_same_origin_token_endpoint_proceeds(
        self,
        authz_strict: MCPAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Happy path: token_endpoint on the issuer's own origin -> the POST fires."""
        as_issuer = "https://as.public.example"
        server = "https://server.example/mcp"
        token_endpoint = f"{as_issuer}/oauth/token"  # SAME origin as the issuer
        vault_client.read.side_effect = _vault_dispatch(
            allowlist=[as_issuer],
            creds={"client_id": "cid", "client_secret": "s", "auth_method": "client_secret_post"},
        )

        async def _resolve(host: str) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": "Bearer resource_metadata="
                    '"https://server.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": [as_issuer], "scopes_supported": ["mcp:tools"]}
            )
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": token_endpoint})
        )
        token_route = respx.post(token_endpoint).mock(
            return_value=httpx.Response(
                200, json={"access_token": _make_jwt({"aud": server}), "expires_in": 3600,
                          "scope": "mcp:tools"}
            )
        )

        await authz_strict.acquire_token(
            server_url=server, manifest_scopes=("mcp:tools",), request_id="r", tenant_id="bank_a"
        )
        assert token_route.called  # same-origin -> the token POST DID fire

    @respx.mock
    async def test_default_port_token_endpoint_proceeds(
        self, authz_strict: MCPAuthzClient, vault_client: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """issuer `https://h` vs token_endpoint `https://h:443/...` -> same origin -> proceeds."""
        as_issuer = "https://as.public.example"
        server = "https://server.example/mcp"
        token_endpoint = f"{as_issuer}:443/oauth/token"  # explicit :443 == the issuer's default port
        vault_client.read.side_effect = _vault_dispatch(
            allowlist=[as_issuer],
            creds={"client_id": "cid", "client_secret": "s", "auth_method": "client_secret_post"},
        )

        async def _resolve(host: str) -> list[str]:
            return ["93.184.216.34"]

        monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": "Bearer resource_metadata="
                    '"https://server.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": [as_issuer], "scopes_supported": ["mcp:tools"]}
            )
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": token_endpoint})
        )
        token_route = respx.post(token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": _make_jwt({"aud": server}), "expires_in": 3600,
                      "scope": "mcp:tools"},
            )
        )

        await authz_strict.acquire_token(
            server_url=server, manifest_scopes=("mcp:tools",), request_id="r", tenant_id="bank_a"
        )
        assert token_route.called  # default-port-equivalent origin -> the token POST DID fire
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestTokenEndpointIssuerOriginBinding -v`
Expected: FAIL — the refusal does not fire yet (the AS-3b test's `token_route.called` is True; the assertion on `validation_failure` fails).

- [ ] **Step 3: Implement the check + wire it**

Add the method to `MCPAuthzClient` (next to `_refuse_non_public_discovery_url`):

```python
def _refuse_token_endpoint_origin_mismatch(
    self, token_endpoint: str, *, as_issuer: str
) -> None:
    """Bind the token_endpoint to the selected AS issuer's origin (threat-model AS-3b).

    Passing the SSRF/public-host guard is necessary but NOT sufficient: a
    compromised-but-allow-listed AS can return a ``token_endpoint`` at an arbitrary
    PUBLIC host, exfiltrating the operator ``client_secret``. This refuses unless the
    token_endpoint's canonical origin equals the AS issuer's canonical origin.

    Reuses ``mcp_oauth_as_discovery_invalid`` + a ``validation_failure`` payload tag
    (no new public refusal enum). Raised AFTER the SSRF guard and BEFORE any
    credential material is assembled (PR-2a pre-credential invariant). Never echoes
    the raw token_endpoint or the secret.
    """
    te_origin = _canonical_origin(token_endpoint)
    issuer_origin = _canonical_origin(as_issuer)
    if te_origin is None or issuer_origin is None or te_origin != issuer_origin:
        raise MCPAuthzError(
            "mcp_oauth_as_discovery_invalid",
            "token_endpoint origin does not match the AS issuer origin",
            as_issuer=as_issuer,
            validation_failure="token_endpoint_issuer_origin_mismatch",
        )
```

Wire it in `_request_token`, immediately after the Leg-5 SSRF guard (`mcp_authz.py:1394`) and before the Step-2 body build (`:1399`):

```python
        # Leg 5 (PR-2a): SSRF-guard the token_endpoint BEFORE any credential material.
        await self._refuse_non_public_discovery_url(token_endpoint, leg="token_endpoint")

        # PR-2b-0: bind the token_endpoint to the selected AS issuer's origin — a
        # compromised-but-allow-listed AS must not redirect the client_secret to an
        # arbitrary PUBLIC host (threat-model AS-3b). Also pre-credential.
        self._refuse_token_endpoint_origin_mismatch(token_endpoint, as_issuer=as_issuer)

        # Step 2: token request — credentials in body OR Basic header ...
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestTokenEndpointIssuerOriginBinding -v`
Expected: PASS. Also run the existing `_request_token` suites to confirm no regression: `uv run pytest tests/unit/protocol/test_mcp_authz.py -k "RequestToken or OAuthLeg or acquire_token" -v`.

- [ ] **Step 5: Commit** (exact-path stage `mcp_authz.py` + `test_mcp_authz.py`).

---

### Task 3: No cross-origin redirect on the token POST

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` — add `follow_redirects=False` to `self._http.post(token_endpoint, …)` (`:1432`).
- Test: `tests/unit/protocol/test_mcp_authz.py`

**Rationale:** the origin check validates the AS-document `token_endpoint` URL; a 3xx redirect *response* could still send the credential to a different host. `follow_redirects=False` makes the kernel never follow it (a 3xx falls through to the existing non-200 refusal at `:1456`). Pinned against a future client-level `follow_redirects=True` default.

- [ ] **Step 1: Write the failing test** (load-bearing: a client whose default WOULD follow)

```python
class TestTokenPostNoRedirect:
    @respx.mock
    async def test_token_post_does_not_follow_redirect_even_with_follow_client(
        self, settings_strict: Settings, vault_client: MagicMock,
        audit_store: MagicMock, decision_history_store: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        as_issuer = "https://as.public.example"
        server = "https://server.example/mcp"
        token_endpoint = f"{as_issuer}/token"  # same origin -> passes the origin binding
        secret = "VAULT-CLIENT-SECRET-DO-NOT-LEAK"
        # A client whose default IS to follow redirects — the per-call follow_redirects=False
        # must override it, so this test FAILS if the kwarg is removed.
        async with httpx.AsyncClient(follow_redirects=True) as http_client:
            authz = MCPAuthzClient(
                settings=settings_strict, vault_client=vault_client, http_client=http_client,
                audit_store=audit_store, decision_history_store=decision_history_store,
            )
            vault_client.read.side_effect = _vault_dispatch(
                allowlist=[as_issuer],
                creds={"client_id": "cid", "client_secret": secret, "auth_method": "client_secret_post"},
            )

            async def _resolve(host: str) -> list[str]:
                return ["93.184.216.34"]

            monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
            respx.get(server).mock(return_value=httpx.Response(
                401, headers={"WWW-Authenticate": 'Bearer resource_metadata='
                              '"https://server.example/.well-known/oauth-protected-resource/mcp"'}))
            respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
                return_value=httpx.Response(200, json={"authorization_servers": [as_issuer],
                                                       "scopes_supported": ["mcp:tools"]}))
            respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
                return_value=httpx.Response(200, json={"token_endpoint": token_endpoint}))
            evil = "https://evil.public.example/steal"
            # 307 PRESERVES POST method+body on a follow, so a followed redirect would
            # re-send the secret (making the secret-leak assertion meaningful). The evil
            # route is METHOD-AGNOSTIC (`respx.route(host=...)`) so a 302-as-GET follow is
            # caught too — a method-specific `respx.post(evil)` would miss it.
            token_route = respx.post(token_endpoint).mock(
                return_value=httpx.Response(307, headers={"Location": evil}))
            evil_route = respx.route(host="evil.public.example").mock(
                return_value=httpx.Response(200, json={"access_token": "x"}))

            with pytest.raises(MCPAuthzError):  # 307 -> non-200 -> refused
                await authz.acquire_token(server_url=server, manifest_scopes=("mcp:tools",),
                                          request_id="r", tenant_id="bank_a")
            assert token_route.called
            assert not evil_route.called  # method-agnostic: evil was NEVER contacted (any verb)
            for call in respx.calls:
                assert call.request.url.host != "evil.public.example"
                assert secret not in (call.request.content or b"").decode("utf-8", "ignore")
                assert secret not in str(dict(call.request.headers))
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestTokenPostNoRedirect -v`
Expected: FAIL — the `follow_redirects=True` client follows the 302 → `evil_route.called` is True / the secret reaches `evil`.

- [ ] **Step 3: Implement** — add `follow_redirects=False` to the token POST:

```python
            token_resp = await self._http.post(
                token_endpoint,
                data=body,
                headers=headers,
                timeout=timeout,
                follow_redirects=False,
            )
```

- [ ] **Step 4: Run to verify it passes** (+ the full `mcp_authz` suite).

- [ ] **Step 5: Commit.**

---

### Task 4: Drift-pin + ADR-002 amendment + closeout

**Files:**
- Test: `tests/unit/protocol/test_mcp_authz.py` — a structural pin that the origin check precedes credential assembly.
- Modify: `docs/adrs/ADR-002-mcp-plugin-protocol.md`.

- [ ] **Step 1: Write the drift-pin** (mirror `test_leg5_guard_precedes_all_credential_construction`)

```python
def test_token_endpoint_origin_binding_precedes_credential_construction() -> None:
    """Structural pin: in _request_token the issuer-origin check
    (_refuse_token_endpoint_origin_mismatch) precedes EVERY credential request-material
    assignment (body / headers / encoded_id / encoded_secret / basic_credentials), so no
    secret can be assembled for a mismatched origin even if a future refactor reorders."""
    src = Path(mcp_authz.__file__).read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "_request_token")
    cred_names = {"body", "headers", "encoded_id", "encoded_secret", "basic_credentials"}
    check_line: int | None = None
    cred_lines: list[int] = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_refuse_token_endpoint_origin_mismatch"):
            check_line = node.lineno
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id in cred_names:
                    cred_lines.append(node.lineno)
    assert check_line is not None, "origin-binding call not found in _request_token"
    assert cred_lines, "credential assignments not found"
    assert check_line < min(cred_lines)
```

- [ ] **Step 2: Run it** — PASS (the wiring from Task 2 already satisfies it). Then run the **whole** `mcp_authz` suite: `uv run pytest tests/unit/protocol/test_mcp_authz.py -v`.

- [ ] **Step 3: Amend ADR-002** — add a dated section `## token_endpoint issuer-origin binding (PR-2b-0, 2026-06-25)` recording: the AS-3b threat (a compromised-but-allow-listed AS redirecting the `client_secret` to an arbitrary public host); the binding (canonical origin equality vs the selected AS issuer); the canonicalization rules (scheme/host-lowercase, IDNA A-label, trailing-dot, default-port, scheme+host+port only); `follow_redirects=False`; the reuse of `mcp_oauth_as_discovery_invalid` + `validation_failure="token_endpoint_issuer_origin_mismatch"` (no new public refusal enum); and the residual (the stdlib `idna` codec is IDNA2003 — an `idna`-package IDNA2008 upgrade is a follow-up; the broader override + internal-host allow-list + Proof 1b-2 are PR-2b, not this slice).

- [ ] **Step 4: Closeout gate** (CC discipline — run against fresh data):

```bash
uv run pytest tests/unit/protocol/test_mcp_authz.py --cov=cognic_agentos.protocol.mcp_authz --cov-branch -q
uv run python tools/check_critical_coverage.py 2>&1 | grep mcp_authz   # must hold >= 95% line / 90% branch
uv run mypy src tests
uv run ruff check . && uv run ruff format --check .
```

- [ ] **Step 5: Commit** (exact-path stage `test_mcp_authz.py` + `ADR-002-mcp-plugin-protocol.md`).

---

## Self-review

- **Spec coverage:** §7a(ii) issuer-origin binding (Tasks 1–2), canonicalization rules incl. default-port/IDNA/trailing-dot (Task 1), no-cross-origin-redirect (Task 3), the AS-3b no-secret-sent invariant (Task 2), `validation_failure` payload + `discovery_status=refused` reuse (Task 2 / Global Constraints), residuals named (Task 4 ADR). The override store, internal-host allow-list, and Proof 1b-2 are **intentionally excluded** (PR-2b proper).
- **Placeholder scan:** none — all task code is inline and exact (the review's `...` in `test_default_port_token_endpoint_proceeds` is now the full inlined body).
- **Type consistency:** `_canonical_origin -> tuple[str, str, int] | None` consumed by `_refuse_token_endpoint_origin_mismatch`; `as_issuer` is the existing `_request_token` param. The reused reason `mcp_oauth_as_discovery_invalid` is an existing `AuthzReason` value (no enum change).

## Execution handoff

Plan complete. This is a tight, single-CC-module slice — well suited to **subagent-driven execution** (fresh subagent per task + two-stage review), or inline. **Recommend holding for Codex's review of this plan first** (per the established PR-2a/threat-model cadence), then execute Tasks 1→4 with a commit token per task.
