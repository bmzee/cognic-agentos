# PR-2a MCP OAuth-leg SSRF Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the MCP OAuth-leg SSRF + credential-exfiltration gap by extending the existing prefetch SSRF guard to all five discovery/OAuth fetch legs, default-deny, so no credential-bearing OAuth fetch can reach a non-public/internal URL.

**Architecture:** Reuse the existing `MCPAuthzClient._refuse_non_public_discovery_url` DNS-resolve-and-check (no new policy). Add a closed-enum `leg` discriminator so every refusal identifies which of the five fetches was refused. Wire the guard at the two currently-unguarded `_request_token` fetches (AS-metadata GET, token_endpoint POST — the latter *before* credential material is built). Record `discovery_status=refused` at the `MCPHost` call sites (where `server_id` is known) for `acquire`/retry/step-up; leave `refresh_token` guarded-but-unrecorded (no host call site) and pin that with a drift test. Add an AST drift detector so no future unguarded `_http` fetch can slip in.

**Tech Stack:** Python 3.12, `httpx`, `respx` (test HTTP mock), `pytest`/`pytest-asyncio`, `ast` (drift detectors), `uv` (runner).

## Global Constraints

- `src/cognic_agentos/protocol/mcp_authz.py` is on the **critical-controls durable coverage gate** (95% line / 90% branch — `tools/check_critical_coverage.py`). Negative-path tests are required; the gate must pass on fresh data at the end.
- **Reuse** the existing `AuthzReason` member `mcp_discovery_url_refused` — **no new enum member**. The `TestRefusalReasonClosedEnum` drift pin in `test_mcp_authz.py` must stay green untouched.
- `leg` is a **closed-enum `DiscoveryLeg` Literal**, type-checked at the guard parameter. It rides `MCPAuthzError.payload["leg"]` via the existing `**payload` catch-all — **no `MCPAuthzError` signature change** (a required field would break all 44 in-module raise sites).
- `refused_component` (`not_string`/`scheme`/`host`/`host_address`) is the **failure-type axis and is NOT repurposed** — every refusal carries both `leg` and `refused_component`.
- **Preserve the strict/dev profile distinction.** The guard already early-returns when `runtime_profile not in _STRICT_PROFILES` (`{"stage","prod"}`); 2a does NOT change that. All SSRF negative tests run under the **strict (`prod`)** profile; a dev test pins inertness.
- **Honesty boundary:** 2a guards the prefetch URL/IP classification on every OAuth/discovery leg. It does **NOT** close the DNS-rebinding TOCTOU, the unresolvable-host pass-through, or the dev-profile skip. Never claim "complete SSRF prevention".
- Use `uv run` for every command. Commit at each task with exact-path staging. Do not push/PR without an explicit token.

---

### Task 1: `leg` discriminator on the SSRF guard + wire the three existing legs + semantic-widening doc

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` (add `DiscoveryLeg` Literal near `AuthzReason` ~:165; add `leg` param to `_refuse_non_public_discovery_url` :971; the `:433` call site in `discover_resource_metadata`; the `:1048` call site in `_fetch_prm` + a `discovery_path→leg` map)
- Test: `tests/unit/protocol/test_mcp_authz_ssrf.py`

**Interfaces:**
- Produces: `DiscoveryLeg = Literal["server_url", "prm_metadata", "well_known_prm", "as_metadata", "token_endpoint"]`; `_refuse_non_public_discovery_url(self, url: str, *, leg: DiscoveryLeg) -> None` (now requires keyword-only `leg`); refusals add `payload["leg"]`.

- [ ] **Step 1: Write the failing tests (the three existing legs carry a `leg`)**

Add to `tests/unit/protocol/test_mcp_authz_ssrf.py` (it already imports `mcp_authz`, `MCPAuthzError`, `_StubHttp`, `_client`, `_discover`, `pytest`):

```python
async def _resolve_internal(host: str) -> list[str]:
    return ["10.0.0.5"]


@pytest.mark.asyncio
async def test_server_url_leg_carries_leg_discriminator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve_internal)
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "https://internal.example/mcp")
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("leg") == "server_url"
    assert e.value.payload.get("refused_component") == "host_address"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "discovery_path,expected_leg",
    [
        ("www-authenticate", "prm_metadata"),
        ("endpoint-well-known", "well_known_prm"),
        ("root-well-known", "well_known_prm"),
    ],
)
async def test_fetch_prm_leg_mapping(
    discovery_path: str, expected_leg: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve_internal)
    http = _StubHttp(fail_if_called=True)
    client = _client(http, profile="prod")
    with pytest.raises(MCPAuthzError) as e:
        await client._fetch_prm(
            "https://internal.example/.well-known/oauth-protected-resource",
            discovery_path,
            "https://server.example/mcp",
            5.0,
        )
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("leg") == expected_leg
    assert http.gets == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz_ssrf.py -k "leg" -v`
Expected: FAIL — `_refuse_non_public_discovery_url() got an unexpected keyword argument 'leg'` (the production guard has no `leg` param yet), and `payload.get("leg")` is `None`.

- [ ] **Step 3: Add the `DiscoveryLeg` Literal + the `discovery_path→leg` map**

In `mcp_authz.py`, immediately after the `AuthzReason` Literal (ends at :188), add:

```python
# PR-2a (ADR-002): the prefetch SSRF guard fires on five discovery/OAuth legs.
# `leg` is the closed-enum "which fetch" discriminator (orthogonal to
# `refused_component`, the "why" axis). It rides MCPAuthzError.payload["leg"].
DiscoveryLeg = Literal[
    "server_url",
    "prm_metadata",
    "well_known_prm",
    "as_metadata",
    "token_endpoint",
]

# The 3-value internal `discovery_path` label that `_fetch_prm` already carries
# maps onto the two PRM-family legs.
_PRM_DISCOVERY_PATH_TO_LEG: dict[str, DiscoveryLeg] = {
    "www-authenticate": "prm_metadata",
    "endpoint-well-known": "well_known_prm",
    "root-well-known": "well_known_prm",
}
```

- [ ] **Step 4: Add the `leg` param to the guard + thread it into every raise**

In `mcp_authz.py`, change the signature at :971 and add `leg=leg` to all four raise sites (:988, :995, :1002, :1028). Also widen the docstring's first line:

```python
    async def _refuse_non_public_discovery_url(self, url: str, *, leg: DiscoveryLeg) -> None:
        """SSRF guard (remediation §4.1) for every MCP auth/discovery fetch leg.

        Reused by all five legs (server_url, prm_metadata, well_known_prm,
        as_metadata, token_endpoint — PR-2a). Always rejects non-http(s)
        schemes and host-less URLs. In the strict (stage/prod) profile
        additionally resolves the host and rejects private / loopback /
        link-local / reserved / multicast / unspecified addresses. Rejection
        payloads identify the refused component CLASS + the `leg`, and NEVER
        echo the raw URL.

        Residual: resolve-then-fetch leaves a DNS-rebinding TOCTOU window;
        full connect-time IP-pinning is a tracked follow-up, not claimed here.
        """
        if not isinstance(url, str):
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL is not a string",
                refused_component="not_string",
                leg=leg,
            )
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL scheme is not http/https",
                refused_component="scheme",
                leg=leg,
            )
        host = parsed.hostname
        if not host:
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL has no host",
                refused_component="host",
                leg=leg,
            )
        if self._settings.runtime_profile not in _STRICT_PROFILES:
            return
        try:
            addresses = await _resolve_host_addresses(host)
        except OSError:
            return
        for addr in addresses:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                raise MCPAuthzError(
                    "mcp_discovery_url_refused",
                    "discovery URL host resolves to a non-public address",
                    refused_component="host_address",
                    leg=leg,
                )
```

- [ ] **Step 5: Wire the two existing call sites**

In `discover_resource_metadata`, change :433 from `await self._refuse_non_public_discovery_url(server_url)` to:

```python
        await self._refuse_non_public_discovery_url(server_url, leg="server_url")
```

In `_fetch_prm`, change :1048 from `await self._refuse_non_public_discovery_url(url)` to:

```python
        await self._refuse_non_public_discovery_url(
            url, leg=_PRM_DISCOVERY_PATH_TO_LEG[discovery_path]
        )
```

- [ ] **Step 6: Update the `AuthzReason` semantic-widening comment**

In `mcp_authz.py`, replace the comment above `"mcp_discovery_url_refused"` (currently :184-186) with the widened meaning:

```python
    # Remediation §4.1 (SSRF), widened by PR-2a: an MCP auth-OR-discovery URL
    # was refused by the non-public-URL guard. Covers all five legs —
    # server_url, prm_metadata, well_known_prm (PR-1) + as_metadata,
    # token_endpoint (PR-2a OAuth legs). The refusal payload carries `leg`
    # (which fetch) + `refused_component` (why). Reused, NOT a new member.
    "mcp_discovery_url_refused",
```

- [ ] **Step 7: Run the tests + mypy**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz_ssrf.py -v && uv run mypy src/cognic_agentos/protocol/mcp_authz.py`
Expected: PASS (the new `leg` tests + the existing ssrf tests still green; mypy clean — the `DiscoveryLeg` Literal is satisfied at every call site).

- [ ] **Step 8: Commit**

```bash
git add src/cognic_agentos/protocol/mcp_authz.py tests/unit/protocol/test_mcp_authz_ssrf.py
git commit -m "feat(mcp-authz): add leg discriminator to the SSRF guard + wire the 3 existing legs (PR-2a)"
```

---

### Task 2: Guard leg-4 (AS-metadata discovery) before the GET

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` (`_request_token` :1318-1324)
- Test: `tests/unit/protocol/test_mcp_authz.py` (new `authz_strict` fixture + a leg-4 test)

**Interfaces:**
- Consumes: `_refuse_non_public_discovery_url(url, *, leg)` from Task 1.
- Produces: a strict-profile `authz_strict` fixture for Tasks 2-3.

- [ ] **Step 1: Add the strict fixtures + the failing leg-4 test**

In `tests/unit/protocol/test_mcp_authz.py`, after the `authz` fixture (:153), add:

```python
@pytest.fixture
def settings_strict(settings: Settings) -> Settings:
    return settings.model_copy(update={"runtime_profile": "prod"})


@pytest.fixture
async def authz_strict(
    settings_strict: Settings,
    vault_client: MagicMock,
    http_client: httpx.AsyncClient,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> MCPAuthzClient:
    return MCPAuthzClient(
        settings=settings_strict,
        vault_client=vault_client,
        http_client=http_client,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )
```

Then add a new test class (it needs `import respx`, already at :37, and `from cognic_agentos.protocol import mcp_authz` — add if absent):

```python
class TestOAuthLegSsrfGuard:
    @respx.mock
    async def test_leg4_as_metadata_internal_refused_before_get(
        self,
        authz_strict: MCPAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        as_issuer = "https://as.internal.example"  # allow-listed but internal
        server = "https://server.example/mcp"
        vault_client.read.side_effect = _vault_dispatch(allowlist=[as_issuer])

        async def _resolve(host: str) -> list[str]:
            return ["10.0.0.5"] if host == "as.internal.example" else ["93.184.216.34"]

        monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata='
                    '"https://server.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        respx.get(
            "https://server.example/.well-known/oauth-protected-resource/mcp"
        ).mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": [as_issuer], "scopes_supported": ["mcp:tools"]}
            )
        )
        as_meta = respx.get(
            f"{as_issuer}/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"}))

        with pytest.raises(MCPAuthzError) as exc:
            await authz_strict.acquire_token(
                server_url=server, manifest_scopes=("mcp:tools",), request_id="r", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_discovery_url_refused"
        assert exc.value.payload.get("leg") == "as_metadata"
        assert not as_meta.called  # the AS-metadata GET never fired
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestOAuthLegSsrfGuard::test_leg4_as_metadata_internal_refused_before_get -v`
Expected: FAIL — without the guard, `acquire_token` either issues the AS-metadata GET (`as_meta.called` is True) or raises a different reason; the refusal is not `mcp_discovery_url_refused`/`leg=as_metadata`.

- [ ] **Step 3: Insert the leg-4 guard**

In `_request_token`, replace the inline URL in the GET (:1318-1324) with a named local guarded first:

```python
        # Step 1: AS-discovery via its issuer well-known.
        timeout = self._settings.mcp_oauth_request_timeout_s
        as_metadata_url = f"{as_issuer.rstrip('/')}/.well-known/oauth-authorization-server"
        # Leg 4 (PR-2a): SSRF-guard the AS-metadata discovery URL before the GET.
        await self._refuse_non_public_discovery_url(as_metadata_url, leg="as_metadata")
        try:
            discovery_resp = await self._http.get(as_metadata_url, timeout=timeout)
```

(The `except httpx.TimeoutException ... except httpx.RequestError ...` block below is unchanged.)

- [ ] **Step 4: Run the test + the existing OAuth suite**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py -k "TestOAuthLegSsrfGuard or TestRequestTokenErrorPaths" -v`
Expected: PASS (leg-4 refuses before the GET; the existing AS-discovery error-path tests still green — the guard is inert for their public `as_issuer`).

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/protocol/mcp_authz.py tests/unit/protocol/test_mcp_authz.py
git commit -m "feat(mcp-authz): SSRF-guard leg-4 AS-metadata discovery before the GET (PR-2a)"
```

---

### Task 3: Guard leg-5 (token_endpoint) before credential construction + credential-exfil test

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` (`_request_token` :1360-1365)
- Test: `tests/unit/protocol/test_mcp_authz.py` (`TestOAuthLegSsrfGuard` — the credential-exfil test + a structural ordering test)

**Interfaces:**
- Consumes: `_refuse_non_public_discovery_url(url, *, leg)`; `authz_strict` fixture.

- [ ] **Step 1: Write the failing credential-exfil test**

Add to `TestOAuthLegSsrfGuard`:

```python
    @respx.mock
    @pytest.mark.parametrize("auth_method", ["client_secret_post", "client_secret_basic"])
    async def test_leg5_credential_exfil_blocked_both_auth_methods(
        self,
        authz_strict: MCPAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        auth_method: str,
    ) -> None:
        """The headline credential-exfil case, for BOTH transports (the threat model
        covers form-body AND HTTP Basic credentials): a PUBLIC allow-listed AS returns
        a discovery doc steering token_endpoint to an INTERNAL host. The guard refuses
        before any credential material is built — no POST, so neither the form body
        (`client_secret_post`) nor the Basic `Authorization` header
        (`client_secret_basic`) is ever sent."""
        as_issuer = "https://as.public.example"  # public, allow-listed
        server = "https://server.example/mcp"
        internal_token_endpoint = "https://token.internal.example/token"
        secret = "VAULT-CLIENT-SECRET-DO-NOT-LEAK"
        vault_client.read.side_effect = _vault_dispatch(
            allowlist=[as_issuer],
            creds={"client_id": "cid", "client_secret": secret, "auth_method": auth_method},
        )

        async def _resolve(host: str) -> list[str]:
            return ["10.0.0.9"] if host == "token.internal.example" else ["93.184.216.34"]

        monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve)
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata='
                    '"https://server.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        respx.get(
            "https://server.example/.well-known/oauth-protected-resource/mcp"
        ).mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": [as_issuer], "scopes_supported": ["mcp:tools"]}
            )
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": internal_token_endpoint})
        )
        token_route = respx.post(internal_token_endpoint).mock(
            return_value=httpx.Response(200, json={"access_token": "x", "expires_in": 3600, "scope": "mcp:tools"})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz_strict.acquire_token(
                server_url=server, manifest_scopes=("mcp:tools",), request_id="r", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_discovery_url_refused"
        assert exc.value.payload.get("leg") == "token_endpoint"
        assert not token_route.called  # NO POST -> neither form body nor Basic header sent
        # The internal token endpoint received NO request at all, and the raw secret
        # (the form-body value for _post) never appears in any sent request.
        for call in respx.calls:
            assert call.request.url.host != "token.internal.example"
            body = (call.request.content or b"").decode("utf-8", "ignore")
            assert secret not in body
            assert secret not in str(dict(call.request.headers))
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::TestOAuthLegSsrfGuard::test_leg5_credential_exfil_blocked_both_auth_methods -v`
Expected: FAIL (both params) — without the guard, `token_route.called` is True (the POST fired) carrying the secret (form body for `_post`, Basic header for `_basic`); the raised reason is not `mcp_discovery_url_refused`.

- [ ] **Step 3: Insert the leg-5 guard (before credential construction)**

In `_request_token`, insert the guard between the `token_endpoint` validation (ends :1360) and the `# Step 2` comment / `body` dict (:1362-1365):

```python
        token_endpoint = discovery_doc.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise MCPAuthzError(
                "mcp_oauth_as_discovery_invalid",
                f"AS {as_issuer} discovery has no token_endpoint",
                as_issuer=as_issuer,
            )
        # Leg 5 (PR-2a): SSRF-guard the token_endpoint BEFORE any credential
        # material (body / headers / Basic-auth) is built — the secret is never
        # assembled into a request for an internal URL.
        await self._refuse_non_public_discovery_url(token_endpoint, leg="token_endpoint")

        # Step 2: token request — credentials in body OR Basic header
```

- [ ] **Step 4: Run the test + the existing OAuth suite**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py -k "TestOAuthLegSsrfGuard or TestRequestTokenErrorPaths or TestVaultOauthCredentials" -v`
Expected: PASS (leg-5 refuses before the POST; no secret in any request; existing token-flow tests still green — their public token_endpoints pass the guard).

- [ ] **Step 5: Write + run the structural ordering test (guard precedes credential construction)**

Add to `test_mcp_authz.py` (needs `import ast` and `from pathlib import Path`):

```python
def test_leg5_guard_precedes_all_credential_construction() -> None:
    """Structural pin (strengthened): in _request_token the token_endpoint guard
    precedes EVERY credential request-material assignment — `body`, `headers`,
    `encoded_id`, `encoded_secret`, `basic_credentials` — so neither the form body
    (`client_secret_post`) nor the Basic-auth header (`client_secret_basic`) can be
    assembled for an internal URL even if a future refactor reorders statements."""
    src = Path(mcp_authz.__file__).read_text()
    tree = ast.parse(src)
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_request_token"
    )
    cred_names = {"body", "headers", "encoded_id", "encoded_secret", "basic_credentials"}
    guard_line: int | None = None
    cred_lines: dict[str, int] = {}
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_refuse_non_public_discovery_url"
            and any(
                kw.arg == "leg"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == "token_endpoint"
                for kw in node.keywords
            )
        ):
            guard_line = node.lineno
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in cred_names:
                    cred_lines.setdefault(t.id, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            # `body: dict[str, str] = {...}` and `headers: dict[str, str] = {}`
            # are ANNOTATED assignments (single `.target`, not `.targets`) — the
            # two most security-sensitive credential-material names (the form body
            # carries `client_secret` for `client_secret_post`), so the pin MUST
            # cover them too, not just the plain-`ast.Assign` encoded_*/basic ones.
            t = node.target
            if isinstance(t, ast.Name) and t.id in cred_names:
                cred_lines.setdefault(t.id, node.lineno)
    assert guard_line is not None, "leg-5 token_endpoint guard not found in _request_token"
    assert cred_names <= set(cred_lines), (
        f"missing credential-material assignments: {cred_names - set(cred_lines)}"
    )
    earliest = min(cred_lines.values())
    assert guard_line < earliest, (
        f"leg-5 guard (line {guard_line}) must precede ALL credential request-material "
        f"construction (earliest credential assign at line {earliest})"
    )
```

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py::test_leg5_guard_precedes_all_credential_construction -v`
Expected: PASS (the guard, inserted after the token_endpoint validation and before the `body` dict, precedes all five credential-material names).

- [ ] **Step 6: Commit**

```bash
git add src/cognic_agentos/protocol/mcp_authz.py tests/unit/protocol/test_mcp_authz.py
git commit -m "feat(mcp-authz): SSRF-guard leg-5 token_endpoint before credential construction (PR-2a)"
```

---

### Task 4: Record `discovery_status` (refused/unreachable via the mapper) at the step-up call site

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py` (the `step_up_token` call site :1810-1817)
- Test: `tests/unit/protocol/test_mcp_host.py`

**Interfaces:**
- Consumes: `_record_discovery_status(*, tenant_id, server_id, status)` + `discovery_status_for_authz_reason` (both already in `mcp_host.py` from PR-1) + the leg-5 SSRF refusal from Task 3.

- [ ] **Step 1: Write the failing tests (step-up SSRF refusal records; auth-denial does NOT)**

Add to `tests/unit/protocol/test_mcp_host.py` (mirror the existing `TestDiscoveryStatusRecording` + the step-up call_tool scaffolding — reuse the fixtures/builders those tests use to construct a `MCPHost` with an injected `InMemoryDiscoveryStatusRecorder` and drive a `call_tool` that returns a step-up signal). The two behaviors to pin:

```python
class TestStepUpDiscoveryStatusRecording:
    @pytest.mark.parametrize(
        "reason,expected",
        [
            ("mcp_discovery_url_refused", "refused"),  # leg-4/leg-5 SSRF refusal
            ("mcp_oauth_request_timeout", "unreachable"),  # endpoint unreachable
        ],
    )
    async def test_step_up_reachability_failure_records(
        self, reason: str, expected: str
    ) -> None:
        """A step-up failure reflecting endpoint/OAuth reachability surfaces on the
        discovery-status axis via the shared mapper — the step-up path is not a
        second unobserved invoke path. (step_up_token reaches _request_token, which
        can fail with SSRF/timeout/transport/discovery/token errors.)"""
        recorder = InMemoryDiscoveryStatusRecorder()
        host, entry, tenant_id = _host_with_step_up_raising(
            recorder, MCPAuthzError(reason, "step-up reachability failure")
        )
        with pytest.raises(MCPAuthzError):
            await _drive_call_tool_into_step_up(host, entry, tenant_id)
        assert recorder.get(tenant_id=tenant_id, pack_id=entry.server_id) == expected

    async def test_step_up_authorization_denial_does_not_record(self) -> None:
        """mcp_step_up_unauthorised is an AUTHORIZATION denial (the original token is
        fine, only the wider scope was denied), NOT endpoint reachability — it must
        NOT touch the discovery-status axis (it stays whatever it was)."""
        recorder = InMemoryDiscoveryStatusRecorder()
        recorder.record(tenant_id="bank_a", pack_id="pack-x", status="auth_ready")
        host, entry, tenant_id = _host_with_step_up_raising(
            recorder,
            MCPAuthzError("mcp_step_up_unauthorised", "scope denied"),
            server_id="pack-x",
            tenant_id="bank_a",
        )
        with pytest.raises(MCPAuthzError):
            await _drive_call_tool_into_step_up(host, entry, tenant_id)
        assert recorder.get(tenant_id=tenant_id, pack_id=entry.server_id) == "auth_ready"
```

> Implementer note: `_host_with_step_up_raising` and `_drive_call_tool_into_step_up` are local helpers you build by mirroring the exact existing class **`TestCallToolStepUpOn403InsufficientScope`** in `test_mcp_host.py` — it already constructs an `MCPHost`, registers an entry, and drives `call_tool` through a transport that returns a `step_up` interrupt signal. Inject `discovery_status_recorder=recorder` into the host the same way **`TestDiscoveryStatusRecording`** does, and stub `authz.step_up_token` to raise the given `MCPAuthzError`. Do not invent new production seams.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/protocol/test_mcp_host.py::TestStepUpDiscoveryStatusRecording -v`
Expected: FAIL — the two reachability params (`mcp_discovery_url_refused`, `mcp_oauth_request_timeout`) see `unprobed` (no recording at the step-up site yet); the auth-denial test passes vacuously (nothing records). The reachability params are the load-bearing RED.

- [ ] **Step 3: Wrap the step-up call with the gated recorder**

In `mcp_host.py`, replace the `step_up_token` call (:1810-1817) with:

```python
                try:
                    stepped_up = await self._authz.step_up_token(
                        server_url=entry.server_url,
                        current_token=token,
                        requested_scope=signal_payload["requested_scope"],
                        manifest_scopes=entry.manifest_scopes,
                        request_id=request_id,
                        tenant_id=tenant_id,
                    )
                except MCPAuthzError as exc:
                    # PR-2a: a step-up failure that reflects endpoint/OAuth
                    # reachability (SSRF refusal, timeout, transport, AS-discovery /
                    # token errors) surfaces on the discovery-status axis via the
                    # SHARED mapper — so step-up is not a second unobserved invoke
                    # path. mcp_step_up_unauthorised is an authorization denial (the
                    # original token is fine, only the wider scope was denied), NOT
                    # endpoint reachability, so it is the one excluded reason.
                    if exc.reason != "mcp_step_up_unauthorised":
                        self._record_discovery_status(
                            tenant_id=tenant_id,
                            server_id=entry.server_id,
                            status=discovery_status_for_authz_reason(exc.reason),
                        )
                    raise
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/unit/protocol/test_mcp_host.py::TestStepUpDiscoveryStatusRecording -v`
Expected: PASS (SSRF refusal → `refused`; OAuth timeout → `unreachable`; auth-denial → unchanged `auth_ready`).

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/test_mcp_host.py
git commit -m "feat(mcp-host): record discovery_status=refused on step-up token-leg SSRF refusal (PR-2a)"
```

---

### Task 5: Drift pin — `MCPHost` has no `refresh_token` invoke path

**Files:**
- Test: `tests/unit/protocol/test_mcp_host.py`

- [ ] **Step 1: Write the pin**

Add to `test_mcp_host.py` (needs `import ast`, `from pathlib import Path`, `from cognic_agentos.protocol import mcp_host`):

```python
def test_mcp_host_has_no_refresh_token_call_path() -> None:
    """PR-2a §3.3 drift pin: refresh_token is guarded-but-unrecorded by design —
    it carries no server_id/pack key and MCPHost never invokes it, so there is no
    production call site that could record discovery_status. If a future MCPHost
    path calls refresh_token, this pin fails and forces the recording decision to
    be revisited (the OAuth-leg guard still applies in _request_token regardless)."""
    src = Path(mcp_host.__file__).read_text()
    tree = ast.parse(src)
    refresh_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "refresh_token"
    ]
    assert refresh_calls == [], (
        "MCPHost now calls refresh_token — revisit PR-2a §3.3 discovery_status recording"
    )
```

- [ ] **Step 2: Run it (passes now) + prove it bites**

Run: `uv run pytest tests/unit/protocol/test_mcp_host.py::test_mcp_host_has_no_refresh_token_call_path -v`
Expected: PASS (no refresh call exists).

Then prove the pin fires: temporarily add `await self._authz.refresh_token(token=token, request_id=request_id, tenant_id=tenant_id)` anywhere in `mcp_host.py`, re-run → it FAILS; remove the temporary line → PASS again. (Do not commit the temporary line.)

- [ ] **Step 3: Commit**

```bash
git add tests/unit/protocol/test_mcp_host.py
git commit -m "test(mcp-host): drift-pin that MCPHost has no refresh_token invoke path (PR-2a)"
```

---

### Task 6: AST drift detector — every `_http` fetch in `mcp_authz.py` is guarded

**Files:**
- Create: `tests/unit/protocol/test_mcp_authz_guarded_fetch.py`

**Interfaces:**
- Produces: `_find_unguarded_fetches(source: str) -> list[tuple[str, int]]` (test-local) + the `_GUARD_EXEMPT_FUNCTIONS` named-exemption registry.

- [ ] **Step 1: Write the detector + its self-tests (RED proven on synthetic source)**

Create `tests/unit/protocol/test_mcp_authz_guarded_fetch.py`:

```python
"""PR-2a §3.4 — AST drift detector: every self._http.get/post in mcp_authz.py is
preceded (within its function) by a _refuse_non_public_discovery_url guard, or is
routed through a NAMED syntactic exemption. Comments are invisible to ast and are
NOT a valid marker."""

from __future__ import annotations

import ast
from pathlib import Path

from cognic_agentos.protocol import mcp_authz

# Named exemption registry: functions allowed to issue a deliberately-public
# _http fetch. Empty today — all five legs are guarded. To exempt a future
# public fetch, add its function name here (a real, AST-visible construct).
_GUARD_EXEMPT_FUNCTIONS: frozenset[str] = frozenset()


def _is_guard_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_refuse_non_public_discovery_url"
    )


def _is_http_fetch(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "post"}
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_http"
    )


def _url_arg_dump(call: ast.Call) -> str | None:
    """ast.dump of a call's first positional arg (the URL expression), or None."""
    return ast.dump(call.args[0]) if call.args else None


def _guard_has_leg(call: ast.Call) -> bool:
    return any(kw.arg == "leg" for kw in call.keywords)


def _find_unguarded_fetches(
    source: str, *, exempt: frozenset[str] = _GUARD_EXEMPT_FUNCTIONS
) -> list[tuple[str, int]]:
    """A fetch is guarded IFF a guard earlier in the same function guards the SAME
    url expression (matched by ast.dump of the first positional arg) AND carries a
    `leg=` kwarg. A guard on a DIFFERENT url (e.g. `as_metadata_url`) does NOT
    cover a later `token_endpoint` POST — that URL pairing is the whole point of
    the pin (a coarse "any guard earlier" check would falsely pass a missing
    token-endpoint guard)."""
    tree = ast.parse(source)
    violations: list[tuple[str, int]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if fn.name in exempt:
            continue
        guards = [
            (n.lineno, _url_arg_dump(n))
            for n in ast.walk(fn)
            if _is_guard_call(n) and _guard_has_leg(n)
        ]
        for node in ast.walk(fn):
            if not _is_http_fetch(node):
                continue
            fetch_url = _url_arg_dump(node)
            if fetch_url is None or not any(
                g_line < node.lineno and g_url == fetch_url for g_line, g_url in guards
            ):
                violations.append((fn.name, node.lineno))
    return violations


def test_real_mcp_authz_has_no_unguarded_fetches() -> None:
    src = Path(mcp_authz.__file__).read_text()
    assert _find_unguarded_fetches(src) == []


def test_detector_flags_unguarded_fetch() -> None:
    bad = (
        "class C:\n"
        "    async def f(self):\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(bad) == [("f", 3)]


def test_detector_passes_url_matched_guarded_fetch() -> None:
    good = (
        "class C:\n"
        "    async def f(self):\n"
        "        await self._refuse_non_public_discovery_url('http://x', leg='server_url')\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(good) == []


def test_detector_flags_mismatched_guard_for_token_post() -> None:
    """The core regression Codex flagged: an `as_metadata_url` guard must NOT make a
    later `token_endpoint` POST look guarded — the POST has no matching-url guard."""
    src = (
        "class C:\n"
        "    async def _request_token(self):\n"
        "        as_metadata_url = 'http://a'\n"
        "        await self._refuse_non_public_discovery_url(as_metadata_url, leg='as_metadata')\n"
        "        await self._http.get(as_metadata_url)\n"
        "        token_endpoint = 'http://t'\n"
        "        await self._http.post(token_endpoint, data={})\n"
    )
    violations = _find_unguarded_fetches(src)
    assert ("_request_token", 7) in violations  # the token POST is unguarded
    assert ("_request_token", 5) not in violations  # the as_metadata GET IS guarded


def test_detector_flags_guard_without_leg() -> None:
    """A guard missing its `leg=` kwarg does not count — every guard must be leg-tagged."""
    bad = (
        "class C:\n"
        "    async def f(self):\n"
        "        await self._refuse_non_public_discovery_url('http://x')\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(bad) == [("f", 4)]


def test_detector_skips_named_exempt_function() -> None:
    """The exemption is a NAMED function in the registry (a real syntactic marker),
    not a comment. An exempted function's fetch is not flagged."""
    bad = (
        "class C:\n"
        "    async def _unguarded_public_fetch(self):\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(bad) == [("_unguarded_public_fetch", 3)]
    assert _find_unguarded_fetches(bad, exempt=frozenset({"_unguarded_public_fetch"})) == []
```

> The last test documents the exemption mechanism by name (`_unguarded_public_fetch` / the `_GUARD_EXEMPT_FUNCTIONS` registry) without needing an exemption today. If you prefer, drop its self-reference line and simply assert the un-exempted flagging — the point is that the marker is a real identifier, never a comment.

- [ ] **Step 2: Run the detector tests**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz_guarded_fetch.py -v`
Expected: PASS — the real module is clean (after Tasks 1-3), the synthetic unguarded fetch is flagged, the guarded + named-exempt cases pass.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/protocol/test_mcp_authz_guarded_fetch.py
git commit -m "test(mcp-authz): AST drift detector — no unguarded _http fetch (PR-2a)"
```

---

### Task 7: ADR-002 amendment + dev-profile preservation + critical-controls gate

**Files:**
- Modify: `docs/adrs/ADR-002-mcp-plugin-protocol.md`
- Test: `tests/unit/protocol/test_mcp_authz_ssrf.py` (dev-profile inertness for the OAuth legs)

- [ ] **Step 1: Write + run the dev-profile inertness test**

Add to `test_mcp_authz_ssrf.py`:

```python
@pytest.mark.asyncio
async def test_oauth_legs_inert_in_dev_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """2a preserves the strict/dev distinction: in dev the guard skips the
    DNS/IP check, so an internal OAuth-leg URL is NOT refused (no behavior change
    in dev). Pins that 2a did not silently start refusing in dev."""
    monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolve_internal)
    client = _client(_StubHttp(), profile="dev")
    # No raise for either OAuth leg in dev (the guard early-returns).
    await client._refuse_non_public_discovery_url(
        "https://as.internal.example/.well-known/oauth-authorization-server", leg="as_metadata"
    )
    await client._refuse_non_public_discovery_url(
        "https://token.internal.example/token", leg="token_endpoint"
    )
```

Run: `uv run pytest tests/unit/protocol/test_mcp_authz_ssrf.py::test_oauth_legs_inert_in_dev_profile -v`
Expected: PASS.

- [ ] **Step 2: Amend ADR-002**

In `docs/adrs/ADR-002-mcp-plugin-protocol.md`, add a dated amendment after the existing trust-register-then-defer section:

```markdown
### OAuth/discovery-leg SSRF hardening (PR-2a, 2026-06-24)

PR-1 moved the OAuth/PRM discovery probe to invoke. The prefetch SSRF guard
(`_refuse_non_public_discovery_url`) covered the three discovery fetches
(server_url, WWW-Authenticate PRM, well-known PRM) but NOT the two OAuth fetches
in `_request_token` — the AS-metadata discovery GET and the credential-bearing
`token_endpoint` POST. The token endpoint is the sharp gap: its URL comes from
the AS discovery document, so an allow-listed-but-compromised AS could steer the
OAuth client credentials to an internal address (SSRF + credential exfiltration).

PR-2a extends the SAME DNS-resolve-and-check guard to all five legs,
default-deny, with the token_endpoint validated BEFORE any credential material
is built. The refusal reuses `mcp_discovery_url_refused` (semantically widened
to "MCP auth-or-discovery URL refused") and gains a closed-enum `leg`
discriminator (`server_url`/`prm_metadata`/`well_known_prm`/`as_metadata`/
`token_endpoint`) alongside the kept `refused_component` failure-type axis. A
refusal surfaces as `discovery_status=refused` at the MCPHost call sites
(acquire / retry-reacquire / step-up); `refresh_token` is guarded but
unrecorded (no host call site / no key), pinned by a drift test. An AST drift
detector keeps every `_http` fetch guarded.

This is NOT complete SSRF prevention: the DNS-rebinding TOCTOU, the
unresolvable-host pass-through, and the dev-profile skip remain (tracked).
PR-2b adds the per-tenant internal-host allow-list + the operator server_url
override + the deployed Proof 1b-2, and never merges without 2a.
```

- [ ] **Step 3: Run the full relevant suites + the critical-controls gate**

Run:
```bash
uv run pytest tests/unit/protocol/test_mcp_authz.py tests/unit/protocol/test_mcp_authz_ssrf.py tests/unit/protocol/test_mcp_authz_guarded_fetch.py tests/unit/protocol/test_mcp_host.py tests/unit/protocol/test_discovery_status.py -v
uv run ruff check src/cognic_agentos/protocol/mcp_authz.py src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/
uv run ruff format --check src/cognic_agentos/protocol/ tests/unit/protocol/
uv run mypy src/cognic_agentos/protocol/mcp_authz.py src/cognic_agentos/protocol/mcp_host.py
uv run pytest --cov=src/cognic_agentos --cov-branch --cov-report=json -q
uv run python tools/check_critical_coverage.py
```
Expected: all green; `check_critical_coverage.py` reports `mcp_authz.py` + `mcp_host.py` at/above 95% line / 90% branch on fresh data.

- [ ] **Step 4: Commit**

```bash
git add docs/adrs/ADR-002-mcp-plugin-protocol.md tests/unit/protocol/test_mcp_authz_ssrf.py
git commit -m "docs(adr-002): record OAuth-leg SSRF hardening + dev-profile pin (PR-2a)"
```

---

## Self-Review

**Spec coverage:** §3.1 (guard 2 OAuth legs; token_endpoint before credentials) → Tasks 2-3; §3.2 (leg discriminator + refused_component kept + semantic widening) → Task 1; §3.3 (host-site recording; refresh guarded-but-unrecorded + drift pin) → Tasks 4-5; §3.4 (AST detector, named exemption) → Task 6; §3.5 (credential-exfil test) → Task 3; §3.6 (profile preserved) → Task 7; §4 (per-leg, credential-exfil, recording, AST, profile, semantic-widening doc, CC gate) → Tasks 1-7; §5 (scope boundary + honesty) → header + Task 7 ADR. No gaps.

**Type consistency:** `DiscoveryLeg` Literal defined in Task 1 and used identically at every call site (Tasks 1-3) and assertion; `_refuse_non_public_discovery_url(self, url, *, leg: DiscoveryLeg)` signature consistent throughout; `_record_discovery_status(*, tenant_id, server_id, status)` matches the verbatim PR-1 helper; `discovery_status_for_authz_reason` reused unchanged; the leg values are the same five strings everywhere.

**Placeholder scan:** Production code is exact at every insertion point (verbatim current code shown). The only delegated detail is the Task-4 `_host_with_step_up_raising` / `_drive_call_tool_into_step_up` local test helpers, which the implementer mirrors from the named existing classes `TestCallToolStepUpOn403InsufficientScope` + `TestDiscoveryStatusRecording` in `test_mcp_host.py` — flagged explicitly with the exact source class, not a silent TODO.
