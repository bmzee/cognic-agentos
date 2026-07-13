#!/usr/bin/env python3
"""Generate the M8.5-C proof Keycloak realm + its per-run credentials.

PROOF-ONLY. Nothing this script emits is ever committed: the realm JSON carries
the client secret and every user password, so the runner writes both artefacts
into the PRIVATE per-run directory (0700, `mktemp -d`, removed by the cleanup
trap) and ships the realm to Keycloak as a k8s **Secret**, never a ConfigMap.

Design spec §4 (identity topology) is the contract this file implements. The
three properties below are the security crux of the whole proof — each is
enforced here AND independently re-asserted against a REAL minted token by
``assert_claim_contract.py`` at runner preflight, because the spec forbids
resting an identity claim on folklore about a vendor default.

1. THE LOCKED GRANT PROFILE (spec §4, "Human identity derivation").
   ``cognic-harness`` enables the interactive Authorization Code flow and
   NOTHING else: ``directAccessGrantsEnabled=false`` (no
   resource-owner-password grant) and ``serviceAccountsEnabled=false`` (no
   client-credentials grant). ``cognic-agentos`` is a pure resource audience
   with every flow disabled — it never performs a browser login. A token
   accepted under this profile can only have come from a human interactive
   login, which is what licenses the reference binder to derive
   ``actor_type="human"``. Bar B proves the negative space by ATTEMPTING both
   disabled grants and requiring them to fail.

2. THE EXACT AUDIENCE ``{cognic-agentos}`` (spec §4; the binder refuses an
   over-broad ``aud`` with ``audience_not_exact``).
   Keycloak populates ``aud`` from two sources (server_admin/con-audience.adoc):
     * a HARDCODED ``oidc-audience-mapper`` — adds its audience unconditionally;
     * the ``oidc-audience-resolve-mapper`` in the built-in ``roles`` client
       scope — adds the client id of every client for which the token carries
       at least one CLIENT ROLE. This is the sole reason a stock Keycloak token
       carries ``"account"``: new users get ``default-roles-<realm>``, which
       composes the ``account`` client's roles.
   Three independent levers make the audience exactly ``{cognic-agentos}``, and
   any ONE of them suffices — they are applied together so a future Keycloak
   default cannot silently re-broaden the audience:
     (a) a hardcoded audience mapper supplies ``cognic-agentos``;
     (b) ``roles`` is REMOVED from the client's default scopes, so the
         audience-resolve mapper never runs at all;
     (c) every user is minted with NO realm roles and NO client roles, so
         audience-resolve would have nothing to resolve even if (b) regressed;
     (d) ``fullScopeAllowed=false`` on the client, so a stray role could not
         enter the token's scope in the first place.

3. THE ``at+jwt`` ACCESS-TOKEN HEADER TYPE (spec §4).
   Keycloak 26.2 added the client attribute ``access.token.header.type.rfc9068``
   (``OIDCConfigAttributes.USE_RFC9068_ACCESS_TOKEN_HEADER_TYPE``). The 26.2
   release note is explicit that **the setting is turned off by default** — so it
   is set here EXPLICITLY. This pins the RFC 9068 *header type* only; it does
   not claim the full RFC 9068 claim profile, and nothing in this proof does.
   The binder's structural ID-token rejection rests on this plus the audience:
   an ID token's header ``typ`` is ``JWT`` and its ``aud`` is the harness client.

Two further identity properties live here (enforced at generation, pinned by
``tests/unit/infra/test_proof_m85c_reference_binder.py``):

4. THE STABLE, ISSUER-QUALIFIED SUBJECT. Every user carries a DETERMINISTIC
   Keycloak user ``id`` (``uuid5`` over a fixed namespace + the username —
   realm import honours an explicit ``id``, and Keycloak's ``sub`` claim IS
   the user id), so the subject the reference binder binds —
   ``Actor.subject = <issuer>#<sub>`` — is known and reproducible BEFORE the
   realm boots. ``realm-subjects.env`` (written next to
   ``realm-credentials.env``) is the single source of truth for the bound
   subjects: the runner and the DB seed (``seed-db.sh`` renders the
   ``__SUBJECT_*__`` placeholders in ``kernel-seed.sql`` from it) both read
   it. ``Actor.subject`` keys data-scope entitlements and approval ORIGINATOR
   binding, so it is NEVER the MUTABLE ``preferred_username`` — a reassigned
   username must not inherit the old holder's authority.

5. THE ``wrong-audience`` NEGATIVE-PROBE SCOPE — OPTIONAL, never default.
   An optional client scope on ``cognic-harness`` carrying an
   ``oidc-audience-mapper`` that adds the hardcoded audience
   ``not-cognic-agentos`` to the ACCESS token. Requesting
   ``scope=openid wrong-audience`` yields ``aud = [cognic-agentos,
   not-cognic-agentos]`` — an otherwise-perfect token (correct ``azp``,
   correct ``typ``, valid signature, unexpired) that the binder MUST refuse
   with ``audience_not_exact``; the live proof exercises exactly that gate.
   Because the scope is OPTIONAL, the DEFAULT scope set (and therefore every
   ordinary login) still yields ``aud`` EXACTLY ``{cognic-agentos}`` — levers
   (a)-(d) above are untouched.

Two RUN-TIME realm capabilities (they make the LIVE session/identity cases
deterministic; they change nothing about the identity contract above):

6. THE PER-CLIENT ACCESS-TOKEN-LIFESPAN OVERRIDE HOME. ``cognic-harness``
   carries an EXPLICIT ``access.token.lifespan`` client attribute
   (``OIDCConfigAttributes.ACCESS_TOKEN_LIFESPAN``; seconds, as a STRING) set
   to the SAME value as the realm-wide ``accessTokenLifespan`` — behaviour is
   UNCHANGED by default; the attribute exists so the runner can TEMPORARILY
   shrink this one client's lifespan over the Admin REST API to make two live
   cases deterministic: the expired-token refusal (mint at ~10s, sleep, use —
   the binder must refuse ``token_expired``) and the concurrent-refresh case
   (~70s puts a fresh session immediately inside the BFF's 60s refresh
   margin). The committed default (900) is what the proof runs with normally.

7. THE REALM USER-EVENT LOG — the INDEPENDENT observer for "exactly one
   refresh". ``eventsEnabled`` + ``enabledEventTypes`` (``REFRESH_TOKEN`` and
   ``REFRESH_TOKEN_ERROR`` among them) make Keycloak record every
   refresh-token grant in its OWN event store, so the live proof can count
   them: the BFF's concurrent-refresh single-flight claim (exactly ONE winner
   across two replicas) is proven by an observer the BFF cannot influence — a
   stampede records N ``REFRESH_TOKEN`` events (and, under refresh-token
   rotation, ``REFRESH_TOKEN_ERROR`` s too). ADMIN events stay OFF: noise.

The claims the reference binder consumes (``overlay_reference/binder.py``) and
therefore the mappers this realm MUST emit into the ACCESS token:
    ``tenant_id``      — closed-shape string (the kernel tenant)
    ``cognic_scopes``  — JSON array of portal RBAC scope names, every value of
                         which must exist in the kernel's own exported scope
                         vocabulary (the binder refuses unknown values)
    ``preferred_username`` — the human-readable DISPLAY name only. MUTABLE and
                         reassignable in Keycloak, so it NEVER determines
                         ``Actor.subject``: the binder binds the
                         issuer-qualified ``sub`` (property 4 above) and the
                         kernel seed matrix keys on THAT
    ``azp``            — ``cognic-harness`` (the requesting client)

Usage:  gen_realm.py <out-dir> <bff-redirect-uri> <driver-loopback-redirect-uri>
Writes: <out-dir>/realm.json          (0600 — contains secrets)
        <out-dir>/realm-credentials.env (0600 — sourced by the runner)
        <out-dir>/realm-subjects.env  (0600 — one ``KC_SUB_<NAME>=<issuer>#<uuid>``
                                       line per identity; the single source of
                                       truth for the bound ``Actor.subject``)
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import uuid
from typing import Any, Final

#: The kernel tenant the proof drives, and the FOREIGN tenant whose reader must
#: see nothing of it (tenant isolation is the storage WHERE clause, not scopes).
TENANT: Final = "proof-m85c"
FOREIGN_TENANT: Final = "proof-foreign"

REALM: Final = "proof-m85c"
HARNESS_CLIENT: Final = "cognic-harness"
AGENTOS_AUDIENCE: Final = "cognic-agentos"

#: ONE hostname => ONE issuer string, everywhere. ``manifests/keycloak.yaml``
#: pins ``KC_HOSTNAME`` to this exact origin and ``run-proof-m85c.sh`` derives
#: the identical ``KC_ISSUER`` — the same string the reference binder validates
#: (``COGNIC_PROOF_M85C_OIDC_ISSUER``) and the same string this generator embeds
#: in every ``realm-subjects.env`` bound subject. Keycloak's issuer is always
#: ``<origin>/realms/<realm>``.
KEYCLOAK_ORIGIN: Final = "https://cognic-proof-keycloak:8443"
ISSUER: Final = f"{KEYCLOAK_ORIGIN}/realms/{REALM}"

#: uuid5 name prefix for the deterministic per-user Keycloak id (property 4).
#: LOCKED — changing it changes every bound subject, orphaning every seeded
#: entitlement and approval-originator row.
_SUBJECT_URN_PREFIX: Final = "urn:cognic:proof-m85c:"

#: The OPTIONAL negative-probe client scope (property 5) and the deliberately
#: wrong audience it injects. ``not-cognic-agentos`` names NO client in this
#: realm — the point is an otherwise-perfect token with an over-broad ``aud``.
WRONG_AUDIENCE_SCOPE: Final = "wrong-audience"
WRONG_AUDIENCE_VALUE: Final = "not-cognic-agentos"

#: Realm-wide access-token lifespan (seconds) AND — by construction, the same
#: constant — the committed default of the ``cognic-harness`` PER-CLIENT
#: ``access.token.lifespan`` override attribute (property 6). Keycloak reads the
#: client attribute first and falls back to the realm value, so with both equal
#: the override is a PURE toggle home: the runner shrinks the client attribute
#: at run time (Admin REST) for the expired-token / concurrent-refresh live
#: cases and restores it; nothing else ever notices it exists.
_ACCESS_TOKEN_LIFESPAN_S: Final = 900

#: USER event types persisted to Keycloak's event store (property 7). Setting
#: ``enabledEventTypes`` at all means ONLY these are saved — the two REFRESH_*
#: types are the load-bearing single-flight observer; the LOGIN/LOGOUT/
#: CODE_TO_TOKEN pairs are diagnostic context for reading a failed run. Every
#: name is an ``org.keycloak.events.EventType`` enum constant.
_REALM_EVENT_TYPES: Final = [
    "LOGIN",
    "LOGIN_ERROR",
    "LOGOUT",
    "LOGOUT_ERROR",
    "CODE_TO_TOKEN",
    "CODE_TO_TOKEN_ERROR",
    "REFRESH_TOKEN",
    "REFRESH_TOKEN_ERROR",
]


def stable_user_id(username: str) -> str:
    """The DETERMINISTIC Keycloak user id for ``username`` (property 4).

    ``uuid5`` over a fixed namespace, so the value is reproducible across runs
    and known before the realm boots. Keycloak realm import honours an explicit
    user ``id``, and the ``sub`` claim IS the user id.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{_SUBJECT_URN_PREFIX}{username}"))


def bound_subject(username: str) -> str:
    """The exact ``Actor.subject`` the reference binder binds for ``username``:
    the ISSUER-QUALIFIED stable ``sub`` (``<issuer>#<uuid>``). This is the value
    ``realm-subjects.env`` carries and the DB seed keys entitlements on."""
    return f"{ISSUER}#{stable_user_id(username)}"


def env_var_suffix(username: str) -> str:
    """Shell-safe env-var suffix shared by ``KC_PW_*`` / ``KC_SUB_*`` (and the
    seed's ``__SUBJECT_*__`` placeholders): analyst.amir -> ANALYST_AMIR."""
    return username.upper().replace(".", "_").replace("-", "_")


#: Client scopes attached to ``cognic-harness`` as DEFAULT (always in the token).
#: ``roles`` is DELIBERATELY ABSENT — see lever (b) in the module docstring. The
#: built-ins kept here are the ones the binder depends on and none of them
#: contributes an audience:
#:   basic       -> ``sub`` + ``auth_time``   (the binder requires a nonempty sub;
#:                  the issuer-qualified sub IS the Actor subject)
#:   profile     -> ``preferred_username``    (human-readable DISPLAY only —
#:                  MUTABLE, so it never determines the Actor subject)
#:   web-origins -> CORS origins only
#:   acr         -> ``acr`` only
_DEFAULT_CLIENT_SCOPES: Final = [
    "basic",
    "profile",
    "web-origins",
    "acr",
    "cognic-agentos-audience",
    "cognic-identity",
]

#: The eight PROOF IDENTITIES (spec §5.1). Every scope name below is verified
#: against the kernel's exported vocabulary by ``kernel_scope_allow_list()`` —
#: the binder REFUSES any value the kernel does not know, so a typo here fails
#: closed at bind time rather than silently granting nothing.
#:
#: NOTE — the inherited proof-m85 ``mcp`` SERVICE role is RETIRED, not ported.
#: The reference binder derives ``actor_type="human"`` from the locked grant
#: profile, and that profile has NO client-credentials grant (Bar B proves the
#: attempt fails), so a machine principal cannot exist in this proof. Its only
#: job — the warm-up ``list_tools`` probe — folds into ``analyst.amir``, who
#: carries ``mcp.tool.list`` for exactly that reason.
_CONVERSATION_SCOPES: Final = [
    "conversation.create",
    "conversation.read",
    "conversation.post_turn",
    "conversation.close",
]
#: amir and sara are deliberately SCOPE-IDENTICAL and TENANT-IDENTICAL. They
#: differ ONLY by subject — that is what makes Bar D.6 (originator isolation)
#: load-bearing: sara's replay of amir's granted request cannot be explained
#: away by a scope difference or by tenant invisibility.
_ANALYST_SCOPES: Final = [*_CONVERSATION_SCOPES, "mcp.tool.list", "mcp.tool.invoke"]
#: The four-eyes approvers. ``tool.approve.high_risk_custom`` is the tier the
#: probe pack declares (spec §6); ``tool.approve.observe`` is what renders the
#: queue. dana and erin are DISTINCT humans — ADR-014 four-eyes requires the
#: second approver to differ from the first.
_APPROVER_SCOPES: Final = ["tool.approve.high_risk_custom", "tool.approve.observe"]

IDENTITIES: Final[tuple[dict[str, Any], ...]] = (
    # --- SETUP identities: the governed operator pack lifecycle (M4 flow) -----
    {"username": "proof-m85c-author", "tenant": TENANT, "scopes": ["pack.submit"]},
    {
        # DISTINCT subject from the author so ADR-012 §17 role-separation passes.
        "username": "proof-m85c-reviewer",
        "tenant": TENANT,
        "scopes": [
            "pack.review.claim",
            "pack.review.approve",
            "pack.review.reject",
            "pack.override.approval_gate",
        ],
    },
    {
        "username": "proof-m85c-operator",
        "tenant": TENANT,
        "scopes": [
            "pack.allow_list",
            "pack.configure",
            "pack.install",
            "pack.disable",
            "pack.revoke",
            "pack.uninstall",
            "pack.audit.read",
        ],
    },
    # --- BAR identities -------------------------------------------------------
    # amir: the requester. Drives chat (Bar C) and originates the high-risk probe
    # call (Bar D). Holds NO approve scope, so he is also the NON-OBSERVER whose
    # approvals-screen request must render a governed 403 (Bar D.8).
    {"username": "analyst.amir", "tenant": TENANT, "scopes": list(_ANALYST_SCOPES)},
    # sara: same tenant, same MCP invocation authority, DIFFERENT subject.
    {"username": "analyst.sara", "tenant": TENANT, "scopes": list(_ANALYST_SCOPES)},
    # dana + erin: the two distinct four-eyes humans.
    {"username": "approver.dana", "tenant": TENANT, "scopes": list(_APPROVER_SCOPES)},
    {"username": "approver.erin", "tenant": TENANT, "scopes": list(_APPROVER_SCOPES)},
    # zara: fully-scoped reader in ANOTHER tenant. Carries tool.approve.observe so
    # her empty approvals queue proves tenant isolation rather than missing scope.
    {
        "username": "analyst.zara",
        "tenant": FOREIGN_TENANT,
        "scopes": [*_CONVERSATION_SCOPES, "tool.approve.observe"],
    },
)


def _password() -> str:
    """A per-run, per-user password. Never committed; written 0600 to the
    private per-run dir and consumed only by the scripted login flow."""
    return secrets.token_urlsafe(24)


def _client_scope(
    name: str,
    mappers: list[dict[str, Any]],
    description: str,
    *,
    include_in_token_scope: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "protocol": "openid-connect",
        "attributes": {
            # Default False — NOT in the `scope` request parameter / `scope`
            # claim: the DEFAULT scopes are internal claim carriers, not
            # resources the client asks for. The `wrong-audience` NEGATIVE-PROBE
            # scope overrides to True: it exists precisely to be REQUESTED
            # (`scope=openid wrong-audience`).
            "include.in.token.scope": "true" if include_in_token_scope else "false",
            "display.on.consent.screen": "false",
        },
        "protocolMappers": mappers,
    }


def build_realm(
    *,
    bff_redirect_uri: str,
    driver_redirect_uri: str,
    client_secret: str,
    passwords: dict[str, str],
) -> dict[str, Any]:
    users = []
    for identity in IDENTITIES:
        username = str(identity["username"])
        users.append(
            {
                # DETERMINISTIC, STABLE user id (property 4): realm import
                # honours an explicit `id`, and Keycloak's `sub` claim IS the
                # user id — so the issuer-qualified subject the binder binds
                # (`<issuer>#<sub>`) is known BEFORE the realm boots, and the
                # DB seed can key entitlements on it (realm-subjects.env).
                "id": stable_user_id(username),
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "email": f"{username}@bank.example",
                "attributes": {
                    # Keycloak user attributes are Map<String, List<String>>. The
                    # tenant mapper reads the single value; the scopes mapper is
                    # multivalued and emits a JSON array.
                    "tenant_id": [str(identity["tenant"])],
                    "cognic_scopes": list(identity["scopes"]),
                },
                # Lever (c): NO realm roles and NO client roles. Without
                # `default-roles-<realm>` the user holds no `account` client role,
                # so the audience-resolve mapper has nothing to resolve even if
                # the `roles` scope were re-attached.
                "realmRoles": [],
                "clientRoles": {},
                "credentials": [
                    {"type": "password", "value": passwords[username], "temporary": False}
                ],
            }
        )

    return {
        "realm": REALM,
        "enabled": True,
        # Keycloak serves HTTPS with the per-run proof CA (the TLS matrix, spec
        # §5.1): require TLS for every request, not just external ones.
        "sslRequired": "all",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "rememberMe": False,
        "loginWithEmailAllowed": False,
        # The proof pins the approval TTL above the worst-case browser-bar
        # duration (spec §5.1 "Four-eyes TTL") on the KERNEL side; realm token
        # lifespans are sized so a Playwright-paced bar never trips a token
        # expiry mid-flow. These are PROOF ergonomics, not product defaults.
        "accessTokenLifespan": _ACCESS_TOKEN_LIFESPAN_S,
        "ssoSessionIdleTimeout": 3600,
        "ssoSessionMaxLifespan": 7200,
        # --- the realm USER-event log (property 7) -------------------------
        # The INDEPENDENT observer for the concurrent-refresh live case: the
        # proof counts Keycloak's OWN REFRESH_TOKEN events to prove the BFF
        # single-flight has exactly ONE winner across two replicas. Key names
        # are the Keycloak RealmRepresentation fields (eventsEnabled /
        # eventsExpiration / enabledEventTypes / adminEventsEnabled /
        # adminEventsDetailsEnabled).
        "eventsEnabled": True,
        # Seconds a stored event survives; sized to outlive a ~40-minute proof
        # run with generous headroom.
        "eventsExpiration": 7200,
        "enabledEventTypes": list(_REALM_EVENT_TYPES),
        # ADMIN events are noise for this proof — explicitly OFF, pinned here
        # so a future Keycloak default cannot silently turn them on.
        "adminEventsEnabled": False,
        "adminEventsDetailsEnabled": False,
        "clientScopes": [
            _client_scope(
                "cognic-agentos-audience",
                [
                    {
                        # Lever (a): the HARDCODED audience. Unlike audience-resolve
                        # this does not depend on the user holding any client role.
                        "name": "agentos-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.client.audience": AGENTOS_AUDIENCE,
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "introspection.token.claim": "true",
                        },
                    }
                ],
                "Adds the AgentOS resource audience to the ACCESS token only.",
            ),
            _client_scope(
                "cognic-identity",
                [
                    {
                        "name": "tenant_id",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-attribute-mapper",
                        "config": {
                            "user.attribute": "tenant_id",
                            "claim.name": "tenant_id",
                            "jsonType.label": "String",
                            "multivalued": "false",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "userinfo.token.claim": "false",
                            "introspection.token.claim": "true",
                        },
                    },
                    {
                        "name": "cognic_scopes",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-attribute-mapper",
                        "config": {
                            "user.attribute": "cognic_scopes",
                            "claim.name": "cognic_scopes",
                            "jsonType.label": "String",
                            # multivalued -> a JSON array, which is what the
                            # binder's scopes-claim shape check requires.
                            "multivalued": "true",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "userinfo.token.claim": "false",
                            "introspection.token.claim": "true",
                        },
                    },
                ],
                "Carries the kernel tenant + the closed portal RBAC scope set.",
            ),
            _client_scope(
                WRONG_AUDIENCE_SCOPE,
                [
                    {
                        # Property 5: the NEGATIVE-PROBE audience. A CUSTOM
                        # (non-client) audience — `not-cognic-agentos` names no
                        # client in this realm, which is the point: requesting
                        # this OPTIONAL scope yields an otherwise-perfect token
                        # whose aud is [cognic-agentos, not-cognic-agentos], so
                        # the live proof can exercise the binder's EXACT-audience
                        # gate (audience_not_exact) in isolation.
                        "name": "wrong-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": WRONG_AUDIENCE_VALUE,
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "introspection.token.claim": "true",
                        },
                    }
                ],
                "NEGATIVE PROBE (optional, never default): broadens the ACCESS-token "
                "audience so the binder's exact-audience refusal can be exercised live.",
                include_in_token_scope=True,
            ),
        ],
        "clients": [
            {
                "clientId": HARNESS_CLIENT,
                "description": (
                    "The BFF. CONFIDENTIAL client, Authorization Code + PKCE (S256) ONLY. "
                    "The proof driver reuses this same client via a loopback redirect so "
                    "azp stays cognic-harness on every token the kernel ever sees."
                ),
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": client_secret,
                # --- THE LOCKED GRANT PROFILE (property 1) ---------------------
                "standardFlowEnabled": True,  # Authorization Code — the ONLY way in
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,  # no resource-owner password grant
                "serviceAccountsEnabled": False,  # no client-credentials grant
                # --------------------------------------------------------------
                # Lever (d): a stray role could not enter this client's scope.
                "fullScopeAllowed": False,
                "redirectUris": [bff_redirect_uri, driver_redirect_uri],
                "webOrigins": [bff_redirect_uri.rsplit("/", 2)[0]],
                "attributes": {
                    # PKCE is MANDATORY for this client — not merely offered.
                    "pkce.code.challenge.method": "S256",
                    # Property 3: OFF BY DEFAULT in Keycloak 26.2 — set explicitly.
                    "access.token.header.type.rfc9068": "true",
                    # Property 6: the PER-CLIENT lifespan override home
                    # (OIDCConfigAttributes.ACCESS_TOKEN_LIFESPAN; seconds, as a
                    # STRING). Committed default == the realm accessTokenLifespan
                    # (same constant), so behaviour is UNCHANGED by default — the
                    # attribute exists ONLY so the runner can TEMPORARILY shrink
                    # this client's token lifespan via the Admin REST API for the
                    # expired-token (~10s) and concurrent-refresh (~70s, inside
                    # the BFF's 60s refresh margin) live cases, then restore it.
                    "access.token.lifespan": str(_ACCESS_TOKEN_LIFESPAN_S),
                },
                # Lever (b): `roles` is absent -> the audience-resolve mapper that
                # would otherwise inject "account" never runs.
                "defaultClientScopes": list(_DEFAULT_CLIENT_SCOPES),
                # OPTIONAL (never default): the wrong-audience negative probe is
                # applied ONLY when a flow explicitly requests
                # `scope=openid wrong-audience`; the default token's audience
                # levers (a)-(d) are untouched and aud stays EXACTLY
                # {cognic-agentos} for every ordinary login.
                "optionalClientScopes": [WRONG_AUDIENCE_SCOPE],
            },
            {
                "clientId": AGENTOS_AUDIENCE,
                "description": (
                    "The AgentOS RESOURCE audience (the second OIDC entity, spec §4). "
                    "Never performs a browser login: every flow is disabled. It exists so "
                    "the audience mapper above has a real client id to name."
                ),
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": secrets.token_urlsafe(32),
                "standardFlowEnabled": False,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
                "redirectUris": [],
                "webOrigins": [],
            },
        ],
        "users": users,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: gen_realm.py <out-dir> <bff-redirect-uri> <driver-loopback-redirect-uri>",
            file=sys.stderr,
        )
        return 2
    out_dir, bff_redirect_uri, driver_redirect_uri = argv[1], argv[2], argv[3]

    client_secret = secrets.token_urlsafe(32)
    passwords = {str(i["username"]): _password() for i in IDENTITIES}
    realm = build_realm(
        bff_redirect_uri=bff_redirect_uri,
        driver_redirect_uri=driver_redirect_uri,
        client_secret=client_secret,
        passwords=passwords,
    )

    realm_path = os.path.join(out_dir, "realm.json")
    creds_path = os.path.join(out_dir, "realm-credentials.env")
    subjects_path = os.path.join(out_dir, "realm-subjects.env")

    # 0600 on ALL artefacts BEFORE any bytes land (open with mode, not chmod
    # after — a chmod-after leaves a window where the secret is world-readable).
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = stat.S_IRUSR | stat.S_IWUSR
    with os.fdopen(os.open(realm_path, flags, mode), "w", encoding="utf-8") as fh:
        json.dump(realm, fh, indent=2, sort_keys=False)
        fh.write("\n")

    lines = [f"KC_CLIENT_SECRET={client_secret}"]
    for username, password in passwords.items():
        # A shell-safe env var name per identity: analyst.amir -> KC_PW_ANALYST_AMIR
        lines.append(f"KC_PW_{env_var_suffix(username)}={password}")
    with os.fdopen(os.open(creds_path, flags, mode), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # The bound-subject map (property 4): KC_SUB_ANALYST_AMIR=<issuer>#<uuid5>.
    # Deterministic across runs (unlike the credentials above) — the single
    # source of truth for Actor.subject; the runner exports its path as
    # COGNIC_PROOF_M85C_REALM_SUBJECTS and seed-db.sh renders kernel-seed.sql's
    # __SUBJECT_<NAME>__ placeholders from it. Subjects are NOT secrets (they
    # ride in every token) but the file lives 0600 beside its siblings.
    subject_lines = [
        f"KC_SUB_{env_var_suffix(str(identity['username']))}"
        f"={bound_subject(str(identity['username']))}"
        for identity in IDENTITIES
    ]
    with os.fdopen(os.open(subjects_path, flags, mode), "w", encoding="utf-8") as fh:
        fh.write("\n".join(subject_lines) + "\n")

    print(
        f"  realm: {len(IDENTITIES)} identities (deterministic ids), 2 clients, "
        f"3 custom client scopes (wrong-audience OPTIONAL) -> {realm_path}"
    )
    print(f"  credentials (0600, per-run, never committed) -> {creds_path}")
    print(f"  bound subjects (0600, deterministic, <issuer>#<sub>) -> {subjects_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
