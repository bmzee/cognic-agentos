"""Reference OIDC binder (M8.5-C design §4) — the ten ruled requirements, each
load-bearing: header extraction, alg allow-list + at+jwt pre-parse, kid
resolution with single-flight background refresh (and NO refresh on a bad
signature), RS256 verification, exact issuer, EXACT audience set, the pinned
azp contract, strict finite time claims with skew, subject/tenant shape, and
the closed kernel scope vocabulary. Tokens are genuinely RS256-signed.

M8.5-C P2 remediation pins (2026-07-12) — the stable-subject coupling:

* ``Actor.subject`` is the ISSUER-QUALIFIED stable ``sub`` (``<issuer>#<sub>``).
  The MUTABLE ``preferred_username`` NEVER determines it — a reassigned
  username must not inherit the old holder's entitlements or replay their
  approval grants.
* Every refusal emits exactly ONE value-free WARNING with the stable greppable
  prefix ``reference_binder.refused reason=`` and never any token/claim
  material — the live proof greps the kernel pod log to tell WHICH gate fired.
* ``gen_realm.py``'s deterministic ``uuid5`` user ids + ``realm-subjects.env``
  are in lockstep with the binder's bound subject AND with
  ``kernel-seed.sql``'s ``__SUBJECT_*__`` entitlement placeholders (rendered
  fail-loud by ``seed-db.sh``); the ``wrong-audience`` negative-probe scope is
  OPTIONAL-only and the default-token audience levers hold.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from joserfc import jws
from joserfc.jwk import RSAKey
from starlette.datastructures import Headers
from starlette.requests import Request

from cognic_agentos.portal.rbac.actor import ActorBinderUnauthenticated

_REPO = Path(__file__).resolve().parents[3]
_PROOF = _REPO / "infra" / "proof-m85c"
_BINDER_PATH = _PROOF / "overlay_reference" / "binder.py"
_GEN_REALM_PATH = _PROOF / "keycloak" / "gen_realm.py"
_KERNEL_SEED_PATH = _PROOF / "kernel-seed.sql"
_SEED_DB_PATH = _PROOF / "seed-db.sh"


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    # register BEFORE exec so dataclasses' forward-ref resolution (the module
    # uses `from __future__ import annotations`) can find the module by name.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


_B = _load_module(_BINDER_PATH, "m85c_reference_binder")
_GEN = _load_module(_GEN_REALM_PATH, "m85c_gen_realm")

_ISSUER = "https://keycloak.proof/realms/proof-m85c"
_SUB = "8b7c0d1e-uuid"
#: The bound Actor.subject for `_claims()` defaults: the issuer-qualified sub.
_QUALIFIED_SUBJECT = f"{_ISSUER}#{_SUB}"
_KEY = RSAKey.generate_key(2048, parameters={"kid": "proof-key"}, private=True)
_JWKS = {"keys": [_KEY.as_dict(private=False)]}


def _now() -> int:
    return int(datetime.now(tz=UTC).timestamp())


def _claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": "cognic-agentos",
        "azp": "cognic-harness",
        "sub": _SUB,
        "preferred_username": "analyst.amir",
        "tenant_id": "proof-m85c",
        "cognic_scopes": ["conversation.create", "conversation.read"],
        "iat": _now(),
        "exp": _now() + 300,
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not ...}


def _mint(
    claims: dict[str, Any],
    *,
    key: RSAKey = _KEY,
    typ: str = "at+jwt",
    kid: str | None = "proof-key",
) -> str:
    header: dict[str, Any] = {"alg": "RS256", "typ": typ}
    if kid is not None:
        header["kid"] = kid
    return jws.serialize_compact(header, json.dumps(claims).encode(), key)


def _request(token: str | None) -> Request:
    headers = Headers({} if token is None else {"Authorization": f"Bearer {token}"})
    return Request({"type": "http", "headers": headers.raw})


def _binder(*, refresh_fn: Any = None, min_refresh_interval_s: float = 5.0) -> Any:
    config = _B.ReferenceBinderConfig(
        issuer=_ISSUER, jwks_min_refresh_interval_s=min_refresh_interval_s
    )
    cache = _B._JwksCache(_JWKS, refresh_fn or (lambda: _JWKS))
    # the initial install stamps last-refresh; rewind it so unknown-kid tests
    # exercise the trigger without waiting out the stampede floor.
    cache._last_refresh_monotonic = 0.0
    return _B.ReferenceOidcBinder(config=config, jwks_cache=cache)


def _refused(binder: Any, token: str | None) -> str:
    with pytest.raises(ActorBinderUnauthenticated) as excinfo:
        binder.bind(request=_request(token))
    return str(excinfo.value)


# --- happy paths ----------------------------------------------------------------


def test_binds_human_actor_with_kernel_scopes() -> None:
    actor = _binder().bind(request=_request(_mint(_claims())))
    # ISSUER-QUALIFIED stable sub — NEVER the mutable preferred_username.
    assert actor.subject == _QUALIFIED_SUBJECT
    assert actor.tenant_id == "proof-m85c"
    assert actor.scopes == frozenset({"conversation.create", "conversation.read"})
    assert actor.actor_type == "human"


def test_audience_accepts_exact_single_element_array() -> None:
    actor = _binder().bind(request=_request(_mint(_claims(aud=["cognic-agentos"]))))
    assert actor.actor_type == "human"


def test_subject_is_issuer_qualified_sub_without_preferred_username() -> None:
    actor = _binder().bind(request=_request(_mint(_claims(preferred_username=...))))
    assert actor.subject == _QUALIFIED_SUBJECT


def test_preferred_username_never_determines_the_subject() -> None:
    """A username REASSIGNMENT (the P2 finding) must not move the subject: two
    tokens differing ONLY in preferred_username bind the IDENTICAL sub-derived
    subject, and the username value appears nowhere in it."""
    baseline = _binder().bind(request=_request(_mint(_claims())))
    reassigned = _binder().bind(
        request=_request(_mint(_claims(preferred_username="mallory.new-holder")))
    )
    assert baseline.subject == reassigned.subject == _QUALIFIED_SUBJECT
    assert "analyst.amir" not in baseline.subject
    assert "mallory.new-holder" not in reassigned.subject
    # And a non-string preferred_username changes nothing either (it is IGNORED
    # for the subject, not shape-validated as a subject source).
    odd = _binder().bind(request=_request(_mint(_claims(preferred_username=123))))
    assert odd.subject == _QUALIFIED_SUBJECT


def test_absent_scopes_claim_binds_empty_scope_set() -> None:
    actor = _binder().bind(request=_request(_mint(_claims(cognic_scopes=...))))
    assert actor.scopes == frozenset()


def test_caller_supplied_actor_type_claim_never_decides() -> None:
    actor = _binder().bind(request=_request(_mint(_claims(actor_type="service"))))
    assert actor.actor_type == "human"  # the locked grant profile decides, not a claim


# --- 1. bearer extraction ---------------------------------------------------------


def test_missing_authorization_refused() -> None:
    assert _refused(_binder(), None) == "bearer_missing"


def test_non_bearer_scheme_refused() -> None:
    binder = _binder()
    request = Request({"type": "http", "headers": Headers({"Authorization": "Basic dXNlcg=="}).raw})
    with pytest.raises(ActorBinderUnauthenticated) as excinfo:
        binder.bind(request=request)
    assert str(excinfo.value) == "bearer_missing"


# --- 2. pre-parse: alg allow-list + at+jwt ----------------------------------------


def test_malformed_token_refused() -> None:
    assert _refused(_binder(), "not-a-jwt") == "token_malformed"


def test_alg_swap_refused_before_any_crypto() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS512", "typ": "at+jwt", "kid": "proof-key"}).encode()
    ).rstrip(b"=")
    fake = header.decode() + ".e30.c2ln"  # never reaches signature verification
    assert _refused(_binder(), fake) == "alg_not_allowed"


def test_id_token_typ_refused() -> None:
    # a REAL RS256-signed token whose header typ is JWT — the ID-token shape.
    token = _mint(_claims(aud="cognic-harness"), typ="JWT")
    assert _refused(_binder(), token) == "typ_not_at_jwt"


# --- 3. kid resolution + single-flight refresh -------------------------------------


def test_missing_kid_refused() -> None:
    assert _refused(_binder(), _mint(_claims(), kid=None)) == "kid_missing"


def test_unknown_kid_fails_closed_and_triggers_one_refresh() -> None:
    calls = {"n": 0}
    gate = threading.Event()

    def refresh() -> dict[str, Any]:
        calls["n"] += 1
        gate.wait(timeout=2)
        return _JWKS

    binder = _binder(refresh_fn=refresh, min_refresh_interval_s=0.0)
    rotated = RSAKey.generate_key(2048, parameters={"kid": "rotated-key"}, private=True)
    token = jws.serialize_compact(
        {"alg": "RS256", "typ": "at+jwt", "kid": "rotated-key"},
        json.dumps(_claims()).encode(),
        rotated,
    )
    assert _refused(binder, token) == "kid_unknown"  # the request fails CLOSED
    assert _refused(binder, token) == "kid_unknown"  # second request: refresh in flight
    gate.set()
    deadline = time.monotonic() + 2
    while calls["n"] == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert calls["n"] == 1  # SINGLE-flight: exactly one background refresh


def test_bad_signature_never_triggers_refresh() -> None:
    calls = {"n": 0}

    def refresh() -> dict[str, Any]:
        calls["n"] += 1
        return _JWKS

    binder = _binder(refresh_fn=refresh, min_refresh_interval_s=0.0)
    attacker = RSAKey.generate_key(2048, parameters={"kid": "proof-key"}, private=True)
    forged = jws.serialize_compact(
        {"alg": "RS256", "typ": "at+jwt", "kid": "proof-key"},
        json.dumps(_claims()).encode(),
        attacker,
    )
    assert _refused(binder, forged) == "signature_invalid"
    time.sleep(0.05)
    assert calls["n"] == 0  # never refresh on an ordinary bad signature


# --- 5-7. issuer / audience / azp ---------------------------------------------------


def test_issuer_mismatch_refused() -> None:
    token = _mint(_claims(iss="https://evil/realms/x"))
    assert _refused(_binder(), token) == "issuer_mismatch"


def test_wrong_audience_refused() -> None:
    assert _refused(_binder(), _mint(_claims(aud="cognic-harness"))) == "audience_not_exact"


def test_over_broad_audience_refused() -> None:
    token = _mint(_claims(aud=["cognic-agentos", "account"]))
    assert _refused(_binder(), token) == "audience_not_exact"


def test_malformed_audience_refused() -> None:
    assert _refused(_binder(), _mint(_claims(aud=123))) == "audience_malformed"


def test_azp_mismatch_refused() -> None:
    assert _refused(_binder(), _mint(_claims(azp="other-client"))) == "azp_mismatch"
    assert _refused(_binder(), _mint(_claims(azp=...))) == "azp_mismatch"


# --- 8. time claims -----------------------------------------------------------------


def test_expired_refused() -> None:
    token = _mint(_claims(exp=_now() - 3600, iat=_now() - 7200))
    assert _refused(_binder(), token) == "token_expired"


def test_bool_exp_refused() -> None:
    assert _refused(_binder(), _mint(_claims(exp=True))) == "token_expired"


def test_missing_iat_refused() -> None:
    assert _refused(_binder(), _mint(_claims(iat=...))) == "iat_invalid"


def test_future_iat_refused() -> None:
    assert _refused(_binder(), _mint(_claims(iat=_now() + 3600))) == "iat_invalid"


def test_future_or_malformed_nbf_refused() -> None:
    assert _refused(_binder(), _mint(_claims(nbf=_now() + 3600))) == "nbf_invalid"
    assert _refused(_binder(), _mint(_claims(nbf="soon"))) == "nbf_invalid"


# --- 9. subject + tenant --------------------------------------------------------------


def test_missing_empty_or_non_string_sub_refused() -> None:
    # preferred_username stays PRESENT in every case: it must never rescue a
    # bad `sub` into a bound subject.
    assert _refused(_binder(), _mint(_claims(sub=...))) == "subject_missing"
    assert _refused(_binder(), _mint(_claims(sub=""))) == "subject_missing"
    assert _refused(_binder(), _mint(_claims(sub=12345))) == "subject_missing"


def test_missing_or_malformed_tenant_refused() -> None:
    assert _refused(_binder(), _mint(_claims(tenant_id=...))) == "tenant_claim_invalid"
    assert _refused(_binder(), _mint(_claims(tenant_id="Bad_Tenant!"))) == ("tenant_claim_invalid")


# --- 10. closed scope vocabulary -------------------------------------------------------


def test_non_list_scopes_claim_refused() -> None:
    assert _refused(_binder(), _mint(_claims(cognic_scopes="conversation.read"))) == (
        "scopes_claim_malformed"
    )
    assert _refused(_binder(), _mint(_claims(cognic_scopes=[123]))) == ("scopes_claim_malformed")


def test_unknown_scope_value_refused() -> None:
    token = _mint(_claims(cognic_scopes=["conversation.read", "made.up.scope"]))
    assert _refused(_binder(), token) == "scope_not_in_vocabulary"


def test_kernel_scope_allow_list_is_the_kernel_vocabulary() -> None:
    allowed = _B.kernel_scope_allow_list()
    for expected in (
        "conversation.create",
        "conversation.read",
        "conversation.post_turn",
        "tool.approve.observe",
        "tool.approve.high_risk_custom",
        "pack.submit",
        "mcp.tool.invoke",
    ):
        assert expected in allowed
    assert "made.up.scope" not in allowed


# --- startup discovery (build_reference_binder) ----------------------------------------


def _discovery_doc(**overrides: Any) -> dict[str, Any]:
    doc = {
        "issuer": _ISSUER,
        "authorization_endpoint": f"{_ISSUER}/protocol/openid-connect/auth",
        "token_endpoint": f"{_ISSUER}/protocol/openid-connect/token",
        "jwks_uri": f"{_ISSUER}/protocol/openid-connect/certs",
    }
    doc.update(overrides)
    return doc


def test_build_binder_end_to_end_via_discovery() -> None:
    with respx.mock:
        respx.get(f"{_ISSUER}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_discovery_doc())
        )
        respx.get(f"{_ISSUER}/protocol/openid-connect/certs").mock(
            return_value=httpx.Response(200, json=_JWKS)
        )
        binder = _B.build_reference_binder(issuer=_ISSUER)
    actor = binder.bind(request=_request(_mint(_claims())))
    assert actor.subject == _QUALIFIED_SUBJECT


def test_build_binder_rejects_discovery_issuer_mismatch() -> None:
    with respx.mock:
        respx.get(f"{_ISSUER}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=_discovery_doc(issuer="https://evil"))
        )
        with pytest.raises(RuntimeError, match="issuer mismatch"):
            _B.build_reference_binder(issuer=_ISSUER)


def test_build_binder_rejects_jwks_scheme_downgrade() -> None:
    with respx.mock:
        respx.get(f"{_ISSUER}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200,
                json=_discovery_doc(jwks_uri="http://keycloak.proof/certs"),
            )
        )
        with pytest.raises(RuntimeError, match="scheme downgrade"):
            _B.build_reference_binder(issuer=_ISSUER)


# --- refusal logging (value-free, greppable — the live proof greps for it) ---------

_REFUSED_LOG_PREFIX = "reference_binder.refused reason="


def _refusal_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith(_REFUSED_LOG_PREFIX)]


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ({"iss": "https://evil/realms/x"}, "issuer_mismatch"),
        ({"aud": ["cognic-agentos", "not-cognic-agentos"]}, "audience_not_exact"),
        ({"azp": "other-client"}, "azp_mismatch"),
        ({"sub": ""}, "subject_missing"),
        ({"cognic_scopes": ["conversation.read", "made.up.scope"]}, "scope_not_in_vocabulary"),
    ],
)
def test_each_refusal_emits_exactly_one_greppable_warning(
    caplog: pytest.LogCaptureFixture, mutation: dict[str, Any], expected_reason: str
) -> None:
    token = _mint(_claims(**mutation))
    with caplog.at_level(logging.WARNING):
        assert _refused(_binder(), token) == expected_reason
    records = _refusal_records(caplog)
    assert len(records) == 1, "exactly ONE refusal log line per refused bind"
    record = records[0]
    assert record.levelno == logging.WARNING
    # EXACT message equality: the stable greppable literal + the reason and
    # NOTHING else — no token, no subject, no username, no claim value.
    assert record.getMessage() == f"{_REFUSED_LOG_PREFIX}{expected_reason}"


def test_bearer_missing_refusal_is_logged_too(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        assert _refused(_binder(), None) == "bearer_missing"
    records = _refusal_records(caplog)
    assert len(records) == 1
    assert records[0].getMessage() == f"{_REFUSED_LOG_PREFIX}bearer_missing"


def test_refusal_log_carries_no_token_or_claim_material(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refusal fires DEEP in the chain (full claims already decoded) and the
    emitted records must still carry zero token/claim material — the raw token,
    the username, the sub and the tenant value appear NOWHERE in any record."""
    token = _mint(_claims(azp="other-client"))
    with caplog.at_level(logging.DEBUG):
        assert _refused(_binder(), token) == "azp_mismatch"
    assert _refusal_records(caplog), "the refusal must be logged"
    for record in caplog.records:
        # vars() sweep catches `extra=` smuggling, not just the message.
        blob = record.getMessage() + " " + str(vars(record))
        assert token not in blob
        assert "analyst.amir" not in blob
        assert _SUB not in blob
        # The tenant VALUE must not ride the message. (vars() includes the
        # binder file's path, which contains the string "proof-m85c" for an
        # unrelated reason — the directory name — so pin the message only.)
        assert "proof-m85c" not in record.getMessage()


# --- the stable-subject coupling: gen_realm -> realm-subjects.env -> kernel seed ----
#
# The binder binds `<issuer>#<sub>`; the DB seed keys entitlements by the SAME
# string. These pins hold the whole chain in lockstep: the LOCKED uuid5
# derivation, the deterministic realm-subjects.env, the realm.json user ids,
# the binder's composition rule, and kernel-seed.sql's placeholders.

_REALM_GEN_ARGS = (
    "https://cognic-proof-harness:8443/auth/callback",
    "http://127.0.0.1:47113/proof-driver-callback",
)


def _generate_realm_artifacts(out_dir: Path) -> None:
    rc = _GEN.main(["gen_realm.py", str(out_dir), *_REALM_GEN_ARGS])
    assert rc == 0


def _parse_env(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in path.read_text().strip().splitlines():
        var, _, value = raw.partition("=")
        parsed[var] = value
    return parsed


def test_gen_realm_user_ids_pin_the_locked_uuid5_derivation() -> None:
    """INDEPENDENT recomputation (not a call-it-twice tautology): the namespace
    + URN template are LOCKED — changing either orphans every seeded row."""
    for identity in _GEN.IDENTITIES:
        username = str(identity["username"])
        expected = str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:cognic:proof-m85c:{username}"))
        assert _GEN.stable_user_id(username) == expected
        assert _GEN.bound_subject(username) == f"{_GEN.ISSUER}#{expected}"


def test_gen_realm_issuer_matches_the_keycloak_manifest_hostname() -> None:
    """gen_realm embeds the issuer into every bound subject; the manifest's
    KC_HOSTNAME is what makes Keycloak SERVE that issuer. Drift here would seed
    subjects no token ever binds."""
    manifest = (_PROOF / "manifests" / "keycloak.yaml").read_text()
    assert f'value: "{_GEN.KEYCLOAK_ORIGIN}"' in manifest, (
        "manifests/keycloak.yaml KC_HOSTNAME must pin the exact origin gen_realm embeds"
    )
    expected_issuer = f"{_GEN.KEYCLOAK_ORIGIN}/realms/proof-m85c"
    assert expected_issuer == _GEN.ISSUER


def test_realm_subjects_env_is_deterministic_and_matches_the_realm_ids(
    tmp_path: Path,
) -> None:
    out_a, out_b = tmp_path / "a", tmp_path / "b"
    out_a.mkdir()
    out_b.mkdir()
    _generate_realm_artifacts(out_a)
    _generate_realm_artifacts(out_b)
    subjects_a = (out_a / "realm-subjects.env").read_text()
    subjects_b = (out_b / "realm-subjects.env").read_text()
    # Deterministic ACROSS runs (credentials differ per run; subjects must not).
    assert subjects_a == subjects_b
    assert stat.S_IMODE((out_a / "realm-subjects.env").stat().st_mode) == 0o600
    realm: dict[str, Any] = json.loads((out_a / "realm.json").read_text())
    lines = _parse_env(out_a / "realm-subjects.env")
    assert len(lines) == len(realm["users"]) == 8
    for user in realm["users"]:
        username = str(user["username"])
        # (a) every user carries the deterministic id...
        assert user["id"] == _GEN.stable_user_id(username)
        # ...and (b) the KC_SUB_* line is EXACTLY `<issuer>#<that id>`.
        var = "KC_SUB_" + _GEN.env_var_suffix(username)
        assert lines[var] == f"{_GEN.ISSUER}#{user['id']}"
        assert lines[var] == _GEN.bound_subject(username)


def test_binder_binds_exactly_the_subject_the_db_seed_reads(tmp_path: Path) -> None:
    """THE coupling pin of the P2 remediation: a real bind() against the realm's
    pinned issuer yields byte-for-byte the KC_SUB_* value seed-db.sh renders
    into the entitlements rows."""
    _generate_realm_artifacts(tmp_path)
    seeded = _parse_env(tmp_path / "realm-subjects.env")["KC_SUB_ANALYST_AMIR"]
    config = _B.ReferenceBinderConfig(issuer=_GEN.ISSUER)
    binder = _B.ReferenceOidcBinder(config=config, jwks_cache=_B._JwksCache(_JWKS, lambda: _JWKS))
    token = _mint(_claims(iss=_GEN.ISSUER, sub=_GEN.stable_user_id("analyst.amir")))
    actor = binder.bind(request=_request(token))
    assert actor.subject == seeded == _GEN.bound_subject("analyst.amir")


def test_wrong_audience_scope_is_optional_only_and_default_levers_hold(
    tmp_path: Path,
) -> None:
    _generate_realm_artifacts(tmp_path)
    realm: dict[str, Any] = json.loads((tmp_path / "realm.json").read_text())
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    # (c) attached as OPTIONAL — and NEVER default.
    assert harness["optionalClientScopes"] == ["wrong-audience"]
    assert "wrong-audience" not in harness["defaultClientScopes"]
    # (b) the default-token audience levers hold byte-for-byte: same default
    # scope set as before the probe scope landed (no `roles`), and the
    # hardcoded cognic-agentos audience mapper still present.
    assert harness["defaultClientScopes"] == [
        "basic",
        "profile",
        "web-origins",
        "acr",
        "cognic-agentos-audience",
        "cognic-identity",
    ]
    assert harness["fullScopeAllowed"] is False
    scope = next(s for s in realm["clientScopes"] if s["name"] == "wrong-audience")
    mapper = scope["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    # A CUSTOM audience (`not-cognic-agentos` names no client) on the ACCESS token.
    assert mapper["config"]["included.custom.audience"] == "not-cognic-agentos"
    assert mapper["config"]["access.token.claim"] == "true"
    # Requestable: `scope=openid wrong-audience` must reach the token.
    assert scope["attributes"]["include.in.token.scope"] == "true"
    # The wrong audience must not leak into any DEFAULT scope's mappers.
    for default_scope in realm["clientScopes"]:
        if default_scope["name"] in harness["defaultClientScopes"]:
            assert "not-cognic-agentos" not in json.dumps(default_scope)


def test_kernel_seed_keys_entitlements_by_placeholder_not_username() -> None:
    sql = _KERNEL_SEED_PATH.read_text()
    placeholders = set(re.findall(r"__SUBJECT_([A-Z0-9_]+)__", sql))
    assert placeholders == {"ANALYST_AMIR", "ANALYST_SARA"}
    # Every placeholder suffix corresponds to a real generated identity's
    # KC_SUB_* var suffix (seed <-> generator lockstep, test-only drift pin).
    identity_suffixes = {_GEN.env_var_suffix(str(i["username"])) for i in _GEN.IDENTITIES}
    assert placeholders <= identity_suffixes
    # The MUTABLE usernames are no longer SQL string literals anywhere.
    assert "'analyst.amir'" not in sql
    assert "'analyst.sara'" not in sql
    # Two entitlement rows per analyst ride the placeholders.
    assert sql.count("'__SUBJECT_ANALYST_AMIR__'") == 2
    assert sql.count("'__SUBJECT_ANALYST_SARA__'") == 2


# --- seed-db.sh renders the placeholders FAIL-LOUD (no cluster needed: every ---------
# --- refusal below exits BEFORE any kubectl invocation) ------------------------------


def _run_seed_db(subjects_env: str | None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("COGNIC_PROOF_M85C_REALM_SUBJECTS", None)
    if subjects_env is not None:
        env["COGNIC_PROOF_M85C_REALM_SUBJECTS"] = subjects_env
    return subprocess.run(
        ["bash", str(_SEED_DB_PATH)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_seed_db_fails_loud_without_the_subjects_env_var() -> None:
    result = _run_seed_db(None)
    assert result.returncode != 0
    assert "COGNIC_PROOF_M85C_REALM_SUBJECTS" in result.stderr


def test_seed_db_fails_loud_when_the_subjects_file_is_missing(tmp_path: Path) -> None:
    result = _run_seed_db(str(tmp_path / "does-not-exist.env"))
    assert result.returncode != 0
    assert "not a file" in result.stderr


def test_seed_db_dies_on_an_unsubstituted_placeholder(tmp_path: Path) -> None:
    """A partial realm-subjects.env (sara's line missing) must die NAMING the
    surviving placeholder — a literal __SUBJECT_*__ string seeded as a subject
    would make every entitlement check fail confusingly downstream."""
    partial = tmp_path / "realm-subjects.env"
    partial.write_text(f"KC_SUB_ANALYST_AMIR={_GEN.bound_subject('analyst.amir')}\n")
    result = _run_seed_db(str(partial))
    assert result.returncode != 0
    assert "__SUBJECT_ANALYST_SARA__" in result.stderr
    # amir's placeholder WAS rendered — only sara's survives.
    assert "__SUBJECT_ANALYST_AMIR__" not in result.stderr
