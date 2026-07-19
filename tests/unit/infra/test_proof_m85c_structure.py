"""Structural pins for the ``infra/proof-m85c/`` tree (M8.5-C live proof).

M8.5-C carries the proven M8.5-A/B bring-up forward (the same seven signed
packs, the same M4 operator lifecycle, the same seed matrix, the same
conversation substrate) and adds the Cognic Harness v1 surface: a real OIDC
identity path (Keycloak + the reference binder, replacing the retired
``X-Proof-Role`` header binder), a TLS matrix, the paginated approvals surface,
and the four-eyes approval probe.

This suite pins the M8.5-C DELTAS — the places where a regression would either
open a governance hole or make a bar pass vacuously. The carried-forward
bring-up (pack staging, trust roots, Oracle/Vault/litellm) mirrors the proven
``infra/proof-m85/`` tree; its invariants are pinned by that tree's suite and by
the live run, and are not re-duplicated here.

The load-bearing deltas, each with a test:

* **No fallback (spec §4).** The ``X-Proof-Role`` binder is deleted, not gated —
  no ``X-Proof-Role`` header, no ``MultiActorProofBinder``, no
  ``PROOF_ROLE_HEADER`` anywhere in the proof code paths. Identity arrives ONLY
  as a real Keycloak token verified by the reference binder.
* **The locked grant profile + exact audience (spec §4).** The generated realm
  disables the client-credentials and direct-access grants, sets the RFC 9068
  ``at+jwt`` header type explicitly (off by default in Keycloak 26.2), and pins
  the audience to EXACTLY ``{cognic-agentos}`` via four independent levers.
* **The live session-case realm levers.** The harness client carries an
  explicit per-client ``access.token.lifespan`` override home (committed EQUAL
  to the realm default — a pure runtime toggle for the expired-token and
  concurrent-refresh live cases), and the realm USER-event log is ON with both
  ``REFRESH_TOKEN`` / ``REFRESH_TOKEN_ERROR`` types so Keycloak's own event
  store can serve as the independent exactly-one-refresh observer.
* **Realm ↔ runner ↔ kernel scope lockstep.** Every scope the realm mints exists
  in the kernel's own exported vocabulary, and the runner's identity→scope map
  matches the realm generator's — so a scope drift fails HERE, not 30 minutes
  into a live bar.
* **The claim-contract preflight bites.** The asserter that runs before any bar
  catches the exact realm regressions (typ dropped, audience broadened, scope
  shape) that would otherwise make every request 403 identically.
* **The TLS matrix.** AgentOS terminates TLS; the CA is one per-run root; no
  ``verify=False``/``-k`` on the identity path; the kernel image copies the
  reference-binder overlay so the factory can import it.
* **Key custody carries forward.** No private-key material and no bypass flags
  anywhere in the tree; the realm (client secret + passwords) is a Secret, never
  a ConfigMap or a committed file.
* **The kernel is untouched.** ``protocol/mcp_authz.py`` is byte-identical to
  ``main`` and the migration head is ``0017``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[3]
_PROOF = _REPO / "infra" / "proof-m85c"
_RUNNER = _PROOF / "run-proof-m85c.sh"
_PROOF_APP = _PROOF / "proof_m85c" / "proof_app.py"

# AGENTS.md-locked digest of protocol/mcp_authz.py (the M4/M5 standing byte-lock).
_MCP_AUTHZ_PATH = _REPO / "src" / "cognic_agentos" / "protocol" / "mcp_authz.py"
_MCP_AUTHZ_LOCKED_SHA256 = "3a9724d3891f11b539f141d888bb8e8318f25b73cd7820ea5b11830b364ffaac"
_GEN_REALM = _PROOF / "keycloak" / "gen_realm.py"
_PKCE = _PROOF / "keycloak" / "pkce_login.py"
_ASSERT_CLAIM = _PROOF / "keycloak" / "assert_claim_contract.py"
_MINT_PKI = _PROOF / "mint-pki.sh"
_KEYCLOAK_YAML = _PROOF / "manifests" / "keycloak.yaml"
_ORACLE_DB_YAML = _PROOF / "manifests" / "oracle-db.yaml"
_ORACLE_PACK_YAML = _PROOF / "manifests" / "oracle-pack.yaml"
_ORACLE_SEED = _PROOF / "oracle-seed" / "seed_schema.sql"
_KERNEL_SEED = _PROOF / "kernel-seed.sql"


def _load(path: Path, name: str) -> ModuleType:
    """Import a proof-tree module by path (it is not on the package path). The
    spec name must be registered in ``sys.modules`` BEFORE ``exec_module`` so
    that ``from __future__ import annotations`` dataclass forward-refs resolve."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# --- existence + shape -------------------------------------------------------------


def test_proof_dir_carries_the_m85c_identity_file_set() -> None:
    for rel in (
        "run-proof-m85c.sh",
        "mint-pki.sh",
        "manifests/keycloak.yaml",
        "keycloak/gen_realm.py",
        "keycloak/pkce_login.py",
        "keycloak/assert_claim_contract.py",
        "proof_m85c/proof_app.py",
        "overlay_reference/binder.py",
        "overlay_reference/__init__.py",
    ):
        assert (_PROOF / rel).is_file(), f"missing proof asset {rel}"


def test_identity_scripts_are_executable() -> None:
    import os

    for path in (_RUNNER, _MINT_PKI, _GEN_REALM, _PKCE, _ASSERT_CLAIM):
        assert os.access(path, os.X_OK), f"{path.name} is not executable"


# --- Oracle Free substrate (D3 Task 8) -------------------------------------------


def test_oracle_free_substrate_is_multi_arch_digest_pinned() -> None:
    text = _ORACLE_DB_YAML.read_text()
    image = re.search(r"image:\s*(gvenzl/oracle-free@sha256:[0-9a-f]{64})", text)

    assert image is not None, "Oracle Free must use an immutable manifest-list digest"
    assert (
        image.group(1) == "gvenzl/oracle-free@sha256:"
        "fbbd3023d5abc33e36d3814816e6fd740e8efabeaa70cf470ddeab5874a3f6f8"
    )
    assert "Oracle AI Database 26ai Free Release 23.26.2.0.0" in text
    assert re.search(r"name:\s*ORACLE_DATABASE\b", text) is None
    assert "FREEPDB1" in text


def test_oracle_free_names_and_dsn_replace_xe_everywhere_live() -> None:
    assert not (_PROOF / "manifests" / "oracle-xe.yaml").exists()
    assert _ORACLE_DB_YAML.is_file()

    live_text = "\n".join(
        [
            _RUNNER.read_text(),
            *(path.read_text() for path in sorted((_PROOF / "manifests").glob("*.yaml"))),
        ]
    )
    assert "oracle-xe" not in live_text
    assert "wait-for-xe" not in live_text
    assert "XEPDB1" not in live_text
    assert "oracle-db:1521/FREEPDB1" in _ORACLE_PACK_YAML.read_text()
    assert "nc -z oracle-db 1521" in _ORACLE_PACK_YAML.read_text()
    assert "ALTER SESSION SET CONTAINER = FREEPDB1;" in _ORACLE_SEED.read_text()


def test_runner_prepulls_and_applies_the_pinned_oracle_free_substrate() -> None:
    text = _RUNNER.read_text()
    pinned = (
        "gvenzl/oracle-free@sha256:fbbd3023d5abc33e36d3814816e6fd740e8efabeaa70cf470ddeab5874a3f6f8"
    )

    assert pinned in text
    assert "create configmap oracle-db-seed" in text
    assert "manifests/oracle-db.yaml" in text
    assert "app=oracle-db" in text


# --- Oracle sample schemas + six-scope governed surface (M8.5-E Task 1) ----------


_SAMPLE_SCHEMA_URL = (
    "https://github.com/oracle-samples/db-sample-schemas/archive/refs/tags/v23.3.tar.gz"
)
_SAMPLE_SCHEMA_SHA256 = "94d47c97fb71227f88bfc01100b07de4622d7db592dec74f2d581f4fb9cbe509"
_SAMPLE_INIT_FILES = (
    "01_oracle_samples_hr.sql",
    "02_oracle_samples_co.sql",
    "03_oracle_samples_sh.sql",
    "10_seed_schema.sql",
)
_NEW_SCOPE_VIEWS = {
    "hr": {
        "HR.V_EMPLOYEES",
        "HR.V_DEPARTMENT_HEADCOUNT",
        "HR.V_JOB_HISTORY",
    },
    "orders": {
        "CO.V_ORDERS_FLAT",
        "CO.V_ORDER_ITEMS",
        "CO.V_PRODUCT_REVIEWS_FLAT",
    },
    "warehouse": {
        "SH.V_SALES_BY_CHANNEL",
        "SH.V_SALES_STAR",
        "SH.V_PROMOTIONS",
        "SH.V_CALENDAR",
    },
}
_NEW_SCOPE_PROXY = {
    "hr": "AN_HR",
    "orders": "AN_ORDERS",
    "warehouse": "AN_WAREHOUSE",
}
_NEW_VIEW_COLUMNS = {
    "hr.v_employees": (
        "employee_id",
        "first_name",
        "last_name",
        "hire_date",
        "salary",
        "commission_pct",
        "manager_id",
        "department_id",
        "department_name",
        "job_id",
        "job_title",
    ),
    "hr.v_department_headcount": ("department_id", "department_name", "headcount"),
    "hr.v_job_history": (
        "employee_id",
        "start_date",
        "end_date",
        "job_id",
        "job_title",
        "department_id",
        "department_name",
    ),
    "co.v_orders_flat": (
        "order_id",
        "order_tms",
        "order_status",
        "customer_id",
        "customer_name",
        "store_id",
        "store_name",
    ),
    "co.v_order_items": (
        "order_id",
        "line_item_id",
        "product_id",
        "product_name",
        "unit_price",
        "quantity",
        "line_total",
        "product_details",
    ),
    "co.v_product_reviews_flat": (
        "product_id",
        "product_name",
        "rating",
        "review_text",
    ),
    "sh.v_sales_by_channel": (
        "channel_id",
        "channel_desc",
        "calendar_year",
        "calendar_month_number",
        "calendar_month_desc",
        "total_quantity_sold",
        "total_amount_sold",
    ),
    "sh.v_sales_star": (
        "prod_id",
        "cust_id",
        "time_id",
        "channel_id",
        "promo_id",
        "quantity_sold",
        "amount_sold",
    ),
    "sh.v_promotions": (
        "promo_id",
        "promo_name",
        "promo_subcategory",
        "promo_category",
        "promo_begin_date",
        "promo_end_date",
    ),
    "sh.v_calendar": (
        "time_id",
        "day_name",
        "calendar_week_number",
        "calendar_month_number",
        "calendar_month_desc",
        "calendar_month_name",
        "calendar_quarter_number",
        "calendar_quarter_desc",
        "calendar_year",
        "fiscal_week_number",
        "fiscal_month_number",
        "fiscal_month_desc",
        "fiscal_month_name",
        "fiscal_quarter_number",
        "fiscal_quarter_desc",
        "fiscal_year",
    ),
}


def _declared_view_columns(seed: str, qualified_name: str) -> tuple[str, ...]:
    match = re.search(
        rf"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+{re.escape(qualified_name)}\s*"
        r"\((?P<columns>.*?)\)\s+AS\b",
        seed,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert match is not None, f"missing explicit column contract for {qualified_name}"
    return tuple(column.strip().lower() for column in match.group("columns").split(","))


def _new_kernel_scope_rows() -> dict[str, tuple[set[str], str]]:
    text = _KERNEL_SEED.read_text()
    rows: dict[str, tuple[set[str], str]] = {}
    pattern = re.compile(
        r"\('proof-m85c',\s*'(?P<scope>hr|orders|warehouse)',\s*'[^']+',\s*"
        r"'(?P<objects>\[[^']+\])'::json,\s*'(?P<proxy>AN_[A-Z_]+)'",
        flags=re.DOTALL,
    )
    for match in pattern.finditer(text):
        objects = json.loads(match.group("objects"))
        rows[match.group("scope")] = (set(objects), match.group("proxy"))
    return rows


def test_runner_pins_and_stages_official_v233_sample_scripts_in_init_order() -> None:
    text = _RUNNER.read_text()
    assert _SAMPLE_SCHEMA_URL in text
    assert _SAMPLE_SCHEMA_SHA256 in text
    assert "db-sample-schemas-23.3.tar.gz" in text
    assert "oracle-samples-23.3-sql.tar.gz" in text
    for source in (
        "human_resources/hr_create.sql",
        "human_resources/hr_populate.sql",
        "human_resources/hr_code.sql",
        "customer_orders/co_create.sql",
        "customer_orders/co_populate.sql",
        "sales_history/sh_create.sql",
        "sales_history/sh_populate.sql",
    ):
        assert source in text, f"official sample source not staged: {source}"
    positions = [text.index(f"--from-file={name}=") for name in _SAMPLE_INIT_FILES]
    assert positions == sorted(positions), "initdb scripts must be staged lexicographically"
    executable = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "sqlldr" not in executable.lower(), "sample install must not invoke SQL*Loader"


def test_new_governed_views_match_the_corpus_pinned_column_contracts() -> None:
    seed = _ORACLE_SEED.read_text()
    for view_name, expected in _NEW_VIEW_COLUMNS.items():
        assert _declared_view_columns(seed, view_name) == expected

    employees = re.search(
        r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+hr\.v_employees\b.*?;",
        seed,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert employees is not None
    assert "LEFT JOIN hr.departments" in employees.group(0), (
        "v_employees must retain the department-less employee (107-row canary)"
    )

    orders = _declared_view_columns(seed, "co.v_orders_flat")
    items = _declared_view_columns(seed, "co.v_order_items")
    promotions = _declared_view_columns(seed, "sh.v_promotions")
    assert "email_address" not in orders and "email" not in orders
    assert "product_details" in items and "shipment_id" not in items
    assert "promo_cost" not in promotions
    reviews = re.search(
        r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+co\.v_product_reviews_flat\b.*?;",
        seed,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert reviews is not None
    assert "JSON_TABLE" in reviews.group(0) and "NESTED PATH '$.reviews[*]'" in reviews.group(0)


def test_new_scope_rows_and_oracle_grants_are_exactly_lockstep() -> None:
    rows = _new_kernel_scope_rows()
    assert set(rows) == set(_NEW_SCOPE_VIEWS)
    seed = _ORACLE_SEED.read_text()
    grants: dict[str, set[str]] = {scope: set() for scope in _NEW_SCOPE_VIEWS}
    proxy_to_scope = {proxy.lower(): scope for scope, proxy in _NEW_SCOPE_PROXY.items()}
    for view, proxy in re.findall(
        r"GRANT\s+SELECT\s+ON\s+([a-z_]+\.[a-z_]+)\s+TO\s+(an_[a-z_]+)\s*;",
        seed,
        flags=re.IGNORECASE,
    ):
        scope = proxy_to_scope.get(proxy.lower())
        if scope is not None:
            grants[scope].add(view.upper())

    for scope, expected_views in _NEW_SCOPE_VIEWS.items():
        objects, proxy = rows[scope]
        assert objects == expected_views
        assert proxy == _NEW_SCOPE_PROXY[scope]
        assert grants[scope] == expected_views


def test_a005_writer_has_execute_only_and_subject_mapping_is_hash_keyed() -> None:
    seed = _ORACLE_SEED.read_text()
    assert "CREATE TABLE hr_app.subject_employee" in seed
    assert "subject_ref" in seed and "employee_id" in seed
    assert "__SUBJECT_ANALYST_AMIR_SHA256__" in seed
    assert "CREATE OR REPLACE PROCEDURE hr_app.apply_leave" in seed
    assert "GRANT EXECUTE ON hr_app.apply_leave TO an_hr_writer;" in seed
    assert "GRANT SELECT ON hr.v_employees TO an_hr_writer;" in seed
    assert (
        re.search(
            r"GRANT\s+(?:INSERT|UPDATE|DELETE)\b.*?\bTO\s+an_[a-z_]+\b",
            seed,
            flags=re.IGNORECASE | re.DOTALL,
        )
        is None
    ), "A-005 forbids table DML grants to every agent-lane identity"


def test_only_amir_receives_the_three_new_entitlements_and_skills() -> None:
    text = _KERNEL_SEED.read_text()
    amir_scopes = set(
        re.findall(
            r"'__SUBJECT_ANALYST_AMIR__',\s*'(hr|orders|warehouse)'",
            text,
        )
    )
    sara_scopes = set(
        re.findall(
            r"'__SUBJECT_ANALYST_SARA__',\s*'(hr|orders|warehouse)'",
            text,
        )
    )
    assert amir_scopes == {"hr", "orders", "warehouse"}
    assert sara_scopes == set()
    for skill in ("hr-data", "orders-data", "warehouse-data"):
        assert f"'bank-analyst', 'skill', '{skill}'" in text, (
            f"missing bank-analyst assignment for {skill}"
        )


# --- no fallback (spec §4) ---------------------------------------------------------


def test_no_proof_role_header_binder_anywhere_in_the_proof_code() -> None:
    """The X-Proof-Role binder is DELETED, not gated (spec §4). Prose in the
    proof app + runner may EXPLAIN the deletion, but no code path may set the
    header, and the header-binder class + constant must not exist at all."""
    banned_symbols = ("MultiActorProofBinder", "PROOF_ROLE_HEADER", "UnknownProofRole")
    for path in (_PROOF_APP, _PROOF / "overlay_reference" / "binder.py"):
        text = path.read_text()
        for symbol in banned_symbols:
            assert symbol not in text, f"{path.name} still references {symbol}"

    # The runner must never SEND an X-Proof-Role header (a comment mentioning the
    # retired mechanism is fine; a curl -H line is not).
    for line in _RUNNER.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "X-Proof-Role" not in line, f"runner sends a proof-role header: {line!r}"


def test_proof_app_builds_only_the_reference_oidc_binder() -> None:
    text = _PROOF_APP.read_text()
    assert "build_reference_binder" in text, "proof app does not build the reference binder"
    assert "actor_binder=actor_binder" in text, (
        "proof app does not inject the binder into create_app"
    )
    # It must also mount the approvals surface (the HP-4 queue the harness reads).
    assert "approval_store=approval_store" in text and "approval_engine=approval_engine" in text, (
        "proof app does not mount the approvals router"
    )


def test_proof_app_wires_assignments_across_its_eager_router_engine() -> None:
    text = _PROOF_APP.read_text()
    assert "ApprovalAssignmentStore(decision_history_store)" in text
    assert "assignments=approval_assignment_store" in text
    assert "approval_assignment_store=approval_assignment_store" in text


# --- the locked grant profile + exact audience (spec §4) ---------------------------


def _generate_realm() -> dict[str, Any]:
    """Run the realm generator into a temp dir and return the parsed realm."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [
                sys.executable,
                str(_GEN_REALM),
                tmp,
                "https://cognic-proof-harness:8443/auth/callback",
                "http://127.0.0.1:47113/proof-driver-callback",
            ],
            check=True,
            capture_output=True,
        )
        realm: dict[str, Any] = json.loads((Path(tmp) / "realm.json").read_text())
        return realm


def test_realm_locks_the_grant_profile() -> None:
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    agentos = next(c for c in realm["clients"] if c["clientId"] == "cognic-agentos")
    # The interactive flow is the ONLY way in.
    assert harness["standardFlowEnabled"] is True
    assert harness["directAccessGrantsEnabled"] is False, (
        "resource-owner-password grant must be OFF"
    )
    assert harness["serviceAccountsEnabled"] is False, "client-credentials grant must be OFF"
    assert harness["implicitFlowEnabled"] is False
    assert harness["publicClient"] is False, "the BFF client must be confidential"
    assert harness["attributes"]["pkce.code.challenge.method"] == "S256"
    # The resource audience never performs a browser login.
    for flow in (
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
    ):
        assert agentos[flow] is False, f"the resource audience must not enable {flow}"


def test_realm_materializes_every_referenced_default_client_scope() -> None:
    """Full realm imports do not seed Keycloak's built-in scopes. Every name the
    client references must therefore have a real representation in this document;
    otherwise Keycloak warns, drops it, and mints an access token without ``sub``
    or ``preferred_username``."""
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    defined = {scope["name"]: scope for scope in realm["clientScopes"]}
    assert set(harness["defaultClientScopes"]) <= set(defined)

    basic_mappers = defined["basic"]["protocolMappers"]
    sub = next(mapper for mapper in basic_mappers if mapper["name"] == "sub")
    assert sub["protocolMapper"] == "oidc-sub-mapper"
    assert sub["config"]["access.token.claim"] == "true"

    profile_mappers = defined["profile"]["protocolMappers"]
    username = next(mapper for mapper in profile_mappers if mapper["name"] == "username")
    assert username["protocolMapper"] == "oidc-usermodel-attribute-mapper"
    assert username["config"] == {
        "user.attribute": "username",
        "claim.name": "preferred_username",
        "jsonType.label": "String",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true",
    }


def test_realm_users_are_profile_complete_and_have_no_required_actions() -> None:
    """A missing first/last name makes Keycloak 26.2 redirect a successful login
    to ``VERIFY_PROFILE`` instead of the registered callback. The proof driver
    deliberately refuses required-action detours, so profile completeness is part
    of the generated identity contract."""
    realm = _generate_realm()
    assert len(realm["users"]) == 10
    for user in realm["users"]:
        assert isinstance(user.get("firstName"), str) and user["firstName"]
        assert isinstance(user.get("lastName"), str) and user["lastName"]
        assert user["requiredActions"] == []


def test_realm_id_token_carries_bff_identity_but_not_authorization_scopes() -> None:
    realm = _generate_realm()
    identity = next(scope for scope in realm["clientScopes"] if scope["name"] == "cognic-identity")
    mappers = {mapper["name"]: mapper for mapper in identity["protocolMappers"]}
    assert mappers["tenant_id"]["config"]["id.token.claim"] == "true"
    assert mappers["tenant_id"]["config"]["access.token.claim"] == "true"
    assert mappers["cognic_scopes"]["config"]["id.token.claim"] == "false"
    assert mappers["cognic_scopes"]["config"]["access.token.claim"] == "true"


def test_realm_pins_the_rfc9068_header_type_explicitly() -> None:
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    # Keycloak 26.2 defaults this OFF; the realm must set it ON explicitly.
    assert harness["attributes"].get("access.token.header.type.rfc9068") == "true"


def test_realm_forces_the_audience_to_exactly_cognic_agentos() -> None:
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    # Lever (a): a hardcoded audience mapper.
    has_hardcoded_audience = any(
        m["protocolMapper"] == "oidc-audience-mapper"
        and m["config"].get("included.client.audience") == "cognic-agentos"
        for s in realm["clientScopes"]
        for m in s["protocolMappers"]
    )
    assert has_hardcoded_audience, "no hardcoded cognic-agentos audience mapper"
    # Lever (b): the built-in `roles` scope (which carries audience-resolve, the
    # source of the stray `account` audience) is NOT a default client scope.
    assert "roles" not in harness["defaultClientScopes"], "the `roles` scope must not be default"
    # Lever (c): no user carries realm or client roles (audience-resolve resolves nothing).
    for user in realm["users"]:
        assert user["realmRoles"] == [], f"{user['username']} has realm roles"
        assert user["clientRoles"] == {}, f"{user['username']} has client roles"
    # Lever (d): the client cannot pull in a stray role.
    assert harness["fullScopeAllowed"] is False


def test_realm_emits_cognic_scopes_as_a_multivalued_array() -> None:
    realm = _generate_realm()
    multivalued = any(
        m["config"].get("claim.name") == "cognic_scopes"
        and m["config"].get("multivalued") == "true"
        for s in realm["clientScopes"]
        for m in s["protocolMappers"]
    )
    assert multivalued, (
        "cognic_scopes must be a multivalued mapper (a JSON array, not a bare string)"
    )


def test_realm_manages_identity_claim_sources_for_admin_updates() -> None:
    """Keycloak 26 ignores unmanaged attributes in Admin REST by default.

    Bar G temporarily changes Amir's approval scope through that API, so both
    mapper source attributes must be explicit, admin-only managed attributes.
    The disabled unmanaged-attribute posture is represented by omitting the
    optional policy key; Keycloak 26.2 rejects the literal ``DISABLED`` value.
    """
    realm = _generate_realm()
    providers = realm["components"]["org.keycloak.userprofile.UserProfileProvider"]
    assert len(providers) == 1
    provider = providers[0]
    assert provider["providerId"] == "declarative-user-profile"
    assert provider["subComponents"] == {}

    encoded = provider["config"]["kc.user.profile.config"]
    assert isinstance(encoded, list) and len(encoded) == 1
    profile = json.loads(encoded[0])
    assert "unmanagedAttributePolicy" not in profile
    attributes = {item["name"]: item for item in profile["attributes"]}
    assert {"username", "email", "firstName", "lastName", "tenant_id", "cognic_scopes"} == set(
        attributes
    )
    for name, multivalued in (("tenant_id", False), ("cognic_scopes", True)):
        assert attributes[name]["permissions"] == {
            "view": ["admin"],
            "edit": ["admin"],
        }
        assert attributes[name]["multivalued"] is multivalued


# --- the live session-case realm levers (lifespan override + event log) ------------


def test_realm_gives_the_harness_client_an_explicit_lifespan_override_home() -> None:
    """The runner TEMPORARILY shrinks the cognic-harness access-token lifespan
    at run time (Admin REST) for the expired-token and concurrent-refresh live
    cases. The committed default must EQUAL the realm-wide lifespan — a pure
    override home, no behavioural change — and adding it must not have
    disturbed the neighbouring load-bearing client attributes."""
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    attrs = harness["attributes"]
    # Keycloak's per-client override attribute takes SECONDS AS A STRING.
    assert attrs["access.token.lifespan"] == "900"
    assert attrs["access.token.lifespan"] == str(realm["accessTokenLifespan"])
    # Regression pin: the at+jwt header type (the floor the identity story
    # rests on) and mandatory PKCE survived the attribute addition.
    assert attrs["access.token.header.type.rfc9068"] == "true"
    assert attrs["pkce.code.challenge.method"] == "S256"


def test_realm_enables_the_user_event_log_as_the_refresh_observer() -> None:
    """Keycloak's own event log is the INDEPENDENT observer for the BFF
    concurrent-refresh single-flight case: exactly ONE REFRESH_TOKEN event
    across two replicas (a stampede records N — plus REFRESH_TOKEN_ERRORs under
    refresh-token rotation)."""
    realm = _generate_realm()
    assert realm["eventsEnabled"] is True
    enabled = set(realm["enabledEventTypes"])
    assert {"REFRESH_TOKEN", "REFRESH_TOKEN_ERROR"} <= enabled
    # Stored events must comfortably outlive a ~40-minute proof run.
    assert realm["eventsExpiration"] >= 3600
    # Admin events are noise for this proof — pinned OFF.
    assert realm["adminEventsEnabled"] is False
    assert realm["adminEventsDetailsEnabled"] is False


def test_realm_grant_profile_survives_the_lifespan_override_addition() -> None:
    """Regression pin: the per-client attribute work must not have re-enabled
    either DISABLED grant — the locked profile is what licenses the binder's
    actor_type="human" derivation."""
    realm = _generate_realm()
    harness = next(c for c in realm["clients"] if c["clientId"] == "cognic-harness")
    assert harness["directAccessGrantsEnabled"] is False, "direct-access grant must stay OFF"
    assert harness["serviceAccountsEnabled"] is False, "client-credentials grant must stay OFF"


# --- realm ↔ runner ↔ kernel scope lockstep ----------------------------------------


def _runner_identity_scopes() -> dict[str, set[str]]:
    """Parse the runner's IDENTITY_SCOPES associative-array block."""
    text = _RUNNER.read_text()
    block = re.search(r"declare -A IDENTITY_SCOPES=\((.*?)\)\n", text, re.DOTALL)
    assert block, "IDENTITY_SCOPES block not found in the runner"
    scopes: dict[str, set[str]] = {}
    for match in re.finditer(r'\[(\w+)\]="([^"]*)"', block.group(1)):
        scopes[match.group(1)] = {s for s in match.group(2).split(",") if s}
    return scopes


def test_every_realm_scope_exists_in_the_kernel_vocabulary() -> None:
    binder = _load(_PROOF / "overlay_reference" / "binder.py", "overlay_reference.binder")
    allowed = binder.kernel_scope_allow_list()
    realm = _generate_realm()
    for user in realm["users"]:
        for scope in user["attributes"]["cognic_scopes"]:
            assert scope in allowed, (
                f"{user['username']} carries scope {scope!r} which is NOT in the kernel vocabulary "
                "— the reference binder would refuse the token"
            )


def test_runner_identity_scopes_match_the_generated_realm() -> None:
    """The runner's identity→scope map (used for the claim preflight) MUST match
    the realm generator's, or the preflight would assert the wrong contract."""
    gen = _load(_GEN_REALM, "gen_realm")
    realm_scopes = {
        str(identity["username"]): set(identity["scopes"]) for identity in gen.IDENTITIES
    }
    # Map the runner's role keys to the realm usernames via the runner's IDENTITY_USER.
    text = _RUNNER.read_text()
    user_block = re.search(r"declare -A IDENTITY_USER=\((.*?)\)\n", text, re.DOTALL)
    assert user_block
    role_to_user = dict(re.findall(r"\[(\w+)\]=(\S+)", user_block.group(1)))
    runner_scopes = _runner_identity_scopes()
    assert set(role_to_user) == set(runner_scopes), (
        "IDENTITY_USER and IDENTITY_SCOPES role sets differ"
    )
    for role, username in role_to_user.items():
        assert runner_scopes[role] == realm_scopes[username], (
            f"scope drift for {role} ({username}): runner={sorted(runner_scopes[role])} "
            f"realm={sorted(realm_scopes[username])}"
        )


def test_realm_carries_exactly_ten_identities_including_assignment_humans() -> None:
    realm = _generate_realm()
    usernames = {u["username"] for u in realm["users"]}
    assert usernames == {
        "proof-m85c-author",
        "proof-m85c-reviewer",
        "proof-m85c-operator",
        "analyst.amir",
        "analyst.sara",
        "approver.dana",
        "approver.erin",
        "approver.fiona",
        "assigner.omar",
        "analyst.zara",
    }
    zara = next(u for u in realm["users"] if u["username"] == "analyst.zara")
    assert zara["attributes"]["tenant_id"] == ["proof-foreign"], (
        "the foreign reader must be off-tenant"
    )

    fiona = next(u for u in realm["users"] if u["username"] == "approver.fiona")
    assert set(fiona["attributes"]["cognic_scopes"]) == {
        "tool.approve.high_risk_custom",
        "tool.approve.observe",
    }
    omar = next(u for u in realm["users"] if u["username"] == "assigner.omar")
    assert set(omar["attributes"]["cognic_scopes"]) == {
        "tool.approve.assign",
        "tool.approve.observe",
    }


def test_amir_and_sara_are_scope_and_tenant_identical() -> None:
    """Bar D.6 (originator isolation) is only load-bearing if the two analysts
    differ ONLY by subject — a scope or tenant difference would confound it."""
    realm = _generate_realm()
    amir = next(u for u in realm["users"] if u["username"] == "analyst.amir")
    sara = next(u for u in realm["users"] if u["username"] == "analyst.sara")
    assert set(amir["attributes"]["cognic_scopes"]) == set(sara["attributes"]["cognic_scopes"])
    assert amir["attributes"]["tenant_id"] == sara["attributes"]["tenant_id"]
    assert amir["username"] != sara["username"]


# --- the claim-contract preflight bites --------------------------------------------


def _seg(doc: dict[str, Any]) -> str:
    import base64

    return base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")


def _token(header: dict[str, Any], claims: dict[str, Any]) -> str:
    return f"{_seg(header)}.{_seg(claims)}.{_seg({'sig': 'x'})}"


def _run_claim_assert(tokens: dict[str, Any], scopes: str) -> int:
    issuer = "https://cognic-proof-keycloak:8443/realms/proof-m85c"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(tokens, fh)
        path = fh.name
    try:
        return subprocess.run(
            [
                sys.executable,
                str(_ASSERT_CLAIM),
                path,
                issuer,
                "analyst.amir",
                "proof-m85c",
                scopes,
            ],
            capture_output=True,
        ).returncode
    finally:
        Path(path).unlink()


_GOOD_HDR = {"alg": "RS256", "typ": "at+jwt", "kid": "k1"}
_ISS = "https://cognic-proof-keycloak:8443/realms/proof-m85c"
_SCOPES_CSV = (
    "conversation.create,conversation.read,conversation.post_turn,"
    "conversation.close,mcp.tool.list,mcp.tool.invoke"
)
_GOOD_CLAIMS = {
    "iss": _ISS,
    "aud": "cognic-agentos",
    "azp": "cognic-harness",
    "sub": "uuid-1",
    "preferred_username": "analyst.amir",
    "tenant_id": "proof-m85c",
    "cognic_scopes": _SCOPES_CSV.split(","),
    "exp": 9_000_000_000.0,
    "iat": 1.0,
}
_ID_HDR = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
_ID_CLAIMS = {
    "iss": _ISS,
    "aud": "cognic-harness",
    "azp": "cognic-harness",
    "sub": "uuid-1",
    "preferred_username": "analyst.amir",
    "tenant_id": "proof-m85c",
    "nonce": "nonce-1",
    "exp": 9_000_000_000.0,
    "iat": 1.0,
}


def test_claim_preflight_accepts_the_designed_contract() -> None:
    tokens = {
        "access_token": _token(_GOOD_HDR, _GOOD_CLAIMS),
        "id_token": _token(_ID_HDR, _ID_CLAIMS),
    }
    assert _run_claim_assert(tokens, _SCOPES_CSV) == 0


@pytest.mark.parametrize(
    "mutate_header,mutate_claims,mutate_id_header,mutate_id_claims",
    [
        # typ dropped (Keycloak 26.2 default) -> the binder would refuse every request.
        ({"typ": "JWT"}, {}, {}, {}),
        # audience broadened with `account` (the roles-scope regression).
        ({}, {"aud": ["cognic-agentos", "account"]}, {}, {}),
        # cognic_scopes a bare string (multivalued flag off).
        ({}, {"cognic_scopes": "conversation.read"}, {}, {}),
        # wrong azp.
        ({}, {"azp": "some-other-client"}, {}, {}),
        # ID token structurally indistinguishable (Bar B substitution would be vacuous).
        ({}, {}, {"typ": "at+jwt"}, {}),
        ({}, {}, {}, {"aud": "cognic-agentos"}),
        # BFF-facing identity/session claims must not be deferred to the browser bar.
        ({}, {}, {}, {"sub": None}),
        ({}, {}, {}, {"preferred_username": "some-other-user"}),
        ({}, {}, {}, {"tenant_id": None}),
        # Authorization scopes belong only in the access token.
        ({}, {}, {}, {"cognic_scopes": ["conversation.read"]}),
    ],
)
def test_claim_preflight_catches_realm_regressions(
    mutate_header: dict[str, Any],
    mutate_claims: dict[str, Any],
    mutate_id_header: dict[str, Any],
    mutate_id_claims: dict[str, Any],
) -> None:
    tokens = {
        "access_token": _token({**_GOOD_HDR, **mutate_header}, {**_GOOD_CLAIMS, **mutate_claims}),
        "id_token": _token({**_ID_HDR, **mutate_id_header}, {**_ID_CLAIMS, **mutate_id_claims}),
    }
    assert _run_claim_assert(tokens, _SCOPES_CSV) != 0, (
        "a realm regression slipped past the preflight"
    )


# --- the TLS matrix ----------------------------------------------------------------


def test_agentos_image_serves_tls_and_copies_the_binder_overlay() -> None:
    dockerfile = (_PROOF / "Dockerfile.agentos-proof").read_text()
    assert "--ssl-certfile" in dockerfile and "--ssl-keyfile" in dockerfile, (
        "the kernel image CMD must run uvicorn with TLS"
    )
    assert "COPY overlay_reference/" in dockerfile, (
        "the kernel image must copy the reference-binder overlay so the factory can import it"
    )


def test_runner_verifies_tls_and_never_bypasses_it() -> None:
    text = _RUNNER.read_text()
    assert "--cacert" in text, "the runner must verify AgentOS TLS against the proof CA"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # No curl -k / TLS-verification bypass on the identity path. cosign's
        # `--insecure-ignore-tlog` is a SIGSTORE TRANSPARENCY-LOG flag (required
        # for keyed signing with --tlog-upload=false), NOT a TLS bypass — it is
        # explicitly not in scope here.
        assert not re.search(r"\bcurl\b.*\s-k\b", line), f"runner uses curl -k: {line!r}"
        line_no_tlog = line.replace("--insecure-ignore-tlog", "")
        assert "--insecure" not in line_no_tlog, f"runner uses a TLS-bypass --insecure: {line!r}"


def test_runner_attaches_the_bearer_via_stdin_never_argv() -> None:
    """The access token must never ride a process argument vector (a `ps`
    snapshot would expose it) — it goes through curl's -K config on stdin."""
    text = _RUNNER.read_text()
    assert "curl -s -K -" in text, "api() must feed the Authorization header via curl -K -"
    # And never as a -H argv on the same call surface.
    assert '-H "Authorization: Bearer' not in text, "a Bearer token must not ride -H argv"


def test_mint_pki_emits_a_ca_and_three_leaf_certs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["bash", str(_MINT_PKI), tmp], check=True, capture_output=True)
        out = Path(tmp)
        for name in ("proof-ca.pem", "agentos.crt", "keycloak.crt", "harness.crt"):
            assert (out / name).is_file(), f"mint-pki did not emit {name}"
        # Each leaf chains to the CA.
        for leaf in ("agentos", "keycloak", "harness"):
            result = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(out / "proof-ca.pem"),
                    str(out / f"{leaf}.crt"),
                ],
                capture_output=True,
            )
            assert result.returncode == 0, f"{leaf}.crt does not chain to the proof CA"


# --- Keycloak manifest custody -----------------------------------------------------


def test_keycloak_is_pinned_by_digest_and_imports_the_realm_from_a_secret() -> None:
    text = _KEYCLOAK_YAML.read_text()
    assert "keycloak/keycloak:26.2@sha256:" in text, (
        "Keycloak must be pinned by an immutable digest"
    )
    # The realm carries the client secret + every password -> it must be a Secret,
    # never a ConfigMap.
    assert "secretName: proof-m85c-keycloak-realm" in text
    assert "configMap" not in text or "realm" not in text.split("configMap")[0][-200:], (
        "the realm must not be a ConfigMap"
    )
    assert "KC_HTTP_ENABLED" in text and 'value: "false"' in text, "Keycloak must serve HTTPS only"


# --- key custody + kernel-untouched (carried forward) ------------------------------


def test_no_tracked_private_key_material_anywhere_in_the_proof_tree() -> None:
    # The DANGER is real PEM armor (a `-----BEGIN ... PRIVATE KEY-----` block),
    # not the bare string — the runner's own custody GUARD greps for
    # "PRIVATE KEY-----" as a defence, and that pattern must not itself trip this.
    armor = re.compile(r"-----BEGIN[^\n]*PRIVATE KEY-----")
    for path in _PROOF.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or "proof-m85c-staging" in path.parts:
            continue
        text = path.read_text(errors="ignore")
        assert not armor.search(text), f"private key material (PEM armor) tracked in {path}"


def _verify_false_kwargs(source: str) -> list[int]:
    """Line numbers of REAL ``verify=False`` (or ``verify=0``) keyword arguments,
    via AST — so prose / docstrings / comments mentioning it never false-trip."""
    import ast

    hits: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value
                    in (
                        False,
                        0,
                    )
                ):
                    hits.append(node.lineno)
    return hits


def test_no_tls_bypass_kwargs_anywhere_in_the_proof_python() -> None:
    for path in _PROOF.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        hits = _verify_false_kwargs(path.read_text())
        assert not hits, f"real verify=False kwarg in {path} at line(s) {hits}"


def test_no_insecure_tls_markers_in_the_proof_shell() -> None:
    # For the shell surfaces, an executable (non-comment) line must never carry a
    # TLS bypass. `-k`/`--insecure` are covered by the dedicated curl test; here
    # we catch the openssl/cosign/wget style skips.
    banned = ("--tls-skip-verify", "--no-check-certificate", "--allow-insecure")
    for path in list(_PROOF.rglob("*.sh")):
        for line in path.read_text().splitlines():
            if line.strip().startswith("#"):
                continue
            for flag in banned:
                assert flag not in line, f"TLS bypass {flag!r} in {path}: {line!r}"


def test_migration_head_and_d2_shapes_are_0021() -> None:
    text = _RUNNER.read_text()
    assert 'SCHEMA_REV" = "0021"' in text or '= "0021"' in text, (
        "runner must assert alembic head 0021"
    )
    assert 'SHAPE_D2" = "4|5|2|1"' in text, (
        "runner must read back the D2 assignment, replay, entitlement, and "
        "conversation-turn schema shapes"
    )


def test_migrate_failure_capture_uses_selector_only_for_job_and_pod() -> None:
    text = _RUNNER.read_text()
    assert "get job,pod -l job-name=agentos-migrate -o wide" in text
    assert "get job/agentos-migrate,pod -l" not in text


def test_mcp_authz_is_byte_identical_to_main() -> None:
    # Assert the AGENTS.md-locked sha256 directly. A ``git diff main`` is NOT
    # portable: CI's shallow PR checkout has no local ``main`` ref (it resolves
    # ``origin/<base>`` instead), so the ref form fails with "bad revision".
    # The digest is self-contained and cannot break on checkout topology; the
    # dynamic base-ref byte-compare lives in
    # tests/unit/architecture/test_mcp_authz_untouched.py.
    digest = hashlib.sha256(_MCP_AUTHZ_PATH.read_bytes()).hexdigest()
    assert digest == _MCP_AUTHZ_LOCKED_SHA256, (
        "protocol/mcp_authz.py has drifted from the AGENTS.md-locked digest "
        "(must stay byte-identical to main); a deliberate, separately-reviewed "
        "change must update the lock in AGENTS.md and this constant together."
    )
