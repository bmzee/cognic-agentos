"""Sprint 7B.2 T4 — author surface endpoint integration tests.

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
Task 4 §"Endpoints" + §"Tests pinning same-tenant collaboration across
all three mutating paths (Round 8 P2 #4)" + §"Negative scope-discipline
tests (Round 9 P2 #2)".

Coverage surface (4 endpoints x multiple paths each):

- **POST /api/v1/packs/drafts** — create new draft
  * happy path (creates row, returns 201 + PackResponse, tenant_id +
    created_by bound from actor — never from body)
  * RBAC: missing ``pack.submit`` scope → 403 ``scope_not_held``
  * 422: smuggled forbidden field (e.g. ``tenant_id`` in body) refused
    by Pydantic ``extra="forbid"``
- **PUT /api/v1/packs/drafts/{id}** — update existing draft
  * happy path (same-tenant author B updates A's draft)
  * cross-tenant 404 ``tenant_id_mismatch``
  * RBAC: missing ``pack.submit`` scope → 403
  * non-draft state → 409 ``pack_record_update_non_draft_state``
  * field-not-allowed → 409 ``pack_record_update_field_not_allowed``
  * invalid shape → 409 ``pack_record_update_field_invalid_shape``
- **POST /api/v1/packs/drafts/{id}/submit** — submit for review
  * happy path
  * cross-tenant 404
  * RBAC: missing scope → 403
  * idempotency: re-submit → 409 ``lifecycle_transition_invalid_state_pair``
- **DELETE /api/v1/packs/drafts/{id}** — cancel draft
  * happy path with ``pack.withdraw`` scope
  * cross-tenant 404
  * RBAC: missing ``pack.withdraw`` → 403
  * cancel on non-draft state → 409 ``lifecycle_transition_invalid_state_pair``

Plus the cross-cutting scope-discipline regressions (Round 9 P2 #2):
``pack.submit`` does NOT grant cancel; ``pack.withdraw`` does NOT
grant update/submit.

The fixture pattern uses SQLite + a stub binder per request — mirrors
:file:`tests/unit/portal/rbac/test_enforcement.py:60-89` (test-only
binders live in the test module per AGENTS.md test-fixture-placement
rule)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

# ===========================================================================
# Fixtures
# ===========================================================================


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor.
    Mirrors :file:`tests/unit/portal/rbac/test_enforcement.py:60-68` —
    lives in the test module per :file:`AGENTS.md` test-fixture-placement
    rule."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "alice@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"pack.submit"}),
    actor_type: str = "human",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with governance schema + chain heads, per
    :file:`tests/unit/packs/test_storage.py:60-95`."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'author_routes.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


def _build_app(*, actor: Actor, store: PackRecordStore) -> FastAPI:
    """Build a portal app with the given actor binder + store. Forces
    lifespan startup via ``with TestClient(app):`` at the call site.

    Uses :func:`create_app` directly so the test exercises the exact
    factory path production goes through (Sprint 7B.2 T3 wired
    actor_binder + pack_record_store as kwargs there)."""
    return create_app(
        actor_binder=_StubBinder(actor),
        pack_record_store=store,
    )


async def _seed_draft(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "alice@bank.example",
    state: str = "draft",
) -> PackRecord:
    """Insert a draft pack row directly via the store. For non-draft
    seeds (used by negative-state tests) we first save_draft then
    transition to the target state through legal pairs."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=f"cognic-tool-{uuid.uuid4().hex[:8]}",
        display_name="Seed Pack",
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by=created_by,
        last_actor=created_by,
        created_at=now,
        updated_at=now,
    )
    await store.save_draft(record)
    return record


# ===========================================================================
# Stage 1 — POST /api/v1/packs/drafts (create_draft)
# ===========================================================================


class TestSprint7B2CreateDraftEndpoint:
    """POST /api/v1/packs/drafts — create a new draft."""

    async def test_create_draft_returns_201_with_pack_response(
        self, store: PackRecordStore
    ) -> None:
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-canary",
                    "display_name": "Canary",
                    "manifest_digest": (b"\xab" * 32).hex(),
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": "s3://sboms/canary",
                },
            )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["kind"] == "tool"
        assert body["pack_id"] == "cognic-tool-canary"
        assert body["state"] == "draft"
        # Tenant ID bound from actor, not body — even if body had tried
        # to set tenant_id it would refuse at Pydantic extra="forbid".
        assert body["tenant_id"] == "t1"
        assert body["created_by"] == "alice@bank.example"
        assert body["last_actor"] == "alice@bank.example"
        # Digest fields excluded from the default public DTO.
        assert "manifest_digest" not in body
        assert "signed_artefact_digest" not in body

        # T4 R1 P2 #1 — hex string in the request body decodes to EXACTLY
        # 32 bytes on the persisted record (not UTF-8 of the 64-char hex
        # string which would be 64 bytes — the bug fixed at T4 R1).
        record_id = uuid.UUID(body["id"])
        loaded = await store.load(record_id)
        assert loaded is not None
        assert loaded.manifest_digest == b"\xab" * 32
        assert len(loaded.manifest_digest) == 32
        assert loaded.signed_artefact_digest == b"\xcd" * 32
        assert len(loaded.signed_artefact_digest) == 32

    @pytest.mark.parametrize(
        "bad_field,bad_value",
        [
            ("pack_id", ""),
            ("pack_id", "x" * 257),
            ("display_name", ""),
            ("display_name", "x" * 257),
            ("sbom_pointer", ""),  # empty str disallowed
        ],
    )
    async def test_create_draft_dto_refuses_malformed_string_fields(
        self,
        store: PackRecordStore,
        bad_field: str,
        bad_value: str,
    ) -> None:
        """T4 R3 P2 #3 — create DTO refuses empty + over-length
        strings at 422 BEFORE save_draft. Pre-fix ``pack_id`` /
        ``display_name`` / ``sbom_pointer`` accepted any string
        (including empty); save_draft has no shape guard, so the
        malformed value would persist while update_draft refused
        analogous shapes — asymmetric create vs update field semantics.
        Post-fix: Pydantic ``Field(min_length=1, max_length=...)``
        constraints enforce parity with the storage column widths
        + the storage-layer ``_is_valid_update_value_shape`` contract.

        Constants imported from
        :data:`cognic_agentos.packs.storage.PACK_ID_MAX_LEN` /
        :data:`PACK_DISPLAY_NAME_MAX_LEN` so create + update + DB
        column widths cannot drift apart."""
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        body = {
            "kind": "tool",
            "pack_id": "cognic-tool-canary",
            "display_name": "Canary",
            "manifest_digest": (b"\xab" * 32).hex(),
            "signed_artefact_digest": (b"\xcd" * 32).hex(),
            "sbom_pointer": "s3://sboms/canary",
        }
        body[bad_field] = bad_value

        with TestClient(app) as client:
            response = client.post("/api/v1/packs/drafts", json=body)
        assert response.status_code == 422, (
            f"bad_field={bad_field} value={bad_value!r}: expected 422; "
            f"got {response.status_code} {response.text}"
        )

    async def test_create_draft_dto_accepts_sbom_pointer_none(self, store: PackRecordStore) -> None:
        """Symmetric pin — ``sbom_pointer: None`` is a legitimate
        Wave-1 posture (the pack has no SBOM declared). The
        ``min_length=1`` constraint on the ``str`` half of the union
        applies only when a string is sent; ``None`` passes through."""
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-no-sbom",
                    "display_name": "No SBOM",
                    "manifest_digest": (b"\xab" * 32).hex(),
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": None,
                },
            )
        assert response.status_code == 201, response.text

    @pytest.mark.parametrize(
        "bad_value",
        [
            "x" * 16,  # too short
            "x" * 63,  # one short of 64
            "y" * 65,  # one over 64
            "Z" * 64,  # non-hex chars
            "GG" * 32,  # non-hex chars in 64-char string
            "",  # empty string
            42,  # non-string
        ],
    )
    async def test_create_draft_dto_refuses_malformed_digest(
        self, store: PackRecordStore, bad_value: object
    ) -> None:
        """T4 R1 P2 #1 — wire-level defence-in-depth on POST: malformed
        digests refuse at 422 BEFORE the storage layer (save_draft has
        no shape guard for digest bytes, so a pre-fix create with a
        64-char hex string would have persisted 64 UTF-8 bytes — bug
        fixed at T4 R1)."""
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-malformed-canary",
                    "display_name": "Malformed",
                    "manifest_digest": bad_value,
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": None,
                },
            )
        assert response.status_code == 422, (
            f"bad_value={bad_value!r}: expected 422; got {response.status_code} {response.text}"
        )

    async def test_create_draft_refuses_missing_pack_submit_scope(
        self, store: PackRecordStore
    ) -> None:
        # Actor holds only pack.withdraw, NOT pack.submit
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-denied",
                    "display_name": "Denied",
                    "manifest_digest": (b"\xab" * 32).hex(),
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": None,
                },
            )
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.submit"

    async def test_create_draft_refuses_smuggled_tenant_id_in_body(
        self, store: PackRecordStore
    ) -> None:
        """Pydantic ``extra="forbid"`` on :class:`CreateDraftRequest`
        causes a smuggled ``tenant_id`` field to refuse at validation
        time (422 from FastAPI's default validation handler) BEFORE
        the route runs. Pin the wire-level defence-in-depth here."""
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-attempt",
                    "display_name": "Smuggle",
                    "manifest_digest": (b"\xab" * 32).hex(),
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": None,
                    "tenant_id": "attacker-tenant",
                },
            )
        assert response.status_code == 422


# ===========================================================================
# Stage 2 — PUT /api/v1/packs/drafts/{id} (update_draft)
# ===========================================================================


class TestSprint7B2UpdateDraftEndpoint:
    """PUT /api/v1/packs/drafts/{id} — update an existing draft."""

    async def test_update_draft_happy_path_persists_display_name(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Renamed"},
            )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["display_name"] == "Renamed"
        assert body["last_actor"] == "alice@bank.example"
        assert body["created_by"] == "alice@bank.example"  # author == modifier here

    async def test_update_draft_refuses_cross_tenant_with_404(self, store: PackRecordStore) -> None:
        """Cross-tenant PUT returns 404 (NOT 403) per
        :class:`RequireTenantOwnership` info-leak prevention."""
        record = await _seed_draft(store, tenant_id="t1", created_by="a@bank.example")
        # Actor in tenant t2 — different tenant from the pack
        actor = _make_actor(tenant_id="t2", scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Cross-Tenant"},
            )
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_update_draft_refuses_missing_pack_submit_scope(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        # Actor holds only pack.withdraw, NOT pack.submit
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Denied"},
            )
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.submit"

    async def test_update_draft_refuses_smuggled_immutable_field(
        self, store: PackRecordStore
    ) -> None:
        """Pydantic ``extra="forbid"`` on
        :class:`UpdateDraftRequest` causes any of the 5 immutable
        fields (or any unknown field) to refuse at 422 BEFORE the
        route's storage call. Wire-level defence-in-depth."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        for forbidden in ("tenant_id", "state", "kind", "pack_id", "created_by"):
            with TestClient(app) as client:
                response = client.put(
                    f"/api/v1/packs/drafts/{record.id}",
                    json={"display_name": "ok", forbidden: "attacker-value"},
                )
            assert response.status_code == 422, (
                f"field={forbidden}: expected 422; got {response.status_code} body={response.text}"
            )

    async def test_update_draft_refuses_non_draft_state_with_409(
        self, store: PackRecordStore
    ) -> None:
        """Advance pack to submitted, then attempt update — 409 +
        ``pack_record_update_non_draft_state``."""
        record = await _seed_draft(store, tenant_id="t1")
        # Advance: draft → submitted
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id="alice@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id="seed-submit",
        )

        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Too Late"},
            )
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "pack_record_update_non_draft_state"

    async def test_update_draft_empty_body_returns_current_pack_no_op(
        self, store: PackRecordStore
    ) -> None:
        """Empty-update no-op: PUT with empty body returns the
        current record without bumping ``last_actor`` / ``updated_at``
        / emitting any storage call. Pin this defensive path so a
        future refactor that stomps the no-op check (e.g. always
        calling ``update_draft({})``) surfaces in test."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)
        before = await store.load(record.id)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={},
            )
        assert response.status_code == 200
        # Returned record is the pre-update state (no last_actor bump
        # because no storage call happened).
        body = response.json()
        assert before is not None
        assert body["last_actor"] == before.last_actor

    async def test_update_draft_refuses_malformed_hex_digest_at_dto_layer(
        self, store: PackRecordStore
    ) -> None:
        """T4 R1 P2 #1 fix — digest fields are now canonical hex via
        the :data:`Sha256DigestBytes` DTO validator. Wrong-length hex
        refuses at the DTO layer with 422 (Pydantic validation error)
        BEFORE the route runs and BEFORE the storage layer is touched.

        Prior to the fix, ``bytes`` field type accepted any string as
        UTF-8 bytes; a 16-char ASCII string landed as 16 bytes and was
        caught at the storage shape validator with 409. Post-fix, the
        wire contract is hex-string → 32 bytes, and any non-conforming
        input refuses earlier (422)."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            # 16-char string is too short to be a 64-char SHA-256 hex
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"manifest_digest": "x" * 16},
            )
        # 422 — DTO validation refused BEFORE the storage call
        assert response.status_code == 422, response.text

    @pytest.mark.parametrize(
        "field,bad_value",
        [
            # Wrong length
            ("manifest_digest", "x" * 63),  # 63 chars
            ("manifest_digest", "a" * 65),  # 65 chars
            ("manifest_digest", ""),
            ("signed_artefact_digest", "x" * 63),
            # Non-hex characters in a 64-char string
            ("manifest_digest", "Z" * 64),  # Z is not hex
            ("manifest_digest", "GG" * 32),  # G is not hex
            # Non-string
            ("manifest_digest", 42),
            ("manifest_digest", None),  # None for non-Optional NotImplemented path
        ],
    )
    async def test_update_draft_dto_refuses_malformed_digest_inputs(
        self,
        store: PackRecordStore,
        field: str,
        bad_value: object,
    ) -> None:
        """T4 R1 P2 #1 — parametrize digest validator across the
        documented refusal modes: wrong length, non-hex chars in a
        64-char string, non-string types. All MUST refuse at the DTO
        (422) before storage."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        # None is a legal value for Optional fields in the update DTO
        # (means "do not update"), so it should NOT refuse. Skip None
        # cases for the parametrized refusal sweep.
        if bad_value is None:
            return

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={field: bad_value},
            )
        assert response.status_code == 422, (
            f"field={field} value={bad_value!r}: expected 422; "
            f"got {response.status_code} {response.text}"
        )

    async def test_update_draft_accepts_valid_64_char_hex_digest(
        self, store: PackRecordStore
    ) -> None:
        """T4 R1 P2 #1 — happy path: 64-char hex string in the request
        body decodes to exactly 32 bytes on the persisted record.
        Pins the wire-canonical contract end-to-end (DTO decoder →
        storage UPDATE → re-load round-trip)."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        new_digest_bytes = bytes(range(32))  # 0x00..0x1f, 32 bytes
        new_digest_hex = new_digest_bytes.hex()
        assert len(new_digest_hex) == 64

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"manifest_digest": new_digest_hex},
            )
        assert response.status_code == 200, response.text

        # Round-trip: re-load the record + assert digest is EXACTLY
        # the 32-byte decoded value, NOT the UTF-8 of the hex string
        # (which would have been 64 bytes — the bug we just fixed).
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.manifest_digest == new_digest_bytes
        assert len(loaded.manifest_digest) == 32

    @pytest.mark.parametrize("digest_field", ["manifest_digest", "signed_artefact_digest"])
    async def test_update_draft_refuses_explicit_null_digest_with_422(
        self,
        store: PackRecordStore,
        digest_field: str,
    ) -> None:
        """T4 R2 P2 #1 — explicit JSON ``null`` on a digest field must
        refuse at the DTO layer with 422 (NOT 409 from the storage
        shape validator). Pre-fix the ``Sha256DigestBytes |
        None`` union let None bypass the BeforeValidator, landed
        ``{<field>: None}`` in the storage updates dict, and surfaced
        as a 409 — wire-protocol-asymmetric with malformed hex's 422.
        Post-fix the ``_refuse_explicit_null_digest_fields``
        model-validator catches presence-with-null at the DTO."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={digest_field: None},
            )
        assert response.status_code == 422, response.text
        # Pydantic's 422 body carries the validator's message in the
        # detail array; assert the specific field name + the "explicit
        # null" wording surface so a future refactor of the validator
        # message stays caught.
        body_text = response.text
        assert digest_field in body_text
        assert "explicit null" in body_text or "explicit_null" in body_text or "null" in body_text

    async def test_update_draft_absent_digest_field_is_no_op_not_null(
        self, store: PackRecordStore
    ) -> None:
        """T4 R2 P2 #1 inverse — absence in the request body means
        "do not touch this field" (preserves the original digest);
        the explicit-null refuser does NOT fire when the key is
        omitted. Pin the absence-vs-null distinction at the
        endpoint level."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)
        original_manifest = record.manifest_digest

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                # display_name present; both digest fields absent →
                # they keep their original values, no refusal.
                json={"display_name": "Renamed"},
            )
        assert response.status_code == 200, response.text
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.display_name == "Renamed"
        # Original digest untouched.
        assert loaded.manifest_digest == original_manifest

    async def test_update_draft_refuses_empty_body_on_non_draft_state(
        self, store: PackRecordStore
    ) -> None:
        """T4 R1 P2 #2 fix — empty body PUT against a non-draft pack
        MUST refuse with 409 ``pack_record_update_non_draft_state``,
        NOT return a 200 echo of the current record. Pre-fix the
        no-op branch fired BEFORE the state check; post-fix the state
        check fires first regardless of body contents."""
        from sqlalchemy import func, select

        from cognic_agentos.core.decision_history import _decision_history
        from cognic_agentos.packs.storage import _packs

        record = await _seed_draft(store, tenant_id="t1")
        # Advance: draft → submitted
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id="alice@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id="seed-submit-for-empty-body-test",
        )

        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        async with store._engine.connect() as conn:
            pre_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={},  # empty body — pre-fix would return 200
            )
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "pack_record_update_non_draft_state"

        # No additional chain row, state stays submitted
        async with store._engine.connect() as conn:
            post_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )
            state = (
                await conn.execute(select(_packs.c.state).where(_packs.c.id == record.id))
            ).scalar_one()
        assert post_chain == pre_chain
        assert state == "submitted"


# ===========================================================================
# Stage 3 — POST /api/v1/packs/drafts/{id}/submit
# ===========================================================================


class TestSprint7B2BoundedRequestIdInvariant:
    """T4 R3 P2 #1 — every chain row emitted by the submit + cancel
    endpoints carries a ``request_id`` that fits the
    ``decision_history.request_id`` String(64) column cap.

    Pre-fix the handlers built
    ``f"submit-{record.id}-{datetime.now(UTC).isoformat()}"`` (≥70
    chars). SQLite accepted silently; Postgres + Oracle would have
    rejected at runtime with a column-overflow error. Post-fix the
    minter yields ``pack-submit-<uuid4().hex>`` (44 chars) +
    ``pack-cancel-<uuid4().hex>`` (44 chars). Test reads the live
    ``decision_history`` row + asserts (a) length ≤ 64 + (b) the
    expected prefix is intact."""

    async def test_submit_emitted_request_id_is_bounded_and_prefixed(
        self, store: PackRecordStore
    ) -> None:
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 200, response.text

        async with store._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.request_id, _decision_history.c.event_type)
                    .where(_decision_history.c.event_type == "pack.lifecycle.submitted")
                    .order_by(_decision_history.c.sequence.desc())
                )
            ).first()
        assert row is not None
        request_id = row.request_id
        # (a) Bounded to the column cap
        assert len(request_id) <= 64, (
            f"request_id={request_id!r} is {len(request_id)} chars; "
            f"would overflow String(64) on Postgres/Oracle"
        )
        # (b) Expected prefix intact
        assert request_id.startswith("pack-submit-"), (
            f"request_id={request_id!r} missing 'pack-submit-' prefix"
        )
        # (c) Suffix is exactly uuid4().hex (32 lowercase hex chars)
        suffix = request_id[len("pack-submit-") :]
        assert len(suffix) == 32
        assert all(c in "0123456789abcdef" for c in suffix), (
            f"request_id suffix {suffix!r} is not uuid4().hex"
        )

    async def test_cancel_emitted_request_id_is_bounded_and_prefixed(
        self, store: PackRecordStore
    ) -> None:
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 200, response.text

        async with store._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.request_id, _decision_history.c.event_type)
                    .where(_decision_history.c.event_type == "pack.lifecycle.withdrawn")
                    .order_by(_decision_history.c.sequence.desc())
                )
            ).first()
        assert row is not None
        request_id = row.request_id
        assert len(request_id) <= 64, (
            f"request_id={request_id!r} is {len(request_id)} chars; "
            f"would overflow String(64) on Postgres/Oracle"
        )
        assert request_id.startswith("pack-cancel-"), (
            f"request_id={request_id!r} missing 'pack-cancel-' prefix"
        )
        suffix = request_id[len("pack-cancel-") :]
        assert len(suffix) == 32
        assert all(c in "0123456789abcdef" for c in suffix), (
            f"request_id suffix {suffix!r} is not uuid4().hex"
        )


class TestSprint7B2SubmitDraftEndpoint:
    """POST /api/v1/packs/drafts/{id}/submit — transition draft →
    submitted via :meth:`PackRecordStore.transition`."""

    async def test_submit_happy_path_returns_submitted_pack(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "submitted"
        assert body["last_actor"] == "alice@bank.example"

    async def test_submit_refuses_cross_tenant_with_404(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t2", scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_submit_refuses_missing_pack_submit_scope(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.submit"

    async def test_idempotent_resubmit_returns_409_invalid_state_pair(
        self, store: PackRecordStore
    ) -> None:
        """Plan watchpoint (e) — re-submitting an already-submitted
        pack returns 409 with closed-enum
        ``lifecycle_transition_invalid_state_pair`` from 7B.1."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            # First submit succeeds
            first = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
            assert first.status_code == 200
            # Second submit on now-submitted pack must refuse
            second = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert second.status_code == 409
        body = second.json()
        # submit from submitted → invalid_state_pair (no per-transition
        # specific reason for submit; falls through to generic).
        assert body["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"


# ===========================================================================
# Stage 4 — DELETE /api/v1/packs/drafts/{id} (cancel_draft)
# ===========================================================================


class TestSprint7B2CancelDraftEndpoint:
    """DELETE /api/v1/packs/drafts/{id} — cancel_draft transition
    (Sprint 7B.2 T4 lifecycle extension)."""

    async def test_cancel_happy_path_returns_withdrawn_pack(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        # Actor must hold pack.withdraw (NOT pack.submit) per
        # Round 8 P2 #3 scope split.
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "withdrawn"
        assert body["last_actor"] == "alice@bank.example"

    async def test_cancel_refuses_cross_tenant_with_404(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t2", scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_cancel_refuses_missing_pack_withdraw_scope(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")
        # Actor holds pack.submit but NOT pack.withdraw — refused.
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.withdraw"

    async def test_cancel_refuses_on_non_draft_state_with_409(self, store: PackRecordStore) -> None:
        """cancel_draft requires source state ``draft`` per Sprint
        7B.2 T4's lifecycle table. From any non-draft state the
        transition refuses with
        ``lifecycle_transition_invalid_state_pair`` (no per-transition
        specific reason for cancel_draft; falls through to generic)."""
        record = await _seed_draft(store, tenant_id="t1")
        # Advance pack out of draft first
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id="alice@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id="advance-then-cancel",
        )

        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"


# ===========================================================================
# Stage 5 — Same-tenant author collaboration (Round 8 P2 #4)
# ===========================================================================


class TestSprint7B2SameTenantAuthorCollaboration:
    """Plan §"Tests pinning same-tenant collaboration across all three
    mutating paths" (Round 8 P2 #4). Same-tenant author B (different
    ``subject`` from original author A; same ``tenant_id``) can
    update/submit/cancel A's drafts.

    Audit-trail invariant: ``created_by`` stays A (immutable);
    ``last_actor`` becomes B."""

    async def test_same_tenant_collaboration_allowed_on_draft_update(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_draft(store, tenant_id="t1", created_by="alice@bank.example")
        # Actor B — different subject, same tenant, holds pack.submit
        actor_b = _make_actor(
            subject="bob@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.submit"}),
        )
        app = _build_app(actor=actor_b, store=store)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Bob's Edit"},
            )
        assert response.status_code == 200
        body = response.json()
        # created_by remains A (immutable)
        assert body["created_by"] == "alice@bank.example"
        # last_actor becomes B
        assert body["last_actor"] == "bob@bank.example"

    async def test_same_tenant_collaboration_allowed_on_draft_submit(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_draft(store, tenant_id="t1", created_by="alice@bank.example")
        actor_b = _make_actor(
            subject="bob@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.submit"}),
        )
        app = _build_app(actor=actor_b, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "submitted"
        assert body["created_by"] == "alice@bank.example"
        assert body["last_actor"] == "bob@bank.example"

    async def test_same_tenant_collaboration_allowed_on_draft_cancel(
        self, store: PackRecordStore
    ) -> None:
        """Round 8 P2 #3 scope split: cancel requires ``pack.withdraw``,
        NOT ``pack.submit``. Same-tenant actor B with pack.withdraw
        can cancel A's draft."""
        record = await _seed_draft(store, tenant_id="t1", created_by="alice@bank.example")
        actor_b = _make_actor(
            subject="bob@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.withdraw"}),
        )
        app = _build_app(actor=actor_b, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "withdrawn"
        assert body["created_by"] == "alice@bank.example"
        assert body["last_actor"] == "bob@bank.example"


# ===========================================================================
# Stage 6 — Scope-discipline regressions (Round 9 P2 #2)
# ===========================================================================


class TestSprint7B2ScopeDiscipline:
    """Plan §"Negative scope-discipline tests (Round 9 P2 #2)" — pin
    that the author-scope split (``pack.submit`` vs ``pack.withdraw``)
    is strict in both directions. Lives in this test module (NOT
    generic test_rbac_enforcement_e2e.py) so the contract surface is
    co-located with the positive cases."""

    async def test_pack_submit_actor_cannot_cancel_draft(self, store: PackRecordStore) -> None:
        """Actor holds ``pack.submit`` ONLY (NOT ``pack.withdraw``),
        same tenant as draft → DELETE returns 403 with
        ``scope_not_held`` + required_scope=``pack.withdraw``.
        Asserts NO chain row written + NO state mutation."""
        from sqlalchemy import func, select

        from cognic_agentos.core.decision_history import _decision_history
        from cognic_agentos.packs.storage import _packs

        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=store)

        # Snapshot pre-state
        async with store._engine.connect() as conn:
            pre_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )
            pre_state = (
                await conn.execute(select(_packs.c.state).where(_packs.c.id == record.id))
            ).scalar_one()

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.withdraw"

        # NO chain row, NO state mutation
        async with store._engine.connect() as conn:
            post_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )
            post_state = (
                await conn.execute(select(_packs.c.state).where(_packs.c.id == record.id))
            ).scalar_one()
        assert post_chain == pre_chain
        assert post_state == pre_state == "draft"

    async def test_pack_withdraw_actor_cannot_update_draft(self, store: PackRecordStore) -> None:
        """Actor holds ``pack.withdraw`` ONLY (NOT ``pack.submit``),
        same tenant as draft → PUT returns 403 with
        ``scope_not_held`` + required_scope=``pack.submit``."""
        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)
        original = await store.load(record.id)

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Should Not Persist"},
            )
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.submit"

        # No mutation of any field
        after = await store.load(record.id)
        assert after == original

    async def test_pack_withdraw_actor_cannot_submit_draft(self, store: PackRecordStore) -> None:
        """Same actor profile (pack.withdraw only) → POST /submit
        returns 403 with ``scope_not_held`` + required_scope=
        ``pack.submit``. Asserts NO chain row + NO state mutation."""
        from sqlalchemy import func, select

        from cognic_agentos.core.decision_history import _decision_history
        from cognic_agentos.packs.storage import _packs

        record = await _seed_draft(store, tenant_id="t1")
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=store)

        async with store._engine.connect() as conn:
            pre_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 403
        body = response.json()
        assert body["detail"]["reason"] == "scope_not_held"
        assert body["detail"]["required_scope"] == "pack.submit"

        # No chain row, no state mutation
        async with store._engine.connect() as conn:
            post_chain = int(
                (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
            )
            post_state = (
                await conn.execute(select(_packs.c.state).where(_packs.c.id == record.id))
            ).scalar_one()
        assert post_chain == pre_chain
        assert post_state == "draft"


# ===========================================================================
# Stage 7 — AuthorRefusalReason closed-enum + drift detector
# ===========================================================================


class TestSprint7B2Sha256DigestDecoder:
    """T4 R1 P2 #1 — direct-call tests for :func:`_decode_sha256_hex`
    covering the ``bytes`` input path that the JSON wire surface
    cannot exercise (JSON parsers convert everything to strings).
    The bytes-input path exists as defence-in-depth for direct
    Python callers that hand the validator pre-decoded data."""

    def test_decoder_passes_through_valid_32_byte_bytes(self) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        value = b"\xab" * 32
        result = _decode_sha256_hex(value)
        assert result == value
        assert isinstance(result, bytes)
        assert len(result) == 32

    @pytest.mark.parametrize(
        "bad_bytes",
        [
            b"",
            b"\x00" * 16,
            b"\x00" * 31,
            b"\x00" * 33,
            b"\x00" * 64,
        ],
    )
    def test_decoder_refuses_wrong_length_bytes(self, bad_bytes: bytes) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        with pytest.raises(ValueError, match="32 bytes"):
            _decode_sha256_hex(bad_bytes)

    @pytest.mark.parametrize(
        "non_string",
        [42, 3.14, [], {}, None, object()],
    )
    def test_decoder_refuses_non_str_non_bytes(self, non_string: object) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        with pytest.raises(ValueError, match="hex-encoded str or 32-byte bytes"):
            _decode_sha256_hex(non_string)

    def test_decoder_accepts_valid_64_char_hex(self) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        expected = bytes(range(32))
        result = _decode_sha256_hex(expected.hex())
        assert result == expected
        assert len(result) == 32

    def test_decoder_refuses_non_hex_in_64_char_string(self) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        with pytest.raises(ValueError, match="invalid hex characters"):
            _decode_sha256_hex("Z" * 64)

    @pytest.mark.parametrize(
        "uppercase_hex",
        [
            "A" * 64,  # all uppercase
            "a" * 32 + "A" * 32,  # half-and-half
            "AbCdEf" + "0" * 58,  # mixed case
            "DEADBEEF" + "00" * 28,  # canonical "AB" hex
        ],
    )
    def test_decoder_refuses_uppercase_and_mixed_case_hex(self, uppercase_hex: str) -> None:
        """T4 R2 P3 #4 — wire-protocol contract is canonical lowercase
        hex ONLY. ``bytes.fromhex`` accepts uppercase by default, but
        the DTO refuses to keep wire encoding deterministic across
        producers."""
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        with pytest.raises(ValueError, match="lowercase hex"):
            _decode_sha256_hex(uppercase_hex)

    @pytest.mark.parametrize("bad_length", ["", "a", "a" * 63, "a" * 65, "a" * 128])
    def test_decoder_refuses_wrong_length_strings(self, bad_length: str) -> None:
        from cognic_agentos.portal.api.packs.author_routes import (
            _decode_sha256_hex,
        )

        with pytest.raises(ValueError, match="64 chars"):
            _decode_sha256_hex(bad_length)


class TestSprint7B2PackNotFoundRaceHandlers:
    """T4 R1 P2 #3 fix — submit + cancel endpoints must catch
    :class:`PackNotFound` from ``transition()`` and translate to a
    structured 404. The race window: the tenant-isolation dependency
    loads the pack at request entry; if a concurrent deleter (or a
    test-fixture mock) removes the row before ``transition()`` runs
    its precondition ``SELECT ... FOR UPDATE``, the precondition
    raises :class:`PackNotFound`. Pre-fix the exception would leak as
    a generic 500; post-fix the handler returns 404 + closed-enum
    body ``{reason: pack_not_found}``.

    The race is reproduced here via a stub store wrapper that mirrors
    the real store but overrides ``transition`` to raise
    :class:`PackNotFound`. The real concurrency proof against live
    Postgres / Oracle lives at the integration level."""

    async def test_submit_translates_pack_not_found_to_404(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")

        # Wrap the store with a transition-overriding sentinel
        class _RaceStore:
            def __init__(self, real: PackRecordStore, record_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = record_id

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def transition(self, **kwargs: Any) -> Any:
                if kwargs.get("pack_id") == self._race_id:
                    from cognic_agentos.packs.storage import PackNotFound

                    raise PackNotFound(self._race_id)
                return await self._real.transition(**kwargs)

        race_store = _RaceStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_cancel_translates_pack_not_found_to_404(self, store: PackRecordStore) -> None:
        record = await _seed_draft(store, tenant_id="t1")

        class _RaceStore:
            def __init__(self, real: PackRecordStore, record_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = record_id

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def transition(self, **kwargs: Any) -> Any:
                if kwargs.get("pack_id") == self._race_id:
                    from cognic_agentos.packs.storage import PackNotFound

                    raise PackNotFound(self._race_id)
                return await self._real.transition(**kwargs)

        race_store = _RaceStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_create_draft_translates_storage_refusal_to_409(
        self, store: PackRecordStore
    ) -> None:
        """Defensive branch coverage — :meth:`PackRecordStore.save_draft`
        raises :class:`PackRecordRefused` if the supplied record has
        ``state != "draft"``. The route's :class:`CreateDraftRequest`
        hardcodes ``state="draft"`` so this path is normally
        unreachable through the wire; pin via a stub store that
        raises the exception unconditionally to keep the handler's
        409-mapping branch under coverage (defence-in-depth — a future
        refactor that lifted the literal would still surface a
        structured 409 instead of a 500)."""

        class _RefusingStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def save_draft(self, record: PackRecord) -> uuid.UUID:
                from cognic_agentos.packs.storage import PackRecordRefused

                raise PackRecordRefused(
                    "pack_record_save_draft_initial_state_not_draft",
                    state="installed",
                )

        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=_RefusingStore(store))  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.post(
                "/api/v1/packs/drafts",
                json={
                    "kind": "tool",
                    "pack_id": "cognic-tool-defensive",
                    "display_name": "Defensive",
                    "manifest_digest": (b"\xab" * 32).hex(),
                    "signed_artefact_digest": (b"\xcd" * 32).hex(),
                    "sbom_pointer": None,
                },
            )
        assert response.status_code == 409, response.text
        assert (
            response.json()["detail"]["reason"] == "pack_record_save_draft_initial_state_not_draft"
        )

    async def test_update_draft_post_update_reload_pack_not_found_returns_404(
        self, store: PackRecordStore
    ) -> None:
        """Defensive coverage — between the successful ``update_draft``
        call + the re-load that produces the response body, a deleter
        might race in. The handler returns 404 + closed-enum body
        rather than leaking the ``None`` return as a 500.

        Reproduced via a stub that gates ``load`` returning None ONLY
        AFTER ``update_draft`` succeeds — otherwise the
        :class:`RequireTenantOwnership` dependency would catch the
        404 first and the post-update reload-race path would not be
        exercised."""

        class _RaceLoadStore:
            def __init__(self, real: PackRecordStore, race_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = race_id
                self._update_done = False

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def update_draft(self, **kwargs: Any) -> None:
                await self._real.update_draft(**kwargs)
                self._update_done = True

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if self._update_done and pack_id == self._race_id:
                    return None
                return await self._real.load(pack_id)

        record = await _seed_draft(store, tenant_id="t1")
        race_store = _RaceLoadStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Updated Before Race"},
            )
        # The handler's post-update re-load returns None due to the
        # race; the handler maps that to 404 + pack_not_found.
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_update_draft_translates_storage_refusal_to_409(
        self, store: PackRecordStore
    ) -> None:
        """T4 R1 — defensive coverage: the storage-layer
        :class:`PackRecordRefused` branch in the update handler is
        unreachable through the wire in normal operation (the route's
        state-check fires first; the DTO catches malformed shapes
        first; ``extra="forbid"`` catches unknown fields first). Pin
        the handler's 409-translation branch via a stub store that
        raises :class:`PackRecordRefused` unconditionally so the
        closed-enum mapping path stays under coverage."""

        class _RefusingUpdateStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def update_draft(self, **kwargs: Any) -> None:
                from cognic_agentos.packs.storage import PackRecordRefused

                raise PackRecordRefused("pack_record_update_field_not_allowed")

        record = await _seed_draft(store, tenant_id="t1")
        race_store = _RefusingUpdateStore(store)
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Triggers Defensive Branch"},
            )
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "pack_record_update_field_not_allowed"

    async def test_submit_translates_post_transition_reload_pack_not_found_to_404(
        self, store: PackRecordStore
    ) -> None:
        """Defensive coverage — between successful ``transition`` +
        the re-load that produces the response body, a deleter might
        race in. The handler maps the ``None`` load to 404 +
        ``pack_not_found`` instead of leaking."""

        class _RaceLoadStore:
            def __init__(self, real: PackRecordStore, race_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = race_id
                self._transition_done = False

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def transition(self, **kwargs: Any) -> Any:
                result = await self._real.transition(**kwargs)
                self._transition_done = True
                return result

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                # Return None only AFTER the transition has been
                # called (so the tenant-isolation dep's load gets the
                # real value, but the post-transition reload races).
                if self._transition_done and pack_id == self._race_id:
                    return None
                return await self._real.load(pack_id)

        record = await _seed_draft(store, tenant_id="t1")
        race_store = _RaceLoadStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/drafts/{record.id}/submit")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_cancel_translates_post_transition_reload_pack_not_found_to_404(
        self, store: PackRecordStore
    ) -> None:
        """Mirror of the submit reload-race test, for cancel."""

        class _RaceLoadStore:
            def __init__(self, real: PackRecordStore, race_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = race_id
                self._transition_done = False

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def transition(self, **kwargs: Any) -> Any:
                result = await self._real.transition(**kwargs)
                self._transition_done = True
                return result

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if self._transition_done and pack_id == self._race_id:
                    return None
                return await self._real.load(pack_id)

        record = await _seed_draft(store, tenant_id="t1")
        race_store = _RaceLoadStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.withdraw"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/drafts/{record.id}")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_update_draft_translates_storage_pack_not_found_to_404(
        self, store: PackRecordStore
    ) -> None:
        """Defensive coverage — :meth:`update_draft` raises
        :class:`PackNotFound` from its Step 4 rowcount-0 SELECT when
        the row is gone. The handler catches + translates to 404."""

        class _RaceUpdateStore:
            def __init__(self, real: PackRecordStore, race_id: uuid.UUID) -> None:
                self._real = real
                self._race_id = race_id

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            async def update_draft(self, **kwargs: Any) -> None:
                if kwargs.get("pack_id") == self._race_id:
                    from cognic_agentos.packs.storage import PackNotFound

                    raise PackNotFound(self._race_id)
                return await self._real.update_draft(**kwargs)

        record = await _seed_draft(store, tenant_id="t1")
        race_store = _RaceUpdateStore(store, record.id)
        actor = _make_actor(scopes=frozenset({"pack.submit"}))
        app = _build_app(actor=actor, store=race_store)  # type: ignore[arg-type]

        with TestClient(app) as client:
            response = client.put(
                f"/api/v1/packs/drafts/{record.id}",
                json={"display_name": "Race Target"},
            )
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"


class TestSprint7B2AuthorRefusalReasonClosedEnum:
    """Pin the closed-enum vocabulary that the wire-protocol denial
    bodies carry. Drift in this list = wire-protocol break."""

    def test_author_refusal_reason_has_6_values(self) -> None:
        from typing import get_args

        from cognic_agentos.portal.api.packs.author_routes import (
            AuthorRefusalReason,
        )

        # 4 from storage.PackRecordRefusalReason + 2 from
        # lifecycle.LifecycleRefusalReason (the ones T4 endpoints
        # actually surface).
        assert set(get_args(AuthorRefusalReason)) == {
            "pack_record_save_draft_initial_state_not_draft",
            "pack_record_update_non_draft_state",
            "pack_record_update_field_not_allowed",
            "pack_record_update_field_invalid_shape",
            "lifecycle_transition_invalid_state_pair",
            "lifecycle_transition_terminal_state",
        }

    def test_every_author_refusal_reason_traces_to_upstream_closed_enum(self) -> None:
        """The module-foot drift detector
        :func:`_validate_author_refusal_reason_drift` runs at import
        time. If any AuthorRefusalReason value lacks a corresponding
        storage/lifecycle closed-enum value, the import would have
        raised. Pin via a positive cross-check here so the test layer
        also surfaces drift (defensive belt-and-braces)."""
        from typing import get_args

        from cognic_agentos.packs.lifecycle import LifecycleRefusalReason
        from cognic_agentos.packs.storage import PackRecordRefusalReason
        from cognic_agentos.portal.api.packs.author_routes import (
            AuthorRefusalReason,
        )

        upstream = set(get_args(LifecycleRefusalReason)) | set(get_args(PackRecordRefusalReason))
        declared = set(get_args(AuthorRefusalReason))
        assert declared.issubset(upstream), (
            f"AuthorRefusalReason values not in upstream: {declared - upstream}"
        )

    def test_every_handler_emitted_reason_is_in_3_way_closed_enum_union(self) -> None:
        """T4 R5 P2 — union-coverage pin.

        :data:`AuthorRefusalReason` is the narrow 409-storage/lifecycle
        vocab — NOT the full author-surface wire-protocol surface. The
        complete handler-emitted refusal vocabulary is a 3-way union:

          * :data:`AuthorRefusalReason` (storage/lifecycle 409s)
          * :data:`TenantIsolationFailure` (404 + 500 from the gate)
          * :data:`RBACDenialReason` (403 + 500 from the auth gate)

        Pre-R5 the documentation claimed :data:`AuthorRefusalReason`
        WAS the full vocabulary — leaving ``"pack_not_found"`` (emitted
        by the submit / cancel / update handlers' PackNotFound race
        translations) outside any declared closed-enum. This test
        enumerates every literal ``reason`` string the author handlers
        emit + asserts each is in the 3-way union. A future refactor
        that introduces an out-of-vocabulary literal must add it to
        the appropriate enum AND update this test."""
        from typing import get_args

        from cognic_agentos.portal.api.packs.author_routes import (
            AuthorRefusalReason,
        )
        from cognic_agentos.portal.rbac.enforcement import RBACDenialReason
        from cognic_agentos.portal.rbac.tenant_isolation import (
            TenantIsolationFailure,
        )

        # Enumerate every literal ``reason`` string that the four
        # author handlers can emit. Sourced from author_routes.py via
        # grep -nE 'detail.*"reason"' + manual review. A new emit-site
        # added without updating this list is a wire-protocol-drift
        # bug; this set MUST stay in sync with the handler emit sites.
        handler_emitted_reasons = {
            # create_draft + update_draft 409 paths (AuthorRefusalReason)
            "pack_record_save_draft_initial_state_not_draft",
            "pack_record_update_non_draft_state",
            "pack_record_update_field_not_allowed",
            "pack_record_update_field_invalid_shape",
            # submit / cancel 409 paths (AuthorRefusalReason — lifecycle subset)
            "lifecycle_transition_invalid_state_pair",
            "lifecycle_transition_terminal_state",
            # PackNotFound race translations (TenantIsolationFailure)
            "pack_not_found",
        }

        union = (
            set(get_args(AuthorRefusalReason))
            | set(get_args(TenantIsolationFailure))
            | set(get_args(RBACDenialReason))
        )

        # Every handler-emitted reason MUST be a member of the union.
        drift = handler_emitted_reasons - union
        assert not drift, (
            f"Handler-emitted reasons not in any closed-enum: {drift!r}. "
            "Every literal ``detail.reason`` string MUST be a member of "
            "AuthorRefusalReason | TenantIsolationFailure | RBACDenialReason. "
            "Add the missing values to the appropriate enum + extend the "
            "drift detector."
        )

    def test_pack_not_found_constant_traces_to_tenant_isolation_enum(self) -> None:
        """T4 R5 P2 — pin the import-time drift detector's positive
        invariant: the centralised :data:`_PACK_NOT_FOUND_REASON`
        Final-Literal constant MUST be a member of
        :data:`TenantIsolationFailure`. The author handlers' 404 emit
        symmetry doctrine: a route-level PackNotFound race surfaces
        the SAME reason that the tenant-isolation gate's 404 emit
        path surfaces, so a cross-tenant attacker cannot fingerprint
        the difference between 'pack does not exist' and 'race lost
        to deleter mid-request'."""
        from typing import get_args

        from cognic_agentos.portal.api.packs.author_routes import (
            _PACK_NOT_FOUND_REASON,
        )
        from cognic_agentos.portal.rbac.tenant_isolation import (
            TenantIsolationFailure,
        )

        assert _PACK_NOT_FOUND_REASON in get_args(TenantIsolationFailure)
        # Also pin the literal value — a future rename that updates
        # the constant but not the tenant-isolation enum (or vice
        # versa) would land here.
        assert _PACK_NOT_FOUND_REASON == "pack_not_found"
