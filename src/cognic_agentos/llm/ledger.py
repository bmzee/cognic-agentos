"""GatewayCallLedger — operational ledger feeding ADR-007.

Layer classification: **platform primitive** (operational; not on
AGENTS.md's hash-chain critical-controls list — that's audit_event /
decision_history. The ledger is on the **provider-honesty ledger
feed** side per AGENTS.md §"LLM gateway", which means halt-before-
commit + ≥80% per-file coverage floor at T11 vs the ≥95%/≥90% gate
on gateway.py / policy.py / preflight.py).

Plain INSERT semantics; no chain head, no SELECT FOR UPDATE. Per
ADR-007 §"two layers" this is the **authoritative** source for
``/api/v1/system/effective-routing`` because it is local,
transactional, and never lossy. Hash-chained tamper-evidence for
the violation cases lives in ``audit_event`` (Sprint 2 substrate);
duplicating tamper-evidence here would impose a write-rate ceiling
that ADR-007 explicitly rejects.

Round-4 reviewer-P2 docstring contract: ``write_row`` raises on
persistence failure — it is the gateway's job (T6 LLMGateway) to
choose between best-effort vs strict regimes per the ADR-007
success contract. The ledger primitive itself does NOT swallow
write failures; that posture decision belongs at the call site,
where the gateway knows whether LiteLLM dispatched.

Read-side (``read_recent_calls``) serves the provider-honesty
endpoint (T9 ``/api/v1/system/effective-routing``).

Sprint 3 — 9.5a contract — ``model_id`` was reserved + always written
as ``None`` (the column existed in the row dataclass + table, but the
two gateway construction sites in ``llm/gateway.py`` hardcoded ``None``).
Sprint 9.5b C2 (ADR-013) — gateway now threads
``Settings.llm_model_id_map[litellm_alias]`` into write-site
``model_id``; unmapped aliases still write ``None`` (the honest posture
per ADR-007 — the gateway never invents a ``model_id``). No backfill
of historical rows; pre-C2 rows stay ``model_id IS NULL`` permanently.

References:
- Plan Decision-Locking §5 (audit + decision-history emission contract,
  including the no-prompt-content-in-payload privacy contract).
- ADR-007 (Provider-Honesty Enforcement).
- T4's ``20260430_0002_gateway_call_ledger.py`` migration ships the
  schema this module's ``_ledger_table`` mirrors. The ``ts`` column
  type matches the migration's ``GATEWAY_LEDGER_TS_TYPE`` —
  ``sa.TIMESTAMP(timezone=True)``, NOT ``sa.DateTime(timezone=True)``,
  so Oracle preserves the offset on read-back. The migration's
  per-file regression test in ``tests/unit/db/test_run_migrations.py``
  pins the migration's choice; the same convention applies here.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import typing as _t
import uuid
from typing import Literal

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

#: Outcomes the gateway records on every call. Whitelist enforced at
#: ``GatewayCallRow.__post_init__`` so a typo at the gateway boundary
#: never lands a malformed row in the authoritative ledger.
_ALLOWED_OUTCOMES: frozenset[str] = frozenset(
    {
        "ok",
        "denied",  # pre- OR post-dispatch policy denial
        "drift",  # actual_model_string != preflight; actual policy allowed
        "guardrail_input",
        "guardrail_output",
        "concurrency_exhausted",
        "upstream_error",
    }
)

#: Round-6 reviewer-P1: provenance status persisted at write time so
#: ``/effective-routing`` can authoritatively classify historical rows
#: without re-resolving current YAML. Whitelist enforced at construction.
_ALLOWED_PROVENANCES: frozenset[str] = frozenset(
    {
        "resolved",  # actual upstream identified unambiguously
        "unresolved",  # zero reverse_lookup matches OR missing/invalid response model field
        "ambiguous",  # mixed-classification collision (multiple matches disagree)
        # Pre-dispatch failure — upstream_model + api_base reflect
        # the INTENDED preflight target, not actual provenance.
        "no_dispatch",
    }
)


@dataclasses.dataclass(frozen=True, slots=True)
class GatewayCallRow:
    """A single ledger entry — one LLM call's metadata.

    Frozen + slotted: callers pass an immutable row to ``write_row``;
    no field can be mutated after construction. Construction-time
    validation (``__post_init__``) rejects naive timestamps + unknown
    outcome / provenance values so a malformed row never reaches the
    authoritative ledger.
    """

    id: uuid.UUID
    ts: _dt.datetime
    request_id: str
    tenant_id: str | None
    tier: Literal["tier1", "tier2"]
    litellm_alias: str
    upstream_model: str
    upstream_api_base: str | None  # Round-6 reviewer-P1
    external: bool
    provenance: str  # Round-6 reviewer-P1 — see _ALLOWED_PROVENANCES
    latency_ms: int
    outcome: str
    model_id: str | None  # reserved — Sprint 9.5 (ADR-013)

    def __post_init__(self) -> None:
        # Sprint 2 R3 canonical-form contract: a tzinfo whose
        # ``utcoffset()`` returns ``None`` is treated as naive, mirroring
        # ``core/canonical.py`` (see line 109) and ``core/sla.py``
        # ``_require_tz_aware``. Without this second clause an exotic
        # tzinfo subclass that lies about its offset would slip past the
        # boundary and corrupt the canonical-form round-trip downstream.
        if self.ts.tzinfo is None or self.ts.utcoffset() is None:
            raise ValueError("ts must be timezone-aware (Sprint 2 R3 canonical-form contract)")
        if self.outcome not in _ALLOWED_OUTCOMES:
            raise ValueError(f"outcome {self.outcome!r} not in {sorted(_ALLOWED_OUTCOMES)}")
        if self.provenance not in _ALLOWED_PROVENANCES:
            raise ValueError(
                f"provenance {self.provenance!r} not in {sorted(_ALLOWED_PROVENANCES)}"
            )


# SQLAlchemy core Table mirroring T4's gateway_call_ledger migration.
# ``sa.TIMESTAMP(timezone=True)`` matches the migration's
# GATEWAY_LEDGER_TS_TYPE — Oracle compiles this to TIMESTAMP WITH TIME
# ZONE, preserving the offset across PG/Oracle. Using
# ``sa.DateTime(timezone=True)`` here would compile to DATE on Oracle
# and silently drop the tz on read.
_ledger_table = sa.Table(
    "gateway_call_ledger",
    sa.MetaData(),
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("request_id", sa.String(length=128), nullable=False),
    sa.Column("tenant_id", sa.String(length=128), nullable=True),
    sa.Column("tier", sa.String(length=16), nullable=False),
    sa.Column("litellm_alias", sa.String(length=128), nullable=False),
    sa.Column("upstream_model", sa.String(length=256), nullable=False),
    sa.Column("upstream_api_base", sa.String(length=512), nullable=True),
    sa.Column("external", sa.Boolean(), nullable=False),
    sa.Column("provenance", sa.String(length=16), nullable=False),
    sa.Column("latency_ms", sa.Integer(), nullable=False),
    sa.Column("outcome", sa.String(length=32), nullable=False),
    sa.Column("model_id", sa.String(length=128), nullable=True),
)


class GatewayCallLedger:
    """Operational ledger writer + reader.

    Single transaction per ``write_row``; a single SELECT against the
    ``ts`` index for ``read_recent_calls``. No batching, no caching —
    the gateway hot path consumes one write per LLM call; the
    endpoint reads the recent window on every probe (≤60s cache TTL
    sits at the endpoint layer, not here).
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def write_row(self, row: GatewayCallRow) -> None:
        """Persist one ledger row.

        Round-4 reviewer-P2 contract: raises on persistence failure.
        The primitive does NOT swallow the error; the gateway picks
        best-effort (log + continue) vs strict (raise
        :class:`LedgerWriteFailed`) at the call site, where it knows
        whether LiteLLM dispatched. Returns ``None`` on success.
        """
        async with self._engine.begin() as conn:
            await conn.execute(_ledger_table.insert().values(**dataclasses.asdict(row)))

    async def read_recent_calls(self, *, window_minutes: int) -> list[GatewayCallRow]:
        """Return rows with ``ts >= now - window_minutes``, newest first.

        Used by ``/api/v1/system/effective-routing`` (T9). The endpoint
        filters drift-detection to ``provenance != "no_dispatch"`` —
        that filter happens at the endpoint layer, not here, so the
        ledger primitive stays general-purpose.
        """
        cutoff = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=window_minutes)
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.select(_ledger_table)
                .where(_ledger_table.c.ts >= cutoff)
                .order_by(_ledger_table.c.ts.desc())
            )
            return [
                GatewayCallRow(**_normalise_row_for_construction(dict(r._mapping)))
                for r in result.fetchall()
            ]


def _normalise_row_for_construction(mapping: dict[str, _t.Any]) -> dict[str, _t.Any]:
    """Re-attach UTC to naive ``ts`` on read-back.

    Mirrors the Sprint-2 ``core.chain_verifier._normalise_datetime``
    convention: SQLite drops tzinfo on ``TIMESTAMP`` round-trip;
    Postgres + Oracle preserve it. The original write was always
    UTC-aware (Sprint-2 R3 contract enforced at ``__post_init__``),
    so a naive value here is unambiguous — it represents UTC. On
    dialects that preserve tzinfo this is a no-op; on SQLite it
    restores the tz so ``GatewayCallRow.__post_init__`` accepts the
    value rather than raising "must be timezone-aware".
    """
    ts = mapping.get("ts")
    if isinstance(ts, _dt.datetime) and ts.tzinfo is None:
        mapping = {**mapping, "ts": ts.replace(tzinfo=_dt.UTC)}
    return mapping


__all__ = ("GatewayCallLedger", "GatewayCallRow")
