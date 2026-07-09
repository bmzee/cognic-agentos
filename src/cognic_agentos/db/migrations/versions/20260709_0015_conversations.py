"""conversations + conversation_turns — ADR-028 M8.5-A conversation substrate.

The durable conversation record backing
``core.conversation.storage.ConversationStore``. ``conversation.*`` aggregate
evidence lives in the ``decision_history`` chain (digest-only); these tables
hold the operational per-conversation state and the ERASABLE plaintext.

Pins (mirroring 0011 / 0014): ``sa.TIMESTAMP(timezone=True)`` for timestamps —
NOT ``sa.DateTime`` (Oracle drops the offset); ``tenant_id`` is
``String(length=128)`` and ``creator_subject`` ``String(length=256)``, matching
the ``runs`` / ``entitlements`` substrates. Column shapes MUST agree with the
in-process Tables at ``core/conversation/storage.py``; drift pinned by
``tests/unit/db/test_migration_20260709_0015.py``.

``user_message`` / ``answer`` are NULLABLE: the M8.5-F erasure pathway NULLs the
plaintext while preserving the row, so ``seq`` integrity and the
``agent_run_id`` chain correlation survive erasure (ADR-028 §3).

``turn_in_progress`` + ``turn_claimed_at`` implement the atomic single-writer
claim (ADR-028 §4, PT-6): turn POSTs may land on any replica, so the claim is a
DB predicate, never an in-process lock.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | None = None
depends_on: str | None = None

_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("conversation_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("creator_subject", sa.String(length=256), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("turn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cumulative_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("turn_in_progress", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("turn_claimed_at", _TS, nullable=True),
        sa.Column("retention_class", sa.String(length=64), nullable=True),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("last_turn_at", _TS, nullable=True),
        sa.Column("erased_at", _TS, nullable=True),
        sa.CheckConstraint(
            "state IN ('active', 'closed', 'expired', 'erased')",
            name="ck_conversations_state",
        ),
    )
    op.create_index(
        "ix_conversations_tenant_creator_state",
        "conversations",
        ["tenant_id", "creator_subject", "state"],
    )

    op.create_table(
        "conversation_turns",
        sa.Column("turn_id", sa.Uuid(), primary_key=True),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("user_message", sa.Text(), nullable=True),
        sa.Column("answer", sa.Text(), nullable=True),
        sa.Column("agent_run_id", sa.String(length=64), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("erased_at", _TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["conversations.conversation_id"],
            name="fk_conversation_turns_conversation_id",
        ),
        sa.UniqueConstraint(
            "conversation_id", "seq", name="uq_conversation_turns_conversation_seq"
        ),
    )


def downgrade() -> None:
    op.drop_table("conversation_turns")
    op.drop_index("ix_conversations_tenant_creator_state", table_name="conversations")
    op.drop_table("conversations")
