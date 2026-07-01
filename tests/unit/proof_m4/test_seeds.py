"""Structural pin — the DB + Vault seed scripts (M4 Task 8).

The headline M4 delta: ``seed-db.sh`` MUST NOT seed the derived MCP carve-out
rows (``install`` materializes them). ``seed-vault.sh`` is KEPT (the OAuth + AS
allow-list material is provisioned BY REFERENCE per ADR-026 D5).
"""

import stat
from pathlib import Path

DB_PATH = Path("infra/proof-m4/seed-db.sh")
VAULT_PATH = Path("infra/proof-m4/seed-vault.sh")
DB = DB_PATH.read_text()
VAULT = VAULT_PATH.read_text()


def test_db_seed_does_not_insert_the_derived_carveout_rows():
    """M4: the override + allow-list rows are MATERIALIZED by install, NEVER
    seeded directly. The whole point of the proof — the derived-row INSERT SQL
    (in EITHER table) must not appear anywhere in seed-db.sh."""
    assert "INSERT INTO mcp_server_url_override" not in DB
    assert "INSERT INTO mcp_internal_host_allowlist" not in DB
    # It targets the proof tenant + namespace but is a documented no-op.
    assert 'T="proof-m4"' in DB
    assert "no-op" in DB
    # The materializer is the sole writer (ADR-026 D7) — documented here.
    assert "materialized by \\`install\\`" in DB
    assert "SOLE" in DB


def test_vault_kept_as_allowlist_trailing_slash_and_oauth_by_reference():
    assert 'NS="${NS:-cognic-proofm4}"' in VAULT
    assert 'T="proof-m4"' in VAULT
    assert 'ASHOST="192.88.99.9_9000"' in VAULT
    assert 'AS="http://192.88.99.9:9000"' in VAULT
    assert "VAULT_TOKEN=smoke-root-token" in VAULT
    assert "VX secrets enable -version=1 -path=secret kv" in VAULT
    # The seeded servers entry carries a TRAILING SLASH via runtime ${AS}/ —
    # load-bearing: FastMCP normalizes the PRM issuer to ".../" and the kernel
    # exact-string compares it (mcp_as_not_allowlisted otherwise).
    assert 'echo "{\\"servers\\":[\\"${AS}/\\"]}"' in VAULT
    assert "@/tmp/as-allowlist.json" in VAULT
    assert '"secret/cognic/$T/mcp-as-allowlist"' in VAULT
    assert '"secret/cognic/$T/mcp-oauth/$ASHOST"' in VAULT
    assert "client_id=proof-client" in VAULT
    assert "client_secret=proof-secret" in VAULT
    assert "auth_method=client_secret_post" in VAULT
    # D5 — provisioned BY REFERENCE (configure records the paths; install validates).
    assert "BY REFERENCE" in VAULT


def test_vault_never_uses_inline_servers_string_form():
    # `servers=` stores a string in Vault; the kernel expects a JSON list.
    assert "servers=" not in VAULT


def test_seeds_target_the_proof_namespace_and_commit_as_executable():
    assert "cognic-proofm4" in DB and "cognic-proofm4" in VAULT
    assert DB_PATH.stat().st_mode & stat.S_IXUSR
    assert VAULT_PATH.stat().st_mode & stat.S_IXUSR
