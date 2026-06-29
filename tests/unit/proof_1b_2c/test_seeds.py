"""Structural pin — the DB + Vault seed scripts (M3-E2c Task 8)."""

import stat
from pathlib import Path

DB_PATH = Path("infra/proof-1b-2c/seed-db.sh")
VAULT_PATH = Path("infra/proof-1b-2c/seed-vault.sh")
DB = DB_PATH.read_text()
VAULT = VAULT_PATH.read_text()


def test_db_seeds_oracle_pack_override_and_allowlist():
    assert 'T="proof-1b-2c"' in DB
    assert 'URL="http://10.96.0.51:8765/mcp"' in DB
    assert 'IP="10.96.0.51"' in DB
    assert "'cognic-tool-oracle-schema'" in DB
    assert "INSERT INTO mcp_server_url_override" in DB
    assert "ON CONFLICT (tenant_id, pack_id) DO UPDATE SET" in DB
    assert "INSERT INTO mcp_internal_host_allowlist" in DB
    assert "ON CONFLICT (tenant_id, ip) DO NOTHING" in DB
    assert "proof-1b-2c-seed" in DB


def test_vault_as_allowlist_trailing_slash_and_oauth():
    assert 'NS="${NS:-cognic-proof1b2c}"' in VAULT
    assert 'T="proof-1b-2c"' in VAULT
    assert 'ASHOST="192.88.99.9_9000"' in VAULT
    assert 'AS="http://192.88.99.9:9000"' in VAULT
    assert "VAULT_TOKEN=smoke-root-token" in VAULT
    assert "VX secrets enable -version=1 -path=secret kv" in VAULT
    # The seeded servers entry carries a TRAILING SLASH via runtime ${AS}/ — load-bearing:
    # FastMCP normalizes the PRM issuer to ".../" and the kernel exact-string compares it.
    assert 'echo "{\\"servers\\":[\\"${AS}/\\"]}"' in VAULT
    assert "@/tmp/as-allowlist.json" in VAULT
    assert '"secret/cognic/$T/mcp-as-allowlist"' in VAULT
    assert '"secret/cognic/$T/mcp-oauth/$ASHOST"' in VAULT
    assert "client_id=proof-client" in VAULT
    assert "client_secret=proof-secret" in VAULT
    assert "auth_method=client_secret_post" in VAULT


def test_vault_does_not_seed_scope():
    # The OAuth scope (oracle_schema.read) is requested by AgentOS at runtime from
    # the pack manifest [tool.cognic.mcp].scopes — it is NOT seeded into Vault.
    assert "oracle_schema.read" not in VAULT


def test_vault_never_uses_inline_servers_string_form():
    # `servers=` stores a string in Vault; the kernel expects a JSON list.
    assert "servers=" not in VAULT


def test_seeds_target_the_proof_namespace_and_commit_as_executable():
    assert "cognic-proof1b2c" in DB and "cognic-proof1b2c" in VAULT
    assert DB_PATH.stat().st_mode & stat.S_IXUSR
    assert VAULT_PATH.stat().st_mode & stat.S_IXUSR
