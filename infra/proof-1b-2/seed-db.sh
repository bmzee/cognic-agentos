#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proof1b2}"; T="proof-1b-2"; URL="http://10.96.0.50:8765/mcp"; IP="10.96.0.50"
kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 -c "
INSERT INTO mcp_server_url_override (id, tenant_id, pack_id, server_url_override, set_by_actor, set_at, last_request_id)
VALUES (gen_random_uuid(), '$T', 'cognic-tool-search', '$URL', 'proof-1b-2-seed', now(), 'proof-seed-0001')
ON CONFLICT (tenant_id, pack_id) DO UPDATE SET server_url_override = EXCLUDED.server_url_override;
INSERT INTO mcp_internal_host_allowlist (id, tenant_id, ip, set_by_actor, set_at, last_request_id)
VALUES (gen_random_uuid(), '$T', '$IP', 'proof-1b-2-seed', now(), 'proof-seed-0001')
ON CONFLICT (tenant_id, ip) DO NOTHING;"
