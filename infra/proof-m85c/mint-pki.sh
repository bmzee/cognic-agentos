#!/usr/bin/env bash
# infra/proof-m85c/mint-pki.sh — mint the per-run proof PKI (spec §5.1 TLS matrix).
#
# ONE per-run CA signs a server certificate for each TLS-terminating surface:
#   * AgentOS  — SANs: rel-agentos (in-cluster), 127.0.0.1 + localhost (host PF)
#   * Keycloak — SANs: cognic-proof-keycloak, 127.0.0.1, localhost
#   * the BFF  — SANs: cognic-proof-harness, 127.0.0.1, localhost
#
# Every client (the BFF, the kernel's JWKS cache, the proof driver, curl, the
# browser) verifies against this ONE CA. There is no `verify=False` and no
# `-k` on the human-identity path anywhere in the proof — a surface that cannot
# present a CA-signed cert simply does not serve.
#
# Everything is written into the caller-supplied 0700 directory (a per-run
# mktemp removed by the runner's cleanup trap). No key material is ever
# committed, staged into a build context, or baked into an image; the private
# keys reach the cluster ONLY as `kubectl create secret` inputs from this dir.
#
# Usage:  mint-pki.sh <out-dir>
# Emits (all under <out-dir>):
#   proof-ca.pem  proof-ca-key.pem
#   agentos.crt   agentos.key
#   keycloak.crt  keycloak.key
#   harness.crt   harness.key
set -euo pipefail

OUT="${1:?usage: mint-pki.sh <out-dir>}"
[ -d "$OUT" ] || { echo "mint-pki: out-dir $OUT does not exist" >&2; exit 1; }

# --- the root CA -------------------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$OUT/proof-ca-key.pem" -out "$OUT/proof-ca.pem" \
  -days 7 -subj "/CN=Cognic Proof M8.5-C Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
chmod 600 "$OUT/proof-ca-key.pem"
chmod 644 "$OUT/proof-ca.pem"

# _leaf <name> <SAN-list> — mint <name>.key + <name>.crt signed by the CA.
_leaf() {
  local name="$1" sans="$2"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUT/$name.key" -out "$OUT/$name.csr" \
    -subj "/CN=$name" >/dev/null 2>&1
  openssl x509 -req -in "$OUT/$name.csr" \
    -CA "$OUT/proof-ca.pem" -CAkey "$OUT/proof-ca-key.pem" -CAcreateserial \
    -days 7 -out "$OUT/$name.crt" \
    -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$sans") \
    >/dev/null 2>&1
  rm -f "$OUT/$name.csr"
  chmod 600 "$OUT/$name.key"
  chmod 644 "$OUT/$name.crt"
}

# The in-cluster Service names + the host-port-forward loopback both need to
# verify, so every leaf carries its Service DNS name AND 127.0.0.1 + localhost.
_leaf agentos  "DNS:rel-agentos,DNS:rel-agentos.cognic-proofm85c.svc.cluster.local,DNS:localhost,IP:127.0.0.1"
_leaf keycloak "DNS:cognic-proof-keycloak,DNS:cognic-proof-keycloak.cognic-proofm85c.svc.cluster.local,DNS:localhost,IP:127.0.0.1"
_leaf harness  "DNS:cognic-proof-harness,DNS:cognic-proof-harness.cognic-proofm85c.svc.cluster.local,DNS:localhost,IP:127.0.0.1"
# The BFF's dedicated session-store Redis (spec §3.3: TLS, BFF-only, persistence
# off). Reached in-cluster only, by its Service name.
_leaf redis-bff "DNS:redis-bff,DNS:redis-bff.cognic-proofm85c.svc.cluster.local"

echo "  minted the per-run proof CA + 4 leaf certs (agentos / keycloak / harness / redis-bff) under $OUT"
