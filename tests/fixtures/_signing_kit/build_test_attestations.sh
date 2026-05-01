#!/usr/bin/env bash
# Sprint-4 T12 — idempotent regeneration of cognic_test_pack attestations.
#
# Usage:
#   bash tests/fixtures/_signing_kit/build_test_attestations.sh [--regenerate]
#
# By default, this script just validates that the existing attestation
# files are present + JSON-parseable; CI runs it in this mode to detect
# accidental fixture corruption. With --regenerate, it ALSO refreshes
# the cosign.sig + bundle.sigstore using a real cosign sign-blob call
# against an ephemeral keypair (local dev only — CI does not regenerate
# because it would invalidate the @pytest.mark.cosign_real test path's
# expected fixture state).
#
# Per the Sprint-4 plan §"T12 fixture": this script is the only place
# real cosign / Sigstore credentials touch the fixture. Unit tests use
# the shimmed-cosign path (T6's _make_cosign_shim helper) which never
# requires a real signature; the @pytest.mark.cosign_real integration
# path requires both cosign installed AND Sigstore.dev keyless OIDC
# access, so it's gated behind an env var (COGNIC_RUN_COSIGN_REAL=1).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)/cognic_test_pack"
ATTESTATIONS_DIR="${FIXTURE_ROOT}/attestations"

REGENERATE=0
for arg in "$@"; do
  case "${arg}" in
    --regenerate) REGENERATE=1 ;;
    *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
  esac
done

# --- validate existing fixture state ----------------------------------

REQUIRED_FILES=(
  "sbom.cdx.json"
  "slsa-provenance.intoto.json"
  "intoto-layout.json"
  "vuln-scan.json"
  "license-audit.json"
  "cosign.sig"
  "bundle.sigstore"
)

echo "validating ${ATTESTATIONS_DIR} contains all required files..."
for f in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "${ATTESTATIONS_DIR}/${f}" ]]; then
    echo "MISSING: ${f}" >&2
    exit 3
  fi
done

# JSON files parse cleanly (cosign.sig + bundle.sigstore are opaque).
JSON_FILES=(
  "sbom.cdx.json"
  "slsa-provenance.intoto.json"
  "intoto-layout.json"
  "vuln-scan.json"
  "license-audit.json"
)
for f in "${JSON_FILES[@]}"; do
  if ! python3 -c "import json,sys; json.load(open('${ATTESTATIONS_DIR}/${f}'))" 2>/dev/null; then
    echo "MALFORMED JSON: ${f}" >&2
    exit 4
  fi
done

echo "ok: existing fixture state validates"

# --- optionally regenerate cosign.sig + bundle.sigstore ----------------

if [[ "${REGENERATE}" == "1" ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign not on PATH; skipping regeneration (install cosign first)" >&2
    exit 5
  fi

  KEY_DIR="$(mktemp -d)"
  trap 'rm -rf "${KEY_DIR}"' EXIT

  # Ephemeral keypair — fixture signatures are throwaway.
  echo "generating ephemeral cosign keypair in ${KEY_DIR}..."
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "${KEY_DIR}/cosign"

  # Build a tiny "blob" file that represents the wheel (the real cosign
  # signs the wheel; for fixture purposes we sign a stable marker).
  BLOB="${ATTESTATIONS_DIR}/.regen-blob"
  echo "cognic-test-pack-0.1.0-fixture-blob" > "${BLOB}"

  echo "signing fixture blob with ephemeral key..."
  COSIGN_PASSWORD="" cosign sign-blob \
    --key "${KEY_DIR}/cosign.key" \
    --output-signature "${ATTESTATIONS_DIR}/cosign.sig" \
    --output-certificate "${KEY_DIR}/cosign.cert" \
    --yes \
    "${BLOB}"

  # Bundle.sigstore is the modern Sigstore envelope; for the regen
  # path we just record the signature + ephemeral cert into a JSON
  # envelope so the file shape resembles a real bundle. The T9
  # persister doesn't introspect the bundle; only its bytes get
  # SHA-256'd + persisted with retention metadata.
  python3 - <<PY
import base64, json, pathlib
sig = pathlib.Path("${ATTESTATIONS_DIR}/cosign.sig").read_bytes()
cert = pathlib.Path("${KEY_DIR}/cosign.cert").read_bytes()
bundle = {
    "_type": "https://docs.sigstore.dev/Bundle/v0.3",
    "verificationMaterial": {
        "x509CertificateChain": {
            "certificates": [{"rawBytes": base64.b64encode(cert).decode()}],
        },
    },
    "messageSignature": {
        "messageDigest": {
            "algorithm": "SHA2_256",
            "digest": base64.b64encode(b"fixture-digest-placeholder").decode(),
        },
        "signature": base64.b64encode(sig).decode(),
    },
}
pathlib.Path("${ATTESTATIONS_DIR}/bundle.sigstore").write_text(json.dumps(bundle, indent=2))
PY

  rm -f "${BLOB}"
  echo "ok: cosign.sig + bundle.sigstore regenerated against ephemeral key"
fi

echo "done"
