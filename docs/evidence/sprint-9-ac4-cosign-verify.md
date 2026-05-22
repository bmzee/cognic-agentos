# Sprint 9 AC4 — external cosign verify-blob evidence

Date: 2026-05-22
Branch: `feat/sprint-9-iso42001-control-mapping`
Workspace: `/Users/bmz/development/cognic-agentos`

## Purpose

Spec AC4 requires a generated Sprint 9 evidence pack to pass external verification:

- `cosign verify-blob` over `manifest.json`
- the bundled `manifest.json.sig`
- the bundled `manifest.json.bundle.sigstore`
- independent Merkle-root recomputation from the bundled evidence rows

This run used the shipped `export_evidence_pack(...)` path, a temporary local cosign
keypair under `/private/tmp/sprint9-ac4-cosign-verify`, and the real `cosign` binary.
No private key material is stored in this evidence document.

## Tool version

Command:

```bash
cosign version
```

Output:

```text
GitVersion:    v3.0.6
GitCommit:     f1ad3ee952313be5d74a49d67ba0aa8d0d5e351f
GitTreeState:  "clean"
BuildDate:     2026-04-06T21:39:58Z
GoVersion:     go1.26.1
Compiler:      gc
Platform:      darwin/arm64
```

## Compatibility finding fixed before AC4 pass

The first real-exporter attempt exposed a cosign v3 behavior change:

```text
cognic_agentos.compliance.iso42001.signing.EvidencePackSigningError:
cosign sign-blob exited 0 but did not produce both the signature and the Sigstore bundle.
```

Root cause: cosign v3 defaults to the new signing-config/new-bundle path. With the
Sprint 9 argv (`--output-signature` plus `--bundle`), cosign v3 can exit 0 while
ignoring `--output-signature`, producing only a bundle. The evidence-pack wire shape
requires both `manifest.json.sig` and `manifest.json.bundle.sigstore`.

Fix in this branch: `cosign_sign_blob(...)` now passes:

```text
--use-signing-config=false --new-bundle-format=false
```

The regression test
`tests/unit/compliance/iso42001/test_signing_coverage.py::test_cosign_sign_blob_pins_v3_compat_flags_for_sig_and_bundle`
pins both flags.

## Evidence-pack generation

Command:

```bash
COSIGN_PASSWORD=sprint9-ac4 uv run python /private/tmp/sprint9_ac4_generate_pack.py /private/tmp/sprint9-ac4-cosign-verify /private/tmp/sprint9-ac4-cosign-verify/evidence-pack.key
```

Output:

```text
tarball=/private/tmp/sprint9-ac4-cosign-verify/evidence-pack.tar.gz
manifest=/private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json
signature=/private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.sig
bundle=/private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.bundle.sigstore
audit_jsonl=/private/tmp/sprint9-ac4-cosign-verify/extracted/audit_event.jsonl
decision_history_jsonl=/private/tmp/sprint9-ac4-cosign-verify/extracted/decision_history.jsonl
tenant_id=tenant-ac4
merkle_root=48aa30cf18a44b06bbe8e2dccbbb5619621889b0cd615f475ba1c8950bafb7c0
audit_event_row_count=1
decision_history_row_count=1
signing_identity=/private/tmp/sprint9-ac4-cosign-verify/evidence-pack.key
```

Artifact SHA-256:

```text
24cabb485f48fd5cc17a889a2ea74f70b9d749cb17865d9b6a95039309271242  /private/tmp/sprint9-ac4-cosign-verify/evidence-pack.tar.gz
9edc8bb1969c208d2e85e83d07668850bde7dc1f654480b765a4403c4ad5b06b  /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json
2d037c3eeac47e4b97d26ec678e4af2730040484b043c7366b725f07fb624f44  /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.sig
772f73e7fd9ca42dd3c2d464d5d106ac7f1fb67267d3aa1c91748b7461de58a8  /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.bundle.sigstore
```

Artifact sizes:

```text
    2011 /private/tmp/sprint9-ac4-cosign-verify/evidence-pack.tar.gz
    1265 /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json
      96 /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.sig
    1147 /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.bundle.sigstore
     546 /private/tmp/sprint9-ac4-cosign-verify/extracted/audit_event.jsonl
     600 /private/tmp/sprint9-ac4-cosign-verify/extracted/decision_history.jsonl
    5665 total
```

## External cosign verification

Command:

```bash
cosign verify-blob --key /private/tmp/sprint9-ac4-cosign-verify/evidence-pack.pub --signature /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.sig --bundle /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json.bundle.sigstore /private/tmp/sprint9-ac4-cosign-verify/extracted/manifest.json
```

Output:

```text
Verified OK
```

Exit code: 0.

## Independent Merkle recomputation

Command:

```bash
uv run python /private/tmp/sprint9_ac4_verify_merkle.py /private/tmp/sprint9-ac4-cosign-verify/extracted
```

Output:

```text
manifest_merkle_root=48aa30cf18a44b06bbe8e2dccbbb5619621889b0cd615f475ba1c8950bafb7c0
recomputed_merkle_root=48aa30cf18a44b06bbe8e2dccbbb5619621889b0cd615f475ba1c8950bafb7c0
audit_event_rows=1
decision_history_rows=1
match=True
```

Exit code: 0.

## Result

AC4 is satisfied for this generated evidence pack: external `cosign verify-blob`
returned `Verified OK`, and the Merkle root recomputed from bundled JSONL rows matches
the manifest root exactly.
