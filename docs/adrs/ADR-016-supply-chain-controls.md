# ADR-016 — Supply-Chain Controls (SLSA / in-toto / Sigstore Bundles / Vulnerability + License Policy)

## Status
**APPROVED for implementation** on 2026-04-26.

**Amended on 2026-05-16** — minor amendment shipped alongside the Sprint 8A T1 design spec. Adds the **canonical sandbox runtime image catalog** as a new class of AgentOS-published runtime artifact subject to the same cosign + SBOM + vuln + license + Sigstore-bundle pipeline as plugin packs. See new subsection §"AgentOS-published runtime artifacts" below.

**Amended on 2026-05-29** (this revision) — Sprint 10.6 / T30 carve-out. The 2026-05-16 amendment said the full plugin-pack verification path (including the catalog's tenant/default **license-deny** policy) re-runs on canonical images at sandbox-create time. That is corrected for the license gate specifically: AgentOS-published canonical platform images are **exempt from the tenant/default license-deny gate at sandbox-create time** — they keep cosign verification + full SBOM/license-inventory generation + retention. See the **2026-05-29 amendment** under §"AgentOS-published runtime artifacts" below.

## Context

ADR-002 specifies cosign signature verification + per-tenant allow-list as the trust gate for plugin packs. That's necessary but insufficient for bank-grade supply-chain assurance. Modern banking + EU AI Act + US Executive Order 14028 expectations:

- **SLSA (Supply-chain Levels for Software Artefacts)** Level 3+ provenance attestations — the artefact came from a hardened build pipeline with non-falsifiable provenance
- **in-toto** layout attestations — the build steps were performed in the declared order by the declared parties
- **Retained Sigstore bundles** per artefact — tamper-evident transparency-log entries that can be re-verified offline years later
- **Vulnerability policy** — each pack scanned for CVEs against bank-tenant-specific severity threshold; fails approval if violated
- **License policy** — each pack's transitive dependency licenses screened against bank's allowed-license list (e.g. some banks refuse AGPL, GPL3, or anything not OSI-approved)
- **Dependency pinning + reproducibility** — every pack ships a lockfile; rebuilds are byte-identical from the same source

Without these, a "signed pack" only proves *who* built it, not *how it was built, what it depends on, what vulnerabilities it carries, or whether the dependency licenses are acceptable*.

## Decision

Extend the trust gate (ADR-002) and pack lifecycle (ADR-012) with a **layered supply-chain assurance model**. Every pack version registered in AgentOS must carry, and the trust gate must verify:

### Required attestations per pack version

| Attestation | What it proves | Tooling |
|---|---|---|
| **cosign signature** (existing per ADR-002) | Identity of publisher | `cosign sign` keyless via OIDC |
| **SLSA provenance v1+** | Artefact built in hardened pipeline matching the declared one (build-id, source ref, builder, materials) | `slsa-github-generator` or equivalent |
| **in-toto layout** | Build steps performed by declared parties in declared order | `in-toto-attest` |
| **SBOM** (existing) | Full transitive dependency inventory in CycloneDX or SPDX | `syft` |
| **Vulnerability scan** | Each dep scanned against current CVE DB at build time + at registration | `grype` or `trivy` |
| **License audit** | Transitive license list with policy match | `syft` + bank's allowed-license JSON |
| **Sigstore bundle** | Combined cosign + Rekor transparency log entry that re-verifies offline | `cosign attest --bundle` |
| **Reproducibility manifest** | Lockfile (uv.lock / package-lock.json / etc.) + builder image digest | pack CI |

All of these are **bundled into a single pack-attestation directory** that travels with the artefact. AgentOS trust gate verifies each at pack registration time.

### AgentOS-published runtime artifacts (2026-05-16 amendment)

Beyond plugin-pack artifacts, AgentOS itself publishes a small set of runtime container images that EVERY sandbox launches from. These images are subject to the same supply-chain pipeline as plugin packs — they are NOT trusted by default just because AgentOS published them.

**Wave-1 canonical sandbox image catalog** (per Sprint 8A spec §9):

| Image | Role |
|---|---|
| `cognic/sandbox-runtime-python:vX.Y@sha256:...` | Pure Python execution (runtime image) |
| `cognic/sandbox-runtime-shell:vX.Y@sha256:...` | Shell scripts + small CLIs (runtime image) |
| `cognic/sandbox-runtime-data:vX.Y@sha256:...` | Data tooling — psql, poppler, pandas (runtime image) |
| `cognic/sandbox-egress-proxy:vX.Y@sha256:...` | Egress proxy sidecar (dual-container topology per ADR-004 Wave-1 amendment) |

Each image carries the full 8-attestation bundle (cosign + SLSA + in-toto + SBOM + vuln scan + license audit + Sigstore bundle + reproducibility manifest). The trust-gate verification path that runs on plugin packs at registration time also runs on these images at sandbox-create time via `sandbox/catalog.py` per Sprint 8A spec §9 (cosign signature verification; see the 2026-05-29 license-gate carve-out below). Banks may tighten via Rego policy (require specific minimum SLSA level, reject specific CVE classes, narrow the license allow-list) but cannot loosen the kernel default-deny posture *for tenant/pack images* without a kernel + ADR amendment. **Refresh cadence**: monthly base-image refresh + on-CVE; tracked in a published cadence policy.

**2026-05-29 amendment (Sprint 10.6 / T30) — canonical platform-image license-policy carve-out.** The 2026-05-16 amendment's "the full pack verification path also runs at sandbox-create time" included the catalog's tenant/default **license-deny** policy (`sandbox/catalog.py: _DEFAULT_LICENSE_POLICY` — a permissive-allow-only set, non-loosenable via `_compose_policy`). That is corrected here for the **license gate specifically**:

- **Canonical platform images carry full supply-chain evidence.** They remain cosign-signed (verified under the canonical trust root at sandbox-create time) and still ship a full SBOM + license inventory + vuln scan + retained attestations as part of the 8-attestation bundle, generated at AgentOS build/sign time. Nothing about evidence generation or retention changes.
- **The tenant/default license-DENY policy does NOT apply to canonical platform images at sandbox-create time.** That policy is a *tenant-content* legal-review control (prevent copyleft/GPL contamination in deployed pack/workload content). AgentOS's own platform base images are necessarily GPL/LGPL-bearing — glibc (LGPL), coreutils/bash (GPL), and the canonical egress proxy (tinyproxy, GPL-2.0) — so applying the permissive-allow-only deny policy to them would make every canonical image unadmittable. Tenant-allow-listed (per-pack) images keep the full license gate unchanged.
- **Canonical platform-image acceptance is an AgentOS release/signing decision** taken under the canonical trust root, not a per-sandbox-create license re-evaluation. The licenses AgentOS's platform images carry are vetted once, at release/signing time, and attested by the canonical signature the sandbox verifies at step 7.
- **Banks retain operational audit.** The full SBOM/license inventory is retained per ADR-006 + this ADR, so a bank can audit exactly which licenses a given AgentOS release's canonical images carry and refuse to *deploy* that release operationally — but runtime sandbox admission does not re-apply the tenant pack license policy to canonical images.

Enforcement: `sandbox/admission.py` step 8 skips `catalog.verify_sbom_policy_or_refuse(...)` when `runtime_image_in_canonical_set` is true; cosign verification (step 7) still runs for canonical images. This carve-out is narrow — it does NOT loosen the license posture for tenant/pack images (the "cannot loosen" rule above stands for that class).

**Per-pack-image escape hatch** — pack manifests may declare their own `[tool.cognic.sandbox] runtime_image = "bank/my-custom-sandbox@sha256:..."` as long as the image (a) carries the full 8-attestation bundle, (b) is signed by a key in the tenant cosign allow-list, and (c) is explicitly tenant-allow-listed in policy.yaml. Per-pack images go through the same trust-gate verification as catalog images; nothing about "we published this one" makes catalog images more trusted at the cryptographic-verification layer — the catalog is a convenience contract for the common case, not a trust shortcut.

### Per-tenant policy gates (delegated to ADR-015 Rego policies)

Banks set their thresholds via Rego policy:

```rego
# packs.rego excerpt
package cognic.packs

# Reject any pack with a CVSS ≥ 7.0 unfixed vulnerability
deny[msg] {
    some vuln in input.attestations.vuln_scan.findings
    vuln.cvss >= 7.0
    not vuln.has_fix
    msg := sprintf("vulnerability %s exceeds CVSS threshold", [vuln.id])
}

# Reject any pack with non-allowlisted license
deny[msg] {
    some lib in input.attestations.sbom.dependencies
    not data.cognic.licenses.allowed[lib.license]
    msg := sprintf("dependency %s has disallowed license %s", [lib.name, lib.license])
}

# Require SLSA Level 3+ provenance
deny[msg] {
    input.attestations.slsa.level < 3
    msg := "SLSA Level 3+ required"
}
```

Bank security team owns the policy bundle; bank operations team configures per-tenant tolerance (e.g. dev tenant allows CVSS 7.0, prod tenant requires 4.0).

### Retention + offline re-verification

- Sigstore bundles **retained for 7 years** in ObjectStoreAdapter (per ADR-009; longest expected regulator retention window). Pack records never lose their attestation pointer.
- Re-verification is offline — bundles are self-contained (Rekor entry + signed metadata). Works even if Sigstore.dev is down or the project sunsets.
- Annual integrity sweep: a scheduled job picks 1% of registered packs at random, re-verifies their bundles, alerts on failure.

### Reproducibility commitment

Pack manifests declare a `reproducible: true` flag if the publisher commits to byte-identical rebuilds. Reviewers can re-run the published build pipeline against the recorded source ref and verify the resulting artefact digest matches. This is **opt-in**, not mandatory — but tenants can require `reproducible: true` via policy.

### Pack-side tooling (Sprint 7A SDK extension)

`agentos sign` (Sprint 7A) extends to:
- `agentos sign --bundle vault://...` — produces cosign signature + SLSA provenance + in-toto layout + SBOM + vuln-scan-baseline + license audit, all attached as the pack-attestation bundle
- `agentos verify <pack-path>` — local verification before submission (catches issues before they hit reviewer)

### What this is NOT

- **Not a runtime check.** Supply-chain attestations are verified at **registration** (pack lifecycle `submitted → approved` transition). Once approved, the runtime trusts the registered signature + SBOM; it doesn't re-scan on every invocation.
- **Not a substitute for adversarial testing** (ADR-011) or eval (ADR-010). Supply-chain proves the *build*; eval/adversarial prove the *behaviour*.
- **Not vendored Sigstore infra.** Banks who run their own Sigstore-compatible transparency log substitute via config; AgentOS verifies bundles, doesn't host them.

## Consequences

### Positive
- **EU AI Act / Executive Order 14028 / FedRAMP-style supply-chain expectations** are met by construction
- **Offline re-verification** survives Sigstore-the-service going down or sunsetting
- **Per-tenant policy** lets dev tenants iterate fast (loose CVSS) while prod tenants enforce strictly (tight CVSS)
- **License hygiene** — banks know exactly which deps they're shipping; AGPL accidents caught at registration
- **Reviewer evidence** — Sprint 7B reviewer dashboard shows the full attestation bundle in one view; approval is data-driven

### Negative
- **Significant CI burden on pack authors** — `agentos sign --bundle` runs ~5-10 minutes for a full bundle. Mitigation: cache slow steps (SBOM, license scan); incremental for dep-only changes.
- **Bundle storage** — SLSA + in-toto + Sigstore bundles add ~5-10 MB per pack version. ObjectStoreAdapter handles this; retention cost is negligible.
- **Vuln DB drift** — a pack vuln-scanned at registration may have new CVEs by deployment time. Mitigation: scheduled re-scan job emits `pack.vuln_drift` events when a registered pack's deps gain a new CVE that exceeds policy.
- **Reproducibility ambition** — "byte-identical rebuilds" is hard. Most packs won't claim it. Acceptable; opt-in flag.

### Neutral
- Cognic Forge (Wave 2 — fine-tuning) inherits the same supply-chain controls for model artefacts: SLSA provenance on training run, attested data manifest, Sigstore bundle for the model weights file.

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 4** (extended) | Trust gate verifies SLSA + in-toto + SBOM + vuln scan + license audit + Sigstore bundle. Bundle parsing + verification helpers. Wave 1 ships strict cosign + SBOM + Sigstore bundle as **mandatory**; SLSA L3 + in-toto + vuln + license declared **mandatory but with grace-period**: packs without these can register but show `attestation_grade: partial` in the registry; tenants can require `attestation_grade: full` via policy. |
| **Sprint 7A** | `agentos sign --bundle` produces full attestation set; `agentos verify` runs offline check |
| **Sprint 7B** | Reviewer evidence view includes attestation summary; approval gates check policy thresholds (delegated to ADR-015 Rego) |
| **Sprint 14 (deployment kit)** | Per-tenant policy bundle templates for vuln/license thresholds |
| **Wave 2** | Annual integrity sweep job; reproducibility verifier; vuln-drift alerting |

Sprint 4 grows from ~3 wu to ~3.5 wu. Sprint 7A grows from 2 wu to ~2.5 wu.

## MCP/A2A startup discovery cross-ref (2026-06-21) — first runtime caller of the full attestation pipeline

The startup plugin-registry boot-builder (`harness/registry_boot.build_and_populate_registry`, per the ADR-002 "MCP/A2A startup discovery + trust-registration amendment (2026-06-21)") is the **first production runtime caller** of the full `register_with_full_attestation_check` supply-chain attestation pipeline (cosign verify-blob over the signed wheel → SBOM digest match → SLSA + in-toto shape → Sigstore-bundle persistence → policy) — previously only the offline CLI (`agentos verify`) + a unit test exercised it. At boot the runtime resolves each installed pack's signed wheel + attestations from a deployment `Settings.pack_attestation_root_path` (via the on-gate trust-input resolver `protocol/pack_attestation_resolver.py`, CC 134) and runs the full pipeline per pack under `_default`. The supply-chain controls themselves are unchanged; this is a new *consumer* of them.

## Amendment (2026-06-22) — cosign 3.x legacy-compat bridge (Fork A)

cosign 3.x changed the `sign-blob` defaults: it defaults to
`--new-bundle-format=true`, deprecates + ignores `--output-signature`, and
uploads to public Rekor by default. The kernel's pack/CLI signing path was
hard-wired to cosign 2.x's detached-signature contract and broke (the
`cosign.sig` artifact was never produced). This amendment adopts **Fork A —
a legacy-compat bridge** that keeps the existing `cosign.sig` + `bundle.sigstore`
attestation contract (filenames, `PackAttestations`, the resolver required-set,
the `SignatureRedReason` 5-gate vocab, and all manifest templates UNCHANGED) by
adding the verified compat flags. Verified on cosign 3.0.6.

**Sign argv** (`cli/sign.py`, `compliance/iso42001/signing.py`): add
`--tlog-upload=false --use-signing-config=false --new-bundle-format=false`.
`--tlog-upload=false` is what disables the public-Rekor upload (air-gapped-
correct); the evidence-pack signing path (`compliance/iso42001/signing.py`) adds
only `--tlog-upload=false` (it already carried the other two).

**Verify argv** (`cli/verify.py`, `protocol/trust_gate.py`): add
`--insecure-ignore-tlog --new-bundle-format=false` (the offline-signed artifact
has no Rekor entry, so verify must not search the public log). `trust_gate.
verify_pack_signature` additionally gains a required `bundle_path: Path`
parameter + passes `--bundle`; `signature_digest` stays the SHA-256 of
`cosign.sig`. The model path (`models/trust.py`) is bundle-only and adds only
`--insecure-ignore-tlog` (no `--signature`, no `--new-bundle-format=false`).

**Posture:** signing is now offline / no public Rekor upload by default. On
cosign 3.0.6 the produced legacy bundle is `base64Signature`-only — it carries
neither a `tlogEntries` (new format) nor a `rekorBundle` (legacy format) key,
confirming nothing was uploaded.

**Known debt + long-term cleanup (Fork B):** this bridge deliberately rides
cosign's **deprecated-but-functional** `--tlog-upload` + `--output-signature`
flags (both emit deprecation warnings on 3.0.6 and are on cosign's removal path).
When cosign removes them, **Fork B — true bundle-only verification (drop
`cosign.sig`, verify against `--bundle` only, converge on the `models/trust.py`
shape)** becomes mandatory for the pack path; it is tracked as the long-term
cleanup (it touches the wire-public attestation vocab + must separately solve
air-gapped signing, so it is out of scope for this bridge). The narrow model-path
`--insecure-ignore-tlog` is a current, non-deprecated flag and does not carry
this debt.

The end-to-end offline round-trip (real `agentos sign-blob` → offline bundle →
both `cli/verify.py` and runtime `trust_gate` verify) is pinned by the env-gated
proof `tests/integration/cli/test_real_cosign_sign_verify_proof.py`
(`COGNIC_RUN_COSIGN_INTEGRATION=1`; skip-by-default, fail-loud when opted in
without cosign).

## Amendment (2026-06-23) — in-toto Wave-1 simplified layout contract

`agentos sign` emits a **Wave-1 simplified** in-toto layout declaring
`_type = "in-toto-layout/v1-wave1-simplified"` that intentionally omits the full
in-toto step-graph + expiration (deferred to Wave-2). The runtime trust gate
(`protocol/supply_chain.py:_verify_intoto`) verifies this declared contract by
branching on `_type`: a simplified layout is validated on its security fields —
`pack_id`, `pack_version`, `pack_kind` (∈ `{tool, skill, agent, hook}`),
`signing_identity`, `artifact_paths` (non-empty list of non-blank strings) — all
present-structural hard-refusals (`IntotoTampered`). A layout without that `_type`
(including the Statement-wrapped full layout) still goes through the full
`steps`+`expires` branch (unchanged). The contract type is single-sourced as
`AGENTOS_INTOTO_LAYOUT_TYPE` in `protocol/supply_chain.py` and imported by
`cli/sign.py` + `cli/verify.py`. `pack_kind` is validated structurally only; the
full in-toto layout (steps / inspections / key-thresholds) and a cross-layer
manifest pack_kind-flip comparison remain Wave-2. Surfaced + proven by Proof 1a
Task 7 (the first real `agentos sign` → runtime registration exercise).

## References
- ADR-002 (cosign signing — extended here)
- ADR-009 (ObjectStoreAdapter — bundle retention)
- ADR-012 (pack lifecycle — registration is the verification point)
- ADR-015 (Rego policy decides per-tenant thresholds)
- [SLSA framework](https://slsa.dev/)
- [in-toto specification](https://in-toto.io/)
- [Sigstore](https://www.sigstore.dev/)
- [Syft / Grype — SBOM + vuln scanning](https://github.com/anchore)
- [US Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
