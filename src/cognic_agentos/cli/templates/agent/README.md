# {{ pack_id }}

AUTHOR-FILL: short description of what this {{ kind }} pack does.

## Quick start

```sh
uv lock
uv lock --check
uv sync --frozen --extra dev
uv run agentos validate .
```

Replace every `AUTHOR-FILL:` placeholder + iterate until exit 0.

## Implementing the {{ kind }}

Override `handle(payload, *, task)` in `src/{{ module_name }}/{{ kind }}.py`.
The signature matches the shipped Sprint-6 `A2AEndpoint` dispatch
contract:

  - `payload: bytes` — the inbound JSON-RPC envelope (already
    authn-validated + Wave-2-feature-refusal-checked + version-
    negotiated by the endpoint's gates 1-3).
  - `task: TaskRecord` — the lifecycle record the endpoint mints at
    gate 5; read `task.task_id`, `task.parent_trace_id`, and
    `task.child_trace_id` for cross-agent chain linkage.

```python
class {{ class_name }}(Agent):
    name = "{{ pack_name }}"
    declared_capabilities = A2ACapabilities(...)

    async def handle(self, payload, *, task):
        # AUTHOR-FILL: implement
        return {...}
```

## Agent cards + JWS key custody

The `agent_cards/` directory holds your AGNTCY/OASF-formatted agent
card (`agent-card.json`, tracked — it is the JWS payload) + the
JWS-signed envelope at the path declared in
`cognic-pack-manifest.toml`'s `identity.agent_card_jws_path`. Generate
the JWS via `agentos sign --bundle .`.

The AgentCard JWS signs with a SEPARATE cryptographic identity from
the cosign wheel signature (M8 finding #4, ADR-016 amendment):

  - `COGNIC_SIGNING_KEY_PATH` — the sigstore-encrypted cosign key
    (wheel + attestations).
  - `COGNIC_AGENT_CARD_JWS_SIGNING_KEY_PATH` — an UNENCRYPTED RSA
    private PEM (RS256 detached JWS). Never the cosign key: neither
    file format satisfies the other.

Commit the matching RSA PUBLIC key as the tracked pack-root
`agent-card.pub` (mirrors `cosign.pub`) BEFORE tag/release, and upload
it as a release asset. `agentos verify` checks the JWS against
`--agent-card-trust-root` / `COGNIC_AGENT_CARD_JWS_TRUST_ROOT_PATH` /
the tracked `agent-card.pub` — never against `cosign.pub`.

## Release assets

Derive the release asset list from the actual `agentos sign --bundle .`
output. For an agent pack that is: the wheel, the `attestations/`
bundle (cosign.sig, bundle.sigstore, sbom.cdx.json,
slsa-provenance.intoto.json, intoto-layout.json, vuln-scan.json,
license-audit.json), `agent_cards/agent-card.jws`, plus the two
tracked trust roots `cosign.pub` and `agent-card.pub`.

## Testing

```sh
uv sync --frozen --extra dev
uv run pytest tests/
```

Commit `uv.lock` before release. Run `uv lock --check` and a frozen sync
before `uv build --wheel` + `uv run agentos sign --bundle .`; the lock is the
runtime inventory attested by the SBOM, vulnerability scan, and license report.
