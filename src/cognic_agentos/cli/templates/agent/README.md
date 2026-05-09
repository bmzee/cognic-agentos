# {{ pack_id }}

AUTHOR-FILL: short description of what this {{ kind }} pack does.

## Quick start

```sh
agentos validate .
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

## Agent cards

The `agent_cards/` directory holds your AGNTCY/OASF-formatted agent
card + the JWS-signed envelope at the path declared in
`cognic-pack-manifest.toml`'s `identity.agent_card_jws_path`. Generate
the JWS via `agentos sign --bundle .`.

## Testing

```sh
pip install -e ".[dev]"
pytest tests/
```
