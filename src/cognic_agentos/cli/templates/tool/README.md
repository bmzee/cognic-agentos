# {{ pack_id }}

AUTHOR-FILL: short description of what this {{ kind }} pack does.

## Quick start

After scaffolding, edit `cognic-pack-manifest.toml` to replace every
`AUTHOR-FILL:` placeholder. Then:

```sh
agentos validate .
```

surfaces any remaining gaps before you publish. Iterate until exit 0.

## Layout

```
{{ pack_id }}/
├── pyproject.toml
├── cognic-pack-manifest.toml
├── README.md
├── src/{{ module_name }}/
│   ├── __init__.py
│   └── {{ kind }}.py        # Subclass of cognic_agentos.sdk.tool.Tool
├── tests/
│   ├── conftest.py          # Re-exports SDK fixtures
│   └── test_{{ kind }}.py
├── attestations/            # Populated by `agentos sign --bundle .`
└── .github/workflows/sign-and-publish.yml
```

## Implementing the {{ kind }}

Override `_invoke()` in `src/{{ module_name }}/{{ kind }}.py`. The SDK's
`Tool.invoke()` is `@final` — pack code MUST NOT override it; the
SDK's `__init_subclass__` rejects subclasses that try.

```python
class {{ class_name }}(Tool):
    name = "{{ pack_name }}"
    input_schema = {...}
    output_schema = {...}

    async def _invoke(self, **kwargs):
        # AUTHOR-FILL: implement
        ...
```

## Testing locally

```sh
pip install -e ".[dev]"
pytest tests/
```

The SDK ships `fixture_settings`, `fixture_tool_registry`, and
`fixture_audit_capture` — `tests/conftest.py` re-exports them so
they're available as pytest fixture parameters.

## Publishing

```sh
agentos sign --bundle .
agentos verify .
```

The reference workflow at `.github/workflows/sign-and-publish.yml`
wires this into CI on every push to main. AUTHOR-FILL: review +
customize the workflow's publish step for your registry.
