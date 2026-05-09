# {{ pack_id }}

AUTHOR-FILL: short description of what this {{ kind }} pack does.

Skills compose tools deterministically — NO LLM calls in skill code
per ADR-001 three-pool rule. Use `self._tools.get(name)` to resolve a
registered tool inside `execute()`.

## Quick start

```sh
agentos validate .
```

Replace every `AUTHOR-FILL:` placeholder in `cognic-pack-manifest.toml`
+ `pyproject.toml`, then iterate on `agentos validate` until exit 0.

## Implementing the {{ kind }}

Override `execute()` in `src/{{ module_name }}/{{ kind }}.py`. The SDK's
`Skill.__init__` is `@final` + the SDK's `__init_subclass__` rejects
subclasses that define their own constructor — pack-specific init
logic goes in the `setup()` hook the base class calls AFTER the
declared-tools registry cross-check.

```python
class {{ class_name }}(Skill):
    name = "{{ pack_name }}"
    declared_tools = ("alpha", "beta")  # tool names you depend on

    def setup(self) -> None:
        # Pack-specific construction logic here.
        ...

    async def execute(self, **kwargs):
        alpha = self._tools.get("alpha")
        result = await alpha.invoke(...)
        return {...}
```

## Testing

```sh
pip install -e ".[dev]"
pytest tests/
```
