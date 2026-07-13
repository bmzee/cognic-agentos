# {{ pack_id }}

AUTHOR-FILL: short description of what this {{ kind }} pack does.

Skills compose tools deterministically — NO LLM calls in skill code
per ADR-001 three-pool rule. At runtime the action executes fully
sandboxed (M6, ADR-025) and reaches MCP tools ONLY through the
kernel-side broker; `self._tools.get("<server_id>/<tool_name>")`
resolves a declared tool inside `execute()`.

## Quick start

```sh
uv lock
uv lock --check
uv sync --frozen --extra dev
uv run agentos validate .
```

Replace every `AUTHOR-FILL:` placeholder in `cognic-pack-manifest.toml`
+ `pyproject.toml` + `SKILL.md`, then iterate on `agentos validate`
until exit 0.

## The SKILL.md

`SKILL.md` at the pack root is the agentskills.io artifact AgentOS
hosts: frontmatter `name` (lowercase alphanumerics + hyphens, <= 64
chars) + `description` (<= 1024 chars) + a non-empty instructions
body. The build ships it as package data (see the `force-include` in
`pyproject.toml`) so the hosting layer validates it without importing
pack code.

## Implementing the {{ kind }}

Override `execute()` in `src/{{ module_name }}/{{ kind }}.py`. The SDK's
`Skill.__init__` is `@final` + the SDK's `__init_subclass__` rejects
subclasses that define their own constructor — pack-specific init
logic goes in the `setup()` hook the base class calls AFTER the
declared-tools registry cross-check.

```python
class {{ class_name }}(Skill):
    name = "{{ pack_name }}"
    # MCP tool identities ("<server_id>/<tool_name>"); MUST mirror the
    # manifest's [skill].declared_tools list.
    declared_tools = ("cognic-tool-oracle-schema/describe_table",)

    def setup(self) -> None:
        # Pack-specific construction logic here.
        ...

    async def execute(self, **kwargs):
        describe = self._tools.get("cognic-tool-oracle-schema/describe_table")
        result = await describe.invoke(...)
        return {...}
```

## Testing

```sh
uv sync --frozen --extra dev
uv run pytest tests/
```

Commit `uv.lock` before release. Run `uv lock --check` and a frozen sync
before `uv build --wheel` + `uv run agentos sign --bundle .`; the lock is the
runtime inventory attested by the SBOM, vulnerability scan, and license report.
