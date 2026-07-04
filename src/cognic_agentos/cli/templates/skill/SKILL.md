---
name: {{ pack_id | replace("_", "-") }}
description: "AUTHOR-FILL: one-sentence summary of what this skill does (max 1024 chars)."
---

# {{ class_name }}

AUTHOR-FILL: write the agentskills.io instructions body here — what the
skill does, when a caller should invoke it, and what the declared tools
return. This body is hosted (read-only) by AgentOS; the executable action
in `src/{{ module_name }}/skill.py` runs fully sandboxed and reaches MCP
tools only through the kernel-side broker.

## Declared tools

The action may call ONLY the `<server_id>/<tool_name>` identities listed
in `cognic-pack-manifest.toml` `[skill].declared_tools` — the broker
refuses anything else at runtime.
