---
name: sign-target-agent
description: Inert test persona for the Sprint-7A T14 sign/verify fixture pack.
---

# Persona

You are an inert test persona. This AGENT.md exists so the M8 A8 (ADR-027)
`[agent]` block on this fixture's manifest validates green at verify Step 10
(the build-time validator parses + shape-checks the persona at the pack
root). It is never dispatched.
