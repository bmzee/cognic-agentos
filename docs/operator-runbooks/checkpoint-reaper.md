# Operator runbook — checkpoint-retention reaper

## What the reaper does

The checkpoint reaper enforces the resumable-session retention floor
(ADR-004). It sweeps every `sandbox_reaper_interval_s` seconds and purges
checkpoints whose `retention_window_s` has elapsed, emitting a
`sandbox.lifecycle.checkpoint_purged` audit-chain row per purge. Without
the reaper running, expired checkpoints accumulate indefinitely.

## Enabling the reaper

The reaper is **OFF by default**. Set `sandbox_reaper_enabled=true`
(env var `COGNIC_SANDBOX_REAPER_ENABLED=true`) to enable it.

**Enable it on EXACTLY ONE instance.** AgentOS production runs multiple
Kubernetes replicas. The Sprint 8.5 reaper is single-instance by design:
if N replicas each enable it, N reapers sweep the same shared object-store
backend and produce N duplicate `checkpoint_purged` audit rows per purge.
The byte-level deletes stay idempotent and safe — the cost is
examiner-facing audit noise. Cross-instance leader election is deferred to
Sprint 10.5; until then, run exactly one reaper.

Recommended deployment: a dedicated single-replica reaper Deployment with
`sandbox_reaper_enabled=true`, while the request-serving Deployment leaves
it `false`.

## Preconditions

1. **Persistent object-store root.** The `local_fs` object-store driver
   (`local_object_store_root`) must point at a persistent path. In
   Kubernetes that is a PersistentVolume, mounted by whichever instance
   runs the reaper. A reaper on an ephemeral path sees an empty store and
   purges nothing.
2. **Database migrations.** The `decision_history` and `audit_event`
   tables must exist — run `uv run alembic upgrade head` (or the migration
   Job) before rolling out the reaper instance. Migrations are not run by
   the app at startup.

## Confirming the posture at startup

The app logs its reaper posture once at startup, on logger
`cognic_agentos.portal.api.app`:

- `sandbox.reaper.started` with `source=settings` — the setting-driven
  reaper is running on this instance.
- `sandbox.reaper.started` with `source=explicit_injection` — a reaper was
  started from an injected `CheckpointStore` (test / embedding scenarios).
- `sandbox.reaper.disabled` — no reaper on this instance; the log carries
  a `remediation` field. Expected on every instance except the designated
  reaper one.

## Fail-loud behaviour

If `sandbox_reaper_enabled=true` but the production adapters are missing or
unusable — no adapter registry, no object-store adapter, or the relational
adapter engine unavailable — the process **fails to start** with a
`RuntimeError` naming the missing dependency. This is intentional: an
operator who explicitly asked for the reaper is never silently given a
no-op. Fix the adapter configuration and restart.
