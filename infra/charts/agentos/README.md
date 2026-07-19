# Cognic AgentOS Helm Chart

This chart deploys the AgentOS kernel and its operator-owned migration step.
See `values.yaml` for the complete configuration surface.

## Secret Sources And Migrations

Choose exactly one bootstrap-secret source:

- `secrets.create=true` is for smoke and development. The chart-created Secret
  is a persistent `pre-install,pre-upgrade` hook at weight `-10`; a temporary
  migration ServiceAccount and parity ConfigMap run at the same earlier weight.
  The temporary resources are deleted after the migration Job at weight `-5`;
  the normal Deployment resources remain ordinary Helm-managed objects.
- `secrets.existingSecret=<name>` uses a Secret the operator creates before the
  Helm release.
- `externalSecrets.enabled=true` uses an ESO-managed Secret. The
  `ExternalSecret` remains a normal resource because its controller must
  materialize the target Secret asynchronously.

For ESO deployments, set `migrations.enabled=false`, wait until the target
Secret is Ready, and run migrations as a post-gate non-hook Job. This is the
same ordering used by the live-proven AKS smoke. Do not turn the
`ExternalSecret` into a Helm pre-install hook: Helm cannot make the ESO
controller finish materialization before another pre-install hook runs.
