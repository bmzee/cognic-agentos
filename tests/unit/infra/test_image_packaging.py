"""Structural gate: the AgentOS runtime image stages package the OPA policy bundles
(``policies/``) and ``alembic.ini`` in-image.

Per ADR-024 the image "ships the OPA policy bundles in-image under ``/app/policies/_default/``"
and runs deployed migrations via ``alembic upgrade head`` from the same image. Proof 1b-1
surfaced that the Dockerfile did NOT actually ``COPY`` either (Gap 7: kernel boot fails with
``RegoBundleNotFoundError: policies/_default/tools.rego``; Gap 5: ``alembic`` finds no
``script_location``). This gate pins the packaging so the drift cannot silently return.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOCKERFILE = _REPO_ROOT / "infra" / "agentos" / "Dockerfile"

# The two final stages that boot AgentOS (kernel = create_app; default-adapters = create_prod_app).
# The intermediate ``*-builder`` stages only resolve the venv and are intentionally excluded.
_RUNTIME_STAGES = ("runtime", "default-adapters")


def _stage_bodies() -> dict[str, str]:
    """Split the Dockerfile into ``{stage_name: body}`` keyed by ``FROM ... AS <name>`` markers."""
    text = _DOCKERFILE.read_text()
    markers = list(re.finditer(r"^FROM\s+\S+(?:\s+AS\s+(\S+))?\s*$", text, re.MULTILINE))
    bodies: dict[str, str] = {}
    for i, m in enumerate(markers):
        name = m.group(1)
        if name is None:
            continue
        start = m.end()
        end = markers[i + 1].start() if i + 1 < len(markers) else len(text)
        bodies[name] = text[start:end]
    return bodies


def test_runtime_stages_exist() -> None:
    bodies = _stage_bodies()
    for stage in _RUNTIME_STAGES:
        assert stage in bodies, f"runtime stage {stage!r} not found in the Dockerfile"


def test_runtime_stages_package_policies_and_alembic_ini() -> None:
    bodies = _stage_bodies()
    for stage in _RUNTIME_STAGES:
        body = bodies[stage]
        # The OPA policy bundles build_runtime's OPAEngine loads (/app/policies/_default/*.rego).
        assert re.search(r"COPY\s+--chown=root:cognic\s+policies\s+\./policies", body), (
            f"{stage}: missing `COPY --chown=root:cognic policies ./policies`"
        )
        # The migration script_location config (alembic upgrade head reads /app/alembic.ini).
        assert re.search(r"COPY\s+--chown=root:cognic\s+alembic\.ini\s+\./", body), (
            f"{stage}: missing `COPY --chown=root:cognic alembic.ini ./`"
        )


def test_runtime_stages_make_policies_alembic_and_src_readable_for_non_root() -> None:
    bodies = _stage_bodies()
    for stage in _RUNTIME_STAGES:
        body = bodies[stage]
        # a+rX guarantees the non-root `cognic` user can read these regardless of the build-context
        # umask (a+rX = read for all + traverse for dirs; never adds execute to regular files).
        # /app/src is included because `alembic upgrade head` reads the migrations from
        # src/cognic_agentos/db/migrations (alembic script_location) as the non-root user — a 600
        # migration file from a restrictive build-context umask would otherwise be unreadable and
        # the migrate Job fails with PermissionError (Proof 1b-2 attempt-3 finding).
        assert re.search(
            r"chmod\s+-R\s+a\+rX\s+/app/policies\s+/app/alembic\.ini\s+/app/src\b", body
        ), f"{stage}: `chmod -R a+rX` must cover /app/policies /app/alembic.ini /app/src"
        # The packaging + chmod must run BEFORE the image drops to USER cognic (chmod needs root).
        user_idx = body.find("USER cognic")
        copy_idx = body.find("policies ./policies")
        assert user_idx != -1, f"{stage}: no `USER cognic` in stage"
        assert 0 <= copy_idx < user_idx, f"{stage}: policies packaging must precede `USER cognic`"
