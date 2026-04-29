"""Programmatic Alembic config — resolves ``script_location`` from
the package, immune to the current working directory.

The ``alembic.ini`` file at the repo root is for the **alembic CLI**
(``uv run alembic upgrade head`` — the operator path documented in
``docs/operator-runbooks/governance-tables-grants.md``). It ships in
the source tree but is intentionally **NOT** copied into the runtime
Docker images: a Kubernetes migration job, an operator script run
from ``/opt`` or ``/srv``, or any packaged programmatic call must
work without it.

Both adapter migration entrypoints (``PostgresAdapter.run_migrations``
and ``OracleAdapter.run_migrations``) MUST go through
``make_alembic_config`` so the Alembic ``script_location`` is
anchored at this module's filesystem path — wherever the package is
installed — rather than at a CWD-relative ``alembic.ini`` that may
not exist.

Originally surfaced as a P1 deployment-path finding on PR #6 review:
``Config("alembic.ini")`` returns an empty config + raises
``CommandError: No 'script_location' key found in configuration`` when
called from any non-repo-root CWD. The bug is invisible to CI (which
runs from the repo root) but breaks every production deployment that
calls ``adapter.run_migrations()`` from a packaged context.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config

#: Absolute path to the migrations package — resolved from this
#: module's own filesystem location. ``Path(__file__).parent`` is the
#: ``db/migrations/`` directory itself, which is exactly what alembic
#: wants for ``script_location`` (it expects a directory containing
#: ``env.py`` + ``versions/``).
_MIGRATIONS_DIR: Path = Path(__file__).resolve().parent


def make_alembic_config(url: str) -> Config:
    """Build an Alembic ``Config`` with absolute ``script_location``
    and the caller-provided ``sqlalchemy.url`` pinned.

    Pinning ``sqlalchemy.url`` here means ``env.py``'s URL-resolution
    fallback chain (operator's ``COGNIC_DATABASE_URL`` via
    ``core.config.Settings``) is bypassed in favour of the adapter's
    own URL. ``env.py`` honours a pre-set ``sqlalchemy.url`` and only
    falls back to ``Settings`` when none is provided (the alembic-CLI
    invocation path).

    ``alembic.ini``-only settings (``file_template``,
    ``truncate_slug_length``, the logging stanzas) are intentionally
    NOT replicated here: those are CLI-shape concerns; programmatic
    ``command.upgrade()`` does not need them.
    """

    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", url)
    return config


__all__: tuple[str, ...] = ("make_alembic_config",)
