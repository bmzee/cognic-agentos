"""M8 (ADR-027 + ADR-002 amendment, 2026-07-06) — instruction-skill
manifest-walk discovery.

Instruction-only skill packs (``[pack] kind="skill"`` + ``[skill]
mode="instruction"``) are CONTENT packs: SKILL.md + the signed
``cognic-pack-manifest.toml`` as package data, with NO entry points of any
kind (the A7 validator refuses a ``cognic.skills`` entry point on an
instruction manifest). ``PluginRegistry.discover()`` therefore gains a
SECOND arm that walks ``importlib.metadata.distributions()`` and yields a
``DiscoveredPack(entry_point=None)`` per installed distribution whose signed
manifest says instruction-skill — strictly filtered, deferred-load
preserved (the manifest is READ, pack code is never imported).

Test strategy: fake-but-real-file distributions. ``_FakeDist`` is an
``importlib.metadata.Distribution``-shaped stub whose ``metadata`` /
``version`` / ``entry_points`` / ``files`` / ``locate_file`` surfaces are
backed by REAL files written under ``tmp_path`` (real TOML bytes at
``<pkg>/cognic-pack-manifest.toml``), so the REAL
``mcp_manifest.extract_pack_manifest`` runs unmodified. One monkeypatch
site (``importlib.metadata``) covers both ``plugin_registry._im`` and
``mcp_manifest._im`` — they alias the same module object.
"""

from __future__ import annotations

import datetime as _dt
import importlib
import importlib.metadata as _im
import logging
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    ManifestOnlyPackNotLoadable,
    PluginNotRegistered,
    PluginRegistry,
    RegistrationRefused,
)

_REGISTRY_LOGGER = "cognic_agentos.protocol.plugin_registry"

#: Mirrors ``_TEST_SIGNATURE_DIGEST`` in ``test_plugin_registry.py`` — the
#: registry only requires a non-empty string per ADR-002.
_TEST_SIGNATURE_DIGEST = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# Fixtures — audit substrate (mirrors test_plugin_registry.py)
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'manifest_discovery_test.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def registry(audit_store: AuditStore) -> PluginRegistry:
    return PluginRegistry(audit_store=audit_store)


# ---------------------------------------------------------------------------
# Fake distribution — real files under tmp_path
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """``importlib.metadata.EntryPoint``-shaped stub (mirrors the sibling
    fake in ``test_plugin_registry.py``)."""

    def __init__(self, *, name: str, value: str, group: str, dist: Any = None) -> None:
        self.name = name
        self.value = value
        self.group = group
        self.dist = dist


class _FakeDist:
    """``importlib.metadata.Distribution``-shaped fake backed by REAL files.

    ``metadata`` / ``version`` / ``entry_points`` / ``files`` /
    ``locate_file`` are exactly the surfaces the manifest-walk discovery arm
    + the real ``extract_pack_manifest`` read. ``files`` entries are real
    ``importlib.metadata.PackagePath`` objects; ``locate_file`` resolves
    against a tmp_path-backed root where the builder wrote real TOML bytes.
    """

    def __init__(
        self,
        *,
        name: str | None,
        version: str | None,
        root: Path,
        files: list[str] | None,
        entry_points: tuple[Any, ...] = (),
        metadata_raises: bool = False,
    ) -> None:
        self._name = name
        self.version = version
        self._root = root
        self._files = files
        self._entry_points = entry_points
        self._metadata_raises = metadata_raises

    @property
    def metadata(self) -> dict[str, Any]:
        if self._metadata_raises:
            raise RuntimeError("broken installed distribution (fixture)")
        return {"Name": self._name}

    @property
    def entry_points(self) -> tuple[Any, ...]:
        return self._entry_points

    @property
    def files(self) -> list[_im.PackagePath] | None:
        if self._files is None:
            return None
        return [_im.PackagePath(f) for f in self._files]

    def locate_file(self, relative: Any) -> Path:
        return self._root / str(relative)


def _instruction_toml(*, mode: str | None = "instruction", kind: str | None = "skill") -> str:
    lines = []
    if kind is not None:
        lines += ["[pack]", 'pack_id = "demo"', f'kind = "{kind}"', ""]
    lines += ["[skill]"]
    if mode is not None:
        lines += [f'mode = "{mode}"']
    return "\n".join(lines) + "\n"


def _write_manifest(root: Path, package: str, toml_text: str) -> Path:
    pkg_dir = root / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    manifest = pkg_dir / "cognic-pack-manifest.toml"
    manifest.write_text(toml_text, encoding="utf-8")
    return manifest


def _make_dist(
    tmp_path: Path,
    *,
    name: str | None = "cognic-skill-notes",
    package: str = "cognic_skill_notes",
    version: str | None = "0.1.0",
    toml_text: str | None = None,
    entry_points: tuple[Any, ...] = (),
    write_manifest: bool = True,
    files: list[str] | None | object = "auto",
    metadata_raises: bool = False,
) -> _FakeDist:
    """One manifest-only fake dist with a REAL manifest file on disk.

    ``files="auto"`` derives the RECORD-style list from the written layout,
    including 1-part / 2-part-non-manifest / 3-part decoys that the discovery
    arm's exactly-2-parts + basename filter must ignore.
    """
    root = tmp_path / (name or "unnamed-dist")
    if write_manifest:
        _write_manifest(root, package, toml_text if toml_text is not None else _instruction_toml())
    if files == "auto":
        file_list = [
            "README.md",  # 1 part — ignored
            f"{name}.dist-info/METADATA",  # 2 parts, wrong basename — ignored
            f"{package}/cognic-pack-manifest.toml",
            f"{package}/SKILL.md",  # 2 parts, wrong basename — ignored
            f"{package}/nested/cognic-pack-manifest.toml",  # 3 parts — ignored
        ]
    else:
        file_list = files  # type: ignore[assignment]
    return _FakeDist(
        name=name,
        version=version,
        root=root,
        files=file_list,
        entry_points=entry_points,
        metadata_raises=metadata_raises,
    )


@pytest.fixture
def metadata_env(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Route ``importlib.metadata.{distributions,distribution,entry_points}``
    to a mutable fake-dist list. ONE patch site covers ``plugin_registry._im``
    AND ``mcp_manifest._im`` (both alias the same module object), so the REAL
    ``extract_pack_manifest`` resolves names to the same fakes."""
    dists: list[Any] = []

    def _distributions() -> Iterator[Any]:
        return iter(list(dists))

    def _distribution(name: str) -> Any:
        for dist in dists:
            try:
                if dist.metadata["Name"] == name:
                    return dist
            except Exception:
                continue
        raise _im.PackageNotFoundError(name)

    def _entry_points(*, group: str) -> list[Any]:
        return [ep for dist in dists for ep in dist.entry_points if ep.group == group]

    monkeypatch.setattr(_im, "distributions", _distributions)
    monkeypatch.setattr(_im, "distribution", _distribution)
    monkeypatch.setattr(_im, "entry_points", _entry_points)
    return dists


def _warnings_for(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        rec.getMessage()
        for rec in caplog.records
        if rec.name == _REGISTRY_LOGGER and rec.levelno >= logging.WARNING
    ]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestManifestWalkHappyPath:
    def test_instruction_pack_discovered_with_exact_record_fields(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        metadata_env.append(_make_dist(tmp_path))
        packs = registry.discover()
        assert len(packs) == 1
        pack = packs[0]
        assert isinstance(pack, DiscoveredPack)
        assert pack.entry_point is None
        rec = pack.record
        assert rec.kind == "skills"
        assert rec.name == "cognic-skill-notes"
        assert rec.distribution_name == "cognic-skill-notes"
        assert rec.distribution_version == "0.1.0"
        # LOCKED convention: entry_point_value carries the bare importable
        # package dir so iter_registered_pack_candidates()' split-derivation
        # yields exactly the right package_name with zero downstream change.
        assert rec.entry_point_value == "cognic_skill_notes"

    def test_missing_version_records_unknown_placeholder(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, version=None))
        packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].record.distribution_version == "<unknown>"

    def test_legacy_dual_path_blocks_discovered(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """Dual-path doctrine: legacy ``[tool.cognic.pack]`` +
        ``[tool.cognic.skill]`` blocks classify identically."""
        legacy_toml = (
            "[tool.cognic.pack]\n"
            'pack_id = "demo"\n'
            'kind = "skill"\n'
            "\n"
            "[tool.cognic.skill]\n"
            'mode = "instruction"\n'
        )
        metadata_env.append(_make_dist(tmp_path, toml_text=legacy_toml))
        packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].entry_point is None
        assert packs[0].record.kind == "skills"

    def test_non_cognic_entry_points_do_not_disqualify(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """The manifest-only rule keys on cognic.* groups ONLY — an
        unrelated ``console_scripts`` entry point must not hide an
        instruction pack."""
        dist = _make_dist(
            tmp_path,
            entry_points=(
                _FakeEntryPoint(name="x", value="pkg.cli:main", group="console_scripts"),
            ),
        )
        metadata_env.append(dist)
        packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].entry_point is None


# ---------------------------------------------------------------------------
# The manifest-only rule (dedup vs entry-point arms)
# ---------------------------------------------------------------------------


class TestManifestOnlyRule:
    @pytest.mark.parametrize("group", ["cognic.skills", "cognic.tools"])
    def test_cognic_entry_point_dist_not_double_discovered(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        group: str,
    ) -> None:
        """A dist declaring ANY cognic.* entry point rides the entry-point
        arms EXCLUSIVELY — even when it also ships an instruction manifest.
        Exactly one DiscoveredPack results, and it is the ep-arm entry."""
        dist = _make_dist(tmp_path)
        ep: Any = _FakeEntryPoint(
            name="notes", value="cognic_skill_notes:Plugin", group=group, dist=dist
        )
        dist._entry_points = (ep,)
        metadata_env.append(dist)
        packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].entry_point is ep  # ep-arm entry, NOT the manifest arm


# ---------------------------------------------------------------------------
# Filters — skip semantics
# ---------------------------------------------------------------------------


class TestManifestWalkFilters:
    def test_tool_kind_manifest_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, toml_text=_instruction_toml(kind="tool")))
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_pack_block_absent_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, toml_text='[skill]\nmode = "instruction"\n'))
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_pack_kind_non_string_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(
            _make_dist(tmp_path, toml_text='[pack]\nkind = 7\n\n[skill]\nmode = "instruction"\n')
        )
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_skill_kind_mode_absent_skipped_with_warning(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """kind="skill" without instruction mode (absent → executable
        default) is undiscoverable any other way — operators need the
        signal."""
        metadata_env.append(_make_dist(tmp_path, toml_text=_instruction_toml(mode=None)))
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("cognic-skill-notes" in m for m in _warnings_for(caplog))

    def test_skill_kind_executable_mode_skipped_with_warning(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, toml_text=_instruction_toml(mode="executable")))
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("cognic-skill-notes" in m for m in _warnings_for(caplog))

    def test_skill_kind_invalid_mode_skipped_with_warning(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, toml_text=_instruction_toml(mode="banana")))
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("cognic-skill-notes" in m for m in _warnings_for(caplog))

    def test_skill_kind_skill_block_absent_skipped_with_warning(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(
            _make_dist(tmp_path, toml_text='[pack]\npack_id = "demo"\nkind = "skill"\n')
        )
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("cognic-skill-notes" in m for m in _warnings_for(caplog))

    def test_malformed_toml_skipped_with_warning(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, toml_text="not [ valid toml ==="))
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("malformed" in m for m in _warnings_for(caplog))

    def test_manifest_listed_but_missing_on_disk_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """RECORD lists the manifest but the file is absent on disk —
        ``extract_pack_manifest`` raises NotFound; skip without warning."""
        metadata_env.append(_make_dist(tmp_path, write_manifest=False))
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_zero_manifest_dist_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(
            _make_dist(
                tmp_path,
                name="plain-lib",
                write_manifest=False,
                files=["plain_lib/__init__.py", "plain_lib.dist-info/METADATA"],
            )
        )
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_files_none_dist_skipped_silently(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, name="no-files-lib", files=None))
        with caplog.at_level(logging.DEBUG, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert _warnings_for(caplog) == []

    def test_missing_or_empty_name_skipped(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        metadata_env.append(_make_dist(tmp_path, name=None))
        metadata_env.append(
            _make_dist(
                tmp_path,
                name="",
                files=["cognic_skill_notes/cognic-pack-manifest.toml"],
                write_manifest=False,
            )
        )
        assert registry.discover() == []

    def test_two_manifest_packages_ambiguous_warn_skips(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        root = tmp_path / "cognic-skill-twin"
        _write_manifest(root, "pkg_a", _instruction_toml())
        _write_manifest(root, "pkg_b", _instruction_toml())
        metadata_env.append(
            _FakeDist(
                name="cognic-skill-twin",
                version="0.1.0",
                root=root,
                files=[
                    "pkg_a/cognic-pack-manifest.toml",
                    "pkg_b/cognic-pack-manifest.toml",
                ],
            )
        )
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            assert registry.discover() == []
        assert any("ambiguous" in m for m in _warnings_for(caplog))

    def test_duplicate_dist_yielded_twice_discovered_once(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        dist = _make_dist(tmp_path)
        metadata_env.append(dist)
        metadata_env.append(dist)
        packs = registry.discover()
        assert len(packs) == 1

    def test_broken_dist_warn_skipped_and_following_dist_still_discovered(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Per-dist fail-soft: one broken installed distribution must never
        kill discovery (mirrors registry_boot's per-pack posture)."""
        metadata_env.append(
            _make_dist(tmp_path, name="broken-dist", write_manifest=False, metadata_raises=True)
        )
        metadata_env.append(_make_dist(tmp_path))
        with caplog.at_level(logging.WARNING, logger=_REGISTRY_LOGGER):
            packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].record.distribution_name == "cognic-skill-notes"
        assert any("RuntimeError" in m for m in _warnings_for(caplog))


# ---------------------------------------------------------------------------
# Deferred-load invariant
# ---------------------------------------------------------------------------


class TestManifestWalkDeferredLoad:
    def test_manifest_discovery_imports_no_pack_module(
        self,
        registry: PluginRegistry,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mirror ``test_discover_does_not_eager_import_pack_modules``: the
        manifest arm reads the manifest FILE only — pack code is never
        imported (ADR-002 §gate 1 deferred-load invariant)."""
        metadata_env.append(_make_dist(tmp_path))

        real_import_module = importlib.import_module

        def _raise_on_pack_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.startswith("cognic_skill_notes"):
                raise AssertionError(
                    "Deferred-load invariant violated: manifest-walk "
                    f"discovery tried to import pack module {name!r}"
                )
            return real_import_module(name, *args, **kwargs)

        monkeypatch.setattr(importlib, "import_module", _raise_on_pack_import)
        packs = registry.discover()
        assert len(packs) == 1
        assert "cognic_skill_notes" not in sys.modules


# ---------------------------------------------------------------------------
# End-to-end: register → candidates → load refusal
# ---------------------------------------------------------------------------


class TestManifestOnlyRegisterAndLoad:
    async def test_register_succeeds_and_candidate_yields_package_name(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        metadata_env.append(_make_dist(tmp_path))
        packs = registry.discover()
        outcome = await registry.register(
            packs[0],
            attestation_grade="full",
            signature_digest=_TEST_SIGNATURE_DIGEST,
        )
        assert outcome.status == "registered"
        assert outcome.pack_id == "cognic-skill-notes"
        candidates = list(registry.iter_registered_pack_candidates())
        assert len(candidates) == 1
        assert candidates[0].distribution_name == "cognic-skill-notes"
        # The LOCKED entry_point_value=package-name convention makes the
        # existing split-derivation yield the importable package dir.
        assert candidates[0].package_name == "cognic_skill_notes"
        assert candidates[0].signature_digest == _TEST_SIGNATURE_DIGEST

    async def test_load_raises_manifest_only_not_loadable(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        metadata_env.append(_make_dist(tmp_path))
        packs = registry.discover()
        await registry.register(
            packs[0],
            attestation_grade="full",
            signature_digest=_TEST_SIGNATURE_DIGEST,
        )
        with pytest.raises(ManifestOnlyPackNotLoadable) as exc:
            registry.load("skills", "cognic-skill-notes")
        assert exc.value.kind == "skills"
        assert exc.value.name == "cognic-skill-notes"
        assert "nothing to load" in str(exc.value)

    async def test_refused_manifest_only_pack_raises_registration_refused_first(
        self, registry: PluginRegistry, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """Precedence: refusal-at-registration outranks the manifest-only
        guard — callers must see the refusal cause, not the loadability
        detail."""
        metadata_env.append(_make_dist(tmp_path))
        packs = registry.discover()
        await registry.register(packs[0], refusal_reason="cosign_verification_failed")
        with pytest.raises(RegistrationRefused):
            registry.load("skills", "cognic-skill-notes")

    def test_unknown_name_still_raises_plugin_not_registered(
        self, registry: PluginRegistry
    ) -> None:
        with pytest.raises(PluginNotRegistered):
            registry.load("skills", "never-registered")


# ---------------------------------------------------------------------------
# Lockstep drift detector vs harness/skill_host (test-only imports; NO
# runtime cross-import — per feedback_drift_detector_test_only_no_runtime_import)
# ---------------------------------------------------------------------------


_LOCKSTEP_MANIFESTS: list[dict[str, Any]] = [
    {"skill": {"mode": "instruction"}},
    {"skill": {"mode": "executable"}},
    {"skill": {}},
    {"skill": {"mode": "banana"}},
    {"skill": {"mode": 7}},
    {"tool": {"cognic": {"skill": {"mode": "instruction"}}}},
    {"tool": {"cognic": {"skill": {"mode": "executable"}}}},
    {"tool": {"cognic": {"skill": {}}}},
    # Top-level non-dict falls back to the legacy path (mirror-exact shape).
    {"skill": "bad", "tool": {"cognic": {"skill": {"mode": "instruction"}}}},
    {"skill": "bad"},
    {"tool": "bad"},
    {"tool": {"cognic": "bad"}},
    {"tool": {"cognic": {"skill": "bad"}}},
    {},
    {"pack": {"kind": "skill"}},
]


class TestSkillModeLockstepWithSkillHost:
    """The registry-local ``[skill]``-block + mode classification MUST agree
    with ``harness/skill_host._skill_block`` / ``._skill_mode`` — protocol
    must not import harness at runtime, so the lockstep is pinned here
    test-only over a parametrized manifest matrix."""

    @pytest.mark.parametrize("manifest", _LOCKSTEP_MANIFESTS)
    def test_block_and_mode_classification_agree(self, manifest: dict[str, Any]) -> None:
        from cognic_agentos.harness import skill_host
        from cognic_agentos.protocol import plugin_registry

        registry_block = plugin_registry._manifest_skill_block(manifest)
        host_block = skill_host._skill_block(manifest)
        assert registry_block == host_block

        registry_mode = (
            plugin_registry._manifest_skill_mode(registry_block)
            if registry_block is not None
            else None
        )
        host_mode = skill_host._skill_mode(host_block) if host_block is not None else None
        assert registry_mode == host_mode
