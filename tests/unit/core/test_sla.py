"""Sprint 2.5 Task 1 — pure-functional SLA timer.

``core/sla`` is timer math: deadline computation + status
classification. No DB, no emission, no I/O. Caller decides whether
breach detection triggers downstream effects (escalation, audit
emission, kill switches).

**Critical-controls module.** Per AGENTS.md + the Sprint 2.5 plan
(merged at PR #7 / commit ``4733b52``): ≥95% line + ≥90% branch
coverage, halt-before-commit per edit.

Tests cover:

  - ``SLAPolicy`` constructor validation (3 preconditions in the
    locked order: total_budget > 0 → warning_threshold ≥ 0 →
    warning_threshold < total_budget). The order matters because
    the original draft (warning < budget FIRST) made the test for
    ``total_budget must be positive`` unreachable on input
    ``(0, 0)``: ``0 >= 0`` is True so the warning-threshold check
    fired first. The reordering is the load-bearing P3 fix from the
    plan-review.
  - ``SLATimer.compute_deadline`` happy path + naive-datetime
    rejection (boundary with canonical-form invariants from
    Sprint 2 R3 — naive datetimes are rejected at the SLA boundary
    so SLA-tracked timestamps can participate in evidence-pack
    export per ADR-006).
  - ``SLATimer.classify`` GREEN / WARNING / BREACHED at the three
    boundaries (one tick before, exactly at, one tick after warning
    + deadline) + naive-``now`` rejection.
  - Frozen+slotted dataclasses raise ``FrozenInstanceError`` on
    attribute mutation — regression test for the ``frozen=True``
    declaration on both ``SLAPolicy`` and ``SLADeadline``.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

from cognic_agentos.core.sla import SLADeadline, SLAPolicy, SLAStatus, SLATimer


class TestSLAPolicyValidation:
    """Constructor validation. Order matters — see the docstring P3
    rationale. Each test exercises exactly one precondition by
    constructing inputs that pass every earlier check."""

    def test_warning_threshold_must_be_strictly_less_than_budget(self) -> None:
        # Equal budget+warning: total_budget passes (10s > 0),
        # warning_threshold passes (10s >= 0), final check fires.
        with pytest.raises(ValueError, match="strictly less than total_budget"):
            SLAPolicy(
                name="api-call",
                total_budget=timedelta(seconds=10),
                warning_threshold=timedelta(seconds=10),
            )

    def test_total_budget_must_be_positive(self) -> None:
        # total_budget=0: first check fires before either later check
        # would have an opportunity. This is the test that broke under
        # the draft-1 validation order.
        with pytest.raises(ValueError, match="total_budget must be positive"):
            SLAPolicy(
                name="zero",
                total_budget=timedelta(0),
                warning_threshold=timedelta(0),
            )

    def test_total_budget_negative_also_rejected(self) -> None:
        # Defence-in-depth: <= 0 catches negative total_budget too.
        with pytest.raises(ValueError, match="total_budget must be positive"):
            SLAPolicy(
                name="neg-budget",
                total_budget=timedelta(seconds=-1),
                warning_threshold=timedelta(0),
            )

    def test_warning_threshold_must_be_non_negative(self) -> None:
        # total_budget=10s passes first check; warning=-1s hits the
        # second check.
        with pytest.raises(ValueError, match="warning_threshold must be non-negative"):
            SLAPolicy(
                name="neg-warning",
                total_budget=timedelta(seconds=10),
                warning_threshold=timedelta(seconds=-1),
            )

    def test_zero_warning_threshold_is_legal(self) -> None:
        # The contract allows warning_threshold==0 (warn immediately
        # on start). Negative is rejected; zero is fine. Boundary
        # test that the >=0 check is non-strict.
        p = SLAPolicy(
            name="warn-immediate",
            total_budget=timedelta(seconds=10),
            warning_threshold=timedelta(0),
        )
        assert p.warning_threshold == timedelta(0)

    def test_happy_path_constructs(self) -> None:
        p = SLAPolicy(
            name="api-call",
            total_budget=timedelta(seconds=10),
            warning_threshold=timedelta(seconds=8),
        )
        assert p.name == "api-call"
        assert p.total_budget == timedelta(seconds=10)
        assert p.warning_threshold == timedelta(seconds=8)


class TestSLAPolicyFrozen:
    """SLAPolicy is frozen + slotted; mutation MUST raise."""

    def test_rejects_attribute_assignment(self) -> None:
        p = SLAPolicy(
            name="api-call",
            total_budget=timedelta(seconds=10),
            warning_threshold=timedelta(seconds=8),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.name = "other"  # type: ignore[misc]


class TestSLAStatusEnum:
    """SLAStatus is a StrEnum with three values matching the contract."""

    def test_values_are_lowercase_strings(self) -> None:
        assert SLAStatus.GREEN.value == "green"
        assert SLAStatus.WARNING.value == "warning"
        assert SLAStatus.BREACHED.value == "breached"

    def test_str_enum_subclasses_str(self) -> None:
        # StrEnum members ARE strings — they pass isinstance(x, str)
        # and round-trip through str() to their .value. The canonical-
        # form serializer relies on this for stable JSON output
        # (Sprint 2 R3 contract: only string-valued enums are
        # serialisable). Assertion via isinstance + str() avoids
        # mypy strict's literal-comparison-overlap flag on a direct
        # `SLAStatus.GREEN == "green"`.
        assert isinstance(SLAStatus.GREEN, str)
        assert str(SLAStatus.GREEN) == "green"

    def test_three_members_exact(self) -> None:
        assert {s.value for s in SLAStatus} == {"green", "warning", "breached"}


class TestComputeDeadline:
    """SLATimer.compute_deadline: pure projection of (start, policy)
    onto absolute timestamps. No I/O."""

    def _policy(self) -> SLAPolicy:
        return SLAPolicy(
            name="api-call",
            total_budget=timedelta(seconds=10),
            warning_threshold=timedelta(seconds=8),
        )

    def test_happy_path_utc_start(self) -> None:
        start = datetime(2026, 4, 29, 12, 0, 0, tzinfo=UTC)
        d = SLATimer.compute_deadline(start, self._policy())
        assert d.policy_name == "api-call"
        assert d.started_at == start
        assert d.warning_at == datetime(2026, 4, 29, 12, 0, 8, tzinfo=UTC)
        assert d.deadline == datetime(2026, 4, 29, 12, 0, 10, tzinfo=UTC)

    def test_happy_path_non_utc_tz(self) -> None:
        # Any tz-aware datetime works — the contract is timezone-aware,
        # not UTC-specific. The arithmetic is on absolute timestamps so
        # downstream comparison is timezone-correct.
        ist = timezone(timedelta(hours=5, minutes=30))
        start = datetime(2026, 4, 29, 17, 30, 0, tzinfo=ist)
        d = SLATimer.compute_deadline(start, self._policy())
        assert d.warning_at == start + timedelta(seconds=8)
        assert d.deadline == start + timedelta(seconds=10)

    def test_rejects_naive_datetime(self) -> None:
        # No tzinfo → reject. canonical-form rejects naive datetimes
        # per Sprint 2 R3; SLA boundary enforces the same so any
        # SLA-tracked timestamp can flow into evidence-pack export.
        naive = datetime(2026, 4, 29, 12, 0, 0)
        with pytest.raises(ValueError, match="must be timezone-aware"):
            SLATimer.compute_deadline(naive, self._policy())

    def test_rejects_tz_with_none_utcoffset(self) -> None:
        # A tzinfo subclass whose utcoffset() returns None is not
        # really tz-aware — same rejection. This boundary mirrors the
        # canonical-form Round-2 hardening: a datetime can have a
        # tzinfo attached and STILL be effectively naive if utcoffset
        # returns None. (Python's stdlib datetime.timezone is not
        # subclassable; subclass datetime.tzinfo directly instead.)
        class NullTz(tzinfo):
            def utcoffset(self, dt: datetime | None) -> timedelta | None:
                return None

            def tzname(self, dt: datetime | None) -> str:
                return "null"

            def dst(self, dt: datetime | None) -> timedelta | None:
                return None

        d = datetime(2026, 4, 29, 12, 0, 0, tzinfo=NullTz())
        with pytest.raises(ValueError, match="must be timezone-aware"):
            SLATimer.compute_deadline(
                d,
                SLAPolicy(
                    name="x",
                    total_budget=timedelta(seconds=10),
                    warning_threshold=timedelta(seconds=8),
                ),
            )

    def test_zero_warning_threshold_collapses_to_start(self) -> None:
        # warning_threshold=0 → warning_at == started_at. Useful for
        # "warn immediately" policies. Boundary test for the
        # warning_threshold >= 0 contract.
        start = datetime(2026, 4, 29, 12, 0, 0, tzinfo=UTC)
        p = SLAPolicy(
            name="warn-immediate",
            total_budget=timedelta(seconds=10),
            warning_threshold=timedelta(0),
        )
        d = SLATimer.compute_deadline(start, p)
        assert d.warning_at == start
        assert d.deadline == start + timedelta(seconds=10)


class TestClassify:
    """SLATimer.classify boundaries — three states, three boundary
    transitions to exercise.

    Contract:
      now < warning_at         → GREEN
      warning_at <= now < ddl  → WARNING
      now >= deadline          → BREACHED
    """

    def _deadline(self) -> SLADeadline:
        start = datetime(2026, 4, 29, 12, 0, 0, tzinfo=UTC)
        return SLADeadline(
            policy_name="api-call",
            started_at=start,
            warning_at=start + timedelta(seconds=8),
            deadline=start + timedelta(seconds=10),
        )

    def test_green_well_before_warning(self) -> None:
        d = self._deadline()
        # 5 seconds in — well before warning_at (8s).
        now = d.started_at + timedelta(seconds=5)
        assert SLATimer.classify(now, d) == SLAStatus.GREEN

    def test_green_one_tick_before_warning(self) -> None:
        d = self._deadline()
        # Strict: warning_at - 1us is still GREEN (now < warning_at).
        now = d.warning_at - timedelta(microseconds=1)
        assert SLATimer.classify(now, d) == SLAStatus.GREEN

    def test_warning_exactly_at_warning_at(self) -> None:
        d = self._deadline()
        # Inclusive lower bound: now == warning_at → WARNING.
        assert SLATimer.classify(d.warning_at, d) == SLAStatus.WARNING

    def test_warning_between_warning_at_and_deadline(self) -> None:
        d = self._deadline()
        # 9 seconds in — between warning_at (8s) and deadline (10s).
        now = d.started_at + timedelta(seconds=9)
        assert SLATimer.classify(now, d) == SLAStatus.WARNING

    def test_warning_one_tick_before_deadline(self) -> None:
        d = self._deadline()
        # Strict: deadline - 1us is still WARNING.
        now = d.deadline - timedelta(microseconds=1)
        assert SLATimer.classify(now, d) == SLAStatus.WARNING

    def test_breached_exactly_at_deadline(self) -> None:
        d = self._deadline()
        # Inclusive lower bound: now == deadline → BREACHED.
        assert SLATimer.classify(d.deadline, d) == SLAStatus.BREACHED

    def test_breached_well_after_deadline(self) -> None:
        d = self._deadline()
        now = d.deadline + timedelta(seconds=60)
        assert SLATimer.classify(now, d) == SLAStatus.BREACHED

    def test_rejects_naive_now(self) -> None:
        d = self._deadline()
        naive = datetime(2026, 4, 29, 12, 0, 5)
        with pytest.raises(ValueError, match="must be timezone-aware"):
            SLATimer.classify(naive, d)


class TestSLADeadlineFrozen:
    """SLADeadline is frozen + slotted; mutation MUST raise."""

    def test_rejects_attribute_assignment(self) -> None:
        start = datetime(2026, 4, 29, 12, 0, 0, tzinfo=UTC)
        d = SLADeadline(
            policy_name="x",
            started_at=start,
            warning_at=start + timedelta(seconds=8),
            deadline=start + timedelta(seconds=10),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            d.policy_name = "other"  # type: ignore[misc]
