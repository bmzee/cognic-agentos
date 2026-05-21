"""Static pins for the #477 live-proof fixture Dockerfiles.

These are deliberately simple text-shape tests. The Dockerfiles are
test fixtures, but the live OpenShift proof depends on their image
metadata: Kubernetes ``runAsNonRoot=True`` refuses an image whose
default user is root/unspecified before the container ever starts.
"""

from pathlib import Path

_FIXTURE_DIR = Path("tests/fixtures/sandbox")


def _lines(name: str) -> list[str]:
    return _FIXTURE_DIR.joinpath(name).read_text(encoding="utf-8").splitlines()


def test_runtime_fixture_declares_non_root_user() -> None:
    lines = _lines("runtime-fixture.Dockerfile")

    assert "USER 65534:65534" in lines
    assert lines.index("USER 65534:65534") < lines.index('CMD ["sleep", "infinity"]')


def test_egress_proxy_fixture_declares_non_root_user_before_runtime_touch() -> None:
    lines = _lines("egress-proxy-fixture.Dockerfile")

    assert "USER 65534:65534" in lines
    assert lines.index("USER 65534:65534") < lines.index(
        'CMD ["sh", "-c", "touch /var/log/cognic-proxy/access.jsonl && exec sleep infinity"]'
    )
