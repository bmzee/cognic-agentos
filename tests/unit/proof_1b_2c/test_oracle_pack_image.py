"""Structural pin — the oracle-pack tool-Service image (M3-E2c Task 3)."""

from pathlib import Path

DF = Path("infra/proof-1b-2c/Dockerfile.oracle-pack").read_text()


def test_uses_python_312_slim_base_and_app_workdir():
    assert "FROM python:3.12-slim" in DF
    assert "WORKDIR /app" in DF


def test_installs_full_runtime_deps():
    for dep in (
        "mcp==1.27.0",
        "uvicorn[standard]>=0.35",
        "oracledb>=2.5",
        "PyJWT[crypto]>=2.10,<3",
    ):
        assert dep in DF, f"missing runtime dep {dep}"


def test_installs_staged_released_wheel_and_runs_server():
    wheel = "cognic_tool_oracle_schema-0.1.0-py3-none-any.whl"
    assert f"COPY proof1b2c-staging/wheel/{wheel} /tmp/" in DF
    assert f"RUN pip install --no-cache-dir --no-deps /tmp/{wheel}" in DF
    assert 'CMD ["python", "-m", "cognic_tool_oracle_schema.server"]' in DF
