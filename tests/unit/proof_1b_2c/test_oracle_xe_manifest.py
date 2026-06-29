"""Structural pin — the in-cluster Oracle XE manifest + single-source seed
(M3-E2c Task 4)."""

import hashlib
from pathlib import Path

import yaml

DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/oracle-xe.yaml").read_text()))
SEED = Path("infra/proof-1b-2c/oracle-seed/seed_schema.sql").read_text()
SEED_BYTES = Path("infra/proof-1b-2c/oracle-seed/seed_schema.sql").read_bytes()
DEP = next(d for d in DOCS if d["kind"] == "Deployment")
C = DEP["spec"]["template"]["spec"]["containers"][0]
SEED_SHA256 = "defa5300c015b4600856417ef0a8578a5a5ae847439575eb6f1d89908e12e3f6"


def test_xe_image_env_and_service():
    assert C["image"] == "gvenzl/oracle-xe:21-slim"
    env = {e["name"]: e.get("value") for e in C["env"]}
    # NO ORACLE_DATABASE: XEPDB1 is gvenzl XE's BUILT-IN PDB; setting ORACLE_DATABASE makes
    # gvenzl try to CREATE it -> collision -> CrashLoopBackOff (ORA-01081 / exit 57), the
    # M3-E2c attempt-3 finding. The seed ALTERs into the built-in XEPDB1.
    assert env == {
        "ORACLE_PASSWORD": "proof_admin_only",
        "APP_USER": "cognic",
        "APP_USER_PASSWORD": "cognic_dev_only",
    }
    assert "ORACLE_DATABASE" not in env  # must NOT be set — collides with the built-in XEPDB1
    svc = next(d for d in DOCS if d["kind"] == "Service")
    assert svc["metadata"]["name"] == "oracle-xe"
    assert svc["spec"]["selector"] == {"app": "oracle-xe"}
    assert svc["spec"]["ports"][0]["port"] == 1521


def test_no_embedded_configmap_single_source_seed():
    # P2 drift fix: the manifest must NOT carry a ConfigMap copy of the seed.
    assert not any(d.get("kind") == "ConfigMap" for d in DOCS)
    vol = next(v for v in DEP["spec"]["template"]["spec"]["volumes"] if v["name"] == "seed")
    assert vol["configMap"]["name"] == "oracle-xe-seed"  # runner-created from the file
    assert "/container-entrypoint-initdb.d" in {m["mountPath"] for m in C["volumeMounts"]}


def test_seed_file_creates_cognic_objects():
    assert hashlib.sha256(SEED_BYTES).hexdigest() == SEED_SHA256
    assert "ALTER SESSION SET CONTAINER = XEPDB1" in SEED
    assert "cognic.departments" in SEED and "cognic.employees" in SEED


def test_readiness_probe_present():
    assert C["readinessProbe"]["exec"]["command"] == ["/bin/sh", "-c", "healthcheck.sh"]
    assert C["readinessProbe"]["failureThreshold"] == 40
