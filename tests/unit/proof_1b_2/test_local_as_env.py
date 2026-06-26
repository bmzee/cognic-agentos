# tests/unit/proof_1b_2/test_local_as_env.py
import importlib
import runpy


def test_as_issuer_env_driven(monkeypatch):
    monkeypatch.setenv("COGNIC_PROOF_AS_ISSUER", "http://192.88.99.9:9000")
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    assert m._AS_ISSUER == "http://192.88.99.9:9000"


def test_as_issuer_default(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_AS_ISSUER", raising=False)
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    assert m._AS_ISSUER == "http://127.0.0.1:9000"


def test_run_local_as_host_env_driven(monkeypatch):
    monkeypatch.setenv("COGNIC_PROOF_AS_HOST", "0.0.0.0")
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    captured: dict[str, object] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: captured.update(kw))
    m.run_local_as(port=9000)
    assert captured["host"] == "0.0.0.0"


def test_run_local_as_host_default(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_AS_HOST", raising=False)
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    captured: dict[str, object] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: captured.update(kw))
    m.run_local_as(port=9000)
    assert captured["host"] == "127.0.0.1"


def test_run_local_as_forwards_port(monkeypatch):
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    captured: dict[str, object] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: captured.update(kw))
    m.run_local_as(port=9123)
    assert captured["port"] == 9123


def test_main_reads_port_env(monkeypatch):
    # Drive the `if __name__ == "__main__"` block end-to-end: it reads
    # COGNIC_PROOF_AS_PORT and forwards it through run_local_as -> uvicorn.run.
    monkeypatch.setenv("COGNIC_PROOF_AS_PORT", "9100")
    import tests.integration.pack_loop._local_as as m

    importlib.reload(m)
    captured: dict[str, object] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: captured.update(kw))
    runpy.run_module("tests.integration.pack_loop._local_as", run_name="__main__")
    assert captured["port"] == 9100
