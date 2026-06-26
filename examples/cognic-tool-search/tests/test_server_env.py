# examples/cognic-tool-search/tests/test_server_env.py
import importlib


def test_server_url_is_env_driven(monkeypatch):
    monkeypatch.setenv("COGNIC_PROOF_SERVER_URL", "http://10.96.0.50:8765/mcp")
    monkeypatch.setenv("COGNIC_PROOF_HOST", "0.0.0.0")
    import cognic_tool_search.server as s

    importlib.reload(s)
    assert s._SERVER_URL == "http://10.96.0.50:8765/mcp"
    assert s._HOST == "0.0.0.0"


def test_defaults_unchanged(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_SERVER_URL", raising=False)
    monkeypatch.delenv("COGNIC_PROOF_HOST", raising=False)
    import cognic_tool_search.server as s

    importlib.reload(s)
    assert s._SERVER_URL == "http://127.0.0.1:8765/mcp"
    assert s._HOST == "127.0.0.1"
