from cognic_egress_shim import render_tinyproxy_conf  # type: ignore[import-not-found]


def test_renders_pinned_directives():
    conf = render_tinyproxy_conf(
        filter_path="/etc/cognic/filter", log_path="/var/log/cognic-proxy/access.jsonl"
    )
    assert "Port 3128" in conf
    assert "FilterDefaultDeny Yes" in conf
    assert 'Filter "/etc/cognic/filter"' in conf
    assert "ConnectPort 443" in conf
    assert 'LogFile "/var/log/cognic-proxy/access.jsonl"' in conf
    assert "LogLevel Info" in conf


def test_never_filter_urls():
    conf = render_tinyproxy_conf(filter_path="/f", log_path="/l")
    assert "FilterURLs" not in conf


def test_loglevel_is_info_not_connect():
    # T1 spike: LogLevel Connect omits the ConnectPort denial entirely.
    conf = render_tinyproxy_conf(filter_path="/f", log_path="/l")
    assert "LogLevel Info" in conf
    assert "LogLevel Connect" not in conf


def test_custom_port():
    conf = render_tinyproxy_conf(filter_path="/f", log_path="/l", port=8888)
    assert "Port 8888" in conf
