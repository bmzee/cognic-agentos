import pytest

# cognic_egress_shim is image content under infra/sandbox/egress-proxy/ (a
# hyphenated, non-importable dir put on sys.path by conftest.py); mypy cannot
# resolve it because infra/ is outside the `src`/`tests` type-check roots.
from cognic_egress_shim import render_filter_file  # type: ignore[import-not-found]


def test_anchored_exact_host():
    assert render_filter_file('["api.example.com"]').splitlines() == [r"^api\.example\.com$"]


def test_dots_escaped_not_wildcard():
    out = render_filter_file('["api.example.com"]')
    assert r"\." in out and out.startswith("^") and out.rstrip().endswith("$")


def test_empty_list_renders_empty_filter_deny_all():
    assert render_filter_file("[]") == ""


def test_malformed_json_fails_closed():
    assert render_filter_file("not json") == ""


def test_non_list_fails_closed():
    assert render_filter_file('{"host":"x"}') == ""


def test_dedup_preserves_first_order():
    assert render_filter_file('["a.com","a.com","b.com"]').splitlines() == [
        r"^a\.com$",
        r"^b\.com$",
    ]


@pytest.mark.parametrize(
    "bad",
    [
        '[""]',
        '["https://api.example.com"]',
        '["api.example.com/path"]',
        '["*.example.com"]',
        '["api.example.com\\n^evil$"]',
        '["api.example.com\\n"]',
        '["api\\t.com"]',
        '["a..b.com"]',
        '["-lead.com"]',
        '["UPPER_under.com"]',
        "[123]",
        '["ok.com","*.bad"]',
    ],
)
def test_malformed_entry_denies_all(bad):
    assert render_filter_file(bad) == ""
