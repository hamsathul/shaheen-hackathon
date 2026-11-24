from baaz.resolve import page_redirect


def test_meta_refresh_target_is_html_unescaped():
    page = '<meta http-equiv="refresh" content="0; url=https://example.com/a?x=1&amp;y=2">'
    assert page_redirect(page) == ("https://example.com/a?x=1&y=2", "meta")


def test_script_redirect_only_on_a_near_empty_page():
    script = '<script>window.location.href = "https://example.com/next";</script>'
    assert page_redirect(script) == ("https://example.com/next", "script")
    assert page_redirect(script + "<p>" + "text " * 100 + "</p>") is None
