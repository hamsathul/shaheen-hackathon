import string

from baaz.models import Finding
from baaz.reasons import TEMPLATES, render
from baaz.score import WEIGHTS


def test_every_weighted_code_has_english_and_arabic_text():
    assert set(WEIGHTS) == set(TEMPLATES)


def test_english_and_arabic_templates_use_the_same_fields():
    fields = lambda t: {name for _, name, _, _ in string.Formatter().parse(t) if name}  # noqa: E731
    for code, (en, ar) in TEMPLATES.items():
        assert fields(en) == fields(ar), code


def test_label_keys_are_translated_per_language():
    r = render(Finding("SENSITIVE_FORM_BRAND", "page.html#forms", {"brand": "TAMM", "fields": ["password", "otp"]}))
    assert "a password, a one-time code (OTP)" in r.en
    assert "كلمة مرور" in r.ar and "a password" not in r.ar
    assert r.weight == WEIGHTS["SENSITIVE_FORM_BRAND"]
    assert r.evidence == "page.html#forms"
