from cognic_agentos.core.dlp.scanner import (
    ChecksumRegexGazetteerScanner,
    DLPVerdict,
    RedactionSpan,
)

S = ChecksumRegexGazetteerScanner()


def test_pan_luhn_valid_detected_as_payment_data():
    # 4111 1111 1111 1111 is a Luhn-valid test PAN
    v = S.scan("card 4111 1111 1111 1111 on file")
    assert "payment_data" in v.detected_classes


def test_pan_luhn_invalid_not_detected():
    # 16 digits but fails Luhn
    assert "payment_data" not in S.scan("ref 4111111111111112").detected_classes


def test_pan_luhn_valid_exercises_doubling_fold_branch():
    # 4539148803436467 is Luhn-valid AND contains doubled-position digits >= 5
    # so the `d -= 9` overflow-fold arm in _luhn_ok executes (covers scanner.py
    # line 39 + the `if d > 9` branch's taken arm). The 4111... datum above only
    # ever doubles 1s and 4s (max 8) so it never folds.
    assert "payment_data" in S.scan("card 4539148803436467").detected_classes


def test_iban_mod97_valid_detected():
    v = S.scan("IBAN GB82WEST12345698765432")
    assert "payment_data" in v.detected_classes


def test_iban_regex_match_but_checksum_fails_not_detected():
    # IBAN-shaped (passes _IBAN_RE) but wrong check digits -> _iban_ok False.
    # No 13-19 consecutive digit run, so PAN does not fire either.
    assert "payment_data" not in S.scan("IBAN XX00ABCDEFGH1234").detected_classes


def test_swift_bic_with_cue_detected():
    assert "payment_data" in S.scan("BIC DEUTDEFF").detected_classes


def test_bare_swift_token_without_cue_not_detected():
    assert "payment_data" not in S.scan("token ABCDEFGH here").detected_classes


def test_email_detected_as_customer_pii():
    assert "customer_pii" in S.scan("reach me at a.b@example.com").detected_classes


def test_phone_e164_detected_as_customer_pii():
    assert "customer_pii" in S.scan("call +442071838750").detected_classes


def test_regulator_gazetteer_detected():
    v = S.scan("letter to the SBP about the breach")
    assert "regulator_communication" in v.detected_classes


def test_clean_text_detects_nothing():
    v = S.scan("the quick brown fox")
    assert v.detected_classes == frozenset()
    assert v.confidence == 0.0


def test_non_string_value_coerced_via_repr():
    # non-str input is coerced via repr(); must not raise and returns a verdict
    v = S.scan(12345)
    assert isinstance(v, DLPVerdict)


def test_verdict_shape_and_spans():
    v = S.scan("a.b@example.com")
    assert isinstance(v, DLPVerdict)
    assert isinstance(v.detected_classes, frozenset)
    assert isinstance(v.redaction_spans, tuple)
    assert all(isinstance(sp, RedactionSpan) for sp in v.redaction_spans)
    assert 0.0 <= v.confidence <= 1.0
    assert v.confidence == 1.0  # something detected
