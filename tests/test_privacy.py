import pytest

from whiff.errors import InvalidOptionError, InvalidReportError
from whiff.privacy import scrub_patch, scrub_string


def test_off_leaves_text_unchanged():
    patch = {"content": {"excerpt": "agent@example.com"}}
    assert scrub_patch(patch, "off") == patch
    assert scrub_string("password=hunter22", "off") == "password=hunter22"


def test_email_phone_card_and_iban_are_redacted():
    assert scrub_string("mail agent@example.com", "strict") == "mail [redacted:email]"
    assert (
        scrub_string("call +44 20 7946 0958 or (555) 123-4567", "strict")
        == "call [redacted:phone] or [redacted:phone]"
    )
    assert scrub_string("card 4111 1111 1111 1111", "strict") == "card [redacted:payment_card]"
    assert scrub_string("IBAN GB82 WEST 1234 5698 7654 32", "strict") == "IBAN [redacted:iban]"


def test_credential_assignment_skips_placeholders():
    assert (
        scrub_string("password=hunter22 token=${TOKEN}", "strict")
        == "[redacted:credential_assignment] token=${TOKEN}"
    )


def test_plain_numbers_are_not_cards():
    assert scrub_patch({"n": "order 20241231 qty 1000000"}, "strict") == {
        "n": "order 20241231 qty 1000000"
    }


def test_sensitive_key_is_rejected():
    with pytest.raises(InvalidReportError, match="sensitive pattern"):
        scrub_patch({"metadata": {"agent@example.com": 1}}, "strict")


def test_unknown_mode():
    with pytest.raises(InvalidOptionError):
        scrub_patch({}, "maybe")
