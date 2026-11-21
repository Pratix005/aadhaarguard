import io
import logging

import pytest

from bharatpii import RedactingFilter, Scanner, partial_mask, redact
from bharatpii.fake import Faker

F = Faker(seed=3)


def test_tag():
    assert redact("PAN ABCPE1234F, ph 9876543210") == "PAN [PAN], ph [PHONE]"


def test_mask_keeps_separators():
    a = F.aadhaar()
    assert redact(f"aadhaar {a}", style="mask") == "aadhaar XXXX XXXX XXXX"


def test_partial_like_masked_aadhaar():
    a = F.aadhaar()
    assert redact(f"aadhaar {a}", style="partial") == f"aadhaar XXXX XXXX {a[-4:]}"


def test_partial_email_and_upi():
    assert partial_mask("email", "ravi.k@gmail.com") == "rXXXXX@gmail.com"
    assert partial_mask("upi", "ab@ybl") == "aXXX@ybl"
    assert partial_mask("pan", "ABC") == "XXX"


def test_hash_is_keyed_and_stable():
    a = F.aadhaar()
    s1 = Scanner(key=b"k1")
    s2 = Scanner(key=b"k2")
    h1 = s1.redact(f"aadhaar {a}", style="hash")
    assert h1 == s1.redact(f"aadhaar {a}", style="hash")
    assert h1 != s2.redact(f"aadhaar {a}", style="hash")
    assert h1.startswith("aadhaar [AADHAAR:") and a not in h1
    # separators don't change the hash
    assert h1 == s1.redact(f"aadhaar {a.replace(' ', '')}", style="hash")


def test_bad_style():
    with pytest.raises(ValueError):
        redact("x", style="nope")


def test_redact_preserves_other_text():
    text = "Hello Ravi,\nyour PAN ABCPE1234F is linked.\n"
    assert redact(text) == "Hello Ravi,\nyour PAN [PAN] is linked.\n"


def _logger(filt):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(filt)
    log = logging.getLogger(f"t{id(filt)}")
    log.handlers[:] = [handler]
    log.propagate = False
    log.setLevel(logging.INFO)
    return log, stream


def test_logging_filter_with_args():
    log, stream = _logger(RedactingFilter(style="partial"))
    log.info("user %s paid from %s", "ravi", "9876543210@ybl")
    assert stream.getvalue().strip() == "user ravi paid from 9XXXXXXXXX@ybl"


def test_logging_filter_exceptions():
    log, stream = _logger(RedactingFilter())
    try:
        raise ValueError("bad PAN ABCPE1234F")
    except ValueError:
        log.exception("failed")
    out = stream.getvalue()
    assert "ABCPE1234F" not in out and "[PAN]" in out


def test_logging_filter_bad_args_does_not_crash():
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "%d", ("notint",), None)
    assert RedactingFilter().filter(rec) is True
