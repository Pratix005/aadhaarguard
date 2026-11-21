import pytest

from aadhaarguard.checksums import (
    gstin_check_char,
    gstin_valid,
    luhn_digit,
    luhn_valid,
    verhoeff_digit,
    verhoeff_valid,
)


def test_verhoeff_reference_values():
    # Reference example from the Verhoeff algorithm literature: 236 -> 3
    assert verhoeff_digit("236") == "3"
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


def test_verhoeff_catches_single_digit_errors_and_swaps():
    body = "23456789012"
    num = body + verhoeff_digit(body)
    assert verhoeff_valid(num)
    for i in range(len(num)):
        for d in "0123456789":
            if d != num[i]:
                assert not verhoeff_valid(num[:i] + d + num[i + 1 :])
    for i in range(len(num) - 1):
        if num[i] != num[i + 1]:
            swapped = num[:i] + num[i + 1] + num[i] + num[i + 2 :]
            assert not verhoeff_valid(swapped)


def test_verhoeff_rejects_non_digits():
    assert not verhoeff_valid("12a4")
    with pytest.raises(ValueError):
        verhoeff_digit("12a")


def test_luhn():
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")
    assert luhn_digit("7992739871") == "3"
    assert not luhn_valid("7")


def test_gstin_published_example():
    # Commonly published GSTIN format example.
    assert gstin_valid("27AAPFU0939F1ZV")
    assert not gstin_valid("27AAPFU0939F1ZW")
    assert gstin_check_char("27AAPFU0939F1Z") == "V"
    assert gstin_valid("27aapfu0939f1zv")  # case-insensitive
    assert not gstin_valid("short")
    assert not gstin_valid("27AAPFU0939F1Z!")
