"""Checksum and structure validators referenced by name from detectors.yaml.

A regex alone is not enough for a CI gate: random 12-digit numbers look like
Aadhaar and random 16-digit numbers look like cards. Validators keep false
positives low enough that teams do not remove the check.
"""

import ipaddress

# Verhoeff tables (Aadhaar check digit).
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def verhoeff(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 12 or len(set(digits)) == 1:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(prefix: str) -> str:
    """Return the digit that makes prefix + digit Verhoeff-valid (used for test data)."""
    for d in "0123456789":
        if verhoeff(prefix + d):
            return d
    raise ValueError("no check digit")


# (prefix range, allowed lengths). Issuer ranges keep IMEIs (15 digits, 35/86...)
# and SIM ICCIDs (89...) from passing as cards: a bare Luhn check accepts them.
_IIN = [
    ((4, 4), (13, 16, 19)),                # Visa
    ((51, 55), (16,)),                     # Mastercard
    ((2221, 2720), (16,)),                 # Mastercard 2-series
    ((34, 34), (15,)), ((37, 37), (15,)),  # Amex
    ((6011, 6011), (16, 19)),              # Discover
    ((644, 649), (16, 19)), ((65, 65), (16, 19)),
    ((60, 60), (16,)), ((508, 508), (16,)), ((81, 82), (16,)),  # RuPay
    ((3528, 3589), (16, 19)),              # JCB
    ((300, 305), (14, 16)), ((36, 36), (14,)), ((38, 39), (16,)),  # Diners
    ((62, 62), (16, 19)),                  # UnionPay
]


def card_issuer(digits: str) -> bool:
    for (lo, hi), lengths in _IIN:
        width = len(str(lo))
        if len(digits) in lengths and lo <= int(digits[:width]) <= hi:
            return True
    return False


def luhn(value: str) -> bool:
    digits = _digits(value)
    if not card_issuer(digits) or len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def gstin(value: str) -> bool:
    value = value.upper()
    if len(value) != 15 or not 1 <= int(value[:2]) <= 38:
        return False
    total = 0
    for i, ch in enumerate(value[:14]):
        product = _GSTIN_CHARS.index(ch) * (1 if i % 2 == 0 else 2)
        total += product // 36 + product % 36
    return _GSTIN_CHARS[(36 - total % 36) % 36] == value[14]


def ipv4_public(value: str) -> bool:
    try:
        return ipaddress.IPv4Address(value).is_global
    except ValueError:
        return False


VALIDATORS = {
    "verhoeff": verhoeff,
    "luhn": luhn,
    "gstin": gstin,
    "ipv4_public": ipv4_public,
}
