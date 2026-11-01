"""Checksum and structure validators referenced by name from detectors.yaml.

A regex alone is not enough for a CI gate: random 12-digit numbers look like
Aadhaar and random 16-digit numbers look like cards. Validators keep false
positives low enough that teams do not remove the check.
"""

import hashlib
import ipaddress
import re
from functools import lru_cache

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


def ipv6_global(value: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(value.split("%", 1)[0])
    except ValueError:
        return False
    return addr.is_global and addr.ipv4_mapped is None


def mac(value: str) -> bool:
    digits = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
    return len(digits) == 12 and len(set(digits)) > 2 and digits != "ffffffffffff"


# IBAN length by country (SWIFT IBAN registry).
_IBAN_LEN = dict(
    (c[:2], int(c[2:])) for c in (
        "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DJ27 DK18 DO28 "
        "EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 "
        "JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 "
        "NO15 OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 SV28 "
        "TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30"
    ).split()
)


def iban(value: str) -> bool:
    s = re.sub(r"[\s-]", "", value).upper()
    if _IBAN_LEN.get(s[:2]) != len(s) or not s[2:4].isdigit() or not s.isalnum():
        return False
    return int("".join(str(int(ch, 36)) for ch in s[4:] + s[:4])) % 97 == 1


def aba_routing(value: str) -> bool:
    """US bank routing number: Federal Reserve prefix and the 3-7-1 checksum."""
    d = _digits(value)
    if len(d) != 9 or len(set(d)) == 1:
        return False
    prefix = int(d[:2])
    if not (prefix <= 12 or 21 <= prefix <= 32 or 61 <= prefix <= 72 or prefix == 80):
        return False
    return sum(int(c) * w for c, w in zip(d, (3, 7, 1) * 3)) % 10 == 0


def ssn(value: str) -> bool:
    """Rules the SSA never breaks: no area 000, 666 or 9xx, no group 00, no serial 0000."""
    d = _digits(value)
    if len(d) != 9 or len(set(d)) == 1 or d in ("123456789", "078051120", "219099999"):
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


_VIN_VALUE = {**{str(i): i for i in range(10)},
              **dict(zip("ABCDEFGHJKLMNPRSTUVWXYZ", [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2, 3, 4, 5, 6, 7, 8, 9]))}
_VIN_WEIGHT = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def vin(value: str) -> bool:
    """North American VIN check digit (position 9)."""
    s = value.upper()
    if len(s) != 17 or any(ch not in _VIN_VALUE for ch in s):
        return False
    total = sum(_VIN_VALUE[ch] * w for ch, w in zip(s, _VIN_WEIGHT)) % 11
    return s[8] == ("X" if total == 10 else str(total))


def swift_bic(value: str) -> bool:
    s = value.upper()
    return len(s) in (8, 11) and s[:4].isalpha() and s[4:6] in _regions()


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(value: str) -> bool:
    """Bitcoin legacy (1...) and P2SH (3...) addresses: version byte and double-SHA256 checksum."""
    n = 0
    for ch in value:
        if ch not in _B58:
            return False
        n = n * 58 + _B58.index(ch)
    pad = len(value) - len(value.lstrip("1"))
    raw = b"\x00" * pad + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    if len(raw) != 25 or raw[0] not in (0, 5):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32(value: str) -> bool:
    """SegWit addresses (bc1...): BIP-173 / BIP-350 checksum."""
    s = value.lower()
    hrp, _, data = s.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(ch not in _BECH32 for ch in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [_BECH32.index(c) for c in data]
    chk = 1
    for x in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ x
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            chk ^= g if (top >> i) & 1 else 0
    return chk in (1, 0x2BC830A3)


def btc_address(value: str) -> bool:
    return bech32(value) if value.lower().startswith("bc1") else base58check(value)


def vehicle_in(value: str) -> bool:
    return 8 <= len(re.sub(r"[ -]", "", value)) <= 11


def latlng(value: str) -> bool:
    nums = re.findall(r"\d+(?:\.\d+)?", value)
    if len(nums) != 2:
        return False
    lat, lng = float(nums[0]), float(nums[1])
    return lat <= 90 and lng <= 180 and (lat, lng) != (0, 0)


@lru_cache(maxsize=1)
def _regions() -> frozenset:
    import phonenumbers
    return frozenset(phonenumbers.SUPPORTED_REGIONS) | {"XK"}


def phone(value: str) -> bool:
    """Valid under the numbering plan: any country when written with +, else US or India.

    India is tried only for a 0 trunk prefix or a mobile (6-9): Indian landline
    area codes accept most other 10-digit numbers.
    """
    import phonenumbers
    s = value.strip()
    if s.startswith("00"):
        s = "+" + s[2:]
    d = _digits(s)
    if s.startswith("+"):
        regions = [None] if 8 <= len(d) <= 15 else []
    elif d.startswith("0"):
        regions = ["IN"] if len(d) in (11, 12) else []
    elif len(d) == 10 or (len(d) == 11 and d[0] == "1"):
        regions = ["US", "IN"] if len(d) == 10 and d[0] in "6789" else ["US"]
    else:
        regions = []
    for region in regions:
        try:
            if phonenumbers.is_valid_number(phonenumbers.parse(s, region)):
                return True
        except phonenumbers.NumberParseException:
            pass
    return False


VALIDATORS = {
    "verhoeff": verhoeff,
    "luhn": luhn,
    "gstin": gstin,
    "ipv4_public": ipv4_public,
    "ipv6_global": ipv6_global,
    "mac": mac,
    "iban": iban,
    "aba_routing": aba_routing,
    "ssn": ssn,
    "vin": vin,
    "swift_bic": swift_bic,
    "base58check": base58check,
    "bech32": bech32,
    "btc_address": btc_address,
    "vehicle_in": vehicle_in,
    "latlng": latlng,
    "phone": phone,
}
