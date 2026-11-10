"""Checksum and heuristic validators. Passing one means 'structurally
plausible', never 'genuine'."""
import re
import ipaddress

_DIGITS = "0123456789"


def digits_only(s: str) -> str:
    # ASCII digits only (str.isdigit/\d also accept other Unicode digits)
    return "".join(ch for ch in s if ch in _DIGITS)


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in digits_only(number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
      [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
      [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
      [9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
      [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
      [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    digits = digits_only(number)
    if len(digits) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(base: str) -> int:
    """Used to build SYNTHETIC test Aadhaar-like numbers."""
    c = 0
    for i, ch in enumerate(reversed(digits_only(base))):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


_PLACEHOLDER = re.compile(
    r"(your|example|placeholder|changeme|dummy|sample|xxxx|\*{3,}|<.*>)", re.I)


def not_placeholder(value: str) -> bool:
    return not _PLACEHOLDER.search(value)


def password_like(value: str) -> bool:
    """Heuristic: not a placeholder AND contains a digit/symbol.
    Rejects 'Password is required'. Misses all-letter passwords (documented limit)."""
    return not_placeholder(value) and any(not ch.isalpha() for ch in value)


def valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def has_digit(value: str) -> bool:
    return any(ch in _DIGITS for ch in value)


def ifsc_ok(value: str) -> bool:
    return any(ch in _DIGITS for ch in value[5:])
