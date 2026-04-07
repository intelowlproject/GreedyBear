# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from ipaddress import ip_address
from datetime import datetime


def is_ip_address(string: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).

    Uses the ipaddress module to perform validation. This function properly
    handles both IPv4 addresses and IPv6 addresses.

    Args:
        string: The string to validate as an IP address

    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    try:
        ip_address(string)
    except ValueError:
        return False
    return True


def is_valid_domain(string: str) -> bool:
    """
    Validate if a string is a safe domain name for use in STIX patterns.

    Rejects empty values and values containing characters that could be used
    for STIX pattern injection (quotes, backslashes, newlines).

    Args:
        string: The string to validate as a domain name

    Returns:
        bool: True if the string is a safe domain value, False otherwise
    """
    if not string:
        return False
    return not any(c in string for c in ("'", '"', "\\", "\n", "\r"))


def is_sha256hash(string: str) -> bool:
    """
    Validate if a string is a valid SHA-256 hash.

    A SHA-256 hash is a string of exactly 64 hexadecimal characters
    (0-9, a-f, A-F). This function checks if the input string matches
    this pattern using a regular expression.

    Args:
        string: The string to validate as a SHA-256 hash

    Returns:
        bool: True if the string is a valid SHA-256 hash, False otherwise
    """
    return bool(re.fullmatch(r"^[A-Fa-f0-9]{64}$", string))


    def parse_timestamp(timestamp: str) -> datetime:
    """
    Parse an ISO-format timestamp string into a naive datetime.
    Strips timezone info because the project uses USE_TZ=False.

    Args:
        timestamp: ISO-format timestamp string.

    Returns:
        Naive datetime object.
    """
    return datetime.fromisoformat(timestamp).replace(tzinfo=None)


