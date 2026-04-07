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


    def is_valid_cidr(candidate: str) -> tuple[bool, str | None]:
    """
    Validate if a string is a valid CIDR notation.

    Args:
        candidate: String to validate as CIDR.

    Returns:
        True if valid CIDR, False otherwise.
    """
    try:
        IPv4Network(candidate.strip(), strict=False)
        return True, candidate.strip()
    except ValueError:
        return False, None



        def is_valid_ipv4(candidate: str) -> tuple[bool, str | None]:
    """
    Validate if a string is a valid IPv4 address.

    Args:
        candidate: String to validate as IPv4 address.

    Returns:
        Tuple of (is_valid, cleaned_ip). If valid, cleaned_ip is the stripped
        IP address; otherwise, it is None.
    """
    try:
        IPv4Address(candidate.strip())
        return True, candidate.strip()
    except ValueError:
        return False, None

        def get_ioc_type(ioc: str) -> str:
    """
    Determine the type of an IOC based on its format.

    Args:
        ioc: IOC name string (IP address or domain).

    Returns:
        IP if the value is a valid IPv4 address, DOMAIN otherwise.
    """
    is_valid, _ = is_valid_ipv4(ioc)
    return IP if is_valid else DOMAIN








