from collections import defaultdict
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from logging import Logger
from urllib.parse import urlparse

import requests
from django.conf import settings

from greedybear.consts import DOMAIN, IP
from greedybear.models import IOC, FireHolList, MassScanner, WhatsMyIPDomain


def is_whatsmyip_domain(domain: str) -> bool:
    """
    Check if a domain is a known "what's my IP" service.

    Args:
        domain: Domain name to check.

    Returns:
        True if the domain is in the WhatsMyIP list, False otherwise.
    """
    try:
        WhatsMyIPDomain.objects.get(domain=domain)
    except WhatsMyIPDomain.DoesNotExist:
        return False
    return True


def correct_ip_reputation(ip: str, ip_reputation: str) -> str:
    """
    Correct IP reputation based on mass scanner database.
    Overrides reputation to "mass scanner" if the IP is found in the MassScanners table.
    This is necessary because we have seen "mass scanners" incorrectly flagged.

    Args:
        ip: IP address to check.
        ip_reputation: Current reputation string.

    Returns:
        Corrected reputation string.
    """
    if not ip_reputation or ip_reputation == "known attacker":
        try:
            MassScanner.objects.get(ip_address=ip)
        except MassScanner.DoesNotExist:
            pass
        else:
            ip_reputation = "mass scanner"
    return ip_reputation


def get_firehol_categories(ip: str, extracted_ip) -> list[str]:
    """
    Get FireHol categories for an IP address.
    Checks both exact IP matches (for .ipset files) and network range
    membership (for .netset files with CIDR notation).

    Args:
        ip: IP address string.
        extracted_ip: Parsed IP address object from ipaddress library.

    Returns:
        List of FireHol source categories.
    """
    firehol_categories = []

    # First check for exact IP match (for .ipset files)
    exact_matches = FireHolList.objects.filter(ip_address=ip).values_list("source", flat=True)
    # Filter out empty strings (from default='')
    firehol_categories.extend([source for source in exact_matches if source])

    # Then check if IP is within any network ranges (for .netset files)
    # Only query entries that contain '/' (CIDR notation)
    network_entries = FireHolList.objects.filter(ip_address__contains="/")
    for entry in network_entries:
        try:
            network_range = ip_network(entry.ip_address, strict=False)
            # Check entry.source is not empty and not already in list
            if extracted_ip in network_range and entry.source and entry.source not in firehol_categories:
                firehol_categories.append(entry.source)
        except (ValueError, IndexError):
            # Not a valid network range, skip
            continue

    return firehol_categories


def iocs_from_hits(hits: list[dict]) -> list[IOC]:
    """
    Convert Elasticsearch hits into IOC objects.
    Groups hits by source IP, filters out non-global addresses, and
    constructs IOC objects with aggregated data.
    Enriches IOCs with FireHol categories at creation time to ensure
    only fresh data is used.

    Args:
        hits: List of Elasticsearch hit dictionaries.

    Returns:
        List of IOC instances, one per unique source IP.
    """
    hits_by_ip = defaultdict(list)
    for hit in hits:
        hits_by_ip[hit["src_ip"]].append(hit)
    iocs = []
    for ip, hits in hits_by_ip.items():
        dest_ports = [hit["dest_port"] for hit in hits if "dest_port" in hit]
        extracted_ip = ip_address(ip)
        if extracted_ip.is_loopback or extracted_ip.is_private or extracted_ip.is_multicast or extracted_ip.is_link_local or extracted_ip.is_reserved:
            continue

        firehol_categories = get_firehol_categories(ip, extracted_ip)

        ioc = IOC(
            name=ip,
            type=get_ioc_type(ip),
            interaction_count=len(hits),
            ip_reputation=correct_ip_reputation(ip, hits[0].get("ip_rep", "")),
            asn=hits[0].get("geoip", {}).get("asn"),
            destination_ports=sorted(set(dest_ports)),
            login_attempts=len(hits) if hits[0].get("type", "") == "Heralding" else 0,
            firehol_categories=firehol_categories,
        )
        timestamps = [hit["@timestamp"] for hit in hits if "@timestamp" in hit]
        if timestamps:
            ioc.first_seen = datetime.fromisoformat(min(timestamps))
            ioc.last_seen = datetime.fromisoformat(max(timestamps))
        iocs.append(ioc)
    return iocs


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


def threatfox_submission(ioc_record: IOC, related_urls: list, log: Logger) -> None:
    """
    Submit IOC URLs to ThreatFox threat intelligence platform.
    Only submits payload request IOCs with URLs containing paths,
    because they are more reliable than scanners.
    Requires THREATFOX_API_KEY to be configured in settings.

    Args:
        ioc_record: IOC record containing honeypot associations.
        related_urls: List of URLs to potentially submit.
        log: Logger instance for status messages.
    """
    if not ioc_record.payload_request:
        return

    if not settings.THREATFOX_API_KEY:
        log.warning("Threatfox API Key not available")
        return

    urls_to_submit = []
    # submit only URLs with paths to avoid false positives
    for related_url in related_urls:
        parsed_url = urlparse(related_url)
        if parsed_url.path not in ["", "/"]:
            urls_to_submit.append(related_url)
        else:
            log.info(f"skipping export of {related_url} cause has no path")

    if not urls_to_submit:
        log.info("No URLs with paths to submit")
        return

    headers = {"Auth-Key": settings.THREATFOX_API_KEY}
    log.info(f"submitting IOC {urls_to_submit} to Threatfox")

    seen_honeypots = []
    if ioc_record.cowrie:
        seen_honeypots.append("cowrie")
    if ioc_record.log4j:
        seen_honeypots.append("log4pot")
    for honeypot in ioc_record.general_honeypot.all():
        seen_honeypots.append(honeypot.name)
    seen_honeypots_str = ", ".join(seen_honeypots)

    json_data = {
        "query": "submit_ioc",
        "threat_type": "payload_delivery",
        "ioc_type": "url",
        "malware": "unknown",
        "confidence_level": "75",
        "reference": "https://greedybear.honeynet.org",
        "comment": f"Seen requesting a payload from {seen_honeypots_str} honeypot and collected in Greedybear, the Threat Intel Platform for T-POTs.",
        "anonymous": 0,
        "tags": ["honeypot"],
        "iocs": urls_to_submit,
    }
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers=headers,
            json=json_data,
            timeout=5,
        )
    except requests.RequestException as e:
        log.exception(f"Threatfox push error: {e}")
    else:
        log.info(f"Threatfox submission successful. Received response: {r.text}")
