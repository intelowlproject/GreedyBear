from collections import defaultdict
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from logging import Logger
from urllib.parse import urlparse

import requests
from django.conf import settings

from greedybear.consts import DOMAIN, IP
from greedybear.models import IOC, FireHolList, MassScanner


def iocs_from_hits(hits: list[dict]) -> list[IOC]:
    """
    Convert Elasticsearch hits into IOC objects with associated sensors.
    Groups hits by source IP, filters out non-global addresses, and
    constructs IOC objects with aggregated data.
    Enriches IOCs with FireHol categories at creation time to ensure
    only fresh data is used.

    Performs bulk database lookups before the main loop to avoid
    N+1 query overhead when processing large batches.

    Args:
        hits: List of Elasticsearch hit dictionaries.

    Returns:
        List of IOC instances, one per unique source IP.
    """
    hits_by_ip = defaultdict(list)
    for hit in hits:
        hits_by_ip[hit["src_ip"]].append(hit)

    all_ips = list(hits_by_ip.keys())

    # --- Bulk prefetch: FireHol exact matches (for .ipset files) ---
    firehol_exact = defaultdict(list)
    for entry_ip, source in FireHolList.objects.filter(
        ip_address__in=all_ips,
    ).values_list("ip_address", "source"):
        if source:
            firehol_exact[entry_ip].append(source)

    # --- Bulk prefetch: FireHol CIDR entries (for .netset files) ---
    # Fetched once; the same set of network ranges applies to every IP.
    cidr_entries = []
    for entry in FireHolList.objects.filter(ip_address__contains="/"):
        try:
            cidr_entries.append((ip_network(entry.ip_address, strict=False), entry.source))
        except (ValueError, IndexError):
            continue

    # --- Bulk prefetch: MassScanner IPs ---
    mass_scanner_ips = set(
        MassScanner.objects.filter(
            ip_address__in=all_ips,
        ).values_list("ip_address", flat=True)
    )

    iocs = []
    for ip, hits in hits_by_ip.items():
        dest_ports = [hit["dest_port"] for hit in hits if "dest_port" in hit]
        extracted_ip = ip_address(ip)
        if extracted_ip.is_loopback or extracted_ip.is_private or extracted_ip.is_multicast or extracted_ip.is_link_local or extracted_ip.is_reserved:
            continue

        # Build FireHol categories from prefetched data
        firehol_categories = list(firehol_exact.get(ip, []))
        for network, source in cidr_entries:
            if source and extracted_ip in network and source not in firehol_categories:
                firehol_categories.append(source)

        # Collect unique sensors from hits, deduplicated by sensor ID
        sensors_map = {hit["_sensor"].id: hit["_sensor"] for hit in hits if hit.get("_sensor") is not None and getattr(hit["_sensor"], "id", None)}
        sensors = list(sensors_map.values())
        # Sort sensors by ID for consistent processing order
        sensors.sort(key=lambda s: s.id)

        # Correct IP reputation from prefetched MassScanner set
        ip_rep = hits[0].get("ip_rep", "")
        if (not ip_rep or ip_rep == "known attacker") and ip in mass_scanner_ips:
            ip_rep = "mass scanner"

        ioc = IOC(
            name=ip,
            type=get_ioc_type(ip),
            interaction_count=len(hits),
            ip_reputation=ip_rep,
            asn=hits[0].get("geoip", {}).get("asn"),
            destination_ports=sorted(set(dest_ports)),
            login_attempts=len(hits) if hits[0].get("type", "") == "Heralding" else 0,
            firehol_categories=firehol_categories,
        )
        # Attach sensors to temporary attribute for later processing.
        # We cannot use `ioc.sensors.add()` here because the IOC instance is not yet saved
        # to the database, and Django requires an ID for M2M relationships.
        ioc._sensors_to_add = sensors

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

    seen_honeypots = [hp.name for hp in ioc_record.general_honeypot.all()]
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
