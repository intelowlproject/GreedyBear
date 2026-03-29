# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
import os
import re

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.pagination import CustomPageNumberPagination
from certego_saas.ext.throttling import UserRateThrottle
from django.conf import settings
from django.http import FileResponse, Http404
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from greedybear.consts import GET
from greedybear.models import Payload, Statistics, ViewType


class PayloadListRateThrottle(UserRateThrottle):
    """Rate limit for payload list endpoint."""

    rate = "100/hour"
    scope = "payload_list"


class PayloadDetailRateThrottle(UserRateThrottle):
    """Rate limit for payload detail endpoint."""

    rate = "200/hour"
    scope = "payload_detail"


class PayloadDownloadRateThrottle(UserRateThrottle):
    """Strict rate limit for payload downloads."""

    rate = "20/hour"
    scope = "payload_download"


class PayloadStatsRateThrottle(UserRateThrottle):
    """Rate limit for payload stats endpoint."""

    rate = "60/hour"
    scope = "payload_stats"

logger = logging.getLogger(__name__)

# Regex for validating SHA256 hash format
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def _validate_sha256(sha256: str) -> bool:
    """Validate that a string is a valid SHA256 hash format.

    Args:
        sha256: The string to validate.

    Returns:
        True if valid SHA256 format, False otherwise.
    """
    return bool(SHA256_REGEX.match(sha256))


def _log_payload_access(request, sha256: str, action: str) -> None:
    """Log payload access for audit trail.

    Args:
        request: The HTTP request object.
        sha256: The SHA256 hash of the accessed payload.
        action: The action performed (e.g., 'view', 'download').
    """
    source_ip = str(request.META.get("REMOTE_ADDR", "unknown"))
    user = request.user.username if request.user.is_authenticated else "anonymous"
    logger.info(
        f"Payload {action}: sha256={sha256[:16]}..., user={user}, ip={source_ip}"
    )


def _serialize_payload(payload: Payload, include_iocs: bool = False) -> dict:
    """Serialize a Payload instance to a dictionary.

    Args:
        payload: The Payload model instance.
        include_iocs: Whether to include related IOC data.

    Returns:
        Dictionary representation of the payload.
    """
    data = {
        "sha256": payload.sha256,
        "sha1": payload.sha1,
        "md5": payload.md5,
        "file_size": payload.file_size,
        "file_type": payload.file_type,
        "file_name": payload.file_name,
        "first_seen": payload.first_seen.isoformat() if payload.first_seen else None,
        "last_seen": payload.last_seen.isoformat() if payload.last_seen else None,
        "times_seen": payload.times_seen,
        "is_quarantined": payload.is_quarantined,
        "honeypot": payload.general_honeypot.name if payload.general_honeypot else None,
    }

    if include_iocs:
        data["related_iocs"] = [
            {
                "name": ioc.name,
                "type": ioc.type,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            }
            for ioc in payload.related_iocs.all()[:100]  # Limit to 100 IOCs
        ]

    return data


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([PayloadListRateThrottle])
def payload_list(request):
    """
    List payloads with optional filtering and pagination.

    Query Parameters:
        honeypot (str): Filter by honeypot name (e.g., 'dionaea', 'cowrie').
        file_type (str): Filter by MIME type (e.g., 'application/x-executable').
        sha256 (str): Filter by SHA256 hash (partial match supported).
        min_size (int): Minimum file size in bytes.
        max_size (int): Maximum file size in bytes.
        first_seen_after (str): ISO date string for filtering by first_seen.
        last_seen_after (str): ISO date string for filtering by last_seen.
        ordering (str): Field to order by. Prefix with '-' for descending.
            Allowed: 'first_seen', 'last_seen', 'file_size', 'times_seen'.
            Default: '-last_seen'.

    Returns:
        Response: Paginated list of payload metadata.
    """
    logger.info(f"Payload list requested with params: {request.query_params}")

    # Track statistics
    source_ip = str(request.META.get("REMOTE_ADDR", "unknown"))
    Statistics.objects.create(source=source_ip, view=ViewType.FEEDS_VIEW.value)

    # Build queryset with filters
    queryset = Payload.objects.select_related("general_honeypot")

    # Apply filters
    honeypot = request.query_params.get("honeypot")
    if honeypot:
        queryset = queryset.filter(general_honeypot__name__iexact=honeypot)

    file_type = request.query_params.get("file_type")
    if file_type:
        queryset = queryset.filter(file_type__icontains=file_type)

    sha256_filter = request.query_params.get("sha256")
    if sha256_filter:
        queryset = queryset.filter(sha256__istartswith=sha256_filter)

    min_size = request.query_params.get("min_size")
    if min_size and min_size.isdigit():
        queryset = queryset.filter(file_size__gte=int(min_size))

    max_size = request.query_params.get("max_size")
    if max_size and max_size.isdigit():
        queryset = queryset.filter(file_size__lte=int(max_size))

    first_seen_after = request.query_params.get("first_seen_after")
    if first_seen_after:
        queryset = queryset.filter(first_seen__gte=first_seen_after)

    last_seen_after = request.query_params.get("last_seen_after")
    if last_seen_after:
        queryset = queryset.filter(last_seen__gte=last_seen_after)

    # Apply ordering with validation
    allowed_ordering = {"first_seen", "last_seen", "file_size", "times_seen"}
    ordering = request.query_params.get("ordering", "-last_seen")
    order_field = ordering.lstrip("-")
    if order_field in allowed_ordering:
        queryset = queryset.order_by(ordering)
    else:
        queryset = queryset.order_by("-last_seen")

    # Paginate results
    paginator = CustomPageNumberPagination()
    page = paginator.paginate_queryset(queryset, request)

    data = [_serialize_payload(payload) for payload in page]
    return paginator.get_paginated_response(data)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([PayloadDetailRateThrottle])
def payload_detail(request, sha256: str):
    """
    Retrieve detailed information about a specific payload.

    Args:
        sha256: The SHA256 hash of the payload (64 hex characters).

    Returns:
        Response: Detailed payload metadata including related IOCs.

    Raises:
        400: If SHA256 format is invalid.
        404: If payload not found.
    """
    logger.info(f"Payload detail requested: {sha256[:16]}...")

    # Validate SHA256 format to prevent injection
    if not _validate_sha256(sha256):
        return Response(
            {"error": "Invalid SHA256 hash format"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        payload = Payload.objects.select_related("general_honeypot").prefetch_related(
            "related_iocs"
        ).get(sha256=sha256.lower())
    except Payload.DoesNotExist:
        raise Http404("Payload not found")

    _log_payload_access(request, sha256, "view")

    data = _serialize_payload(payload, include_iocs=True)
    return Response(data, status=status.HTTP_200_OK)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([PayloadDownloadRateThrottle])
def payload_download(request, sha256: str):
    """
    Securely download a payload file.

    Security measures:
    - Authentication required
    - SHA256 format validation (prevents path traversal)
    - File path constructed from SHA256 only (no user input in path)
    - Audit logging of all download attempts
    - Content-Disposition header forces download (no browser execution)

    Args:
        sha256: The SHA256 hash of the payload (64 hex characters).

    Returns:
        FileResponse: The payload file as a download.

    Raises:
        400: If SHA256 format is invalid.
        403: If downloads are disabled.
        404: If payload not found or file missing.
    """
    logger.info(f"Payload download requested: {sha256[:16]}...")

    # Check if downloads are enabled
    if not getattr(settings, "PAYLOAD_DOWNLOADS_ENABLED", False):
        return Response(
            {"error": "Payload downloads are disabled"},
            status=status.HTTP_403_FORBIDDEN,
        )

    # Validate SHA256 format to prevent path traversal
    if not _validate_sha256(sha256):
        return Response(
            {"error": "Invalid SHA256 hash format"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    sha256_lower = sha256.lower()

    try:
        payload = Payload.objects.get(sha256=sha256_lower)
    except Payload.DoesNotExist:
        raise Http404("Payload not found")

    # Construct file path securely using SHA256 only
    storage_base = getattr(
        settings, "PAYLOAD_STORAGE_PATH", "/var/lib/greedybear/payloads"
    )
    # Use SHA256 prefix for directory sharding (first 2 chars)
    file_path = os.path.join(storage_base, sha256_lower[:2], sha256_lower)

    # Verify the path is within storage directory (defense in depth)
    real_storage_base = os.path.realpath(storage_base)
    real_file_path = os.path.realpath(file_path)
    if not real_file_path.startswith(real_storage_base):
        logger.warning(f"Path traversal attempt detected: {sha256}")
        return Response(
            {"error": "Invalid file path"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not os.path.isfile(file_path):
        logger.warning(f"Payload file not found on disk: {sha256_lower[:16]}...")
        raise Http404("Payload file not found on disk")

    # Audit log the download
    _log_payload_access(request, sha256, "download")

    # Determine safe filename for download
    safe_filename = f"{sha256_lower}.bin"
    if payload.file_name:
        # Sanitize original filename - remove path separators and null bytes
        sanitized = os.path.basename(payload.file_name)
        sanitized = sanitized.replace("\x00", "").replace("/", "_").replace("\\", "_")
        if sanitized:
            safe_filename = f"{sha256_lower[:8]}_{sanitized}"

    # Open file with context manager - FileResponse will close it when done
    # Using a file handle that FileResponse takes ownership of
    file_handle = open(file_path, "rb")
    try:
        response = FileResponse(
            file_handle,
            content_type="application/octet-stream",
            as_attachment=True,
            filename=safe_filename,
        )
        # FileResponse now owns the file handle and will close it
        # Set file_to_stream to ensure proper cleanup
        response.file_to_stream = file_handle

        # Add security headers to prevent browser execution
        response["X-Content-Type-Options"] = "nosniff"
        response["Content-Security-Policy"] = "default-src 'none'"

        return response
    except Exception:
        # Ensure file handle is closed if FileResponse creation fails
        file_handle.close()
        raise


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([PayloadStatsRateThrottle])
def payload_stats(request):
    """
    Retrieve aggregated statistics about payloads.

    Returns:
        Response: Statistics including:
            - total_count: Total number of unique payloads
            - total_size_bytes: Sum of all payload sizes
            - by_honeypot: Count per honeypot
            - by_file_type: Count per file type (top 10)
            - recent_count: Payloads seen in last 24 hours
    """
    from datetime import datetime, timedelta

    from django.db.models import Count, Sum

    logger.info("Payload statistics requested")

    total_count = Payload.objects.count()
    total_size = Payload.objects.aggregate(total=Sum("file_size"))["total"] or 0

    by_honeypot = list(
        Payload.objects.exclude(general_honeypot__isnull=True)
        .values("general_honeypot__name")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    by_file_type = list(
        Payload.objects.exclude(file_type="")
        .values("file_type")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    recent_threshold = datetime.now() - timedelta(hours=24)
    recent_count = Payload.objects.filter(last_seen__gte=recent_threshold).count()

    data = {
        "total_count": total_count,
        "total_size_bytes": total_size,
        "by_honeypot": [
            {"honeypot": item["general_honeypot__name"], "count": item["count"]}
            for item in by_honeypot
        ],
        "by_file_type": [
            {"file_type": item["file_type"], "count": item["count"]}
            for item in by_file_type
        ],
        "recent_count": recent_count,
    }

    return Response(data, status=status.HTTP_200_OK)


__all__ = [
    "payload_list",
    "payload_detail",
    "payload_download",
    "payload_stats",
]
