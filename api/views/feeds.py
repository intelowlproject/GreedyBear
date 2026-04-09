# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.core import signing
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import ASNFeedsOrderingSerializer
from api.throttles import FeedsAdvancedThrottle, FeedsThrottle, SharedFeedRateThrottle
from api.views.utils import (
    FeedRequestParams,
    asn_aggregated_queryset,
    feeds_response,
    get_queryset,
    get_valid_feed_types,
)
from greedybear.consts import GET
from greedybear.models import ShareToken

logger = logging.getLogger(__name__)

ALLOWED_UNAUTHENTICATED_QUERY_PARAMS = [
    "feed_type",
    "attack_type",
    "ioc_type",
    "ordering",
    "include_mass_scanners",
    "include_tor_exit_nodes",
    "prioritize",
]


@extend_schema(
    summary="Get IOC feed",
    parameters=[
        OpenApiParameter("feed_type", str, OpenApiParameter.PATH, description="Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`)."),
        OpenApiParameter("attack_type", str, OpenApiParameter.PATH, description="Attack category: `scanner`, `payload_request`, or `all`."),
        OpenApiParameter(
            "prioritize", str, OpenApiParameter.PATH, description="Prioritization strategy: `recent`, `persistent`, `likely_to_recur`, or `most_expected_hits`."
        ),
        OpenApiParameter("format_", str, OpenApiParameter.PATH, description="Response format: `json`, `csv`, or `txt`."),
        OpenApiParameter("include_mass_scanners", bool, description="Include IOCs flagged as known mass scanners. Excluded by default."),
        OpenApiParameter("include_tor_exit_nodes", bool, description="Include IOCs flagged as known Tor exit nodes. Excluded by default."),
        OpenApiParameter("ordering", str, description="Field to order results by, with optional `-` prefix for descending."),
    ],
    tags=["feeds"],
)
@api_view([GET])
@throttle_classes([FeedsThrottle])
def feeds(request, feed_type, attack_type, prioritize, format_):
    """
    Retrieve an IOC feed filtered by honeypot type, attack type, and prioritization strategy.

    By default, known mass scanners and Tor exit nodes are excluded.

    **Path parameters:**
    - **feed_type**: Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`).
    - **attack_type**: Attack category: `scanner`, `payload_request`, or `all`.
    - **prioritize**: Prioritization strategy: `recent`, `persistent`, `likely_to_recur`, or `most_expected_hits`.
    - **format_**: Response format: `json`, `csv`, or `txt`.

    **Query parameters:**
    - **include_mass_scanners** (bool): Include IOCs flagged as known mass scanners. Excluded by default.
    - **include_tor_exit_nodes** (bool): Include IOCs flagged as known Tor exit nodes. Excluded by default.
    - **ordering** (str): Field to order results by, with optional `-` prefix for descending.
    """
    logger.info(f"request /api/feeds with params: feed type: {feed_type}, attack_type: {attack_type}, prioritization: {prioritize}, format: {format_}")

    filtered_query_params = {key: request.query_params.get(key) for key in ALLOWED_UNAUTHENTICATED_QUERY_PARAMS if key in request.query_params}

    feed_params_data = filtered_query_params.copy()
    feed_params_data.update({"feed_type": feed_type, "attack_type": attack_type, "format": format_})
    feed_params = FeedRequestParams(feed_params_data)
    feed_params.apply_default_filters(filtered_query_params)
    feed_params.set_prioritization(prioritize)

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types)


@extend_schema(
    summary="Get paginated IOC feed",
    parameters=[
        OpenApiParameter("feed_type", str, description="Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`). Default: `all`."),
        OpenApiParameter("attack_type", str, description="Attack category: `scanner`, `payload_request`, or `all`. Default: `all`."),
        OpenApiParameter("ioc_type", str, description="IOC type: `ip`, `domain`, or `all`. Default: `all`."),
        OpenApiParameter("ordering", str, description="Field to order results by, with optional `-` prefix for descending. Default: `-last_seen`."),
        OpenApiParameter("prioritize", str, description="Prioritization strategy: `recent`, `persistent`, `likely_to_recur`, or `most_expected_hits`."),
        OpenApiParameter("include_mass_scanners", bool, description="Include IOCs flagged as known mass scanners. Excluded by default."),
        OpenApiParameter("include_tor_exit_nodes", bool, description="Include IOCs flagged as known Tor exit nodes. Excluded by default."),
        OpenApiParameter("page", int, description="Page number for pagination."),
    ],
    tags=["feeds"],
)
@api_view([GET])
@throttle_classes([FeedsThrottle])
def feeds_pagination(request):
    """
    Retrieve a paginated IOC feed. Always returns JSON format.

    By default, known mass scanners and Tor exit nodes are excluded.

    **Query parameters:**
    - **feed_type** (str): Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`). Default: `all`.
    - **attack_type** (str): Attack category: `scanner`, `payload_request`, or `all`. Default: `all`.
    - **ioc_type** (str): IOC type: `ip`, `domain`, or `all`. Default: `all`.
    - **ordering** (str): Field to order results by, with optional `-` prefix for descending. Default: `-last_seen`.
    - **prioritize** (str): Prioritization strategy: `recent`, `persistent`, `likely_to_recur`, or `most_expected_hits`.
    - **include_mass_scanners** (bool): Include IOCs flagged as known mass scanners. Excluded by default.
    - **include_tor_exit_nodes** (bool): Include IOCs flagged as known Tor exit nodes. Excluded by default.
    - **page** (int): Page number for pagination.
    """

    logger.info(f"request /api/feeds with params: {request.query_params}")

    filtered_query_params = {key: request.query_params.get(key) for key in ALLOWED_UNAUTHENTICATED_QUERY_PARAMS if key in request.query_params}

    feed_params = FeedRequestParams(filtered_query_params)
    feed_params.format = "json"
    feed_params.apply_default_filters(filtered_query_params)
    feed_params.set_prioritization(filtered_query_params.get("prioritize"))

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    paginator = CustomPageNumberPagination()
    iocs = paginator.paginate_queryset(iocs_queryset, request)
    resp_data = feeds_response(request, iocs, feed_params, valid_feed_types, dict_only=True)
    return paginator.get_paginated_response(resp_data)


@extend_schema(
    summary="Get advanced IOC feed (authenticated)",
    parameters=[
        OpenApiParameter("feed_type", str, description="Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`). Default: `all`."),
        OpenApiParameter("attack_type", str, description="Attack category: `scanner`, `payload_request`, or `all`. Default: `all`."),
        OpenApiParameter("max_age", int, description="Maximum number of days since last occurrence. Default: `3`."),
        OpenApiParameter("min_days_seen", int, description="Minimum number of days on which an IOC must have been seen. Default: `1`."),
        OpenApiParameter("include_reputation", str, description="`;`-separated reputation values to include (e.g. `known attacker`). Default: include all."),
        OpenApiParameter("exclude_reputation", str, description="`;`-separated reputation values to exclude (e.g. `mass scanner`). Default: exclude none."),
        OpenApiParameter("feed_size", int, description="Number of IOC items to return. Default: `5000`."),
        OpenApiParameter("ordering", str, description="Field to order results by, with optional `-` prefix for descending. Default: `-last_seen`."),
        OpenApiParameter("verbose", bool, description="`true` to include verbose IOC properties (e.g. days_seen). Default: `false`."),
        OpenApiParameter("paginate", bool, description="`true` to paginate results (forces JSON format). Default: `false`."),
        OpenApiParameter(
            "format", str, description="Response format: `json`, `txt`, `csv`, or `stix21`. Non-JSON formats return IOC values only. Default: `json`."
        ),
        OpenApiParameter("tag_key", str, description="Filter IOCs by tag key (e.g. `malware`, `confidence_of_abuse`)."),
        OpenApiParameter(
            "tag_value", str, description="Filter IOCs by tag value (case-insensitive substring match, e.g. `mirai`). Can be combined with `tag_key`."
        ),
    ],
    tags=["feeds"],
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([FeedsAdvancedThrottle])
def feeds_advanced(request):
    """
    Retrieve IOC feed data with full filtering capabilities. Requires authentication.

    **Query parameters:**
    - **feed_type** (str): Honeypot type to filter by (e.g. `cowrie`, `honeytrap`, or `all`). Default: `all`.
    - **attack_type** (str): Attack category: `scanner`, `payload_request`, or `all`. Default: `all`.
    - **max_age** (int): Maximum number of days since last occurrence. Default: `3`.
    - **min_days_seen** (int): Minimum number of days on which an IOC must have been seen. Default: `1`.
    - **include_reputation** (str): `;`-separated reputation values to include (e.g. `known attacker`). Default: include all.
    - **exclude_reputation** (str): `;`-separated reputation values to exclude (e.g. `mass scanner`). Default: exclude none.
    - **feed_size** (int): Number of IOC items to return. Default: `5000`.
    - **ordering** (str): Field to order results by, with optional `-` prefix for descending. Default: `-last_seen`.
    - **verbose** (bool): `true` to include verbose IOC properties (e.g. days_seen). Default: `false`.
    - **paginate** (bool): `true` to paginate results (forces JSON format). Default: `false`.
    - **format** (str): Response format: `json`, `txt`, `csv`, or `stix21`. Non-JSON formats return IOC values only. Default: `json`.
    - **tag_key** (str): Filter IOCs by tag key (e.g. `malware`, `confidence_of_abuse`).
    - **tag_value** (str): Filter IOCs by tag value (case-insensitive substring match, e.g. `mirai`). Can be combined with `tag_key`.
    """
    logger.info(f"request /api/feeds/advanced/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    verbose = feed_params.verbose == "true"
    paginate = feed_params.paginate == "true"
    if paginate:
        feed_params.format = "json"
    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(
        request,
        feed_params,
        valid_feed_types,
        tag_key=request.query_params.get("tag_key", "").strip(),
        tag_value=request.query_params.get("tag_value", "").strip(),
    )
    if paginate:
        paginator = CustomPageNumberPagination()
        iocs = paginator.paginate_queryset(iocs_queryset, request)
        resp_data = feeds_response(request, iocs, feed_params, valid_feed_types, dict_only=True, verbose=verbose)
        return paginator.get_paginated_response(resp_data)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types, verbose=verbose)


@extend_schema(
    summary="Get IOC feed aggregated by ASN (authenticated)",
    parameters=[
        OpenApiParameter("feed_type", str, description="Honeypot type to filter by. Default: `all`."),
        OpenApiParameter("attack_type", str, description="Attack category: `scanner`, `payload_request`, or `all`. Default: `all`."),
        OpenApiParameter("max_age", int, description="Maximum age of IOCs in days. Default: `3`."),
        OpenApiParameter("min_days_seen", int, description="Minimum days an IOC must have been observed. Default: `1`."),
        OpenApiParameter("exclude_reputation", str, description="`;`-separated reputations to exclude (e.g. `mass scanner`). Default: none."),
        OpenApiParameter("ordering", str, description="Aggregation ordering field (e.g. `total_attack_count`, `asn`). Default: `-ioc_count`."),
        OpenApiParameter("asn", int, description="Filter results to a single ASN."),
    ],
    tags=["feeds"],
)
@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([FeedsAdvancedThrottle])
def feeds_asn(request):
    """
    Retrieve IOC feed data aggregated by ASN (Autonomous System Number). Requires authentication.

    Returns a JSON list where each object contains:
    `asn`, `ioc_count`, `total_attack_count`, `total_interaction_count`, `total_login_attempts`,
    `honeypots`, `expected_ioc_count`, `expected_interactions`, `first_seen`, `last_seen`.

    **Query parameters:**
    - **feed_type** (str): Honeypot type to filter by. Default: `all`.
    - **attack_type** (str): Attack category: `scanner`, `payload_request`, or `all`. Default: `all`.
    - **max_age** (int): Maximum age of IOCs in days. Default: `3`.
    - **min_days_seen** (int): Minimum days an IOC must have been observed. Default: `1`.
    - **exclude_reputation** (str): `;`-separated reputations to exclude (e.g. `mass scanner`). Default: none.
    - **ordering** (str): Aggregation ordering field (e.g. `total_attack_count`, `asn`). Default: `-ioc_count`.
    - **asn** (int): Filter results to a single ASN.
    """
    logger.info(f"request /api/feeds/asn/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    valid_feed_types = get_valid_feed_types()

    iocs_qs = get_queryset(request, feed_params, valid_feed_types, is_aggregated=True, serializer_class=ASNFeedsOrderingSerializer)

    asn_aggregates = asn_aggregated_queryset(iocs_qs, request, feed_params)
    data = list(asn_aggregates)
    return Response(data)


@extend_schema(
    summary="Generate a shareable feed link (authenticated)",
    parameters=[
        OpenApiParameter("feed_type", str, description="Honeypot type to filter by."),
        OpenApiParameter("attack_type", str, description="Attack category to filter."),
        OpenApiParameter("max_age", int, description="Maximum number of days since last occurrence."),
        OpenApiParameter("min_days_seen", int, description="Minimum number of days on which an IOC must have been seen."),
        OpenApiParameter("include_reputation", str, description="`;`-separated reputation values to include."),
        OpenApiParameter("exclude_reputation", str, description="`;`-separated reputation values to exclude."),
        OpenApiParameter("ordering", str, description="Field to order results by."),
        OpenApiParameter("verbose", bool, description="`true` to include verbose IOC properties."),
        OpenApiParameter("asn", int, description="Filter by ASN."),
        OpenApiParameter("min_score", float, description="Filter by minimum recurrence_probability (0–1)."),
        OpenApiParameter("port", int, description="Filter by destination port."),
        OpenApiParameter("start_date", str, description="Filter by start date (`YYYY-MM-DD`)."),
        OpenApiParameter("end_date", str, description="Filter by end date (`YYYY-MM-DD`)."),
    ],
    tags=["feeds"],
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_share(request):
    """
    Generate a signed, shareable link for the current feed configuration. Requires authentication.

    Returns a JSON object with `url` (the shareable feed URL, valid for 30 days) and `revoke_url`.

    **Query parameters:**
    - **feed_type** (str): Honeypot type to filter by.
    - **attack_type** (str): Attack category to filter.
    - **max_age** (int): Maximum number of days since last occurrence.
    - **min_days_seen** (int): Minimum number of days on which an IOC must have been seen.
    - **include_reputation** (str): `;`-separated reputation values to include.
    - **exclude_reputation** (str): `;`-separated reputation values to exclude.
    - **ordering** (str): Field to order results by.
    - **verbose** (bool): `true` to include verbose IOC properties.
    - **asn** (int): Filter by ASN.
    - **min_score** (float): Filter by minimum recurrence_probability (0–1).
    - **port** (int): Filter by destination port.
    - **start_date** (str): Filter by start date (`YYYY-MM-DD`).
    - **end_date** (str): Filter by end date (`YYYY-MM-DD`).
    """
    logger.info(f"request /api/feeds/share with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    data = vars(feed_params)
    # Remove internal or non-serializable objects if any
    data.pop("feed_type_sorting", None)

    # Generate signed token and persist a ShareToken record
    token = signing.dumps(data, salt="greedybear-feeds")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ShareToken.objects.get_or_create(token_hash=token_hash, defaults={"user": request.user})

    host = request.build_absolute_uri("/")
    share_url = f"{host}api/feeds/consume/{token}"
    revoke_url = f"{host}api/feeds/revoke/{token}"
    return Response({"url": share_url, "revoke_url": revoke_url})


@extend_schema(
    summary="Consume a shared feed via token",
    parameters=[
        OpenApiParameter("token", str, OpenApiParameter.PATH, description="Signed token containing the feed configuration (generated by the share endpoint)."),
    ],
    tags=["feeds"],
)
@api_view([GET])
@authentication_classes([])
@permission_classes([])
@throttle_classes([SharedFeedRateThrottle])
def feeds_consume(request, token):
    """
    Consume a shared feed using a signed token. Publicly accessible but strictly rate-limited.

    Tokens are valid for 30 days and can be revoked by the creator.

    **Path parameters:**
    - **token** (str): Signed token containing the feed configuration (generated by the share endpoint).
    """
    logger.info("request /api/feeds/consume with token")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if ShareToken.objects.filter(token_hash=token_hash, revoked=True).exists():
        return Response({"error": "Token has been revoked"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        data = signing.loads(token, salt="greedybear-feeds", max_age=86400 * 30)  # 30 days validity
    except signing.BadSignature:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    # Reconstruct params
    feed_params = FeedRequestParams(data)

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types)


@extend_schema(
    summary="Revoke a shared feed token (authenticated)",
    parameters=[
        OpenApiParameter("token", str, OpenApiParameter.PATH, description="The signed token to revoke."),
    ],
    tags=["feeds"],
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_revoke(request, token):
    """
    Revoke a previously generated shareable feed token. Requires authentication.

    Once revoked, any attempt to consume the feed via that token will return a 400 error.
    Only the token creator (or staff) can revoke it. This is a GET endpoint so the revoke
    link can be opened directly in a browser.

    **Path parameters:**
    - **token** (str): The signed token to revoke.
    """
    logger.info("request /api/feeds/revoke")
    try:
        signing.loads(token, salt="greedybear-feeds", max_age=86400 * 30)
    except signing.BadSignature:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        share_token = ShareToken.objects.get(token_hash=token_hash)
    except ShareToken.DoesNotExist:
        return Response({"error": "Token not found. Only the creator can revoke a token."}, status=status.HTTP_403_FORBIDDEN)

    if share_token.user != request.user and not request.user.is_staff:
        return Response({"error": "You do not have permission to revoke this token."}, status=status.HTTP_403_FORBIDDEN)

    if share_token.revoked:
        return Response({"detail": "Token was already revoked."}, status=status.HTTP_200_OK)
    share_token.revoked = True
    share_token.revoked_at = timezone.now()
    share_token.save(update_fields=["revoked", "revoked_at"])
    return Response({"detail": "Token revoked successfully."}, status=status.HTTP_200_OK)
