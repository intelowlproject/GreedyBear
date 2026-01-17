# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.pagination import CustomPageNumberPagination
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.views.utils import (
    FeedRequestParams,
    aggregate_iocs_by_asn,
    feeds_response,
    get_queryset,
    get_valid_feed_types,
)
from greedybear.consts import GET

logger = logging.getLogger(__name__)


@api_view([GET])
def feeds(request, feed_type, attack_type, prioritize, format_):
    """
    Handle requests for IOC feeds with specific parameters and format the response accordingly.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed (e.g., log4j, cowrie, etc.).
        attack_type (str): Type of attack (e.g., all, specific attack types).
        prioritize (str): Prioritization mechanism to use (e.g., recent, persistent).
        format_ (str): Desired format of the response (e.g., json, csv, txt).
        include_mass_scanners (bool): query parameter flag to include IOCs that are known mass scanners.
        include_tor_exit_nodes (bool): query parameter flag to include IOCs that are known tor exit nodes.

    Returns:
        Response: The HTTP response with formatted IOC data.
    """
    logger.info(f"request /api/feeds with params: feed type: {feed_type}, attack_type: {attack_type}, prioritization: {prioritize}, format: {format_}")

    feed_params_data = request.query_params.dict()
    feed_params_data.update({"feed_type": feed_type, "attack_type": attack_type, "format_": format_})
    feed_params = FeedRequestParams(feed_params_data)
    feed_params.apply_default_filters(request.query_params)
    feed_params.set_prioritization(prioritize)

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    return feeds_response(iocs_queryset, feed_params, valid_feed_types)


@api_view([GET])
def feeds_pagination(request):
    """
    Handle requests for paginated IOC feeds based on query parameters.

    Args:
        request: The incoming request object.

    Returns:
        Response: The paginated HTTP response with IOC data.
    """

    logger.info(f"request /api/feeds with params: {request.query_params}")

    feed_params = FeedRequestParams(request.query_params)
    feed_params.format = "json"
    feed_params.apply_default_filters(request.query_params)
    feed_params.set_prioritization(request.query_params.get("prioritize"))

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    paginator = CustomPageNumberPagination()
    iocs = paginator.paginate_queryset(iocs_queryset, request)
    resp_data = feeds_response(iocs, feed_params, valid_feed_types, dict_only=True)
    return paginator.get_paginated_response(resp_data)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_advanced(request):
    """
    Handle requests for IOC feeds based on query parameters and format the response accordingly.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed to retrieve. (supported: `cowrie`, `log4j`, etc.; default: `all`)
        attack_type (str): Type of attack to filter. (supported: `scanner`, `payload_request`, `all`; default: `all`)
        max_age (int): Maximum number of days since last occurrence. E.g. an IOC that was last seen 4 days ago is excluded by default. (default: 3)
        min_days_seen (int): Minimum number of days on which an IOC must have been seen. (default: 1)
        include_reputation (str): `;`-separated list of reputation values to include, e.g. `known attacker` or `known attacker;` to include IOCs without reputation. (default: include all)
        exclude_reputation (str): `;`-separated list of reputation values to exclude, e.g. `mass scanner` or `mass scanner;bot, crawler`. (default: exclude none)
        feed_size (int): Number of IOC items to return. (default: 5000)
        ordering (str): Field to order results by, with optional `-` prefix for descending. (default: `-last_seen`)
        verbose (bool): `true` to include IOC properties that contain a lot of data, e.g. the list of days it was seen. (default: `false`)
        paginate (bool): `true` to paginate results. This forces the json format. (default: `false`)
        format (str): Response format type. Besides `json`, `txt` and `csv` are supported but the response will only contain IOC values (e.g. IP adresses) without further information. (default: `json`)

    Returns:
        Response: The HTTP response with formatted IOC data.
    """
    logger.info(f"request /api/feeds/advanced/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    verbose = feed_params.verbose == "true"
    paginate = feed_params.paginate == "true"
    if paginate:
        feed_params.format = "json"
        paginator = CustomPageNumberPagination()
        iocs = paginator.paginate_queryset(iocs_queryset, request)
        resp_data = feeds_response(iocs, feed_params, valid_feed_types, dict_only=True, verbose=verbose)
        return paginator.get_paginated_response(resp_data)
    return feeds_response(iocs_queryset, feed_params, valid_feed_types, verbose=verbose)


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_asn(request):
    """
    Handle requests for IOC feeds aggregated by ASN, calculating summary statistics.

    This endpoint groups IOC data by ASN and returns aggregated metrics for each ASN, including counts, sums,
    and unique honeypots.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed to retrieve. Supported: `cowrie`, `log4j`, general honeypot names, or `all`. Default: `all`.
        attack_type (str): Type of attack to filter. Supported: `scanner`, `payload_request`, or `all`. Default: `all`.
        max_age (int): Maximum number of days since last occurrence. Default: 3.
        min_days_seen (int): Minimum number of days an IOC must have been seen. Default: 1.
        include_reputation (str): `;`-separated list of reputations to include, e.g., `known attacker;`. Default: include all.
        exclude_reputation (str): `;`-separated list of reputations to exclude, e.g., `mass scanner;bot`. Default: exclude none.
        feed_size (int): Maximum number of IOC items considered for aggregation. Default: 5000.
        ordering (str): Field to order results by, with optional `-` prefix for descending. Default: `-last_seen`.
        verbose (bool): Not used in this endpoint; included for consistency with Advanced Feeds API. Default: `false`.
        paginate (bool): Not supported in this endpoint; ignored if provided. Default: `false`.
        format (str): Response format type; only `json` is supported. Default: `json`.

    Returns:
     Response: HTTP response with a JSON list of ASN aggregation objects.
     Each object contains:
            asn (int): ASN number.
            ioc_count (int): Number of IOCs for this ASN.
            total_attack_count (int): Sum of attack_count for all IOCs.
            total_interaction_count (int): Sum of interaction_count for all IOCs.
            total_login_attempts (int): Sum of login_attempts for all IOCs.
            honeypots (List[str]): Sorted list of unique honeypots that observed these IOCs.
            expected_ioc_count (float): Sum of recurrence_probability for all IOCs, rounded to 4 decimals.
            expected_interactions (float): Sum of expected_interactions for all IOCs, rounded to 4 decimals.
    """
    logger.info(f"request /api/feeds/asn/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    response_data = aggregate_iocs_by_asn(iocs_queryset)
    return Response(response_data)
