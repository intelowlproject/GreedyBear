# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import logging
from datetime import datetime, timedelta

from api.serializers import EnrichmentSerializer, FeedsRequestSerializer, FeedsResponseSerializer
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.helpers import parse_humanized_range
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import HttpResponse, HttpResponseServerError, StreamingHttpResponse
from greedybear.consts import FEEDS_LICENSE, GET, PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC, GeneralHoneypot, Statistics, viewType
from greedybear.settings import SKIP_FEED_VALIDATION
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class Echo:
    """An object that implements just the write method of the file-like
    interface.
    This class is used to stream data in CSV format.
    """

    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer.

        Args:
            value (str): The value to be written.

        Returns:
            str: The same value that was passed.
        """
        return value


class FeedRequestParams:
    """A class to handle and validate feed request parameters.
    It processes and stores query parameters for feed requests,
    providing default values.

    Attributes:
        feed_type (str): Type of feed to retrieve (default: "all")
        attack_type (str): Type of attack to filter (default: "all")
        max_age (str): Maximum number of days since last occurrence (default: "3")
        min_days_seen (str): Minimum number of days on which an IOC must have been seen (default: "1")
        include_reputation (list): List of reputation values to include (default: [])
        exclude_reputation (list): List of reputation values to exclude (default: [])
        feed_size (int): Number of items to return in feed (default: "5000")
        ordering (str): Field to order results by (default: "-last_seen")
        verbose (str): Whether to include IOC properties that contain a lot of data (default: "false")
        paginate (str): Whether to paginate results (default: "false")
        format (str): Response format type (default: "json")
    """

    def __init__(self, query_params: dict):
        """Initialize a new FeedRequestParams instance.

        Parameters:
            query_params (dict): Dictionary containing query parameters for feed configuration.
        """
        self.feed_type = query_params.get("feed_type", "all").lower()
        self.attack_type = query_params.get("attack_type", "all").lower()
        self.max_age = query_params.get("max_age", "3")
        self.min_days_seen = query_params.get("min_days_seen", "1")
        self.include_reputation = query_params["include_reputation"].split(";") if "include_reputation" in query_params else []
        self.exclude_reputation = query_params["exclude_reputation"].split(";") if "exclude_reputation" in query_params else []
        self.feed_size = query_params.get("feed_size", "5000")
        self.ordering = query_params.get("ordering", "-last_seen").lower().replace("value", "name")
        self.verbose = query_params.get("verbose", "false").lower()
        self.paginate = query_params.get("paginate", "false").lower()
        self.format = query_params.get("format_", "json").lower()

    def set_legacy_age(self, age: str):
        """Translates legacy age specification into max_age and min_days_seen attributes
        and sets ordering accordingly.

        Parameters:
            age (str): Age of the data to filter (recent or persistent).
        """
        match age:
            case "recent":
                self.max_age = "3"
                self.min_days_seen = "1"
                if "feed_type" in self.ordering:
                    self.ordering = "-last_seen"
            case "persistent":
                self.max_age = "14"
                self.min_days_seen: "10"
                if "feed_type" in self.ordering:
                    self.ordering = "-attack_count"


def get_valid_feed_types() -> frozenset[str]:
    general_honeypots = GeneralHoneypot.objects.all().filter(active=True)
    return frozenset(["log4j", "cowrie", "all"] + [hp.name.lower() for hp in general_honeypots])


@api_view([GET])
def feeds(request, feed_type, attack_type, age, format_):
    """
    Handle requests for IOC feeds with specific parameters and format the response accordingly.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed (e.g., log4j, cowrie, etc.).
        attack_type (str): Type of attack (e.g., all, specific attack types).
        age (str): Age of the data to filter (e.g., recent, persistent).
        format_ (str): Desired format of the response (e.g., json, csv, txt).

    Returns:
        Response: The HTTP response with formatted IOC data.
    """
    logger.info(f"request /api/feeds with params: feed type: {feed_type}, " f"attack_type: {attack_type}, Age: {age}, format: {format_}")

    feed_params = FeedRequestParams({"feed_type": feed_type, "attack_type": attack_type, "format_": format_})
    feed_params.set_legacy_age(age)
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
    feed_params.set_legacy_age(request.query_params.get("age"))
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

    Supported query parameters are:

        - **feed_type**: Type of feed to retrieve. (supported: `cowrie`, `log4j`, etc.; default: `all`)
        - **attack_type**: Type of attack to filter. (supported: `scanner`, `payload_request`, `all`; default: `all`)
        - **max_age**: Maximum number of days since last occurrence. \
            E.g. an IOC that was last seen 4 days ago is excluded by default. (default: 3)
        - **min_days_seen**: Minimum number of days on which an IOC must have been seen. (default: 1)
        - **include_reputation**: `;`-separated list of reputation values to include, \
            e.g. `known attacker` or `known attacker;` to include IOCs without reputation. (default: include all)
        - **exclude_reputation**: `;`-separated list of reputation values to exclude, \
            e.g. `mass scanner` or `mass scanner;bot, crawler`. (default: exclude none)
        - **feed_size**: Number of IOC items to return. (default: 5000)
        - **ordering**: Field to order results by, with optional `-` prefix for descending. (default: `-last_seen`)
        - **verbose**: `true` to include IOC properties that contain a lot of data, e.g. the list of days it was seen. (default: `false`)
        - **paginate**: `true` to paginate results (default: `false`)
        - **format_**: Response format type. Besides `json`, `txt` and `csv` are supported \
            but the response will only contain IOC values (e.g. IP adresses) without further information. (default: `json`)

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
        paginator = CustomPageNumberPagination()
        iocs = paginator.paginate_queryset(iocs_queryset, request)
        resp_data = feeds_response(iocs, feed_params, valid_feed_types, dict_only=True, verbose=verbose)
        return paginator.get_paginated_response(resp_data)
    return feeds_response(iocs_queryset, feed_params, valid_feed_types, verbose=verbose)


def get_queryset(request, feed_params, valid_feed_types):
    """
    Build a queryset to filter IOC data based on the request parameters.

    Args:
        request: The incoming request object.
        feed_params: A FeedRequestParams instance.
        valid_feed_types (frozenset): The set of all valid feed types.

    Returns:
        QuerySet: The filtered queryset of IOC data.
    """
    source = str(request.user)
    logger.info(
        f"request from {source}. Feed type: {feed_params.feed_type}, attack_type: {feed_params.attack_type}, "
        f"Age: {feed_params.max_age}, format: {feed_params.format}"
    )

    serializer = FeedsRequestSerializer(
        data=vars(feed_params),
        context={"valid_feed_types": valid_feed_types},
    )
    serializer.is_valid(raise_exception=True)

    query_dict = {}
    if feed_params.feed_type != "all":
        if feed_params.feed_type in ("log4j", "cowrie"):
            query_dict[feed_params.feed_type] = True
        else:
            # accept feed_type if it is in the general honeypots list
            query_dict["general_honeypot__name__iexact"] = feed_params.feed_type

    if feed_params.attack_type != "all":
        query_dict[feed_params.attack_type] = True

    query_dict["last_seen__gte"] = datetime.utcnow() - timedelta(days=int(feed_params.max_age))
    query_dict["number_of_days_seen__gte"] = int(feed_params.min_days_seen)
    if feed_params.include_reputation:
        query_dict["ip_reputation__in"] = feed_params.include_reputation

    iocs = (
        IOC.objects.exclude(general_honeypot__active=False)
        .exclude(ip_reputation__in=feed_params.exclude_reputation)
        .filter(**query_dict)
        .order_by(feed_params.ordering)
        .prefetch_related("general_honeypot")[: int(feed_params.feed_size)]
    )

    # save request source for statistics
    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip)
    request_source.save()

    logger.info(f"Number of iocs returned: {len(iocs)}")
    return iocs


def feeds_response(iocs, feed_params, valid_feed_types, dict_only=False, verbose=False):
    """
    Format the IOC data into the requested format (e.g., JSON, CSV, TXT).

    Args:
        request: The incoming request object.
        iocs (QuerySet): The filtered queryset of IOC data.
        feed_type (str): Type of feed (e.g., log4j, cowrie, etc.).
        valid_feed_types (frozenset): The set of all valid feed types.
        format_ (str): Desired format of the response (e.g., json, csv, txt).
        dict_only (bool): Return IOC dictionary instead of Response object.
        verbose (bool): Include IOC properties that may contain a lot of data.

    Returns:
        Response: The HTTP response containing formatted IOC data.
    """
    logger.info(f"Format feeds in: {feed_params.format}")
    license_text = (
        f"# These feeds are generated by The Honeynet Project" f" once every 10 minutes and are protected" f" by the following license: {FEEDS_LICENSE}"
    )

    if feed_params.format == "txt":
        text_lines = [license_text]
        for ioc in iocs:
            text_lines.append(ioc.name)
        text = "\n".join(text_lines)
        return HttpResponse(text, content_type="text/plain")
    if feed_params.format == "csv":
        rows = []
        rows.append([license_text])
        for ioc in iocs:
            rows.append([ioc.name])
        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer, quoting=csv.QUOTE_NONE)
        return StreamingHttpResponse(
            (writer.writerow(row) for row in rows),
            content_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="feeds.csv"'},
            status=200,
        )
    if feed_params.format == "json":
        # json
        json_list = []
        ioc_feed_type = ""
        for ioc in iocs:
            if feed_params.feed_type not in ["all", "log4j", "cowrie"]:
                ioc_feed_type = feed_params.feed_type
            else:
                if ioc.log4j:
                    ioc_feed_type = "log4j"
                elif ioc.cowrie:
                    ioc_feed_type = "cowrie"
                else:
                    # first() can not be used here because is does not work with prefetching
                    ioc_feed_type = str(ioc.general_honeypot.all()[0]).lower()
            data_ = {
                "value": ioc.name,
                SCANNER: ioc.scanner,
                PAYLOAD_REQUEST: ioc.payload_request,
                "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
                "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
                "attack_count": ioc.attack_count,
                "interaction_count": ioc.interaction_count,
                "feed_type": ioc_feed_type,
                "ip_reputation": ioc.ip_reputation,
                "asn": ioc.asn,
                "destination_port_count": len(ioc.destination_ports),
                "login_attempts": ioc.login_attempts,
            }
            if verbose:
                data_["days_seen"] = ioc.days_seen
                data_["destination_ports"] = ioc.destination_ports
                data_["honeypots"] = [str(pot) for pot in ioc.general_honeypot.all()]
                if ioc_feed_type in ["log4j", "cowrie"]:
                    data_["honeypots"].append(ioc_feed_type)

            if SKIP_FEED_VALIDATION or verbose:
                json_list.append(data_)
                continue
            serializer_item = FeedsResponseSerializer(
                data=data_,
                context={"valid_feed_types": valid_feed_types},
            )
            serializer_item.is_valid(raise_exception=True)
            json_list.append(serializer_item.data)

        # check if sorting the results by feed_type
        sorted_list = []
        if feed_params.ordering == "feed_type":
            sorted_list = sorted(json_list, key=lambda k: k["feed_type"])
        elif feed_params.ordering == "-feed_type":
            sorted_list = sorted(json_list, key=lambda k: k["feed_type"], reverse=True)

        if sorted_list:
            logger.info("Return feeds sorted by feed_type field")
            json_list = sorted_list

        logger.info(f"Number of feeds returned: {len(json_list)}")
        resp_data = {"license": FEEDS_LICENSE, "iocs": json_list}
        if dict_only:
            return resp_data
        else:
            return Response(resp_data, status=status.HTTP_200_OK)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def enrichment_view(request):
    """
    Handle enrichment requests for a specific observable (domain or IP address).

    Args:
        request: The incoming request object containing query parameters.

    Returns:
        Response: A JSON response indicating whether the observable was found,
        and if so, the corresponding IOC.
    """
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {str(observable_name)}")
    serializer = EnrichmentSerializer(data=request.query_params, context={"request": request})
    serializer.is_valid(raise_exception=True)

    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=viewType.ENRICHMENT_VIEW.value)
    request_source.save()

    return Response(serializer.data, status=status.HTTP_200_OK)


class StatisticsViewSet(viewsets.ViewSet):
    """
    A viewset for viewing and editing statistics related to feeds and enrichment data.

    Provides actions to retrieve statistics about the sources and downloads of feeds,
    as well as statistics on enrichment data.
    """

    @action(detail=True, methods=["GET"])
    def feeds(self, request, pk=None):
        """
        Retrieve feed statistics, including the number of sources and downloads.

        Args:
            request: The incoming request object.
            pk (str): The type of statistics to retrieve (e.g., "sources", "downloads").

        Returns:
            Response: A JSON response containing the requested statistics.
        """
        if pk == "sources":
            annotations = {
                "Sources": Count(
                    "source",
                    distinct=True,
                    filter=Q(view=viewType.FEEDS_VIEW.value),
                )
            }
        elif pk == "downloads":
            annotations = {"Downloads": Count("source", filter=Q(view=viewType.FEEDS_VIEW.value))}
        else:
            logger.error("this is impossible. check the code")
            return HttpResponseServerError()
        return self.__aggregation_response_static_statistics(annotations)

    @action(detail=True, methods=["get"])
    def enrichment(self, request, pk=None):
        """
        Retrieve enrichment statistics, including the number of sources and requests.

        Args:
            request: The incoming request object.
            pk (str): The type of statistics to retrieve (e.g., "sources", "requests").

        Returns:
            Response: A JSON response containing the requested statistics.
        """
        if pk == "sources":
            annotations = {
                "Sources": Count(
                    "source",
                    distinct=True,
                    filter=Q(view=viewType.ENRICHMENT_VIEW.value),
                )
            }
        elif pk == "requests":
            annotations = {"Requests": Count("source", filter=Q(view=viewType.ENRICHMENT_VIEW.value))}
        else:
            logger.error("this is impossible. check the code")
            return HttpResponseServerError()
        return self.__aggregation_response_static_statistics(annotations)

    @action(detail=False, methods=["get"])
    def feeds_types(self, request):
        """
        Retrieve statistics for different types of feeds, including Log4j, Cowrie,
        and general honeypots.

        Args:
            request: The incoming request object.

        Returns:
            Response: A JSON response containing the feed type statistics.
        """
        # FEEDS
        annotations = {
            "Log4j": Count("name", distinct=True, filter=Q(log4j=True)),
            "Cowrie": Count("name", distinct=True, filter=Q(cowrie=True)),
        }
        # feed_type for each general honeypot in the list
        generalHoneypots = GeneralHoneypot.objects.all().filter(active=True)
        for hp in generalHoneypots:
            annotations[hp.name] = Count("name", Q(general_honeypot__name__iexact=hp.name.lower()))
        return self.__aggregation_response_static_ioc(annotations)

    def __aggregation_response_static_statistics(self, annotations: dict) -> Response:
        """
        Helper method to generate statistics response based on annotations.

        Args:
            annotations (dict): Dictionary containing the annotations for the query.

        Returns:
            Response: A JSON response containing the aggregated statistics.
        """
        delta, basis = self.__parse_range(self.request)
        qs = Statistics.objects.filter(request_date__gte=delta).annotate(date=Trunc("request_date", basis)).values("date").annotate(**annotations)
        return Response(qs)

    def __aggregation_response_static_ioc(self, annotations: dict) -> Response:
        """
        Helper method to generate IOC response based on annotations.

        Args:
            annotations (dict): Dictionary containing the annotations for the query.

        Returns:
            Response: A JSON response containing the aggregated IOC data.
        """
        delta, basis = self.__parse_range(self.request)

        qs = (
            IOC.objects.filter(last_seen__gte=delta)
            .exclude(general_honeypot__active=False)
            .annotate(date=Trunc("last_seen", basis))
            .values("date")
            .annotate(**annotations)
        )
        return Response(qs)

    @staticmethod
    def __parse_range(request):
        """
        Parse the range parameter from the request query string to determine the time range for the query.

        Args:
            request: The incoming request object.

        Returns:
            tuple: A tuple containing the delta time and basis for the query range.
        """
        try:
            range_str = request.GET["range"]
        except KeyError:
            # default
            range_str = "7d"

        return parse_humanized_range(range_str)


@api_view([GET])
def general_honeypot_list(request):
    """
    Retrieve a list of all general honeypots, optionally filtering by active status.

    Args:
        request: The incoming request object containing query parameters.

    Returns:
        Response: A JSON response containing the list of general honeypots.
    """

    logger.info(f"Requested general honeypots list from {request.user}.")
    active = request.query_params.get("onlyActive")
    honeypots = []
    generalHoneypots = GeneralHoneypot.objects.all()
    if active == "true":
        generalHoneypots = generalHoneypots.filter(active=True)
        logger.info("Requested only active general honeypots")
    honeypots.extend([hp.name for hp in generalHoneypots])

    logger.info(f"General honeypots: {honeypots}")
    return Response(honeypots)
