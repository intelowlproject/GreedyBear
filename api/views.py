# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import logging
from datetime import datetime, timedelta

from api.serializers import EnrichmentSerializer, FeedsResponseSerializer, FeedsSerializer, IOCSerializer
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.helpers import parse_humanized_range
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import HttpResponse, HttpResponseServerError, StreamingHttpResponse
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from greedybear.consts import FEEDS_LICENSE, GET, PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC, GeneralHoneypot, Statistics, viewType
from rest_framework import serializers as rfs
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class Echo:
    """An object that implements just the write method of the file-like
    interface.
    """

    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value


# The Doc does not work as intended. We should refactor this by correctly leveraging DRF
@add_docs(description="Extract Structured IOC Feeds from GreedyBear")
@api_view([GET])
def feeds(request, feed_type, attack_type, age, format_):
    logger.info(f"request /api/feeds with params: feed type: {feed_type}, attack_type: {attack_type}, Age: {age}, format: {format_}")
    iocs_queryset = get_queryset(request, feed_type, attack_type, age, format_)
    resp_data = feeds_response(request, iocs_queryset, feed_type, format_)
    return Response(resp_data, status=status.HTTP_200_OK)


@api_view([GET])
def feeds_pagination(request):
    params = request.query_params
    logger.info(f"request /api/feeds with params: {params}")

    paginator = CustomPageNumberPagination()
    iocs_queryset = get_queryset(request, params["feed_type"], params["attack_type"], params["age"], "json")
    iocs = paginator.paginate_queryset(iocs_queryset, request)
    resp_data = feeds_response(request, iocs, params["feed_type"], "json")
    return paginator.get_paginated_response(resp_data)


def get_queryset(request, feed_type, attack_type, age, format_):
    source = str(request.user)
    logger.info(f"request from {source}. Feed type: {feed_type}, attack_type: {attack_type}, Age: {age}, format: {format_}")

    serializer = FeedsSerializer(data={"feed_type": feed_type, "attack_type": attack_type, "age": age, "format": format_})
    serializer.is_valid(raise_exception=True)

    ordering = request.query_params.get("ordering")
    # if ordering == "value" replace it with "name" (the corresponding field in the iocs model)
    if ordering == "value":
        ordering = "name"
    elif ordering == "-value":
        ordering = "-name"

    query_dict = {}

    if feed_type != "all":
        if feed_type == "log4j" or feed_type == "cowrie":
            query_dict[feed_type] = True
        else:
            # accept feed_type if it is in the general honeypots list
            query_dict["general_honeypot__name__iexact"] = feed_type

    if attack_type != "all":
        query_dict[attack_type] = True

    if age == "recent":
        # everything in the last 3 days
        three_days_ago = datetime.utcnow() - timedelta(days=3)
        query_dict["last_seen__gte"] = three_days_ago
        # if ordering == "feed_type" or None replace it with the default value "-last_seen"
        # ordering by "feed_type" is done in feed_response function
        if ordering is None or ordering == "feed_type" or ordering == "-feed_type":
            ordering = "-last_seen"
        iocs = IOC.objects.exclude(general_honeypot__active=False).filter(**query_dict).order_by(ordering)[:5000]
    elif age == "persistent":
        # scanners detected in the last 14 days
        fourteen_days_ago = datetime.utcnow() - timedelta(days=14)
        query_dict["last_seen__gte"] = fourteen_days_ago
        # ... and at least detected 10 different days
        number_of_days_seen = 10
        query_dict["number_of_days_seen__gte"] = number_of_days_seen
        # if ordering == "feed_type" or None replace it with the default value "-times_seen"
        # ordering by "feed_type" is done in feed_response function
        if ordering is None or ordering == "feed_type" or ordering == "-feed_type":
            ordering = "-times_seen"
        iocs = IOC.objects.exclude(general_honeypot__active=False).filter(**query_dict).order_by(ordering)[:5000]

    # save request source for statistics
    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip)
    request_source.save()

    logger.info(f"Number of iocs returned: {len(iocs)}")
    return iocs


def feeds_response(request, iocs, feed_type, format_):
    logger.info(f"Format feeds in: {format_}")
    license_text = (
        f"# These feeds are generated by The Honeynet Project" f" once every 10 minutes and are protected" f" by the following license: {FEEDS_LICENSE}"
    )

    if format_ == "txt":
        text_lines = [license_text]
        for ioc in iocs:
            text_lines.append(ioc.name)
        text = "\n".join(text_lines)
        return HttpResponse(text, content_type="text/plain")
    elif format_ == "csv":
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
    elif format_ == "json":
        # json
        json_list = []
        ioc_feed_type = ""
        for ioc in iocs:
            if feed_type not in ["all", "log4j", "cowrie"]:
                ioc_feed_type = feed_type
            else:
                if ioc.log4j:
                    ioc_feed_type = "log4j"
                elif ioc.cowrie:
                    ioc_feed_type = "cowrie"
                else:
                    ioc_feed_type = str(ioc.general_honeypot.first()).lower()

            data_ = {
                "value": ioc.name,
                SCANNER: ioc.scanner,
                PAYLOAD_REQUEST: ioc.payload_request,
                "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
                "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
                "times_seen": ioc.times_seen,
                "feed_type": ioc_feed_type,
            }

            serializer_item = FeedsResponseSerializer(data=data_)
            serializer_item.is_valid(raise_exception=True)
            json_list.append(serializer_item.data)

    # check if sorting the results by feed_type
    ordering = request.query_params.get("ordering")
    sorted_list = []
    if ordering == "feed_type":
        sorted_list = sorted(json_list, key=lambda k: k["feed_type"])
    elif ordering == "-feed_type":
        sorted_list = sorted(json_list, key=lambda k: k["feed_type"], reverse=True)

    if sorted_list:
        logger.info("Return feeds sorted by feed_type field")
        json_list = sorted_list

    logger.info(f"Number of feeds returned: {len(json_list)}")
    return {"license": FEEDS_LICENSE, "iocs": json_list}


# The Doc does not work as intended. We should refactor this by correctly leveraging DRF
@add_docs(
    description="Request if a specific observable (domain or IP address) has been listed by GreedyBear",
    request=inline_serializer(
        name="EnrichmentSerializerRequest",
        fields={"query": rfs.CharField()},
    ),
    responses={
        200: inline_serializer(
            name="EnrichmentSerializerResponse",
            fields={"found": rfs.BooleanField(), "ioc": IOCSerializer},
        ),
    },
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def enrichment_view(request):
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {str(observable_name)}")
    serializer = EnrichmentSerializer(data=request.query_params, context={"request": request})
    serializer.is_valid(raise_exception=True)

    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=viewType.ENRICHMENT_VIEW.value)
    request_source.save()

    return Response(serializer.data, status=status.HTTP_200_OK)


class StatisticsViewSet(viewsets.ViewSet):
    @action(detail=True, methods=["GET"])
    def feeds(self, request, pk=None):
        if pk == "sources":
            annotations = {"Sources": Count("source", distinct=True, filter=Q(view=viewType.FEEDS_VIEW.value))}
        elif pk == "downloads":
            annotations = {"Downloads": Count("source", filter=Q(view=viewType.FEEDS_VIEW.value))}
        else:
            logger.error("this is impossible. check the code")
            return HttpResponseServerError()
        return self.__aggregation_response_static_statistics(annotations)

    @action(detail=True, methods=["get"])
    def enrichment(self, request, pk=None):
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
        delta, basis = self.__parse_range(self.request)
        qs = Statistics.objects.filter(request_date__gte=delta).annotate(date=Trunc("request_date", basis)).values("date").annotate(**annotations)
        return Response(qs)

    def __aggregation_response_static_ioc(self, annotations: dict) -> Response:
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
        try:
            range_str = request.GET["range"]
        except KeyError:
            # default
            range_str = "7d"

        return parse_humanized_range(range_str)


@api_view([GET])
def general_honeypot_list(request):
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
