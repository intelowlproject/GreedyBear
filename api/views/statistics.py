# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.ext.helpers import parse_humanized_range
from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import HttpResponseServerError
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from greedybear.models import IOC, GeneralHoneypot, Statistics, ViewType

logger = logging.getLogger(__name__)


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
                    filter=Q(view=ViewType.FEEDS_VIEW.value),
                )
            }
        elif pk == "downloads":
            annotations = {"Downloads": Count("source", filter=Q(view=ViewType.FEEDS_VIEW.value))}
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
                    filter=Q(view=ViewType.ENRICHMENT_VIEW.value),
                )
            }
        elif pk == "requests":
            annotations = {"Requests": Count("source", filter=Q(view=ViewType.ENRICHMENT_VIEW.value))}
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
