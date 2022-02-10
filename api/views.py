# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import logging
from datetime import datetime, timedelta

from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseServerError,
    JsonResponse,
    StreamingHttpResponse,
)
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.response import Response
from greedybear.consts import FEEDS_LICENSE, GET, PAYLOAD_REQUEST, SCANNER
from greedybear.models import IOC
from api.serializers import EnrichmentSerializer
from greedybear.consts import GET

logger = logging.getLogger(__name__)


class Echo:
    """An object that implements just the write method of the file-like
    interface.
    """

    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value


@require_http_methods([GET])
def feeds(request, feed_type, attack_type, age, format_):
    """

    :param request:
    :param feed_type:
    :param attack_type:
    :param age:
    :param format_:
    :return:
    """
    source = str(request.user)
    logger.info(
        f"request from {source}. Feed type: {feed_type}, attack_type: {attack_type},"
        f" Age: {age}, format: {format_}"
    )

    feed_choices = ["log4j", "cowrie", "all"]
    if feed_type not in feed_choices:
        return _formatted_bad_request(format_)

    attack_types = ["scanner", "payload_request", "all"]
    if attack_type not in attack_types:
        return _formatted_bad_request(format_)

    age_choices = ["persistent", "recent"]
    if age not in age_choices:
        return _formatted_bad_request(format_)

    formats = ["csv", "json", "txt"]
    if format_ not in formats:
        return _formatted_bad_request(format_)

    query_dict = {}

    if feed_type != "all":
        query_dict[feed_type] = True

    if attack_type != "all":
        query_dict[attack_type] = True

    if age == "recent":
        # everything in the last 3 days
        three_days_ago = datetime.utcnow() - timedelta(days=3)
        query_dict["last_seen__gte"] = three_days_ago
        iocs = IOC.objects.filter(**query_dict).order_by("-last_seen")[:5000]
    elif age == "persistent":
        # scanners detected in the last 14 days
        fourteen_days_ago = datetime.utcnow() - timedelta(days=14)
        query_dict["last_seen__gte"] = fourteen_days_ago
        # ... and at least detected 10 different days
        number_of_days_seen = 10
        query_dict["number_of_days_seen__gte"] = number_of_days_seen
        # order by the number of times seen
        iocs = IOC.objects.filter(**query_dict).order_by("-times_seen")[:1000]
    else:
        logger.error("this is impossible. check the code")
        return HttpResponseServerError()

    license_text = (
        f"# These feeds are generated by The Honeynet Project"
        f" once every 10 minutes and are protected"
        f" by the following license: {FEEDS_LICENSE}"
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
        for ioc in iocs:
            json_item = {
                "value": ioc.name,
                SCANNER: ioc.scanner,
                PAYLOAD_REQUEST: ioc.payload_request,
                "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
                "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
                "times_seen": ioc.times_seen,
            }
            json_list.append(json_item)
        return JsonResponse({"license": FEEDS_LICENSE, "iocs": json_list})
    else:
        logger.error("this is impossible. check the code")
        return HttpResponseServerError()


def _formatted_bad_request(format_):
    if format_ in ["csv", "txt"]:
        return HttpResponseBadRequest()
    else:
        # json
        return JsonResponse({}, status=400)


@api_view([GET])
def enrichment_view(request):
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {str(observable_name)}")
    serializer = EnrichmentSerializer(
        data=request.query_params, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    return Response(serializer.data, status=status.HTTP_200_OK)
