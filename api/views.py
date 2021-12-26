import csv
import logging
from datetime import datetime, timedelta

from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseServerError,
    StreamingHttpResponse,
)
from django.views.decorators.http import require_http_methods

from greedybear.consts import GET
from greedybear.models import IOC

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

    feed_choices = "log4j"
    if feed_type not in feed_choices:
        return HttpResponseBadRequest()

    attack_types = ["scanner", "payload_request", "all"]
    if attack_type not in attack_types:
        return HttpResponseBadRequest()

    age_choices = ["persistent", "recent"]
    if age not in age_choices:
        return HttpResponseBadRequest()

    formats = ["csv", "json"]
    if format_ not in formats:
        return HttpResponseBadRequest()

    query_dict = {}

    if attack_type != "all":
        query_dict["attack_types__contains"] = attack_type

    if age == "recent":
        # everything in the last 3 days
        three_days_ago = datetime.utcnow() - timedelta(days=3)
        query_dict["last_seen__gte"] = three_days_ago
        iocs = IOC.objects.filter(**query_dict).order_by("-last_seen")[:1000]
    elif age == "persistent":
        # scanners detected in the last 14 days
        fourteen_days_ago = datetime.utcnow() - timedelta(days=14)
        query_dict["last_seen__gte"] = fourteen_days_ago
        # ... and at least detected 10 different days
        number_of_days_seen = 10
        query_dict["number_of_days_seen__gte"] = number_of_days_seen
        # order by the number of times seen
        iocs = IOC.objects.filter(**query_dict).order_by("-times_seen")[:100]
    else:
        logger.error("this is impossible. check the code")
        return HttpResponseServerError()

    if format_ == "csv":
        rows = []
        for ioc in iocs:
            rows.append([ioc.name])
        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer, quoting=csv.QUOTE_NONE)
        return StreamingHttpResponse((writer.writerow(row) for row in rows), status=200)

    else:
        # json
        json_list = []
        for ioc in iocs:
            json_item = {
                "value": ioc.name,
                "attack_types": ioc.attack_types,
                "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
                "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
                "times_seen": ioc.times_seen,
            }
            json_list.append(json_item)
        return HttpResponse(json_list)
