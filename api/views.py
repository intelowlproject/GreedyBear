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
def feeds(request, age, attack_type, format_):
    """

    :param request:
    :param age:
    :param attack_type:
    :param format_:
    :return:
    """
    source = str(request.user)
    logger.info(
        f"request from {source}. Age: {age}, attack_type: {attack_type}, format: {format_}"
    )

    age_choices = ["persistent", "recent"]
    if age not in age_choices:
        return HttpResponseBadRequest()

    attack_types = ["scanner", "payload_request", "all"]
    if attack_type not in attack_types:
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
        iocs = IOC.object.filter(query_dict).order_by("-last_seen")[:1000]
    elif age == "persistent":
        # scanners detected in the last 14 days
        fourteen_days_ago = datetime.utcnow() - timedelta(days=14)
        query_dict["last_seen__gte"] = fourteen_days_ago
        # order by the number of times seen
        iocs = IOC.object.filter(query_dict).order_by("-times_seen")[:1000]
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
                "first_seen": ioc.first_seen,
                "last_seen": ioc.last_seen,
                "times_seen": ioc.times_seen,
            }
            json_list.append(json_item)
        return HttpResponse(json_list)
