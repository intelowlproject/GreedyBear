# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import logging
import re
from datetime import datetime, timedelta
from ipaddress import ip_address

from api.enums import Honeypots
from api.serializers import FeedsRequestSerializer, FeedsResponseSerializer
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import F, Q
from django.http import HttpResponse, HttpResponseBadRequest, StreamingHttpResponse
from greedybear.consts import FEEDS_LICENSE
from greedybear.models import IOC, GeneralHoneypot, Statistics
from greedybear.settings import EXTRACTION_INTERVAL
from rest_framework import status
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
        format_ (str): Response format type (default: "json")
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
        self.feed_type_sorting = None
        self.exclude_reputation.append("mass scanner")

    def include_mass_scanners(self):
        self.exclude_reputation.remove("mass scanner")

    def set_prioritization(self, prioritize: str):
        match prioritize:
            case "recent":
                self.max_age = "3"
                self.min_days_seen = "1"
                if "feed_type" in self.ordering:
                    self.feed_type_sorting = self.ordering
                    self.ordering = "-last_seen"
            case "persistent":
                self.max_age = "14"
                self.min_days_seen: "10"
                if "feed_type" in self.ordering:
                    self.feed_type_sorting = self.ordering
                    self.ordering = "-attack_count"
            case "likely_to_recur":
                self.max_age = "30"
                self.min_days_seen = "1"
                self.ordering = "-recurrence_probability"
            case "most_expected_hits":
                self.max_age = "30"
                self.min_days_seen = "1"
                self.ordering = "-expected_interactions"


def get_valid_feed_types() -> frozenset[str]:
    """
    Retrieve all valid feed types, combining predefined types with active general honeypot names.

    Returns:
        frozenset[str]: An immutable set of valid feed type strings
    """
    general_honeypots = GeneralHoneypot.objects.all().filter(active=True)
    return frozenset([Honeypots.LOG4J.value, Honeypots.COWRIE.value, "all"] + [hp.name.lower() for hp in general_honeypots])


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
        if feed_params.feed_type in (Honeypots.LOG4J.value, Honeypots.COWRIE.value):
            query_dict[feed_params.feed_type] = True
        else:
            # accept feed_type if it is in the general honeypots list
            query_dict["general_honeypot__name__iexact"] = feed_params.feed_type

    if feed_params.attack_type != "all":
        query_dict[feed_params.attack_type] = True

    query_dict["last_seen__gte"] = datetime.now() - timedelta(days=int(feed_params.max_age))
    if int(feed_params.min_days_seen) > 1:
        query_dict["number_of_days_seen__gte"] = int(feed_params.min_days_seen)
    if feed_params.include_reputation:
        query_dict["ip_reputation__in"] = feed_params.include_reputation
        for reputation_type in feed_params.include_reputation:
            if reputation_type in feed_params.exclude_reputation:
                feed_params.exclude_reputation.remove(reputation_type)

    iocs = (
        IOC.objects.filter(**query_dict)
        .filter(Q(cowrie=True) | Q(log4j=True) | Q(general_honeypot__active=True))
        .exclude(Q() if "nothing" in feed_params.exclude_reputation else Q(ip_reputation__in=feed_params.exclude_reputation))
        .annotate(value=F("name"))
        .annotate(honeypots=ArrayAgg("general_honeypot__name"))
        .order_by(feed_params.ordering)[: int(feed_params.feed_size)]
    )

    # save request source for statistics
    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip)
    request_source.save()
    return iocs


def ioc_as_dict(ioc, fields: set) -> dict:
    """
    Convert an IOC object to a dictionary containing only the specified fields.

    Args:
        ioc: An IOC object
        fields (set): A set of field names to include in the output dictionary

    Returns:
        dict: A dictionary containing all fields from the IOC object where the field name exists in fields
    """
    return {k: v for k, v in ioc.__dict__.items() if k in fields}


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
        f"# These feeds are generated by The Honeynet Project once every {EXTRACTION_INTERVAL} minutes "
        f"and are protected by the following license: {FEEDS_LICENSE}"
    )
    match feed_params.format:
        case "txt":
            text_lines = [license_text] + [ioc[0] for ioc in iocs.values_list("name")]
            return HttpResponse("\n".join(text_lines), content_type="text/plain")
        case "csv":
            rows = [[license_text]] + [list(ioc) for ioc in iocs.values_list("name")]
            pseudo_buffer = Echo()
            writer = csv.writer(pseudo_buffer, quoting=csv.QUOTE_NONE)
            return StreamingHttpResponse(
                (writer.writerow(row) for row in rows),
                content_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="feeds.csv"'},
                status=200,
            )
        case "json":
            json_list = []
            required_fields = {
                "value",
                "first_seen",
                "last_seen",
                "attack_count",
                "interaction_count",
                "log4j",
                "cowrie",
                "scanner",
                "payload_request",
                "ip_reputation",
                "asn",
                "destination_ports",
                "login_attempts",
                "honeypots",
                "days_seen",
                "recurrence_probability",
                "expected_interactions",
            }
            iocs = (ioc_as_dict(ioc, required_fields) for ioc in iocs) if isinstance(iocs, list) else iocs.values(*required_fields)
            for ioc in iocs:
                ioc_feed_type = []
                if ioc[Honeypots.LOG4J.value]:
                    ioc_feed_type.append(Honeypots.LOG4J.value)
                if ioc[Honeypots.COWRIE.value]:
                    ioc_feed_type.append(Honeypots.COWRIE.value)
                if len(ioc["honeypots"]):
                    ioc_feed_type.extend([hp.lower() for hp in ioc["honeypots"] if hp is not None])

                data_ = ioc | {
                    "first_seen": ioc["first_seen"].strftime("%Y-%m-%d"),
                    "last_seen": ioc["last_seen"].strftime("%Y-%m-%d"),
                    "feed_type": ioc_feed_type,
                    "destination_port_count": len(ioc["destination_ports"]),
                }

                if verbose:
                    json_list.append(data_)
                    continue

                serializer_item = FeedsResponseSerializer(
                    data=data_,
                    context={"valid_feed_types": valid_feed_types},
                )
                serializer_item.is_valid(raise_exception=True)
                json_list.append(serializer_item.data)

            # check if sorting the results by feed_type
            if feed_params.feed_type_sorting is not None:
                logger.info("Return feeds sorted by feed_type field")
                json_list = sorted(json_list, key=lambda k: k["feed_type"], reverse=feed_params.feed_type_sorting == "-feed_type")

            logger.info(f"Number of feeds returned: {len(json_list)}")
            resp_data = {"license": FEEDS_LICENSE, "iocs": json_list}
            if dict_only:
                return resp_data
            else:
                return Response(resp_data, status=status.HTTP_200_OK)
        case _:
            return HttpResponseBadRequest()


def is_ip_address(string: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).

    Uses the ipaddress module to perform validation. This function properly
    handles both IPv4 addresses and IPv6 addresses.

    Args:
        string: The string to validate as an IP address

    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    try:
        ip_address(string)
    except ValueError:
        return False
    return True


def is_sha256hash(string: str) -> bool:
    """
    Validate if a string is a valid SHA-256 hash.

    A SHA-256 hash is a string of exactly 64 hexadecimal characters
    (0-9, a-f, A-F). This function checks if the input string matches
    this pattern using a regular expression.

    Args:
        string: The string to validate as a SHA-256 hash

    Returns:
        bool: True if the string is a valid SHA-256 hash, False otherwise
    """
    return bool(re.fullmatch(r"^[A-Fa-f0-9]{64}$", string))
