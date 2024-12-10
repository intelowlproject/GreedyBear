import logging
import re
from functools import cache

from greedybear.consts import PAYLOAD_REQUEST, REGEX_DOMAIN, REGEX_IP, SCANNER
from greedybear.models import IOC, GeneralHoneypot
from rest_framework import serializers

logger = logging.getLogger(__name__)
VALID_FEED_TYPES = set()
VALID_ATTACK_TYPES = {"scanner", "payload_request", "all"}
VALID_AGES = {"persistent", "recent"}
VALID_FORMATS = {"csv", "json", "txt"}


class GeneralHoneypotSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeneralHoneypot

    def to_representation(self, value):
        return value.name


class IOCSerializer(serializers.ModelSerializer):
    general_honeypot = GeneralHoneypotSerializer(many=True, read_only=True)

    class Meta:
        model = IOC
        exclude = [
            "related_urls",
        ]


class EnrichmentSerializer(serializers.Serializer):
    found = serializers.BooleanField(read_only=True, default=False)
    ioc = IOCSerializer(read_only=True, default=None)
    query = serializers.CharField(max_length=250)

    def validate(self, data):
        """
        Check a given observable against regex expression
        """
        observable = data["query"]
        if not re.match(REGEX_IP, observable) or not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError("Observable is not a valid IP or domain")
        try:
            required_object = IOC.objects.get(name=observable)
            data["found"] = True
            data["ioc"] = required_object
        except IOC.DoesNotExist:
            data["found"] = False
        return data


@cache
def feed_type_validation(feed_type: str) -> bool:
    if not VALID_FEED_TYPES:
        general_honeypots = GeneralHoneypot.objects.all().filter(active=True)
        VALID_FEED_TYPES.update(["log4j", "cowrie", "all"] + [hp.name.lower() for hp in general_honeypots])
    return feed_type in VALID_FEED_TYPES


def feed_request_validation(data: dict) -> bool:
    if not feed_type_validation(data["feed_type"]):
        raise serializers.ValidationError(f"Invalid feed_type: {data['feed_type']}")
    if data["attack_type"] not in VALID_ATTACK_TYPES:
        raise serializers.ValidationError(f"Invalid attack_type: {data['attack_type']}")
    if data["age"] not in VALID_AGES:
        raise serializers.ValidationError(f"Invalid age: {data['age']}")
    if data["format"] not in VALID_FORMATS:
        raise serializers.ValidationError(f"Invalid format: {data['format']}")
    return True


def ioc_validation(data: dict) -> bool:
    if not feed_type_validation(data["feed_type"]):
        raise serializers.ValidationError(f"Invalid feed_type: {data['feed_type']}")
    if data["times_seen"] < 1:
        raise serializers.ValidationError(f"Invalid value for 'times_seen'': {data['times_seen']}")
    if not (data[SCANNER] or data[PAYLOAD_REQUEST]):
        raise serializers.ValidationError(f"Invalid data: IOC is neither {SCANNER} nor {PAYLOAD_REQUEST}")
    return True


def serialize_ioc(ioc, feed_type: str) -> dict:
    data = {
        "value": ioc.name,
        SCANNER: ioc.scanner,
        PAYLOAD_REQUEST: ioc.payload_request,
        "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
        "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
        "times_seen": ioc.times_seen,
        "feed_type": feed_type,
    }
    if not ioc_validation(data):
        raise serializers.ValidationError(f"Unknown error while validating {data}")
    return data
