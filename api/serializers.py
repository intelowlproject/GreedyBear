import logging
import re

from greedybear.consts import PAYLOAD_REQUEST, REGEX_DOMAIN, REGEX_IP, SCANNER
from greedybear.models import IOC, GeneralHoneypot
from rest_framework import serializers

logger = logging.getLogger(__name__)
general_honeypots = GeneralHoneypot.objects.all().filter(active=True)
valid_feed_types = set(["log4j", "cowrie", "all"] + [hp.name.lower() for hp in general_honeypots])


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


def serialize_ioc(ioc, feed_type: str) -> dict:
    return {
        "value": ioc.name,
        SCANNER: ioc.scanner,
        PAYLOAD_REQUEST: ioc.payload_request,
        "first_seen": ioc.first_seen.strftime("%Y-%m-%d"),
        "last_seen": ioc.last_seen.strftime("%Y-%m-%d"),
        "times_seen": ioc.times_seen,
        "feed_type": feed_type,
    }
