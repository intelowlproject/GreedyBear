import logging
import re
from functools import cache

from greedybear.consts import REGEX_DOMAIN, REGEX_IP
from greedybear.models import IOC, GeneralHoneypot
from rest_framework import serializers

logger = logging.getLogger(__name__)


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
def feed_type_validation(feed_type: str, valid_feed_types: frozenset) -> str:
    if feed_type not in valid_feed_types:
        logger.info(f"Feed type {feed_type} not in feed_choices {valid_feed_types}")
        raise serializers.ValidationError(f"Invalid feed_type: {feed_type}")
    return feed_type


class FeedsSerializer(serializers.Serializer):
    feed_type = serializers.CharField(max_length=120)
    attack_type = serializers.ChoiceField(choices=["scanner", "payload_request", "all"])
    age = serializers.ChoiceField(choices=["persistent", "recent"])
    format = serializers.ChoiceField(choices=["csv", "json", "txt"], default="json")

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsSerializer - Validation feed_type: '{feed_type}'")
        return feed_type_validation(feed_type, self.context["valid_feed_types"])


class FeedsResponseSerializer(serializers.Serializer):
    feed_type = serializers.CharField(max_length=120)
    value = serializers.CharField(max_length=120)
    scanner = serializers.BooleanField()
    payload_request = serializers.BooleanField()
    first_seen = serializers.DateField(format="%Y-%m-%d")
    last_seen = serializers.DateField(format="%Y-%m-%d")
    times_seen = serializers.IntegerField()

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsResponseSerializer - validation feed_type: '{feed_type}'")
        return feed_type_validation(feed_type, self.context["valid_feed_types"])
