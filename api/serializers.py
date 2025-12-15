import logging
import re
from functools import cache

from django.core.exceptions import FieldDoesNotExist
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
        if re.match(r"^[\d\.]+$", observable) and not re.match(REGEX_IP, observable):
            raise serializers.ValidationError("Observable is not a valid IP")
        if not re.match(REGEX_IP, observable) and not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError("Observable is not a valid IP or domain")
        try:
            required_object = IOC.objects.get(name=observable)
            data["found"] = True
            data["ioc"] = required_object
        except IOC.DoesNotExist:
            data["found"] = False
        return data


def feed_type_validation(feed_type: str, valid_feed_types: frozenset) -> str:
    """Validates that a given feed type exists in the set of valid feed types.

    Args:
        feed_type (str): The feed type to validate
        valid_feed_types (frozenset): Set of allowed feed type values

    Returns:
        str: The validated feed type string, unchanged

    Raises:
        serializers.ValidationError: If feed_type is not found in valid_feed_types
    """
    if feed_type not in valid_feed_types:
        logger.info(f"Feed type {feed_type} not in feed_choices {valid_feed_types}")
        raise serializers.ValidationError(f"Invalid feed_type: {feed_type}")
    return feed_type


@cache
def ordering_validation(ordering: str) -> str:
    """Validates that given ordering corresponds to a field in the IOC model.

    Args:
        ordering (str): The ordering to validate

    Returns:
        str: The validated ordering string, unchanged

    Raises:
        serializers.ValidationError: If ordering does not correspond to a field in the IOC model
    """
    if not ordering:
        raise serializers.ValidationError("Invalid ordering: <empty string>")
    # remove minus sign if present
    field_name = ordering[1:] if ordering.startswith("-") else ordering
    try:
        IOC._meta.get_field(field_name)
    except FieldDoesNotExist as exc:
        raise serializers.ValidationError(f"Invalid ordering: {ordering}") from exc
    return ordering


class FeedsRequestSerializer(serializers.Serializer):
    feed_type = serializers.CharField(max_length=120)
    attack_type = serializers.ChoiceField(choices=["scanner", "payload_request", "all"])
    ioc_type = serializers.ChoiceField(choices=["ip", "domain", "all"])
    max_age = serializers.IntegerField(min_value=1)
    min_days_seen = serializers.IntegerField(min_value=1)
    include_reputation = serializers.ListField(child=serializers.CharField(max_length=120))
    exclude_reputation = serializers.ListField(child=serializers.CharField(max_length=120))
    feed_size = serializers.IntegerField(min_value=1)
    ordering = serializers.CharField(max_length=120)
    verbose = serializers.ChoiceField(choices=["true", "false"])
    paginate = serializers.ChoiceField(choices=["true", "false"])
    format = serializers.ChoiceField(choices=["csv", "json", "txt"])

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsRequestSerializer - validation feed_type: '{feed_type}'")
        return feed_type_validation(feed_type, self.context["valid_feed_types"])

    def validate_ordering(self, ordering):
        logger.debug(f"FeedsRequestSerializer - validation ordering: '{ordering}'")
        return ordering_validation(ordering)


class FeedsResponseSerializer(serializers.Serializer):
    feed_type = serializers.ListField(child=serializers.CharField(max_length=120))
    value = serializers.CharField(max_length=256)
    scanner = serializers.BooleanField()
    payload_request = serializers.BooleanField()
    first_seen = serializers.DateField(format="%Y-%m-%d")
    last_seen = serializers.DateField(format="%Y-%m-%d")
    attack_count = serializers.IntegerField(min_value=1)
    interaction_count = serializers.IntegerField(min_value=1)
    ip_reputation = serializers.CharField(allow_blank=True, max_length=32)
    asn = serializers.IntegerField(allow_null=True, min_value=1)
    destination_port_count = serializers.IntegerField(min_value=0)
    login_attempts = serializers.IntegerField(min_value=0)
    recurrence_probability = serializers.FloatField(min_value=0, max_value=1)
    expected_interactions = serializers.FloatField(min_value=0)

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsResponseSerializer - validation feed_type: '{feed_type}'")
        return [feed_type_validation(feed, self.context["valid_feed_types"]) for feed in feed_type]
