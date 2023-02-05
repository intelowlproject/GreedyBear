import re

from rest_framework import serializers

from greedybear.consts import GENERAL_HONEYPOTS, REGEX_DOMAIN, REGEX_IP
from greedybear.models import IOC


class IOCSerializer(serializers.ModelSerializer):
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


class FeedSerializer(serializers.Serializer):
    feed_type = serializers.CharField(max_length=20, write_only=True)
    attack_type = serializers.CharField(max_length=20, write_only=True)
    age = serializers.CharField(max_length=10, write_only=True)
    format_ = serializers.CharField(max_length=5, write_only=True)
    value = serializers.CharField(read_only=True, source="name")
    scanner = serializers.BooleanField(read_only=True)
    payload_request = serializers.BooleanField(read_only=True)
    first_seen = serializers.DateTimeField(read_only=True)
    last_seen = serializers.DateTimeField(read_only=True)
    times_seen = serializers.IntegerField(read_only=True)

    def validate(self, data):
        """
        Check a given value against a list of valid values
        """
        # data is a dictionary
        feed_type = data["feed_type"]
        attack_type = data["attack_type"]
        age = data["age"]
        format_ = data["format_"]

        # valid values
        feed_choices = ["log4j", "cowrie", "all"] + [
            x.lower() for x in GENERAL_HONEYPOTS
        ]
        attack_types = ["scanner", "payload_request", "all"]
        age_choices = ["persistent", "recent"]
        formats = ["csv", "json", "txt"]

        if feed_type not in feed_choices:
            raise serializers.ValidationError("Feed type is not valid")
        if attack_type not in attack_types:
            raise serializers.ValidationError("Attack type is not valid")
        if age not in age_choices:
            raise serializers.ValidationError("Age is not valid")
        if format_ not in formats:
            raise serializers.ValidationError("Format is not valid")
        return data

    def to_representation(self, instance):
        """
        Convert the model instance into a dictionary
        """
        if self.context["format_"] in ["csv", "txt"]:
            return instance.name
        instance.first_seen = instance.first_seen.strftime("%Y-%m-%d")
        instance.last_seen = instance.last_seen.strftime("%Y-%m-%d")
        return super().to_representation(instance)
