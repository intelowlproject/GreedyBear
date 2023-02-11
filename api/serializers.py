import re

from rest_framework import serializers

from greedybear.consts import REGEX_DOMAIN, REGEX_IP
from greedybear.models import IOC, GeneralHoneypot


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
    generalHoneypots = GeneralHoneypot.objects.all()
    feed_choices = ["log4j", "cowrie", "all"] + [hp.name.lower() for hp in generalHoneypots]
    attack_choices = ["scanner", "payload_request", "all"]
    age_choices = ["persistent", "recent"]
    format_choices = ["json", "csv", "txt"]

    feed_type = serializers.ChoiceField(write_only=True, choices=feed_choices)
    attack_type = serializers.ChoiceField(write_only=True, choices=attack_choices)
    age = serializers.ChoiceField(write_only=True, choices=age_choices)
    format_ = serializers.ChoiceField(write_only=True, choices=format_choices)
    value = serializers.CharField(read_only=True, source="name")
    scanner = serializers.BooleanField(read_only=True)
    payload_request = serializers.BooleanField(read_only=True)
    first_seen = serializers.DateTimeField(read_only=True)
    last_seen = serializers.DateTimeField(read_only=True)
    times_seen = serializers.IntegerField(read_only=True)

    def to_representation(self, instance):
        """
        Convert the model instance into a dictionary
        """
        if self.context["format_"] in ["csv", "txt"]:
            return instance.name
        instance.first_seen = instance.first_seen.strftime("%Y-%m-%d")
        instance.last_seen = instance.last_seen.strftime("%Y-%m-%d")
        return super().to_representation(instance)
