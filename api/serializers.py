from asyncore import write
from email.policy import default
from http.client import FOUND
import re
from rest_framework import serializers
from greedybear.models import IOC
from greedybear.consts import REGEX_IP, REGEX_DOMAIN

class IOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOC
        fields = (
            'name', 
            'type', 
            'first_seen', 
            'last_seen', 
            'days_seen',
            'number_of_days_seen',
            'times_seen', 
            'log4j', 
            'cowrie', 
            'scanner', 
            'payload_request', 
            'related_ioc',
        )

class EnrichmentSerializer(IOCSerializer):
    query = serializers.CharField(max_length=255, write_only=True)
    found = serializers.BooleanField(read_only=True, default=False)
    ico = IOCSerializer(read_only=True, default=None)

    def validate(self, data):
        """
        Check the given observable against regex expression
        """
        observable = data['observable_name']
        if not re.match(REGEX_IP, observable) or not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError("Observable is not a valid IP or domain")
        try:
            required_object = IOC.objects.get(name=observable)
        except IOC.DoesNotExist:
            raise serializers.ValidationError("Observable does not exist in the database")
        return required_object