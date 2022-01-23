from email.policy import default
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
    
    def validate(self, data):
        """
        Check the given observable against regex expression
        """
        observable = data['observable_name']
        if not re.match(REGEX_IP, observable) or not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError("Observable must be an IP or a domain")
        return data