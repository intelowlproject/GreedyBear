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
    
    def regex_validate(self, data):
        observable = data['observable_name']
        if not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError('Invalid Observable')
        if not re.match(REGEX_IP, observable):
             raise serializers.ValidationError('Invalid Observable')
        return observable
