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

class EnrichmentSerializer(serializers.Serializer):
    found = serializers.BooleanField(read_only=True, default=False)
    ioc = IOCSerializer(read_only=True, default=None)
    class Meta:
       fields = serializers.ALL_FIELDS

    def validate(self, data):
        """
        Check the given observable against regex expression
        """
        observable = data
        print(f"OBservable: {(observable)}")
        if not re.match(REGEX_IP, observable) or not re.match(REGEX_DOMAIN, observable):
            raise serializers.ValidationError("Observable is not a valid IP or domain")
        try:
            required_object = IOC.objects.get(name=observable)
            data["found"] = True
            data["ioc"] = required_object
        except IOC.DoesNotExist:
            data["found"] = False
        return required_object