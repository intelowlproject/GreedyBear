from rest_framework import serializers
from greedybear.models import IOC

class IOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOC
        fields = ('name', 'type', 'first_seen', 'last_seen', 'days_seen', 'number_of_days_seen', 'times_seen', 'log4j', 'cowrie', 'scanner', 'payload_request', 'related_ioc')