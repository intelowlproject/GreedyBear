# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib import admin

from greedybear.models import IOC

# there is no need to view the sensors in the admin page.
# @admin.register(Sensors)
# class SensorsModelAdmin(admin.ModelAdmin):
#     list_display = [field.name for field in Sensors._meta.get_fields()]


@admin.register(IOC)
class IOCModelAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "type",
        "first_seen",
        "last_seen",
        "days_seen",
        "number_of_days_seen",
        "times_seen",
        "related_urls",
        "scanner",
        "payload_request",
    ]
