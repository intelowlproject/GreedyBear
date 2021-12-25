from django.contrib import admin

from greedybear.models import IOC, Sensors


@admin.register(Sensors)
class SensorsModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Sensors._meta.get_fields()]


@admin.register(IOC)
class IOCModelAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "type",
        "first_seen",
        "last_seen",
        "times_seen",
        "honeypots",
        "attack_types",
        "related_urls",
    ]
