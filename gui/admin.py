from django.contrib import admin

from greedybear.models import IOC, Sensors


@admin.register(Sensors)
class SensorsModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Sensors._meta.get_fields()]


@admin.register(IOC)
class IOCModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in IOC._meta.get_fields()]
