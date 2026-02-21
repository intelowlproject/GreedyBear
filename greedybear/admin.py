# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.contrib import admin, messages
from django.db.models import Q
from django.utils.translation import ngettext

from greedybear.models import (
    IOC,
    AutonomousSystem,
    CommandSequence,
    CowrieSession,
    FireHolList,
    GeneralHoneypot,
    MassScanner,
    Sensor,
    Statistics,
    TorExitNode,
    WhatsMyIPDomain,
)

logger = logging.getLogger(__name__)


@admin.register(TorExitNode)
class TorExitNodeModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "reason"]
    search_fields = ["ip_address"]
    search_help_text = ["search for the IP address"]


@admin.register(Sensor)
class SensorsModelAdmin(admin.ModelAdmin):
    list_display = ["id", "address"]
    search_fields = ["address"]
    search_help_text = ["search for the sensor IP address"]


@admin.register(Statistics)
class StatisticsModelAdmin(admin.ModelAdmin):
    list_display = ["source", "view", "request_date"]
    list_filter = ["source"]
    search_fields = ["source"]
    search_help_text = ["search for the IP address source"]


@admin.register(WhatsMyIPDomain)
class WhatsMyIPModelAdmin(admin.ModelAdmin):
    list_display = ["domain", "added"]
    search_fields = ["domain"]
    search_help_text = ["search for the domain"]


@admin.register(MassScanner)
class MassScannersModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "reason"]
    list_filter = ["reason"]
    search_fields = ["ip_address"]
    search_help_text = ["search for the IP address source"]


@admin.register(FireHolList)
class FireHolListModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "source"]
    list_filter = ["source"]
    search_fields = ["ip_address"]
    search_help_text = ["search for the IP address"]


class SessionInline(admin.TabularInline):
    model = CowrieSession
    fields = [
        "source",
        "start_time",
        "duration",
        "credentials",
        "interaction_count",
        "commands",
    ]
    readonly_fields = fields
    show_change_link = True
    extra = 0
    ordering = ["-start_time"]


@admin.register(CowrieSession)
class CowrieSessionModelAdmin(admin.ModelAdmin):
    list_display = [
        "session_id",
        "start_time",
        "duration",
        "login_attempt",
        "credentials",
        "command_execution",
        "interaction_count",
        "source",
    ]
    search_fields = ["source__name"]
    search_help_text = ["search for the IP address source"]
    raw_id_fields = ["source", "commands"]
    list_filter = ["login_attempt", "command_execution"]


@admin.register(CommandSequence)
class CommandSequenceModelAdmin(admin.ModelAdmin):
    list_display = ["first_seen", "last_seen", "cluster", "commands", "commands_hash"]
    inlines = [SessionInline]
    search_fields = ["source__name", "commands_hash"]
    list_filter = ["cluster", "commands_hash"]


@admin.register(IOC)
class IOCModelAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "type",
        "first_seen",
        "last_seen",
        "days_seen",
        "number_of_days_seen",
        "attack_count",
        "interaction_count",
        "related_urls",
        "scanner",
        "payload_request",
        "general_honeypots",
        "sensor_list",
        "ip_reputation",
        "firehol_categories",
        "autonomous_system_asn",
        "destination_ports",
        "login_attempts",
    ]
    list_filter = [
        "type",
        "scanner",
        "payload_request",
        "ip_reputation",
        "autonomous_system__asn",
    ]
    search_fields = ["name", "related_ioc__name"]
    search_help_text = ["search for the IP address source"]
    raw_id_fields = ["related_ioc"]
    filter_horizontal = ["general_honeypot", "sensors"]
    inlines = [SessionInline]

    def autonomous_system_asn(self, ioc):
        return ioc.autonomous_system.asn if ioc.autonomous_system else None

    autonomous_system_asn.short_description = "ASN"

    def general_honeypots(self, ioc):
        return ", ".join([str(element) for element in ioc.general_honeypot.all()])

    def sensor_list(self, ioc):
        return ", ".join([str(sensor.address) for sensor in ioc.sensors.all()])

    def get_queryset(self, request):
        """Override to prefetch related sensors and honeypots, avoiding N+1 queries."""
        return (
            super()
            .get_queryset(request)
            .prefetch_related("sensors", "general_honeypot", "autonomous_system")
        )


@admin.register(GeneralHoneypot)
class GeneralHoneypotAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "active",
    ]
    actions = ["disable_honeypot", "enable_honeypot"]

    @admin.action(description="Disable selected honeypot")
    def disable_honeypot(self, request, queryset):
        disableable = Q(active=True)
        honeypots = queryset.filter(disableable).all()
        number_updated = honeypots.update(active=False)
        self.message_user(
            request,
            ngettext(
                "%d honeypot was successfully disabled.",
                "%d honeypots were successfully disabled.",
                number_updated,
            )
            % number_updated,
            messages.SUCCESS,
        )

    @admin.action(description="Enable selected honeypot")
    def enable_honeypot(self, request, queryset):
        enableable = Q(active=False)
        honeypots = queryset.filter(enableable).all()
        number_updated = honeypots.update(active=True)
        self.message_user(
            request,
            ngettext(
                "%d honeypot was successfully enabled.",
                "%d honeypots were successfully enabled.",
                number_updated,
            )
            % number_updated,
            messages.SUCCESS,
        )
