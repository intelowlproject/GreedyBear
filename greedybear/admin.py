# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.contrib import admin, messages
from django.db.models import Q
from django.utils.translation import ngettext
from greedybear.models import IOC, CommandSequence, CowrieSession, GeneralHoneypot

logger = logging.getLogger(__name__)

# there is no need to view the sensors in the admin page.
# @admin.register(Sensors)
# class SensorsModelAdmin(admin.ModelAdmin):
#     list_display = [field.name for field in Sensors._meta.get_fields()]


class SessionInline(admin.TabularInline):
    model = CowrieSession
    fields = ["source", "start_time", "duration", "credentials", "interaction_count", "commands"]
    readonly_fields = fields
    show_change_link = True
    extra = 0
    ordering = ["-start_time"]


@admin.register(CowrieSession)
class CowrieSessionModelAdmin(admin.ModelAdmin):
    list_display = ["session_id", "start_time", "duration", "login_attempt", "credentials", "command_execution", "interaction_count", "source"]
    search_fields = ["source__name"]
    raw_id_fields = ["source", "commands"]


@admin.register(CommandSequence)
class CommandSequenceModelAdmin(admin.ModelAdmin):
    list_display = ["first_seen", "last_seen", "cluster", "commands"]
    inlines = [SessionInline]


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
        "log4j",
        "cowrie",
        "general_honeypots",
        "ip_reputation",
        "asn",
        "destination_ports",
        "login_attempts",
    ]
    search_fields = ["name", "related_ioc__name"]
    raw_id_fields = ["related_ioc"]
    filter_horizontal = ["general_honeypot"]
    inlines = [SessionInline]

    def general_honeypots(self, ioc):
        return ", ".join([str(element) for element in ioc.general_honeypot.all()])


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
