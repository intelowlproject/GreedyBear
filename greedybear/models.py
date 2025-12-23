# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from datetime import datetime

from django.contrib.postgres import fields as pg_fields
from django.db import models


class viewType(models.TextChoices):
    FEEDS_VIEW = "feeds"
    ENRICHMENT_VIEW = "enrichment"
    COMMAND_SEQUENCE_VIEW = "command sequence"
    COWRIE_SESSION_VIEW = "cowrie session"


class iocType(models.TextChoices):
    IP = "ip"
    DOMAIN = "domain"


class Sensor(models.Model):
    address = models.CharField(max_length=15, blank=False)


class GeneralHoneypot(models.Model):
    name = models.CharField(max_length=15, blank=False)
    active = models.BooleanField(blank=False, default=True)

    def __str__(self):
        return self.name


class IOC(models.Model):
    name = models.CharField(max_length=256, blank=False)
    type = models.CharField(max_length=32, blank=False, choices=iocType.choices)
    first_seen = models.DateTimeField(blank=False, default=datetime.now)
    last_seen = models.DateTimeField(blank=False, default=datetime.now)
    days_seen = pg_fields.ArrayField(models.DateField(), blank=True, default=list)
    number_of_days_seen = models.IntegerField(default=1)
    attack_count = models.IntegerField(default=1)
    interaction_count = models.IntegerField(default=1)
    # FEEDS - list of honeypots from general list, from which the IOC was detected

    general_honeypot = models.ManyToManyField(GeneralHoneypot, blank=True)
    scanner = models.BooleanField(blank=False, default=False)
    payload_request = models.BooleanField(blank=False, default=False)
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(models.CharField(max_length=900, blank=True), blank=True, default=list)
    ip_reputation = models.CharField(max_length=32, blank=True)
    asn = models.IntegerField(blank=True, null=True)
    destination_ports = pg_fields.ArrayField(models.IntegerField(), blank=False, null=False, default=list)
    login_attempts = models.IntegerField(blank=False, null=False, default=0)
    # SCORES
    recurrence_probability = models.FloatField(blank=False, null=True, default=0)
    expected_interactions = models.FloatField(blank=False, null=True, default=0)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
        ]

    def __str__(self):
        return self.name


class CommandSequence(models.Model):
    first_seen = models.DateTimeField(blank=False, default=datetime.now)
    last_seen = models.DateTimeField(blank=False, default=datetime.now)
    commands = pg_fields.ArrayField(models.CharField(max_length=1024, blank=True), blank=False, null=False, default=list)
    commands_hash = models.CharField(max_length=64, unique=True, blank=True, null=True)
    cluster = models.IntegerField(blank=True, null=True)

    def __str__(self):
        cmd_string = "; ".join(self.commands)
        return cmd_string[:29] + "..." if len(cmd_string) > 32 else cmd_string


class CowrieSession(models.Model):
    session_id = models.BigIntegerField(primary_key=True)
    start_time = models.DateTimeField(blank=True, null=True)
    duration = models.FloatField(blank=True, null=True)
    login_attempt = models.BooleanField(blank=False, null=False, default=False)
    credentials = pg_fields.ArrayField(models.CharField(max_length=256, blank=True), blank=False, null=False, default=list)
    command_execution = models.BooleanField(blank=False, null=False, default=False)
    interaction_count = models.IntegerField(blank=False, null=False, default=0)
    source = models.ForeignKey(IOC, on_delete=models.CASCADE, blank=False, null=False)
    commands = models.ForeignKey(CommandSequence, on_delete=models.SET_NULL, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["source"]),
        ]


class Statistics(models.Model):
    source = models.CharField(max_length=15, blank=False)
    view = models.CharField(
        max_length=32,
        blank=False,
        choices=viewType.choices,
        default=viewType.FEEDS_VIEW.value,
    )
    request_date = models.DateTimeField(blank=False, default=datetime.now)


class MassScanner(models.Model):
    ip_address = models.CharField(max_length=256, blank=False)
    added = models.DateTimeField(blank=False, default=datetime.now)
    reason = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]


class WhatsMyIPDomain(models.Model):
    domain = models.CharField(max_length=256, blank=False)
    added = models.DateTimeField(blank=False, default=datetime.now)

    class Meta:
        indexes = [
            models.Index(fields=["domain"]),
        ]
