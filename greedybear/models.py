# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from datetime import datetime

from django.contrib.postgres import fields as pg_fields
from django.db import models


class viewType(models.TextChoices):
    FEEDS_VIEW = "feeds"
    ENRICHMENT_VIEW = "enrichment"


class iocType(models.TextChoices):
    IP = "ip"
    DOMAIN = "domain"


class Sensors(models.Model):
    address = models.CharField(max_length=15, blank=False)


class GeneralHoneypot(models.Model):
    name = models.CharField(max_length=15, blank=False)
    active = models.BooleanField(blank=False, default=True)

    def __str__(self):
        return self.name


class IOC(models.Model):
    name = models.CharField(max_length=256, blank=False)
    type = models.CharField(max_length=32, blank=False, choices=iocType.choices)
    first_seen = models.DateTimeField(blank=False, default=datetime.utcnow)
    last_seen = models.DateTimeField(blank=False, default=datetime.utcnow)
    days_seen = pg_fields.ArrayField(models.DateField(), blank=True)
    number_of_days_seen = models.IntegerField(default=1)
    times_seen = models.IntegerField(default=1)
    log4j = models.BooleanField(blank=False, default=False)
    cowrie = models.BooleanField(blank=False, default=False)
    # FEEDS - list of honeypots from general list, from which the IOC was detected
    general_honeypot = models.ManyToManyField(GeneralHoneypot, blank=True)
    scanner = models.BooleanField(blank=False, default=False)
    payload_request = models.BooleanField(blank=False, default=False)
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(models.CharField(max_length=900, blank=True), blank=True, default=list)

    def __str__(self):
        return self.name


class Statistics(models.Model):
    source = models.CharField(max_length=15, blank=False)
    view = models.CharField(
        max_length=32,
        blank=False,
        choices=viewType.choices,
        default=viewType.FEEDS_VIEW.value,
    )
    request_date = models.DateTimeField(blank=False, default=datetime.utcnow)
