from datetime import datetime

from django.contrib.postgres import fields as pg_fields
from django.db import models


class Sensors(models.Model):
    address = models.CharField(max_length=15, blank=False)


class IOC(models.Model):
    name = models.CharField(max_length=256, blank=False)
    type = models.CharField(max_length=32, blank=False)
    first_seen = models.DateTimeField(blank=False, default=datetime.utcnow)
    last_seen = models.DateTimeField(blank=False, default=datetime.utcnow)
    days_seen = pg_fields.ArrayField(models.DateField(), blank=True)
    number_of_days_seen = models.IntegerField(default=1)
    times_seen = models.IntegerField(default=1)
    log4j = models.BooleanField(blank=False, default=False)
    cowrie = models.BooleanField(blank=False, default=False)
    scanner = models.BooleanField(blank=False, default=False)
    payload_request = models.BooleanField(blank=False, default=False)
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(
        models.CharField(max_length=900, blank=True), blank=True, default=list
    )
