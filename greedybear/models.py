from django.contrib.postgres import fields as pg_fields
from django.db import models

from greedybear.consts import PAYLOAD_REQUEST, SCANNER


class Sensors(models.Model):
    address = models.CharField(max_length=15, blank=False)


class IOC(models.Model):
    name = models.CharField(max_length=256, blank=False)
    type = models.CharField(max_length=32, blank=False, choices=["ip", "domain"])
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now_add=True)
    times_seen = models.IntegerField(default=1)
    honeypots = pg_fields.ArrayField(
        models.CharField(max_length=900),
        blank=True,
        default=list,
        null=True,
        unique=True,
    )
    attack_types = pg_fields.ArrayField(
        models.CharField(
            max_length=32, blank=False, choices=[SCANNER, PAYLOAD_REQUEST], unique=True
        )
    )
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(
        models.CharField(max_length=900),
        blank=True,
        default=list,
        null=True,
        unique=True,
    )
