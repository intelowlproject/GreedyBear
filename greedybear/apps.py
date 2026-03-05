# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import importlib

from django.apps import AppConfig


class GreedyBearConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "greedybear"

    def ready(self):
        importlib.import_module("greedybear.signals")  # noqa: F401
