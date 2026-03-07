import importlib

from django.apps import AppConfig


class GreedyBearConfig(AppConfig):
    name = "greedybear"

    def ready(self):
        importlib.import_module("greedybear.signals")
        importlib.import_module("greedybear.checks")
