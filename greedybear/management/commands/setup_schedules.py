from django.core.management.base import BaseCommand

from greedybear.cronjobs.schedules import setup_schedules


class Command(BaseCommand):
    help = "Setup Django Q2 scheduled tasks"

    def handle(self, *args, **options):
        setup_schedules()

        self.stdout.write(self.style.SUCCESS("Successfully setup schedules"))
