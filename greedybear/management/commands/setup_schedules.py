from django.core.management.base import BaseCommand
from django_q.models import Schedule

from greedybear.settings import EXTRACTION_INTERVAL


class Command(BaseCommand):
    help = "Setup Django Q2 scheduled tasks"

    def handle(self, *args, **options):
        # 1. Extraction: Every EXTRACTION_INTERVAL minutes
        Schedule.objects.update_or_create(
            name="extract_all",
            defaults={"func": "greedybear.tasks.extract_all", "schedule_type": Schedule.CRON, "cron": f"*/{EXTRACTION_INTERVAL} * * * *", "repeats": -1},
        )

        # 2. Monitor Honeypots: Hourly at :07
        Schedule.objects.update_or_create(
            name="monitor_honeypots",
            defaults={"func": "greedybear.tasks.monitor_honeypots", "schedule_type": Schedule.CRON, "cron": "7 * * * *", "repeats": -1},
        )

        # 3. Monitor Logs: Hourly at :07
        Schedule.objects.update_or_create(
            name="monitor_logs", defaults={"func": "greedybear.tasks.monitor_logs", "schedule_type": Schedule.CRON, "cron": "7 * * * *", "repeats": -1}
        )

        # 4. Training: Daily at 00:XX (calculated)
        minute = int(EXTRACTION_INTERVAL / 3 * 2)
        Schedule.objects.update_or_create(
            name="train_and_update",
            defaults={"func": "greedybear.tasks.chain_train_and_update", "schedule_type": Schedule.CRON, "cron": f"{minute} 0 * * *", "repeats": -1},
        )

        # 5. Cluster Commands: Daily at 01:07
        Schedule.objects.update_or_create(
            name="cluster_commands", defaults={"func": "greedybear.tasks.cluster_commands", "schedule_type": Schedule.CRON, "cron": "7 1 * * *", "repeats": -1}
        )

        # 6. Clean Up DB: Daily at 01:07
        Schedule.objects.update_or_create(
            name="clean_up_db", defaults={"func": "greedybear.tasks.clean_up_db", "schedule_type": Schedule.CRON, "cron": "7 1 * * *", "repeats": -1}
        )

        # 7. Mass Scanners: Weekly (Sunday) at 01:07
        Schedule.objects.update_or_create(
            name="get_mass_scanners",
            defaults={"func": "greedybear.tasks.get_mass_scanners", "schedule_type": Schedule.CRON, "cron": "7 1 * * 0", "repeats": -1},
        )

        # 8. WhatsMyIP: Weekly (Sunday) at 01:07
        Schedule.objects.update_or_create(
            name="get_whatsmyip", defaults={"func": "greedybear.tasks.get_whatsmyip", "schedule_type": Schedule.CRON, "cron": "7 1 * * 0", "repeats": -1}
        )

        # 9. Firehol Lists: Weekly (Sunday) at 01:07
        Schedule.objects.update_or_create(
            name="extract_firehol_lists",
            defaults={"func": "greedybear.tasks.extract_firehol_lists", "schedule_type": Schedule.CRON, "cron": "7 1 * * 0", "repeats": -1},
        )

        # 10. Tor Exit Nodes: Weekly (Sunday) at 01:07
        Schedule.objects.update_or_create(
            name="get_tor_exit_nodes",
            defaults={"func": "greedybear.tasks.get_tor_exit_nodes", "schedule_type": Schedule.CRON, "cron": "7 1 * * 0", "repeats": -1},
        )

        self.stdout.write(self.style.SUCCESS("Successfully setup schedules"))
