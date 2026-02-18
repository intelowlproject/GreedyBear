from django.conf import settings
from django_q.models import Schedule


def setup_schedules():
    """
    Configure Django Q2 scheduled tasks for the GreedyBear application.
    This function reads the ``EXTRACTION_INTERVAL`` setting and creates or
    updates a fixed set of Django Q2 ``Schedule`` entries corresponding to
    the application's periodic tasks (e.g. extraction, monitoring, training,
    clustering, and cleanup). Any existing schedules whose names are not in
    the active schedule list are treated as orphaned and removed.
    Returns:
        None: This function is called for its side effects on the database.
    """
    extraction_interval = settings.EXTRACTION_INTERVAL

    # Define all active schedules
    # NOTE: This list defines all schedules that should exist. Orphaned schedules
    # (those not in this list) are automatically removed during setup. When adding
    # new schedules, ensure they are added to this list to prevent deletion.
    active_schedules = [
        "extract_all",
        "monitor_honeypots",
        "monitor_logs",
        "train_and_update",
        "cluster_commands",
        "clean_up_db",
        "get_mass_scanners",
        "get_whatsmyip",
        "extract_firehol_lists",
        "get_tor_exit_nodes",
        "get_threatfox_feed",
        "get_abuseipdb_feed",
    ]

    # 1. Extraction: Every EXTRACTION_INTERVAL minutes
    Schedule.objects.update_or_create(
        name="extract_all",
        defaults={
            "func": "greedybear.tasks.extract_all",
            "schedule_type": Schedule.CRON,
            "cron": f"*/{extraction_interval} * * * *",
            "repeats": -1,
        },
    )

    # 2. Monitor Honeypots: Hourly at :07
    Schedule.objects.update_or_create(
        name="monitor_honeypots",
        defaults={
            "func": "greedybear.tasks.monitor_honeypots",
            "schedule_type": Schedule.CRON,
            "cron": "7 * * * *",
            "repeats": -1,
        },
    )

    # 3. Monitor Logs: Hourly at :07
    Schedule.objects.update_or_create(
        name="monitor_logs",
        defaults={
            "func": "greedybear.tasks.monitor_logs",
            "schedule_type": Schedule.CRON,
            "cron": "7 * * * *",
            "repeats": -1,
        },
    )

    # 4. Training: Daily at 00:XX (calculated)
    minute = int(extraction_interval / 3 * 2)
    minute = min(59, minute)
    Schedule.objects.update_or_create(
        name="train_and_update",
        defaults={
            "func": "greedybear.tasks.chain_train_and_update",
            "schedule_type": Schedule.CRON,
            "cron": f"{minute} 0 * * *",
            "repeats": -1,
        },
    )

    # 5. Cluster Commands: Daily at 01:07
    Schedule.objects.update_or_create(
        name="cluster_commands",
        defaults={
            "func": "greedybear.tasks.cluster_commands",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * *",
            "repeats": -1,
        },
    )

    # 6. Clean Up DB: Daily at 01:07
    Schedule.objects.update_or_create(
        name="clean_up_db",
        defaults={
            "func": "greedybear.tasks.clean_up_db",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * *",
            "repeats": -1,
        },
    )

    # 7. Mass Scanners: Weekly (Sunday) at 01:07
    Schedule.objects.update_or_create(
        name="get_mass_scanners",
        defaults={
            "func": "greedybear.tasks.get_mass_scanners",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * 0",
            "repeats": -1,
        },
    )

    # 8. WhatsMyIP: Weekly (Sunday) at 01:07
    Schedule.objects.update_or_create(
        name="get_whatsmyip",
        defaults={
            "func": "greedybear.tasks.get_whatsmyip",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * 0",
            "repeats": -1,
        },
    )

    # 9. Firehol Lists: Weekly (Sunday) at 01:07
    Schedule.objects.update_or_create(
        name="extract_firehol_lists",
        defaults={
            "func": "greedybear.tasks.extract_firehol_lists",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * 0",
            "repeats": -1,
        },
    )

    # 10. Tor Exit Nodes: Weekly (Sunday) at 01:07
    Schedule.objects.update_or_create(
        name="get_tor_exit_nodes",
        defaults={
            "func": "greedybear.tasks.get_tor_exit_nodes",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * 0",
            "repeats": -1,
        },
    )

    # 11. ThreatFox Feed: Weekly (Sunday) at 01:07
    Schedule.objects.update_or_create(
        name="get_threatfox_feed",
        defaults={
            "func": "greedybear.tasks.get_threatfox_feed",
            "schedule_type": Schedule.CRON,
            "cron": "7 1 * * 0",
            "repeats": -1,
        },
    )

    # 12. AbuseIPDB Feed: Weekly (Sunday) at 01:10
    Schedule.objects.update_or_create(
        name="get_abuseipdb_feed",
        defaults={
            "func": "greedybear.tasks.get_abuseipdb_feed",
            "schedule_type": Schedule.CRON,
            "cron": "10 1 * * 0",
            "repeats": -1,
        },
    )

    # Remove orphaned schedules that are no longer defined
    Schedule.objects.exclude(name__in=active_schedules).delete()
