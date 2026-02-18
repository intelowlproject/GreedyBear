from django.conf import settings
from django_q.models import Schedule


def setup_schedules():
    """
    Configure Django Q2 scheduled tasks for the GreedyBear application.

    Reads schedule definitions and creates or updates
    the corresponding Django Q2 Schedule entries. Any existing schedules
    whose names are not present in the schedule definitions are treated as orphaned
    and automatically removed.

    Returns:
        None: This function is called for its side effects on the database.
    """
    extraction_interval = settings.EXTRACTION_INTERVAL

    schedules = [
        {
            "name": "extract_all",
            "func": "greedybear.tasks.extract_all",
            "cron": f"*/{extraction_interval} * * * *",
        },
        {
            "name": "monitor_honeypots",
            "func": "greedybear.tasks.monitor_honeypots",
            "cron": "7 * * * *",
        },
        {
            "name": "monitor_logs",
            "func": "greedybear.tasks.monitor_logs",
            "cron": "7 * * * *",
        },
        {
            "name": "train_and_update",
            "func": "greedybear.tasks.chain_train_and_update",
            "cron": f"{min(59, int(extraction_interval * 2 / 3))} 0 * * *",
        },
        {
            "name": "cluster_commands",
            "func": "greedybear.tasks.cluster_commands",
            "cron": "7 1 * * *",
        },
        {
            "name": "clean_up_db",
            "func": "greedybear.tasks.clean_up_db",
            "cron": "7 1 * * *",
        },
        {
            "name": "get_mass_scanners",
            "func": "greedybear.tasks.get_mass_scanners",
            "cron": "7 1 * * 0",
        },
        {
            "name": "get_whatsmyip",
            "func": "greedybear.tasks.get_whatsmyip",
            "cron": "7 1 * * 0",
        },
        {
            "name": "extract_firehol_lists",
            "func": "greedybear.tasks.extract_firehol_lists",
            "cron": "7 1 * * 0",
        },
        {
            "name": "get_tor_exit_nodes",
            "func": "greedybear.tasks.get_tor_exit_nodes",
            "cron": "7 1 * * 0",
        },
    ]

    active_names = []

    for job in schedules:
        active_names.append(job["name"])

        Schedule.objects.update_or_create(
            name=job["name"],
            defaults={
                "func": job["func"],
                "schedule_type": Schedule.CRON,
                "cron": job["cron"],
                "repeats": -1,
            },
        )

    # Remove orphaned schedules
    Schedule.objects.exclude(name__in=active_names).delete()
