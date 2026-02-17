import json
import logging

from django.conf import settings
from django_q.models import Schedule

from greedybear.settings import CRON_CONFIG_FILE

logger = logging.getLogger(__name__)


def setup_schedules():
    """
    Configure Django Q2 scheduled tasks for the GreedyBear application.

    Reads schedule definitions from cron_config.json and creates or updates
    the corresponding Django Q2 Schedule entries. Any existing schedules
    whose names are not present in the JSON config are treated as orphaned
    and automatically removed.

    Returns:
        None: This function is called for its side effects on the database.
    """
    extraction_interval = settings.EXTRACTION_INTERVAL

    try:
        with open(CRON_CONFIG_FILE) as f:
            cron_jobs = json.load(f)
    except FileNotFoundError:
        logger.error(f"Cron config file not found: {CRON_CONFIG_FILE}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse cron config file {CRON_CONFIG_FILE}: {e}")
        raise

    for name, cfg in cron_jobs.items():
        cron_value = cfg["cron"]
        if cron_value == "interval":
            cron_value = f"*/{extraction_interval} * * * *"
        elif cron_value == "calc_train_time":
            cron_value = f"{min(59, int(extraction_interval / 3 * 2))} 0 * * *"

        Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": cfg["func"],
                "schedule_type": Schedule.CRON,
                "cron": cron_value,
                "repeats": cfg.get("repeats", -1),
            },
        )

    # Remove orphaned schedules that are no longer defined in the config
    Schedule.objects.exclude(name__in=cron_jobs.keys()).delete()
