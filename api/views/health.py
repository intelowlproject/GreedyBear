import logging
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.db import connection
from django.db.models import Count, Q
from django_q.models import Schedule, Task
from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from greedybear.consts import START_TIME
from greedybear.models import (
    IOC,
    CowrieSession,
    FireHolList,
    Honeypot,
    MassScanner,
    TorExitNode,
)

logger = logging.getLogger(__name__)


def get_db_status():
    """Check database connectivity."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return "up"
    except Exception as e:
        logger.exception(f"Database connectivity check failed: {e}")
        return "down"


def get_es_status():
    """Check Elasticsearch cluster health."""
    es_client = getattr(settings, "ELASTIC_CLIENT", None)

    if not es_client:
        return "not configured"

    try:
        health = es_client.cluster.health(timeout="5s")
        return {
            "green": "up",
            "yellow": "up",
            "red": "down",
        }.get(health.get("status"), "unknown")
    except Exception as e:
        logger.exception(f"Elasticsearch health check failed:  {e}")
        return "down"


def get_observables_overview(last_24h):
    """
    Aggregates all observable-related statistics:
    IOCs, sessions, honeypots and threat lists.
    """

    ioc_stats = IOC.objects.aggregate(
        total=Count("id"),
        new_last_24h=Count("id", filter=Q(first_seen__gte=last_24h)),
    )

    session_stats = CowrieSession.objects.aggregate(
        total=Count("session_id"),
        last_24h=Count("session_id", filter=Q(start_time__gte=last_24h)),
    )

    honeypot_stats = {
        "total": Honeypot.objects.count(),
        "active": Honeypot.objects.filter(active=True).count(),
    }

    threat_list_stats = {
        "firehol": FireHolList.objects.count(),
        "mass_scanners": MassScanner.objects.count(),
        "tor_exit_nodes": TorExitNode.objects.count(),
    }

    return {
        "iocs": {
            "total": ioc_stats["total"],
            "new_last_24h": ioc_stats["new_last_24h"],
        },
        "sessions": {
            "total": session_stats["total"],
            "last_24h": session_stats["last_24h"],
        },
        "honeypots": honeypot_stats,
        "threat_lists": threat_list_stats,
    }


def get_job_stats(last_24h, last_10min):
    """
    Aggregates Django-Q job statistics and determines cluster status.
    """

    job_stats = Task.objects.aggregate(
        failed_last_24h=Count("id", filter=Q(success=False, stopped__gte=last_24h)),
        successful_last_24h=Count("id", filter=Q(success=True, stopped__gte=last_24h)),
        recent_activity=Count("id", filter=Q(stopped__gte=last_10min)),
    )

    scheduled_count = Schedule.objects.count()

    if job_stats["recent_activity"] > 0:
        q_status = "up"
    elif scheduled_count > 0:
        q_status = "idle"
    else:
        q_status = "down"

    return {
        "q_status": q_status,
        "scheduled": scheduled_count,
        "failed_last_24h": job_stats["failed_last_24h"],
        "successful_last_24h": job_stats["successful_last_24h"],
    }


def get_status_overview():
    """
    Builds the complete health overview response.
    """

    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    last_10min = now - timedelta(minutes=10)

    db_status = get_db_status()
    es_status = get_es_status()

    overview = {}
    q_status = "unknown"

    # only aggregate data  if db is up
    if db_status == "up":
        try:
            observables = get_observables_overview(last_24h)
            job_data = get_job_stats(last_24h, last_10min)

            q_status = job_data.pop("q_status")

            overview = {
                **observables,
                "jobs": job_data,
            }

        except Exception as e:
            logger.exception(f"Status aggregation failed : {e}")
            db_status = "degraded"

    return {
        "system": {
            "uptime_seconds": int(time.time() - START_TIME),
            "database": db_status,
            "qcluster": q_status,
            "elasticsearch": es_status,
        },
        "overview": overview,
    }


@extend_schema(
    summary="System health and overview (admin only)",
    tags=["system"],
)
@api_view(["GET"])
@permission_classes([IsAdminUser])
def health_view(request):
    """
    Return system health status and aggregated observable statistics. Admin only.

    **Response structure:**

    - **system**: Service status overview.
        - **database**: `up`, `down`, or `degraded`.
        - **qcluster**: `up`, `idle`, or `down`.
        - **elasticsearch**: `up`, `down`, or `not configured`.
        - **uptime_seconds**: Total system uptime in seconds.
    - **overview**: Aggregated data (only populated when the database is up).
        - **iocs**: Total count and new IOCs in the last 24 hours.
        - **sessions**: Total Cowrie sessions and sessions in the last 24h.
        - **honeypots**: Total and active honeypot counts.
        - **threat_lists**: Counts of FireHOL entries, mass scanners, and Tor exit nodes.
        - **jobs**: Django-Q job statistics (scheduled, failed last 24h, successful last 24h).
    """
    data = get_status_overview()
    return Response(data)
