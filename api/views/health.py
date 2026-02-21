from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from api.views.utils import get_status_overview


@api_view(["GET"])
@permission_classes([IsAdminUser])
def health_view(request):
    """
    Health & overview endpoint.

    Returns the current system status and aggregated observables. Accessible
    only to admin users.

    System status includes:
        - database: "up", "down", or "degraded"
        - qcluster: "up", "idle", or "down"
        - elasticsearch: "up", "down", or "not configured"
        - uptime_seconds: total system uptime in seconds

    Overview data includes:
        - iocs: total and new IOCs in the last 24 hours
        - sessions: total Cowrie sessions and sessions in the last 24h
        - honeypots: total and active honeypots
        - threat_lists: counts of firehol, mass_scanners, tor_exit_nodes
        - jobs: Django-Q jobs (scheduled, failed last 24h, successful last 24h)
    """
    data = get_status_overview()
    return Response(data)
