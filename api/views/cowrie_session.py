# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import ipaddress
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django.conf import settings
from django.http import Http404, HttpResponseBadRequest
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from greedybear.consts import GET
from greedybear.models import CommandSequence, CowrieSession, Statistics, ViewType
from greedybear.utils import is_ip_address, is_sha256hash

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Look up Cowrie honeypot sessions (authenticated)",
    parameters=[
        OpenApiParameter("query", str, required=True, description="Search term: an IP address, a SHA-256 command sequence hash, or a password."),
        OpenApiParameter(
            "include_similar",
            bool,
            description="Expand results to include sessions with command sequences from the same cluster. Requires command clustering enabled. Default: `false`.",
        ),
        OpenApiParameter("include_credentials", bool, description="Include all credentials used across matching sessions. Default: `false`."),
        OpenApiParameter(
            "include_session_data",
            bool,
            description="Include detailed session information (time, duration, source, interactions, credentials, commands). Default: `false`.",
        ),
    ],
    tags=["cowrie"],
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def cowrie_session_view(request):
    """
    Retrieve Cowrie honeypot session data including command sequences, credentials, and session details.
    Requires authentication.

    Search by IP address (all sessions from that source), SHA-256 hash (sessions containing a specific
    command sequence), or password (sessions where that password was used).

    **Query parameters:**
    - **query** (str, required): Search term — an IP address, a SHA-256 command sequence hash, or a password.
    - **include_similar** (bool): Expand results to include sessions with command sequences from the same cluster. Default: `false`.
    - **include_credentials** (bool): Include all credentials used across matching sessions. Default: `false`.
    - **include_session_data** (bool): Include detailed session information (time, duration, source, interactions, credentials, commands). Default: `false`.

    **Response fields:**
    - **query**: The original search term.
    - **commands**: Unique command sequences (newline-delimited strings).
    - **sources**: Unique source IP addresses.
    - **credentials** (optional): Unique credentials, if `include_credentials=true`.
    - **sessions** (optional): Session details, if `include_session_data=true`.
    """
    observable = request.query_params.get("query")
    include_similar = request.query_params.get("include_similar", "false").lower() == "true"
    include_credentials = request.query_params.get("include_credentials", "false").lower() == "true"
    include_session_data = request.query_params.get("include_session_data", "false").lower() == "true"

    logger.info(f"Cowrie view requested by {request.user} for {observable}")

    if not observable:
        return HttpResponseBadRequest("Missing required 'query' parameter")

    if is_ip_address(observable):
        sessions = CowrieSession.objects.filter(source__name=observable, duration__gt=0).prefetch_related("source", "commands", "credentials")
        if not sessions.exists():
            raise Http404(f"No information found for IP: {observable}")

    elif is_sha256hash(observable):
        try:
            commands = CommandSequence.objects.get(commands_hash=observable.lower())
        except CommandSequence.DoesNotExist as exc:
            raise Http404(f"No command sequences found with hash: {observable}") from exc
        sessions = CowrieSession.objects.filter(commands=commands, duration__gt=0).prefetch_related("source", "commands", "credentials")
    else:
        if len(observable) > 256:  # max_length of Credential.password field
            return HttpResponseBadRequest("Query exceeds maximum password length")
        sessions = CowrieSession.objects.filter(credentials__password=observable, duration__gt=0).prefetch_related("source", "commands", "credentials")
        if not sessions.exists():
            raise Http404(f"No information found for password: {observable}")

    source_ip = str(request.META["REMOTE_ADDR"])
    Statistics(source=source_ip, view=ViewType.COWRIE_SESSION_VIEW.value).save()

    if include_similar:
        commands = {s.commands for s in sessions if s.commands}
        clusters = {cmd.cluster for cmd in commands if cmd.cluster is not None}
        related_sessions = CowrieSession.objects.filter(commands__cluster__in=clusters).prefetch_related("source", "commands", "credentials")
        sessions = sessions.union(related_sessions)

    response_data = {
        "query": observable,
    }
    if settings.FEEDS_LICENSE:
        response_data["license"] = settings.FEEDS_LICENSE

    unique_commands = {s.commands for s in sessions if s.commands}
    response_data["commands"] = sorted("\n".join(cmd.commands) for cmd in unique_commands)
    response_data["sources"] = sorted({s.source.name for s in sessions}, key=lambda ip: ipaddress.ip_address(ip))
    if include_credentials:
        response_data["credentials"] = sorted({str(c) for s in sessions for c in s.credentials.all()})
    if include_session_data:
        response_data["sessions"] = [
            {
                "time": s.start_time,
                "duration": s.duration,
                "source": s.source.name,
                "interactions": s.interaction_count,
                "credentials": [str(c) for c in s.credentials.all()],
                "commands": "\n".join(s.commands.commands) if s.commands else "",
            }
            for s in sessions
        ]

    return Response(response_data, status=status.HTTP_200_OK)
