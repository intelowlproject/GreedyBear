# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import itertools
import logging
import socket

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django.conf import settings
from django.http import Http404, HttpResponseBadRequest
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.views.utils import is_ip_address, is_sha256hash
from greedybear.consts import GET
from greedybear.models import CommandSequence, CowrieSession, Statistics, viewType

logger = logging.getLogger(__name__)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def cowrie_session_view(request):
    """
    Retrieve Cowrie honeypot session data including command sequences, credentials, and session details.
    Queries can be performed using either an IP address to find all sessions from that source,
    or a SHA-256 hash to find sessions containing a specific command sequence.

    Args:
        request: The HTTP request object containing query parameters
        query (str, required): The search term, can be either an IP address or the SHA-256 hash of a command sequence.
            SHA-256 hashes should match command sequences generated using Python's "\\n".join(sequence) format.
        include_similar (bool, optional): When "true", expands the result to include all sessions that executed
            command sequences belonging to the same cluster(s) as command sequences found in the initial query result.
            Requires CLUSTER_COWRIE_COMMAND_SEQUENCES enabled in configuration. Default: false
        include_credentials (bool, optional): When "true", includes all credentials used across matching Cowrie sessions.
            Default: false
        include_session_data (bool, optional): When "true", includes detailed information about matching Cowrie sessions.
            Default: false

    Returns:
        Response (200): JSON object containing:
            - query (str): The original query parameter
            - commands (list[str]): Unique command sequences (newline-delimited strings)
            - sources (list[str]): Unique source IP addresses
            - credentials (list[str], optional): Unique credentials if include_credentials=true
            - sessions (list[dict], optional): Session details if include_session_data=true
                - time (datetime): Session start time
                - duration (float): Session duration in seconds
                - source (str): Source IP address
                - interactions (int): Number of interactions in session
                - credentials (list[str]): Credentials used in this session
                - commands (str): Command sequence executed (newline-delimited)
        Response (400): Bad Request - Missing or invalid query parameter
        Response (404): Not Found - No matching sessions found
        Response (500): Internal Server Error - Unexpected error occurred

    Example Queries:
        /api/cowrie_session?query=1.2.3.4
        /api/cowrie_session?query=5120e94e366ec83a79ee80454e4d1c76c06499ab19032bcdc7f0b4523bdb37a6
        /api/cowrie_session?query=1.2.3.4&include_credentials=true&include_session_data=true&include_similar=true
    """
    observable = request.query_params.get("query")
    include_similar = request.query_params.get("include_similar", "false").lower() == "true"
    include_credentials = request.query_params.get("include_credentials", "false").lower() == "true"
    include_session_data = request.query_params.get("include_session_data", "false").lower() == "true"

    logger.info(f"Cowrie view requested by {request.user} for {observable}")
    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=viewType.COWRIE_SESSION_VIEW.value)
    request_source.save()

    if not observable:
        return HttpResponseBadRequest("Missing required 'query' parameter")

    if is_ip_address(observable):
        sessions = CowrieSession.objects.filter(source__name=observable, duration__gt=0).prefetch_related("source", "commands")
        if not sessions.exists():
            raise Http404(f"No information found for IP: {observable}")

    elif is_sha256hash(observable):
        try:
            commands = CommandSequence.objects.get(commands_hash=observable.lower())
        except CommandSequence.DoesNotExist as exc:
            raise Http404(f"No command sequences found with hash: {observable}") from exc
        sessions = CowrieSession.objects.filter(commands=commands, duration__gt=0).prefetch_related("source", "commands")
    else:
        return HttpResponseBadRequest("Query must be a valid IP address or SHA-256 hash")

    if include_similar:
        commands = {s.commands for s in sessions if s.commands}
        clusters = {cmd.cluster for cmd in commands if cmd.cluster is not None}
        related_sessions = CowrieSession.objects.filter(commands__cluster__in=clusters).prefetch_related("source", "commands")
        sessions = sessions.union(related_sessions)

    response_data = {
        "query": observable,
    }
    if settings.FEEDS_LICENSE:
        response_data["license"] = settings.FEEDS_LICENSE

    unique_commands = {s.commands for s in sessions if s.commands}
    response_data["commands"] = sorted("\n".join(cmd.commands) for cmd in unique_commands)
    response_data["sources"] = sorted({s.source.name for s in sessions}, key=socket.inet_aton)
    if include_credentials:
        response_data["credentials"] = sorted(set(itertools.chain(*[s.credentials for s in sessions])))
    if include_session_data:
        response_data["sessions"] = [
            {
                "time": s.start_time,
                "duration": s.duration,
                "source": s.source.name,
                "interactions": s.interaction_count,
                "credentials": s.credentials if s.credentials else [],
                "commands": "\n".join(s.commands.commands) if s.commands else "",
            }
            for s in sessions
        ]

    return Response(response_data, status=status.HTTP_200_OK)
