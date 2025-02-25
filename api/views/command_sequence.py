# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from api.views.utils import is_ip_address, is_sha256hash
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django.http import Http404, HttpResponseBadRequest
from greedybear.consts import FEEDS_LICENSE, GET
from greedybear.models import IOC, CommandSequence, CowrieSession, Statistics, viewType
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def command_sequence_view(request):
    """
    View function that handles command sequence queries based on IP addresses or SHA-256 hashes.

    Retrieves and returns command sequences and related IOCs based on the query parameter.
    If IP address is given, returns all command sequences executed from this IP.
    If SHA-256 hash is given, returns details about the specific command sequence.
    Can include similar command sequences if requested.

    Args:
        request: The HTTP request object containing query parameters
        query (str): The search term, can be either an IP address or a SHA-256 hash.
        include_similar (bool): When parameter is present, returns related command sequences based on clustering.

    Returns:
        Response object with command sequence data or an error response

    Raises:
        Http404: If the requested resource is not found
    """
    observable = request.query_params.get("query")
    include_similar = request.query_params.get("include_similar") is not None
    logger.info(f"Command Sequence view requested by {request.user} for {observable}")
    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=viewType.COMMAND_SEQUENCE_VIEW.value)
    request_source.save()

    if not observable:
        return HttpResponseBadRequest("Missing required 'query' parameter")

    if is_ip_address(observable):
        sessions = CowrieSession.objects.filter(source__name=observable, start_time__isnull=False, commands__isnull=False)
        sequences = set(s.commands for s in sessions)
        seqs = [
            {
                "time": s.start_time,
                "command_sequence": "\n".join(s.commands.commands),
                "command_sequence_hash": s.commands.commands_hash,
            }
            for s in sessions
        ]
        related_iocs = IOC.objects.filter(cowriesession__commands__in=sequences).distinct().only("name")
        if include_similar:
            related_clusters = set(s.cluster for s in sequences if s.cluster is not None)
            related_iocs = IOC.objects.filter(cowriesession__commands__cluster__in=related_clusters).distinct().only("name")
        if not seqs:
            raise Http404(f"No command sequences found for IP: {observable}")
        data = {
            "license": FEEDS_LICENSE,
            "executed_commands": seqs,
            "executed_by": sorted([ioc.name for ioc in related_iocs]),
        }
        return Response(data, status=status.HTTP_200_OK)

    if is_sha256hash(observable):
        try:
            seq = CommandSequence.objects.get(commands_hash=observable)
            seqs = CommandSequence.objects.filter(cluster=seq.cluster) if include_similar and seq.cluster is not None else [seq]
            commands = ["\n".join(seq.commands) for seq in seqs]
            sessions = CowrieSession.objects.filter(commands__in=seqs, start_time__isnull=False)
            iocs = [
                {
                    "time": s.start_time,
                    "ip": s.source.name,
                }
                for s in sessions
            ]
            data = {
                "license": FEEDS_LICENSE,
                "commands": commands,
                "iocs": sorted(iocs, key=lambda d: d["time"], reverse=True),
            }
            return Response(data, status=status.HTTP_200_OK)
        except CommandSequence.DoesNotExist as exc:
            raise Http404(f"No command sequences found with hash: {observable}") from exc

    return HttpResponseBadRequest("Query must be a valid IP address or SHA-256 hash")
