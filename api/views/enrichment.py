# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import EnrichmentSerializer
from greedybear.consts import GET
from greedybear.models import Statistics, ViewType

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Enrich an observable (authenticated)",
    parameters=[
        OpenApiParameter("query", str, required=True, description="IP address or domain to look up."),
    ],
    tags=["enrichment"],
)
@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def enrichment_view(request):
    """
    Look up an IP address or domain and return matching IOC data. Requires authentication.

    Returns `found: true` with the full IOC object if a match exists, or `found: false` otherwise.

    **Query parameters:**
    - **query** (str, required): IP address (IPv4/IPv6) or domain to look up.
    """
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {str(observable_name)}")
    serializer = EnrichmentSerializer(data=request.query_params, context={"request": request})
    serializer.is_valid(raise_exception=True)

    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=ViewType.ENRICHMENT_VIEW.value)
    request_source.save()

    return Response(serializer.data, status=status.HTTP_200_OK)
