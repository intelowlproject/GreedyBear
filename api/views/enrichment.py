# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from api.serializers import EnrichmentSerializer
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from greedybear.consts import GET
from greedybear.models import Statistics, viewType
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def enrichment_view(request):
    """
    Handle enrichment requests for a specific observable (domain or IP address).

    Args:
        request: The incoming request object containing query parameters.

    Returns:
        Response: A JSON response indicating whether the observable was found,
        and if so, the corresponding IOC.
    """
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {str(observable_name)}")
    serializer = EnrichmentSerializer(data=request.query_params, context={"request": request})
    serializer.is_valid(raise_exception=True)

    source_ip = str(request.META["REMOTE_ADDR"])
    request_source = Statistics(source=source_ip, view=viewType.ENRICHMENT_VIEW.value)
    request_source.save()

    return Response(serializer.data, status=status.HTTP_200_OK)
