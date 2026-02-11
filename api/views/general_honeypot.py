# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from rest_framework.decorators import api_view
from rest_framework.response import Response

from greedybear.consts import GET
from greedybear.models import Honeypot

logger = logging.getLogger(__name__)


@api_view([GET])
def general_honeypot_list(request):
    """
    Retrieve a list of all general honeypots, optionally filtering by active status.

    Args:
        request: The incoming request object containing query parameters.

    Returns:
        Response: A JSON response containing the list of general honeypots.
    """

    logger.info(f"Requested general honeypots list from {request.user}.")
    active = request.query_params.get("onlyActive")
    honeypots = []
    general_honeypots = Honeypot.objects.all()
    if active == "true":
        general_honeypots = general_honeypots.filter(active=True)
        logger.info(f"Requested only active general honeypots from {request.user}")
    honeypots.extend([hp.name for hp in general_honeypots])

    logger.info(f"General honeypots: {honeypots} given back to user {request.user}")
    return Response(honeypots)
