# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from greedybear.consts import GET
from greedybear.models import GeneralHoneypot
from rest_framework.decorators import api_view
from rest_framework.response import Response

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
    generalHoneypots = GeneralHoneypot.objects.all()
    if active == "true":
        generalHoneypots = generalHoneypots.filter(active=True)
        logger.info("Requested only active general honeypots")
    honeypots.extend([hp.name for hp in generalHoneypots])

    logger.info(f"General honeypots: {honeypots}")
    return Response(honeypots)
