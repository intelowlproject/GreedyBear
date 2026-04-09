# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.decorators import api_view
from rest_framework.response import Response

from greedybear.consts import GET
from greedybear.models import Honeypot

logger = logging.getLogger(__name__)


@extend_schema(
    summary="List honeypot types",
    parameters=[
        OpenApiParameter("onlyActive", bool, description="When `true`, return only active honeypots."),
    ],
    tags=["honeypots"],
)
@api_view([GET])
def general_honeypot_list(request):
    """
    Retrieve the list of known honeypot types. Returns a JSON array of honeypot names.

    **Query parameters:**
    - **onlyActive** (bool): When `true`, return only currently active honeypots.
    """

    logger.info(f"Requested honeypots list from {request.user}.")
    active = request.query_params.get("onlyActive")
    honeypots = []
    honeypot_objs = Honeypot.objects.all()
    if active == "true":
        honeypot_objs = honeypot_objs.filter(active=True)
        logger.info(f"Requested only active honeypots from {request.user}")
    honeypots.extend([hp.name for hp in honeypot_objs])

    logger.info(f"Honeypots: {honeypots} given back to user {request.user}")
    return Response(honeypots)
