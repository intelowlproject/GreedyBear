import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def send_ntfy_message(message):
    if not settings.NTFY_URL:
        logger.warning("ntfy is not configured, message not sent")
        return

    try:
        response = requests.post(
            settings.NTFY_URL,
            data=message.encode("utf-8"),
            timeout=(1, 2),
        )
        response.raise_for_status()

    except Exception as error:
        logger.exception(error)
