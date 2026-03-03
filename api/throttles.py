# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.throttling import ScopedRateThrottle


class FeedsThrottle(ScopedRateThrottle):
    """Rate-limit for public (unauthenticated) feeds endpoints."""

    scope = "feeds"


class FeedsAdvancedThrottle(ScopedRateThrottle):
    """Rate-limit for authenticated feeds endpoints (advanced, asn)."""

    scope = "feeds_advanced"
