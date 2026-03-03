# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.throttling import SimpleRateThrottle


class FeedsThrottle(SimpleRateThrottle):
    """Rate-limit for public (unauthenticated) feeds endpoints."""

    scope = "feeds"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class FeedsAdvancedThrottle(SimpleRateThrottle):
    """Rate-limit for authenticated feeds endpoints (advanced, asn)."""

    scope = "feeds_advanced"

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)

        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }
