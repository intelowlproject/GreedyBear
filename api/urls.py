# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from api.views import (
    APIAccessTokenView,
    StatisticsViewSet,
    TokenSessionsViewSet,
    checkAuthentication,
    enrichment_view,
    feeds,
    feeds_pagination,
    general_honeypot_view,
)
from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")
router.register(r"sessions", TokenSessionsViewSet, basename="auth_tokensessions")

# These come after /api/..
urlpatterns = [
    path("feeds/", feeds_pagination),
    path("feeds/<str:feed_type>/<str:attack_type>/<str:age>.<str:format_>", feeds),
    path("enrichment", enrichment_view),
    path("generalhoneypot", general_honeypot_view),
    # router viewsets
    path("", include(router.urls)),
    # authentication
    path("authentication", checkAuthentication),
    path("apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # auth
    path("auth/", include("certego_saas.apps.auth.urls")),
]
