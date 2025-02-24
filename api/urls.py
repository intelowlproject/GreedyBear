# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from api.views import StatisticsViewSet, enrichment_view, feeds, feeds_advanced, feeds_pagination, general_honeypot_list
from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")

# These come after /api/..
urlpatterns = [
    path("feeds/", feeds_pagination),
    path("feeds/advanced/", feeds_advanced),
    path("feeds/<str:feed_type>/<str:attack_type>/<str:prioritize>.<str:format_>", feeds),
    path("enrichment", enrichment_view),
    path("general_honeypot", general_honeypot_list),
    # router viewsets
    path("", include(router.urls)),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # auth
    path("auth/", include("authentication.urls")),
]
