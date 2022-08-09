# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import include, path
from rest_framework import routers

from api.views import StatisticsViewSet, enrichment_view, feeds

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")

# These come after /api/..
urlpatterns = [
    path("feeds/<str:feed_type>/<str:attack_type>/<str:age>.<str:format_>", feeds),
    path("enrichment", enrichment_view),
    # router viewsets
    path("", include(router.urls)),
]
