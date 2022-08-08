# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import path

from api.views import (
    enrichment_view,
    feeds,
    statistics_enrichment_downloads,
    statistics_enrichment_sources,
    statistics_feeds_downloads,
    statistics_feeds_sources,
    statistics_feeds_types,
)

urlpatterns = [
    path("feeds/<str:feed_type>/<str:attack_type>/<str:age>.<str:format_>", feeds),
    path("enrichment", enrichment_view),
    path("statistics/feeds/sources", statistics_feeds_sources),
    path("statistics/feeds/downloads", statistics_feeds_downloads),
    path("statistics/feeds/types", statistics_feeds_types),
    path("statistics/enrichment/sources", statistics_enrichment_sources),
    path("statistics/enrichment/downloads", statistics_enrichment_downloads),
]
