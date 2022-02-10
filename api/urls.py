# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import path

from api.views import enrichment_view, feeds

urlpatterns = [
    path("feeds/<str:feed_type>/<str:attack_type>/<str:age>.<str:format_>", feeds),
    path("enrichment", enrichment_view),
]
