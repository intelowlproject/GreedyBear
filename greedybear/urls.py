# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib import admin
from django.urls import include, path, re_path

urlpatterns = [
    # admin
    path("admin/", admin.site.urls, name="admin"),
    # re_path("^gui/", include("gui.urls")),
    re_path("^api/", include("api.urls")),
]
