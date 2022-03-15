# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # admin
    path("admin/", admin.site.urls, name="admin"),
    path("api/", include("api.urls")),
    # re_path("^gui/", include("gui.urls")),
]
