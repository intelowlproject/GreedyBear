# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path


def render_reactapp(request):
    return render(request, "index.html")


urlpatterns = [
    # admin
    path("admin/", admin.site.urls, name="admin"),
    # re_path("^gui/", include("gui.urls")),
    re_path("^api/", include("api.urls")),
    re_path(r"^(?!api)$", render_reactapp),
    re_path(r"^(?!api)(?:.*)/?$", render_reactapp),
]
