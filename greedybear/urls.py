from django.urls import include, re_path

urlpatterns = [
    re_path("^gui/", include("gui.urls")),
    re_path("^api/", include("api.urls")),
]
