from django.urls import re_path

from api.views import feeds

urlpatterns = [
    re_path("^feeds/<str:age>/<str:attack_type>/<str:format>", feeds),
]
