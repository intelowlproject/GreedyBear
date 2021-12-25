from django.urls import re_path

from api.views import feeds

urlpatterns = [
    re_path("^feeds/<age>/<attack_type>/<format>", feeds),
]
