# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import path
from api.views import feeds
from api.auth import LoginView, LogoutView

urlpatterns = [
    # Auth APIs
    path("auth/login", LoginView.as_view(), name="auth_login"),
    path("auth/logout", LogoutView.as_view(), name="auth_logout"),
    path("feeds/<str:feed_type>/<str:attack_type>/<str:age>.<str:format_>", feeds),
]
