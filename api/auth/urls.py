from django.urls import path

from .views import APIAccessTokenView, LoginView, LogoutView

urlpatterns = [
    path("login", LoginView.as_view(), name="auth_login"),
    path("logout", LogoutView.as_view(), name="auth_logout"),
    path("apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
]
