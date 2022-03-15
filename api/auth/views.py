import logging

from django.contrib.auth import login, logout
from django_user_agents.utils import get_user_agent
from durin import views as DurinViews
from durin.models import Client

logger = logging.getLogger(__name__)


class LoginView(DurinViews.LoginView):
    def get_client_obj(self, request) -> Client:
        user_agent = get_user_agent(request)
        client_name = str(user_agent)
        client, _ = Client.objects.get_or_create(name=client_name)
        return client

    def post(self, request, *args, **kwargs):
        user_name = request.user.username
        logger.info(f"Login Attempt from '{user_name}'.")
        if request.user.is_superuser:
            try:
                login(request, request.user)
                logger.info(f"Admin: '{user_name}' logged in.")
            except Exception:
                logger.exception(f"Admin: '{user_name}' login failed.")
        return super(LoginView, self).post(request, *args, **kwargs)


class LogoutView(DurinViews.LogoutView):
    def post(self, request, *args, **kwargs):
        uname = request.user.username
        logger.info(f"perform_logout received request from '{uname}''.")
        if request.user.is_superuser:
            try:
                logout(request)
                logger.info(f"administrator: '{uname}' was logged out.")
            except Exception:
                logger.exception(f"administrator: '{uname}' session logout failed.")
        return super(LogoutView, self).post(request, format=None)


APIAccessTokenView = DurinViews.APIAccessTokenView
TokenSessionsViewSet = DurinViews.TokenSessionsViewSet
