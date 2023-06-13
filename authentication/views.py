import logging
from typing import List

import rest_email_auth.views
from certego_saas.apps.auth import views as certego_views
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.mixins import RecaptchaV2Mixin
from certego_saas.ext.throttling import POSTUserRateThrottle
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from durin import views as durin_views
from greedybear.consts import GET
from greedybear.enums import FrontendPage
from greedybear.settings import AUTH_USER_MODEL
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import EmailVerificationSerializer, LoginSerializer, RegistrationSerializer

logger = logging.getLogger(__name__)

""" Auth API endpoints """

User: AUTH_USER_MODEL = get_user_model()


class PasswordResetRequestView(rest_email_auth.views.PasswordResetRequestView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class PasswordResetView(rest_email_auth.views.PasswordResetView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class EmailVerificationView(rest_email_auth.views.EmailVerificationView):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = EmailVerificationSerializer


class RegistrationView(rest_email_auth.views.RegistrationView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = RegistrationSerializer


class ResendVerificationView(rest_email_auth.views.ResendVerificationView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def checkAuthentication(request):
    logger.info(f"User: {request.user}, Administrator: {request.user.is_superuser}")
    return Response({"is_superuser": request.user.is_superuser}, status=status.HTTP_200_OK)


@api_view([GET])
def checkConfiguration(request):
    logger.info(f"Requested checking configuration from {request.user}.")
    page = request.query_params.get("page")
    errors = {}

    if page == FrontendPage.REGISTER.value:
        # email setup
        if not settings.DEFAULT_FROM_EMAIL:
            errors["DEFAULT_FROM_EMAIL"] = "required"
        if not settings.DEFAULT_EMAIL:
            errors["DEFAULT_EMAIL"] = "required"

        # if you are in production environment
        if settings.STAGE_PRODUCTION:
            # SES backend
            if settings.AWS_SES:
                if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
                    errors["AWS SES backend"] = "configuration required"
            else:
                # SMTP backend
                required_variables = [settings.EMAIL_HOST, settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD, settings.EMAIL_PORT]
                for variable in required_variables:
                    if not variable:
                        errors["SMTP backend"] = "configuration required"

    # if you are in production environment
    if settings.STAGE_PRODUCTION:
        # recaptcha key
        if settings.DRF_RECAPTCHA_SECRET_KEY == "fake":
            errors["RECAPTCHA_SECRET_KEY"] = "required"

    logger.info(f"Configuration errors: {errors}")
    if errors:
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
    return Response(status=status.HTTP_200_OK)


class LoginView(certego_views.LoginView, RecaptchaV2Mixin):
    @staticmethod
    def validate_and_return_user(request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data["user"]

    def post(self, request, *args, **kwargs):
        try:
            self.get_serializer()  # for RecaptchaV2Mixin
        except AssertionError:
            # it will raise this bcz `serializer_class` is not defined
            pass
        response = super().post(request, *args, **kwargs)
        # just a hacky way to store the current host
        # as this is the first endpoint hit by a user.
        cache.set("current_site", request.get_host(), timeout=60 * 60 * 24)
        return response


TokenSessionsViewSet = durin_views.TokenSessionsViewSet
APIAccessTokenView = durin_views.APIAccessTokenView
