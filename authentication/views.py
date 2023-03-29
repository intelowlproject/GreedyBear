import logging
from typing import List

import rest_email_auth.views
from certego_saas.apps.auth.backend import CookieTokenAuthentication

# from certego_saas.apps.user.models import User
from certego_saas.ext.mixins import RecaptchaV2Mixin
from certego_saas.ext.throttling import POSTUserRateThrottle
from django.contrib.auth import get_user_model
from durin import views as durin_views
from greedybear.consts import GET
from greedybear.settings import AUTH_USER_MODEL
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import EmailVerificationSerializer, PasswordChangeSerializer, RegistrationSerializer

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
# @authentication_classes([CookieTokenAuthentication])
# @permission_classes([IsAuthenticated])
def changePassword(request):
    logger.info(f"User {request.user} requests to change password")
    user = User.objects.get(username=request.user)
    logger.info(user)
    PasswordChangeSerializer
    return Response({user.email}, status=status.HTTP_200_OK)


TokenSessionsViewSet = durin_views.TokenSessionsViewSet
APIAccessTokenView = durin_views.APIAccessTokenView
