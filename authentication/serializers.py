# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
import re

import rest_email_auth.serializers
from certego_saas.ext.upload import Slack
from certego_saas.models import User
from certego_saas.settings import certego_apps_settings
from django.conf import settings
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.utils.translation import gettext_lazy as _
from greedybear.consts import REGEX_PASSWORD
from rest_framework import serializers as rfs
from rest_framework.authtoken.serializers import AuthTokenSerializer
from slack_sdk.errors import SlackApiError

from .models import UserProfile

logger = logging.getLogger(__name__)

__all__ = [
    "UserProfileSerializer",
    "RegistrationSerializer",
    "EmailVerificationSerializer",
]


class UserProfileSerializer(rfs.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ("user",)


class RegistrationSerializer(rest_email_auth.serializers.RegistrationSerializer):
    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "is_active",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "style": {"input_type": "password"},
                "write_only": True,
            },
            "first_name": {
                "required": True,
                "write_only": True,
            },
            "last_name": {
                "required": True,
                "write_only": True,
            },
        }

    profile = UserProfileSerializer(write_only=True)
    is_active = rfs.BooleanField(default=False, read_only=True)

    def validate_profile(self, profile):
        logger.info(f"{profile}")

        self._profile_serializer = UserProfileSerializer(data=profile)
        self._profile_serializer.is_valid(raise_exception=True)
        return profile

    def validate_password(self, password):
        super().validate_password(password)

        if re.match(REGEX_PASSWORD, password):
            return password
        else:
            raise ValidationError("Invalid password")

    def create(self, validated_data):
        validated_data.pop("profile", None)
        validated_data["is_active"] = False
        user = None
        try:
            user = super().create(validated_data)

            # save profile object only if user object was actually saved
            if getattr(user, "pk", None):
                self._profile_serializer.save(user=user)
                user.refresh_from_db()
        except DatabaseError:
            transaction.rollback()
        return user


class EmailVerificationSerializer(rest_email_auth.serializers.EmailVerificationSerializer):
    def validate_key(self, key):
        try:
            return super().validate_key(key)
        except rfs.ValidationError as exc:
            # custom error messages
            err_str = str(exc.detail)
            if "invalid" in err_str:
                exc.detail = "The provided verification key" " is invalid or your email address is already verified."
            if "expired" in err_str:
                exc.detail = "The provided verification key" " has expired or your email address is already verified."
            raise exc

    def save(self):
        """
        Confirm the email address matching the confirmation key.
        Then mark user as active.
        """
        user = self._confirmation.email.user
        with transaction.atomic():
            super().save()

        # Send msg on slack
        if certego_apps_settings.SLACK_TOKEN and certego_apps_settings.DEFAULT_SLACK_CHANNEL:
            try:
                userprofile = user.user_profile
                user_admin_link = f"{settings.HOST_URI}/admin/certego_saas_user/user/{user.pk}"
                userprofile_admin_link = f"{settings.HOST_URI}" f"/admin/authentication/userprofile/{userprofile.pk}"
                slack = Slack()
                slack.send_message(
                    title="Newly registered user!!",
                    body=(
                        f"- User(#{user.pk}, {user.username},"
                        f"{user.email}, <{user_admin_link} |admin link>)\n"
                        f"- UserProfile({userprofile.company_name},"
                        f"{userprofile.company_role}, )"
                        f"<{userprofile_admin_link} |admin link>)"
                    ),
                    channel=certego_apps_settings.DEFAULT_SLACK_CHANNEL,
                )
            except SlackApiError as exc:
                slack.log.error(f"Slack message failed for user(#{user.pk}) with error: {str(exc)}")


class LoginSerializer(AuthTokenSerializer):
    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except rfs.ValidationError as exc:
            try:
                user = User.objects.get(username=attrs["username"])
            except User.DoesNotExist:
                # we do not want to leak info
                # so just raise the original exception
                raise exc
            else:
                # custom error messages
                if not user.is_active:
                    if user.is_email_verified is False:
                        exc.detail = "Your account is pending email verification."
                    elif user.approved is None:
                        exc.detail = "Your account is pending activation by our team."
                    elif user.approved is False:
                        exc.detail = "Your account was declined."
                    logger.info(f"User {user} is not active. Error message: {exc.detail}")
            # else
            raise exc
