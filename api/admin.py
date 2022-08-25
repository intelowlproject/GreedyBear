from certego_saas.apps.user.admin import AbstractUserAdmin
from certego_saas.apps.user.models import User
from django.contrib import admin

# certego-saas


@admin.register(User)
class UserAdminView(AbstractUserAdmin):
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_active",
        "is_staff",
    )
