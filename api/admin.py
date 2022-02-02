# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.


from django.contrib import admin
from durin.admin import AuthTokenAdmin
from durin.models import AuthToken, Client


# Auth Token stuff
class CustomAuthTokenAdmin(AuthTokenAdmin):
    """
    Custom admin view for AuthToken model
    """

    exclude = []
    raw_id_fields = ("user",)
    readonly_fields = ("token", "expiry", "created", "expires_in")

    def get_fieldsets(self, request, obj=None):
        if not obj:
            return [
                (
                    "Create token for Greedybear",
                    {
                        "fields": ("user",),
                        "description": """
                    <h3>Token will be auto-generated on save.</h3>
                    <h3>This token will be valid for 10 years.</h3>
                """,
                    },
                ),
            ]
        return super().get_fieldsets(request, obj)

    def has_change_permission(self, *args, **kwargs):
        return False

    def save_model(self, request, obj, form, change):
        obj.client = Client.objects.get(name="greedybear")
        super(CustomAuthTokenAdmin, self).save_model(request, obj, form, change)


# Unregister the default admin view for AuthToken
admin.site.unregister(AuthToken)
# Register our custom admin view for AuthToken
admin.site.register(AuthToken, CustomAuthTokenAdmin)
