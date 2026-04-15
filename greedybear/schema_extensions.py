from certego_saas.apps.auth.backend import TOKEN_COOKIE_NAME
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class CookieTokenAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "certego_saas.apps.auth.backend.CookieTokenAuthentication"
    name = ["cookieTokenAuth", "tokenAuth"]

    def get_security_definition(self, auto_schema):
        return [
            {
                "type": "apiKey",
                "in": "cookie",
                "name": TOKEN_COOKIE_NAME,
            },
            {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
                "description": 'Durin token. Paste as `Token <your-token>` (including the "Token " prefix).',
            },
        ]
