from django.urls import path

from api.views import feeds

urlpatterns = [
    path("feeds/<str:age>/<str:attack_type>/<str:format>", feeds),
]
