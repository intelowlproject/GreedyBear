from django.urls import path

from api.views import feeds

urlpatterns = [
    path("feeds/<str:feed_type/<str:attack_type>/<str:age>.<str:format_>", feeds),
]
