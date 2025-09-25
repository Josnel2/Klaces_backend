from django.urls import path
from .views import Api_place


urlpatterns = [
 path("", Api_place.as_view())
]