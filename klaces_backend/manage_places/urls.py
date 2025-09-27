from django.urls import path
from .views import Api_place, get_one_place

urlpatterns = [
 path("", Api_place.as_view()),
 path("<int:id_place>", get_one_place)
]