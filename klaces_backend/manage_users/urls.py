from django.urls import path
from .views import UserRegisterView
from .views import UserLoginView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),

]
