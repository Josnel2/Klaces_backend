from django.urls import path
from .views import  UserRegisterView, VerifyEmailView, LoginUserView,UpdateProfileView,UserDetailView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('update-profile/<int:pk>/', UpdateProfileView.as_view(), name='update-profile'),
    path('user-detail/<int:pk>/', UserDetailView.as_view(), name='user-detail'),

]

