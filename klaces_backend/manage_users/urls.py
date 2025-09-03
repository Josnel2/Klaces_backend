from django.urls import path
from .views import  PasswordResetConfirmView, UserRegisterView, VerifyEmailView, LoginUserView,UpdateProfileView,UserDetailView,PasswordResetRequestView,SetNewPasswordView      
urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('update-profile/<int:pk>/', UpdateProfileView.as_view(), name='update-profile'),
    path('user-detail/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),

]

