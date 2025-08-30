from django.urls import path
from .views import  ForgotPasswordView, ResetPasswordView, UserRegisterView, VerifyEmailView, PasswordResetConfirmView, LoginUserView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    # path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
]

