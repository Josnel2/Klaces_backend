from django.shortcuts import render
from .models import User, OneTimePasscode
from .serializers import PasswordResetRequestSerializer, ResetPasswordSerializer, UserLoginSerializer, UserRegisterSerializer, VerifyEmailSerializer
from rest_framework.generics import GenericAPIView
from rest_framework import status
from rest_framework.response import Response
from .utils import send_otp_email
import logging
from rest_framework.permissions import AllowAny
from rest_framework.generics import RetrieveAPIView
from .permissions import IsUser, IsManager

from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from rest_framework.views import APIView

from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings

logger = logging.getLogger(__name__)

class UserRegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()

            send_otp_email(user)

            return Response({
                "data": serializer.data,
                "message": f"Utilisateur {user.full_name} créé avec succès. "
                           f"Un code OTP a été envoyé à votre email.",
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyEmailView(GenericAPIView):
    serializer_class = VerifyEmailSerializer

    def post(self, request):
        code = request.data.get("code")
        try:
            user_code_obj = OneTimePasscode.objects.get(code=code)
            user = user_code_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message' : 'account email verified succesfully'
                }, status=status.HTTP_200_OK)
            return Response({
                'message' : 'code us invalid user already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePasscode.DoesNotExist:
            return Response({
                'message':'passcode not provided'
            }, status=status.HTTP_404_NOT_FOUND)
        
class LoginUserView(GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny] 
    def post(self, request):
       

        serializer = self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
class UserDetailView(RetrieveAPIView):
    queryset = User.objects.all()  
    serializer_class = UserRegisterSerializer  
    permission_classes = [IsUser, IsManager]

class ForgotPasswordView(GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Supprimer l'ancien OTP s'il existe
        OneTimePasscode.objects.filter(user=user).delete()

        # Générer et enregistrer le nouvel OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')
        OneTimePasscode.objects.create(user=user, code=otp)
        send_mail(
            "Your OTP Code",
            f"Your OTP code is {otp}",
            "noreply@klaces.com",
            [email],
            fail_silently=False,
        )

        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP and send email
        otp = get_random_string(length=6, allowed_chars='0123456789')
        OneTimePasscode.objects.create(user=user, code=otp)
        send_mail(
            "Your OTP Code",
            f"Your OTP code is {otp}",
            "noreply@klaces.com",
            [email],
            fail_silently=False,
        )

        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)


class ResetPasswordView(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        email = request.data.get("email")
        # otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not new_password:
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # otp_obj = OneTimePasscode.objects.filter(user=user).first()
        # if not otp_obj or otp_obj.is_expired():
        #     return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.reset_password_token = None
        user.save()

        return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)

# class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        form = PasswordResetForm({'email': email})
        if form.is_valid():
            user = User.objects.filter(email=email).first()
            if user:
                # Generate password reset token
                token = default_token_generator.make_token(user)
                # Send email with password reset link
                send_mail(
                    "Password Reset",
                    f"Click the link to reset your password: {settings.FRONTEND_URL}/reset-password/{token}",
                    "noreply@klaces.com",
                    [email],
                    fail_silently=False,
                )
                return Response({"message": "Password reset email sent"}, status=status.HTTP_200_OK)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Invalid email"}, status=status.HTTP_400_BAD_REQUEST)
