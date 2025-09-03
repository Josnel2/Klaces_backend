from django.shortcuts import render
from .models import User, OneTimePasscode
from .serializers import (
    PasswordResetRequestSerializer, UserLoginSerializer, UserRegisterSerializer,
    VerifyEmailSerializer, SetNewPasswordSerializer, PasswordResetConfirmSerializer
)
from rest_framework.generics import GenericAPIView, RetrieveAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .permissions import IsUser, IsManager
from .utils import send_otp_email
import logging

logger = logging.getLogger(__name__)


class UserRegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        send_otp_email(user)

        return Response({
            "data": serializer.data,
            "message": f"Utilisateur {user.full_name} créé avec succès. "
                       f"Un code OTP a été envoyé à votre email.",
        }, status=status.HTTP_201_CREATED)


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
                return Response({'message': 'Account email verified successfully'}, status=status.HTTP_200_OK)
            return Response({'message': 'Code is invalid or user already verified'}, status=status.HTTP_204_NO_CONTENT)
        except OneTimePasscode.DoesNotExist:
            return Response({'message': 'Passcode not provided'}, status=status.HTTP_404_NOT_FOUND)


class LoginUserView(GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserDetailView(RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [IsUser, IsManager]


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({
            "message": "OTP verified successfully.",
            "uidb64": serializer.validated_data['uidb64'],
            "token": serializer.validated_data['token']
        }, status=status.HTTP_200_OK)


class SetNewPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
