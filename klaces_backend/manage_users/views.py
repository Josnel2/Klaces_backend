from django.shortcuts import render
from .models import User, OneTimePasscode
from .serializers import UserRegisterSerializer
from rest_framework.generics import GenericAPIView
from rest_framework import status
from rest_framework.response import Response
from .utils import send_otp_email
import logging

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
