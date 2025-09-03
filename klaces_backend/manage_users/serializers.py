from rest_framework import serializers
from .models import User,OneTimePasscode
from django.contrib.auth import authenticate, login
from rest_framework.exceptions import AuthenticationFailed
from .utils import generate_otp
from django.utils import timezone
from datetime import timedelta
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from .utils import generate_otp, send_normal_email

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=8, write_only=True)
    password_confirm = serializers.CharField(max_length=68, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'full_name', 'phone_number', 'profile_picture', 'password', 'password_confirm']

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password_confirm'):
            raise serializers.ValidationError("Passwords do not match!")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        return User.objects.create_user(**validated_data)

class VerifyEmailSerializer(serializers.ModelSerializer):
    code = serializers.CharField(max_length=8)

    class Meta:
        model = OneTimePasscode
        fields = ['code']

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=68, write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    full_name = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')

        user = authenticate(request, username=email, password=password)
        if not user:
            raise AuthenticationFailed("Invalid credentials, try again")
        
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")

        tokens = user.tokens()
        login(request, user)

        return {
            'email': user.email,
            'full_name': user.get_full_name,
            'access_token': str(tokens.get('access')),
            'refresh_token': str(tokens.get('refresh')),
        }


class PasswordResetRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email).first()

        if not user:
            raise serializers.ValidationError("No user found with this email address.")

        # Supprimer les anciens OTP
        OneTimePasscode.objects.filter(user=user).delete()

        # Générer un nouveau code OTP
        code = generate_otp()
        expires_at = timezone.now() + timezone.timedelta(minutes=10)
        OneTimePasscode.objects.create(user=user, code=code, expires_at=expires_at)

        # Envoyer l'email
        email_body = f"Hi {user.full_name or 'user'},\n\nUse this code to reset your password: {code}\n\nThis code will expire in 10 minutes."
        send_normal_email({
            'email_body': email_body,
            'email_subject': 'Your code for password reset',
            'to_email': user.email
        })

        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        code = attrs.get('code')
        try:
            otp_record = OneTimePasscode.objects.get(code=code)
        except OneTimePasscode.DoesNotExist:
            raise serializers.ValidationError("Invalid code.")

        if otp_record.is_expired():
            raise serializers.ValidationError("Code has expired.")

        user_id = otp_record.user.id
        attrs['uidb64'] = urlsafe_base64_encode(smart_bytes(user_id))
        attrs['token'] = PasswordResetTokenGenerator().make_token(otp_record.user)
        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, write_only=True)
    confirm_password = serializers.CharField(min_length=6, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        uidb64 = attrs.get('uidb64')
        token = attrs.get('token')

        if password != confirm_password:
            raise AuthenticationFailed("Passwords do not match.")

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
        except Exception:
            raise AuthenticationFailed("Invalid reset element.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationFailed("Token is invalid or has expired.")

        user.set_password(password)
        user.save()

        return {"message": "Password reset successful."}
