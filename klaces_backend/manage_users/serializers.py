from rest_framework import serializers
from .models import User,OneTimePasscode
from django.contrib.auth import authenticate, login
from rest_framework.exceptions import AuthenticationFailed
from django.utils.crypto import get_random_string
from django.core.mail import send_mail


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
    

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        # otp = attrs.get('otp')
        new_password = attrs.get('new_password')

        if not email or not new_password:
            raise serializers.ValidationError("All fields are required")

        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError("User not found")

        # otp_obj = OneTimePasscode.objects.filter(user=user, code=otp).first()
        # if not otp_obj or otp_obj.is_expired():
        #     raise serializers.ValidationError("Invalid or expired OTP")

        return attrs

    def save(self, **kwargs):
        email = self.validated_data['email']
        new_password = self.validated_data['new_password']

        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.reset_password_token = None
        user.save()


class ForgotPasswordSerializer(serializers.Serializer):

    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')

        if not email:
            raise serializers.ValidationError("Email is required")

        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError("User not found")

        return attrs

    def save(self, **kwargs):
        email = self.validated_data['email']

        user = User.objects.get(email=email)
        otp = get_random_string(length=6, allowed_chars='0123456789')
        OneTimePasscode.objects.create(user=user, code=otp)
        send_mail(
            "Your OTP Code",
            f"Your OTP code is {otp}",
            "noreply@klaces.com",
            [email],
            fail_silently=False,
        )


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
