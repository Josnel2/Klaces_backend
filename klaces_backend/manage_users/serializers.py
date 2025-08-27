from rest_framework import serializers
from .models import User

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


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']

    def validate(self, attrs):
        user = User.objects.filter(email=attrs.get('email')).first()
        if not user:
            raise serializers.ValidationError("User not found!")
        if not user.check_password(attrs.get('password')):
            raise serializers.ValidationError("Incorrect password!")
        return attrs
    
    

class UserAccountVerificationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    otp = serializers.CharField(max_length=6, min_length=6)

    class Meta:
        model = User
        fields = ['email', 'otp']

    def validate(self, attrs):
        user = User.objects.filter(email=attrs.get('email')).first()
        if not user:
            raise serializers.ValidationError("User not found!")
        if not user.check_otp(attrs.get('otp')):
            raise serializers.ValidationError("Invalid OTP!")
        return attrs
