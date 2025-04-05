from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from .models import VerificationToken

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email','is_active','is_staff','image']

    def update(self, instance, validated_data):
        validated_data.pop('is_staff', None)
        return super().update(instance, validated_data)
   

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()

        # # Generate a verification token
        # token = get_random_string(length=32)
        # VerificationToken.objects.create(user=user, token=token)

        # # Send verification email
        # verification_link = f"http://localhost:8000/auth/verify-email/{token}/"
        # send_mail(
        #     'Verify Your Email',
        #     f'Please click the link to verify your email: {verification_link}',
        #     'from@example.com',
        #     [user.email],
        #     fail_silently=False,
        # )

        return user