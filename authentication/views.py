from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import UserSerializer, RegisterSerializer
from .models import VerificationToken
from django.utils.translation import gettext as _
from rest_framework.exceptions import ValidationError
from .models import User


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            user.save()
            user_data = UserSerializer(user).data
            return Response(user_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data)

        if serializer.is_valid():
            if user.is_staff:
                print("hello")
                serializer.save(is_staff=True)
            else:
                serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)  
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:  
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            serializer = UserSerializer(user)
            return Response({
                'user': serializer.data,
                'token': token.key
            }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        if not user.check_password(old_password):
            raise ValidationError(_('Old password is not correct.'))
        if not new_password or len(new_password) < 8:
            return Response({'error': 'New password must be at least 8 characters long.'}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_password:
            return Response({'error': 'New passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        Token.objects.filter(user=user).delete()
        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
    
from google.oauth2 import id_token
from google.auth.transport.requests import Request
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.conf import settings



class GoogleLoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        id_token_value = request.data.get('id_token')



        # List of allowed Client IDs (for web, Android, iOS)
        allowed_client_ids = [
            settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            settings.MOBILE_CLIENT_ID,
        ]

        try:
            # Verify the ID token with Google's servers
            id_info = id_token.verify_oauth2_token(id_token_value, Request())

            # Check if the audience matches any of the allowed client IDs
            if id_info['aud'] not in allowed_client_ids:
                raise ValueError(f"Token has wrong audience {id_info['aud']}")

            # Extract user information from the token
            email = id_info.get('email')
            name = id_info.get('name')

            return Response({'email': email, 'name': name, 'message': 'Token verified successfully'})

        except ValueError as e:
            return Response({'error': 'Invalid token', 'details': str(e)}, status=400)
