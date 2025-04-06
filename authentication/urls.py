
from django.urls import path, include
from authentication.views import RegisterView, LoginView, LogoutView,ChangePasswordView,ProfileUpdateView,GoogleLoginAPIView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='cregister'),
    path('profile-update/', ProfileUpdateView.as_view(), name='sprofile-update'),
    # path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('google-login/', GoogleLoginAPIView.as_view(), name='google-login'),
]