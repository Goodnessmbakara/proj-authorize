from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/student/', views.RegisterView.as_view(), name='register-student'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('email-verify', views.VerifyEmailView.as_view(), name='email-verify'),
    path('resend-verification-email/', views.ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    path('delete-account/', views.DeleteAccountView.as_view(), name='delete-account'),
    path('forgot-password/', views.requestForgotPasswordPasscode, name='request-forgot-password-passcode'),
]
