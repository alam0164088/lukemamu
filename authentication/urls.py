# authentication/urls.py
from .views import CustomAppleLogin, DeleteAccountView, InitialAdminSignUpView
from django.urls import path
from .views import (
    RegisterView,
    SendOTPView,
    ResendOTPView,
    VerifyOTPView,
    LoginView,
    RefreshTokenView,
    LogoutView,
    ForgotPasswordView,
    VerifyResetOTPView,
    ResetPasswordConfirmView,
    ChangePasswordView,
    Enable2FAView,
    Verify2FAView,
    MeView,
    GoogleIdTokenLogin
  # ← এটা আবার add করো
  

   
)

urlpatterns = [
    # Registration & OTP
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/otp/send/', SendOTPView.as_view(), name='send-otp'),
    path('auth/otp/resend/', ResendOTPView.as_view(), name='resend-otp'),
    path('auth/otp/verify/', VerifyOTPView.as_view(), name='verify-otp'),

    # Login & Tokens
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/token/refresh/', RefreshTokenView.as_view(), name='refresh-token'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    # Password Management
    path('auth/password/forgot/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('auth/password/reset/verify/', VerifyResetOTPView.as_view(), name='verify-reset-otp'),
    path('auth/password/reset/confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    path('auth/password/change/', ChangePasswordView.as_view(), name='change-password'),

    # Two-Factor Authentication (2FA)
    path('auth/2fa/enable/', Enable2FAView.as_view(), name='enable-2fa'),
    path('auth/2fa/verify/', Verify2FAView.as_view(), name='verify-2fa'),

    # User Profile
    path('auth/me/', MeView.as_view(), name='me'),
    

    # Social logins
    path('auth/google/id-token/', GoogleIdTokenLogin.as_view(), name='google-id-token-login'),

    path('dj-rest-auth/apple/', CustomAppleLogin.as_view(), name='apple_login'),
    path("profile/delete/",DeleteAccountView.as_view(), name="delete-profile"),
    
    # for initial admin creation (one-time)
    path('auth/admin/initial-signup/', InitialAdminSignUpView.as_view(), name='initial-admin-signup'),





]