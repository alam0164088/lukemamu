# authentication/urls.py
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
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
    GoogleIdTokenLogin,
    CustomAppleLogin,
    DeleteAccountView,
    InitialAdminSignUpView,
)
from .views_admin import (
    GetUserProfileView,
    GetAllUsersView,
    GetUsersByRoleView,
    EditAttorneyTierView,
)

urlpatterns = [
    # Registration & OTP
    path('auth/register/', csrf_exempt(RegisterView.as_view()), name='register'),
    path('auth/otp/send/', csrf_exempt(SendOTPView.as_view()), name='send-otp'),
    path('auth/otp/resend/', csrf_exempt(ResendOTPView.as_view()), name='resend-otp'),
    path('auth/otp/verify/', csrf_exempt(VerifyOTPView.as_view()), name='verify-otp'),

    # Single Login & Tokens (user + attorney same endpoint)
    path('auth/login/', csrf_exempt(LoginView.as_view()), name='login'),
    path('auth/token/refresh/', csrf_exempt(RefreshTokenView.as_view()), name='refresh-token'),
    path('auth/logout/', csrf_exempt(LogoutView.as_view()), name='logout'),

    # Password Management
    path('auth/password/forgot/', csrf_exempt(ForgotPasswordView.as_view()), name='forgot-password'),
    path('auth/password/reset/verify/', csrf_exempt(VerifyResetOTPView.as_view()), name='verify-reset-otp'),
    path('auth/password/reset/confirm/', csrf_exempt(ResetPasswordConfirmView.as_view()), name='reset-password-confirm'),
    path('auth/password/change/', csrf_exempt(ChangePasswordView.as_view()), name='change-password'),

    # Two-Factor Authentication (2FA)
    path('auth/2fa/enable/', csrf_exempt(Enable2FAView.as_view()), name='enable-2fa'),
    path('auth/2fa/verify/', csrf_exempt(Verify2FAView.as_view()), name='verify-2fa'),

    # User Profile
    path('auth/me/', csrf_exempt(MeView.as_view()), name='me'),

    # Social logins
    path('auth/google/id-token/', csrf_exempt(GoogleIdTokenLogin.as_view()), name='google-id-token-login'),
    path('dj-rest-auth/apple/', csrf_exempt(CustomAppleLogin.as_view()), name='apple_login'),
    path('profile/delete/', csrf_exempt(DeleteAccountView.as_view()), name='delete-profile'),

    # Initial admin creation
    path('auth/admin/initial-signup/', csrf_exempt(InitialAdminSignUpView.as_view()), name='initial-admin-signup'),

    # Admin Dashboard - User Management
    path('admin/users/', csrf_exempt(GetAllUsersView.as_view()), name='get-all-users'),
    path('admin/attorneys/', csrf_exempt(GetUsersByRoleView.as_view()), name='get-all-attorneys'),
    path('admin/attorneys/<int:attorney_id>/tier/', csrf_exempt(EditAttorneyTierView.as_view()), name='edit-attorney-tier'),
]