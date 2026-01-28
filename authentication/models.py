import uuid
import random
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


class User(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('attorney', 'Attorney'),
        ('admin', 'Admin'),
    )

    email = models.EmailField(_('email address'), unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    full_name = models.CharField(max_length=255, blank=True)

    # Client-specific fields
    location = models.CharField(max_length=255, blank=True)
    preferred_legal_area = models.CharField(max_length=255, blank=True)

    # Authentication & Verification fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    email_verification_code_expires_at = models.DateTimeField(blank=True, null=True)

    password_reset_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_code_expires_at = models.DateTimeField(blank=True, null=True)

    gender = models.CharField(
        max_length=10,
        blank=True,
        choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')]
    )
    is_2fa_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    # ==================== OTP Generation Methods ====================

    def generate_email_verification_code(self):
        """Generate 6-digit OTP for email verification (expires in 5 minutes)"""
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.email_verification_code = code
        self.email_verification_code_expires_at = timezone.now() + timedelta(minutes=5)
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires_at'])
        logger.info(f"Email verification OTP generated for {self.email}: {code}")
        return code

    def generate_password_reset_code(self):
        """Generate 6-digit OTP for password reset (expires in 15 minutes)"""
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.password_reset_code = code
        self.password_reset_code_expires_at = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['password_reset_code', 'password_reset_code_expires_at'])
        logger.info(f"Password reset OTP generated for {self.email}: {code}")
        return code

    def generate_2fa_code(self):
        """Generate 6-digit OTP for 2FA login (reuses email verification fields)"""
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.email_verification_code = code
        self.email_verification_code_expires_at = timezone.now() + timedelta(minutes=5)
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires_at'])
        logger.info(f"2FA OTP generated for {self.email}: {code}")
        return code


class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tokens')
    email = models.EmailField()

    # JWT tokens are long → use TextField instead of CharField(255)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)

    # Optional: for OTP-based login flows
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)

    access_token_expires_at = models.DateTimeField(blank=True, null=True)
    refresh_token_expires_at = models.DateTimeField(blank=True, null=True)
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'refresh_token')

    def __str__(self):
        return f"Token for {self.user.email} ({'Revoked' if self.revoked else 'Active'})"


class PasswordResetSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (timezone.now() - self.created_at) > timedelta(minutes=15)

    def __str__(self):
        return f"Password Reset Session for {self.user.email}"


class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    employee_id = models.CharField(max_length=20, unique=True, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    image = models.ImageField(
        upload_to='profile_images/',
        default='profile_images/default_profile.png'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.employee_id:
            unique_id = uuid.uuid4().hex[:8].upper()
            self.employee_id = f"EMP{unique_id}"
        super().save(*args, **kwargs)


class Attorney(models.Model):
    """Separate table for attorney-specific information.

    Linked one-to-one with `User`. Keeps attorney metadata out of the auth table.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='attorney_profile'
    )
    designation = models.CharField(max_length=255, blank=True)  # e.g. Advocate, Barrister
    area_of_law = models.CharField(max_length=255, blank=True)  # e.g. Criminal, Family, Corporate
    bar_license_number = models.CharField(max_length=128, blank=True)
    bio = models.TextField(blank=True)
    # Additional profile fields useful for display on attorney profile pages
    languages = models.CharField(max_length=255, blank=True, help_text="Comma-separated list of languages")
    experience = models.CharField(max_length=255, blank=True, help_text="Short summary like '8+ years'")
    response_time = models.CharField(max_length=128, blank=True, help_text="E.g. 'Responds in ~2 hrs'")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Attorney profile for {self.user.email}"


class AppleUserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='apple_token')
    id_token = models.TextField()
    email = models.EmailField()
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Apple Token - {self.email}"