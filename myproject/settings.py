import os
from pathlib import Path
from datetime import timedelta
import environ
import dj_database_url
import logging

# suppress noisy PIL/Pillow output in console
logging.getLogger('PIL').setLevel(logging.WARNING)
logging.getLogger('PIL.PngImagePlugin').setLevel(logging.WARNING)
logging.getLogger('PIL.JpegImagePlugin').setLevel(logging.WARNING)

# ------------------------------
# Base directory
# ------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Load environment variables
# ------------------------------
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ["*"]),
    EMAIL_PORT=(int, 587),
    EMAIL_USE_TLS=(bool, True)
)


def _mask_secret(value: str | None, keep: int = 4) -> str:
    """Return a masked version of a secret for safe logging.

    Examples:
        'abcd...wxyz' when keep=4
    """
    try:
        if not value:
            return "<not set>"
        s = str(value)
        if len(s) <= keep * 2 + 3:
            # short secret -> partially mask
            return s[:keep] + "..."
        return f"{s[:keep]}...{s[-keep:]}"
    except Exception:
        return "<masked>"





env_file = BASE_DIR / ".env"
if env_file.exists():
    print(f".env file found, loading...")
    environ.Env.read_env(str(env_file))
else:
    print(".env file not found, using system environment variables")

# ------------------------------
# Core settings
# ------------------------------
SECRET_KEY = env("DJANGO_SECRET_KEY", default="unsafe-secret-key")
DEBUG = env.bool("DEBUG", default=True)


ALLOWED_HOSTS = ['api.helpmespeak.app','10.10.7.19','15.236.180.222', 'localhost', '127.0.0.1']

# When developing and DEBUG=True, allow binding to 0.0.0.0 so incoming
# requests that use that host (e.g., when you visit http://0.0.0.0:8001)
# are accepted. This is intentionally limited to development.
if DEBUG:
    try:
        if '0.0.0.0' not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append('0.0.0.0')
    except Exception:
        # In case ALLOWED_HOSTS was set from env to a non-list, fallback to a permissive setting in dev
        ALLOWED_HOSTS = ['0.0.0.0']



JWT_SECRET = env("JWT_SECRET", default=SECRET_KEY)

# ------------------------------
# Installed apps
# ------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",

    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "dj_rest_auth",
    "dj_rest_auth.registration",
    "rest_framework_simplejwt",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.apple",
    

    "authentication",
    'attorney',
    
]

SITE_ID = 1

# ------------------------------
# Middleware
# ------------------------------
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",   # ← আগে
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware", # ← পরে
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]
# ------------------------------
# URLs & WSGI
# ------------------------------
ROOT_URLCONF = "myproject.urls"
WSGI_APPLICATION = "myproject.wsgi.application"
AUTH_USER_MODEL = "authentication.User"

# ------------------------------
# Templates
# ------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ------------------------------
# Database
# ------------------------------
DATABASES = {
    "default": dj_database_url.config(
        default=env(
            "DATABASE_URL",
            default=f"sqlite:///{BASE_DIR / 'lukemama.sqlite3'}"
        ),
        conn_max_age=600,
    )
}


# ------------------------------
# REST Framework
# ------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.AllowAny",
    ),
}

# ------------------------------
# JWT Settings
# ------------------------------
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=300),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=3000),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "SIGNING_KEY": JWT_SECRET,
}

# ------------------------------
# Authentication Backends
# ------------------------------
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# ------------------------------
# Static & Media
# ------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"


# ------------------------------
# Email (Development - Console Backend)
# ------------------------------
# ------------------------------
# Email Settings (Development vs Production)
# ------------------------------
if DEBUG:
    # ডেভেলপমেন্টে: ইমেইল টার্মিনালে প্রিন্ট হবে (কোনো আসল ইমেইল যাবে না)
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    print("Email backend: Console (emails will print in terminal)")
else:
    # প্রোডাকশনে: আসল SMTP ব্যবহার করুন (PrivateEmail.com)
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = env("EMAIL_HOST")
    EMAIL_PORT = env.int("EMAIL_PORT", default=465)
    EMAIL_USE_SSL = env.bool("EMAIL_USE_SSL", default=True)
    EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=False)
    EMAIL_HOST_USER = env("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
    DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="no-reply@helpmespeak.app")

# 
# ------------------------------
# CORS
# ------------------------------
CORS_ALLOW_ALL_ORIGINS = True

# ------------------------------
# Logging
# ------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "DEBUG"},
}

# ------------------------------
# API Keys
# ------------------------------
GOOGLE_API_KEY = env("GOOGLE_API_KEY", default=None)
OPENAI_API_KEY = env("OPENAI_API_KEY", default=None)

if not GOOGLE_API_KEY:
    print("WARNING: GOOGLE_API_KEY not configured!")
else:
    print(f"SUCCESS: GOOGLE_API_KEY loaded: {_mask_secret(GOOGLE_API_KEY)}")

# ------------------------------
# Google & Apple OAuth
# ------------------------------
GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = env("GOOGLE_REDIRECT_URI")

# ------------------------------
# Apple OAuth Settings
# ------------------------------
APPLE_BUNDLE_ID = env("APPLE_BUNDLE_ID")
APPLE_TEAM_ID = env("APPLE_TEAM_ID")
APPLE_KEY_ID = env("APPLE_KEY_ID")
APPLE_CLIENT_ID = env("APPLE_CLIENT_ID")
APPLE_CALLBACK_URL = env("APPLE_CALLBACK_URL")

# ------------------------------
# SOCIALACCOUNT_PROVIDERS
# ------------------------------
SOCIALACCOUNT_PROVIDERS = {
    'apple': {
        'APP': {
            'client_id': APPLE_CLIENT_ID,
            'secret': '',  # ← views.py থেকে generate হবে
            'key': APPLE_KEY_ID,
        },
        'SCOPE': ['name', 'email'],
        'AUTH_PARAMS': {'response_mode': 'form_post'}
    },
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'offline'},
    }
}

# ------------------------------
# Apple IAP & Google Service Account
# ------------------------------
APPLE_SHARED_SECRET = env("APPLE_SHARED_SECRET", default="")
GOOGLE_PACKAGE_NAME = env("GOOGLE_PACKAGE_NAME", default="")
GOOGLE_SERVICE_ACCOUNT_FILE = env("GOOGLE_SERVICE_ACCOUNT_FILE", default="")

# ------------------------------
# Debug (শুধু ডেভেলপমেন্টে)
# ------------------------------
if DEBUG:
    # For safety, avoid printing full secrets. Show masked values instead.
    logging.getLogger(__name__).info("SECRET_KEY: %s", _mask_secret(SECRET_KEY))
    logging.getLogger(__name__).info("JWT_SECRET: %s", _mask_secret(JWT_SECRET))
    logging.getLogger(__name__).info("APPLE_CALLBACK_URL = %s", _mask_secret(APPLE_CALLBACK_URL))



# ------------------------------
# Apple Private Key (from p.txt)
# ------------------------------
APPLE_PRIVATE_KEY = env("APPLE_PRIVATE_KEY", default="").replace("\\n", "\n")

