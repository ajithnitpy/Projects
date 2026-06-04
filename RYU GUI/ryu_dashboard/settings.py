"""
Django settings for Ryu SDN Controller Dashboard.

Supports:
  - SQLite (default) or PostgreSQL via DB_ENGINE env var
  - Django built-in session auth + DRF SimpleJWT token auth
  - Channels (WebSocket) for live updates from Ryu
"""
from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-secret-key-change-me")
DEBUG = os.getenv("DJANGO_DEBUG", "True").lower() == "true"
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # 3rd-party
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "channels",
    # local apps
    "dashboard",
    "api",
    "gnn_security",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ryu_dashboard.urls"

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
                "dashboard.context_processors.controller_status",
            ],
        },
    },
]

WSGI_APPLICATION = "ryu_dashboard.wsgi.application"
ASGI_APPLICATION = "ryu_dashboard.asgi.application"

# ---------------------------------------------------------------------------
# Database — SQLite by default, PostgreSQL when DB_ENGINE=postgres
# ---------------------------------------------------------------------------
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").lower()
if DB_ENGINE == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "ryu_dashboard"),
            "USER": os.getenv("POSTGRES_USER", "ryu"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", "ryu"),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# ---------------------------------------------------------------------------
# REST Framework — both session and JWT token auth supported
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticatedOrReadOnly",
    ),
    "DEFAULT_PAGINATION_CLASS":
        "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
}

# ---------------------------------------------------------------------------
# Channels — Redis in prod, in-memory in dev
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "")
if REDIS_URL:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {"hosts": [REDIS_URL]},
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }

# ---------------------------------------------------------------------------
# Auth, i18n, static
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

CORS_ALLOW_ALL_ORIGINS = DEBUG
CSRF_TRUSTED_ORIGINS = [
    f"http://{h}" for h in ALLOWED_HOSTS if h not in ("*",)
] + [
    f"https://{h}" for h in ALLOWED_HOSTS if h not in ("*",)
]

# ---------------------------------------------------------------------------
# Ryu controller integration
# ---------------------------------------------------------------------------
RYU_REST_URL = os.getenv("RYU_REST_URL", "http://127.0.0.1:8080")
RYU_OFCTL_URL = os.getenv("RYU_OFCTL_URL", "http://127.0.0.1:8080")
CUSTOM_RYU_APP_URL = os.getenv("CUSTOM_RYU_APP_URL", "http://127.0.0.1:8081")
RYU_WS_URL = os.getenv("RYU_WS_URL", "ws://127.0.0.1:8080/v1.0/topology/ws")

# ---------------------------------------------------------------------------
# GNN security
# ---------------------------------------------------------------------------
GNN_MODEL_PATH = os.getenv("GNN_MODEL_PATH", "gnn_security/checkpoints/hybrid_gcn_gat.pt")
GNN_THREAT_THRESHOLD = float(os.getenv("GNN_THREAT_THRESHOLD", "0.75"))
GNN_MITIGATION_ENABLED = os.getenv("GNN_MITIGATION_ENABLED", "True").lower() == "true"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
