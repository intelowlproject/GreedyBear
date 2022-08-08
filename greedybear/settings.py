# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
# flake8: noqa
import logging
import os
from pathlib import Path

from django.core.management.utils import get_random_secret_key
from elasticsearch import Elasticsearch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_STATIC_PATH = os.path.join(BASE_DIR, "static/")

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("DJANGO_SECRET", None) or get_random_secret_key()

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", False) == "True"

DJANGO_LOG_DIRECTORY = "/var/log/greedybear/django"
MOCK_CONNECTIONS = os.environ.get("MOCK_CONNECTIONS", False) == "True"
ELASTIC_ENDPOINT = os.getenv("ELASTIC_ENDPOINT", "")
if ELASTIC_ENDPOINT:
    ELASTIC_ENDPOINT = ELASTIC_ENDPOINT.split(",")
else:
    print(
        "WARNING!!! You need an ElasticSearch TPOT instance to have the Greedybear to work correctly."
    )
    if not DEBUG:
        print("you are in production mode: closing the application")
        exit(9)

if ELASTIC_ENDPOINT:
    ELASTIC_CLIENT = Elasticsearch(
        ELASTIC_ENDPOINT,
        maxsize=20,
        retry_on_timeout=True,
        timeout=30,
    )
else:
    ELASTIC_CLIENT = None

SLACK_TOKEN = os.environ.get("SLACK_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "")

VERSION = "0.2.1"
# drf-spectacular
SPECTACULAR_SETTINGS = {
    "TITLE": "GreedyBear API specification",
    "VERSION": VERSION,
}

ALLOWED_HOSTS = ["*"]

# Application definition
INSTALLED_APPS = [
    # default
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_spectacular",
    "api.apps.ApiConfig",
    "greedybear.apps.GreedyBearConfig",
    "certego_saas",
]

REST_FRAMEWORK = {"DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema"}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "greedybear.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            os.path.join(BASE_STATIC_PATH, "reactapp"),
        ],
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

WSGI_APPLICATION = "greedybear.wsgi.application"

DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_NAME = os.environ.get("DB_NAME", "greedybear_db")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
    },
}

BROKER_URL = os.environ.get("BROKER_URL", "amqp://guest:guest@rabbitmq:5672")
RESULT_BACKEND = "django-db"


# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
STATIC_ROOT = BASE_STATIC_PATH
STATICFILES_DIRS = [
    ("reactapp", "/var/www/reactapp"),
]


INFO_OR_DEBUG_LEVEL = "DEBUG" if DEBUG else "INFO"
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "stdfmt": {
            "format": "%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s",
        },
    },
    "handlers": {
        "celery": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/celery.log",
            "formatter": "stdfmt",
        },
        "celery_error": {
            "level": "ERROR",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/celery_errors.log",
            "formatter": "stdfmt",
        },
        "elasticsearch": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/elasticsearch.log",
            "formatter": "stdfmt",
        },
        "api": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api.log",
            "formatter": "stdfmt",
        },
        "api_error": {
            "level": "ERROR",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api_errors.log",
            "formatter": "stdfmt",
        },
        "gui": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/gui.log",
            "formatter": "stdfmt",
        },
        "gui_error": {
            "level": "ERROR",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/gui_errors.log",
            "formatter": "stdfmt",
        },
        "greedybear": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/greedybear.log",
            "formatter": "stdfmt",
        },
        "greedybear_error": {
            "level": "ERROR",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/greedybear_errors.log",
            "formatter": "stdfmt",
        },
        "django_unhandled_errors": {
            "level": "ERROR",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/django_errors.log",
            "formatter": "stdfmt",
        },
    },
    "loggers": {
        "celery": {
            "handlers": ["celery", "celery_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "elasticsearch": {
            "handlers": ["elasticsearch"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "api": {
            "handlers": ["api", "api_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "gui": {
            "handlers": ["gui", "gui_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "greedybear": {
            "handlers": ["greedybear", "greedybear_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "django": {
            "handlers": ["django_unhandled_errors"],
            "level": "ERROR",
            "propagate": True,
        },
    },
}

# disable some really noisy logs
es_logger = logging.getLogger("elasticsearch")
if DEBUG:
    es_logger.setLevel(logging.INFO)
else:
    es_logger.setLevel(logging.WARNING)
