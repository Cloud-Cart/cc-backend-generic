"""
Django settings for CloudCart project.

Generated by 'django-admin startproject' using Django 5.1.2.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path

import environ

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
env.read_env(BASE_DIR / '.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env.str('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env.bool('DEBUG', default=True)

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[])

# Application definition

HAS_MULTI_TYPE_TENANTS = True
MULTI_TYPE_DATABASE_FIELD = 'type'
SHOW_PUBLIC_IF_NO_TENANT_FOUND = True

TENANT_TYPES = {
    "public": {
        "APPS": [
            'django_tenants',
            'Tenants',
            'django.contrib.messages',
            'django.contrib.contenttypes',
            'django.contrib.sites',
            'django.contrib.staticfiles',
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.admin',
            'Users.apps.UsersConfig',
            'UserAuth.apps.UserauthConfig',
        ],
        "URLCONF": "CloudCart.urls_public",  # url for the public type here
    },
    "stores": {
        "APPS": [
            'Users.apps.UsersConfig',
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.admin',
            'django.contrib.sessions',
            'django.contrib.messages',
            'UserAuth.apps.UserauthConfig',
            'TenantUsers.apps.TenantusersConfig',
            'TenantEmails.apps.TenantemailsConfig'
        ],
        "URLCONF": "CloudCart.urls_stores",
    },
}

INSTALLED_APPS = []
for schema in TENANT_TYPES:
    INSTALLED_APPS += [app for app in TENANT_TYPES[schema]["APPS"] if app not in INSTALLED_APPS]

MIDDLEWARE = [
    'django_tenants.middleware.main.TenantMainMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'CloudCart.urls_public'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'CloudCart.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': env.str('DATABASE_NAME'),
        'USER': env.str('DATABASE_USER'),
        'PASSWORD': env.str('DATABASE_PASSWORD'),
        'HOST': env.str('DATABASE_HOST'),
        'PORT': env.str('DATABASE_PORT'),
    }
}

DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)

TENANT_MODEL = "Tenants.Tenant"

TENANT_DOMAIN_MODEL = "Tenants.Domain"

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Default rest frame work settings
# https://www.django-rest-framework.org/api-guide/settings/

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning'
}

# Default user model
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-user-model

AUTH_USER_MODEL = 'Users.User'

SITE_ID = 1

# Celery settings
CELERY_BROKER_URL = env.str('CELERY_BROKER_URL')

# Email settings
# https://docs.djangoproject.com/en/5.1/topics/email/#email-backends

EMAIL_BACKEND = env.str('EMAIL_BACKEND')
EMAIL_FILE_PATH = env.str('EMAIL_FILE_PATH', default=BASE_DIR / 'emails')
EMAIL_HOST = env.str('EMAIL_HOST', default=None)
EMAIL_PORT = env.int('EMAIL_PORT', default=25)
EMAIL_HOST_USER = env.str('EMAIL_HOST_USER', default=None)
EMAIL_HOST_PASSWORD = env.str('EMAIL_HOST_PASSWORD', default=None)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
EMAIL_USE_SSL = env.bool('EMAIL_USE_SSL', default=True)
EMAIL_TIMEOUT = env.int('EMAIL_TIMEOUT', default=None)
EMAIL_SSL_KEYFILE = env.str('EMAIL_SSL_KEYFILE', default=None)
EMAIL_SSL_CERTFILE = env.str('EMAIL_SSL_CERTFILE', default=None)
DEFAULT_FROM_EMAIL = env.str('DEFAULT_FROM_EMAIL', None)
