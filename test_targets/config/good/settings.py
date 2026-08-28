"""Correctly configured Django settings. Zero findings expected.

Every setting the bad fixture gets wrong appears here set correctly, so this
file doubles as a check that the rules match the value and not just the name.
"""
import os

DEBUG = False
ALLOWED_HOSTS = ['app.example.com', 'www.example.com']
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = ['https://app.example.com']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

INSTALLED_APPS = ['django.contrib.admin', 'corsheaders']

# Commented-out traps: a scanner that greps without skipping comments fires here.
# DEBUG = True
# ALLOWED_HOSTS = ['*']
