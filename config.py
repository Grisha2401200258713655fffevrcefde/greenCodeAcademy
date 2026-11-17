import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # No public fallback secrets or default database passwords.
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///academy.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 15 * 1024 * 1024

    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'false').lower() == 'true'
    PUBLIC_BASE_URL = os.getenv('PUBLIC_BASE_URL', '').rstrip('/')

    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.yandex.ru')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'true').lower() == 'true'
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'false').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER') or MAIL_USERNAME
    CONTACT_RECIPIENT = os.getenv('CONTACT_RECIPIENT')

    if PUBLIC_BASE_URL and (not PUBLIC_BASE_URL.startswith(('https://', 'http://localhost:', 'http://127.0.0.1:')) or '/' not in PUBLIC_BASE_URL[8:]):
        raise RuntimeError('PUBLIC_BASE_URL must use HTTPS, except for local development.')
    if REQUIRE_EMAIL_VERIFICATION and not PUBLIC_BASE_URL:
        raise RuntimeError('PUBLIC_BASE_URL is required for email verification.')
    if not SECRET_KEY or SECRET_KEY == 'dev_key' or len(SECRET_KEY) < 32:
        raise RuntimeError('Set a strong SECRET_KEY (32+ characters) in the environment.')
