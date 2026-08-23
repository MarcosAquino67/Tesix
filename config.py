import os
import secrets

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'scansensecuredev2024')
    if not SECRET_KEY or SECRET_KEY == '':
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError('SECRET_KEY environment variable is required in production')
        SECRET_KEY = secrets.token_hex(32)

    DB_USER = os.environ.get('DB_USER')
    DB_PASS = os.environ.get('DB_PASS')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_NAME = os.environ.get('DB_NAME', 'scanner_db')

    if not DB_USER or not DB_PASS:
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError('DB_USER and DB_PASS environment variables are required in production')
        SQLALCHEMY_DATABASE_URI = 'sqlite:///scanner_dev.db'
    else:
        SQLALCHEMY_DATABASE_URI = (
            f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4'
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_SCAN = '10 per minute'

    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 1800
