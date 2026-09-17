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

    DATABASE_URL = os.environ.get('DATABASE_URL')

    if DATABASE_URL:
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        if DATABASE_URL.startswith('postgresql://'):
            DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg2://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    elif DB_USER and DB_PASS:
        SQLALCHEMY_DATABASE_URI = (
            f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4'
        )
    else:
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError('DATABASE_URL (or DB_USER/DB_PASS) is required in production')
        SQLALCHEMY_DATABASE_URI = 'sqlite:///scanner_dev.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_SCAN = '10 per minute'

    # SMTP (verificacion en dos pasos por email). Si no esta configurado,
    # el codigo se registra en el log (modo desarrollo) y no se envia email.
    # Con Gmail: SMTP_HOST=smtp.gmail.com, SMTP_PORT=587 y SMTP_PASS es una
    # "Contrasena de aplicacion" (gratis, se genera en tu cuenta Google).
    SMTP_HOST = os.environ.get('SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASS = os.environ.get('SMTP_PASS', '')
    SMTP_FROM = os.environ.get('SMTP_FROM', '') or os.environ.get('SMTP_USER', '')
    TFA_CODIGO_MINUTOS = int(os.environ.get('TFA_CODIGO_MINUTOS', '10'))
    TFA_MAX_INTENTOS = int(os.environ.get('TFA_MAX_INTENTOS', '5'))

    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 1800
