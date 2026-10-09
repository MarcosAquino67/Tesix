import os
import secrets

def _flag(nombre, default='0'):
    return os.environ.get(nombre, default).strip().lower() in ('1', 'true', 'yes', 'on')

def _env_bool(nombre, default=False):
    valor = os.environ.get(nombre)
    if valor is None:
        return default
    return valor.strip().lower() in ('1', 'true', 'yes', 'on')

class Config:
    ENTORNO = os.environ.get('FLASK_ENV', 'production')

    # Clave secreta: en produccion debe venir de variable de entorno.
    # Si falta, se genera una aleatoria por proceso (mejor que una clave
    # debil conocida: invalida sesiones antes que exponerlas).
    _secret = os.environ.get('SECRET_KEY', '').strip()
    if _secret:
        SECRET_KEY = _secret
    elif ENTORNO == 'production':
        SECRET_KEY = secrets.token_hex(32)
    else:
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
        if ENTORNO == 'production':
            raise RuntimeError('DATABASE_URL (or DB_USER/DB_PASS) is required in production')
        SQLALCHEMY_DATABASE_URI = 'sqlite:///scanner_dev.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Sesiones: Secure solo tiene sentido con HTTPS, se activa por variable.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    PERMANENT_SESSION_LIFETIME = 1800

    # Agente local de escaneo (red LAN). El token SOLO se configura por
    # variable de entorno (admite varios separados por coma).
    AGENTE_TOKEN = os.environ.get('AGENTE_TOKEN', '')
    AGENTE_HABILITADO = _flag('AGENTE_HABILITADO')

    # Escaneos en segundo plano: la API responde con el id del trabajo y el
    # frontend consulta el progreso. En tests se ejecuta en linea.
    ESCANEO_EN_SEGUNDO_PLANO = _flag('ESCANEO_EN_SEGUNDO_PLANO', '1')

    # Anti-SSRF: bloquear URLs privadas/locales en el analisis web.
    PERMITIR_URLS_PRIVADAS = _flag('PERMITIR_URLS_PRIVADAS')

    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_SCAN = '10 per minute'

    # SMTP (verificacion en dos pasos y recuperacion de contrasena).
    # Sin configurar: en desarrollo los codigos/enlaces se registran en el log.
    SMTP_HOST = os.environ.get('SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SMTP_PORT') or 587)
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASS = os.environ.get('SMTP_PASS', '')
    SMTP_FROM = os.environ.get('SMTP_FROM', '') or os.environ.get('SMTP_USER', '')
    TFA_CODIGO_MINUTOS = int(os.environ.get('TFA_CODIGO_MINUTOS', '10'))
    TFA_MAX_INTENTOS = int(os.environ.get('TFA_MAX_INTENTOS', '5'))
    RESET_TOKEN_MINUTOS = int(os.environ.get('RESET_TOKEN_MINUTOS', '30'))
    RESET_MAX_INTENTOS = int(os.environ.get('RESET_MAX_INTENTOS', '5'))
