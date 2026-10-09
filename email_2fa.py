"""
Verificacion en dos pasos (2FA) por correo electronico.

Flujo:
  1. El usuario registra su email en Configuracion.
  2. Al iniciar sesion (si tiene 2FA activo) se genera un codigo de
     6 digitos, se guarda hasheado con expiracion y se envia por email.
  3. El usuario ingresa el codigo en /verificar-2fa para completar el login.

Usa SMTP estandar (libreria del propio Python, sin dependencias extra).
Con Gmail se usa una "Contrasena de aplicacion" (gratis).
Si SMTP no esta configurado (desarrollo), el codigo se escribe en el
log de la app en vez de enviarse por email.
"""

import logging
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

log = logging.getLogger(__name__)

CODIGO_MINUTOS_DEFAULT = 10
MAX_INTENTOS_DEFAULT = 5

RE_EMAIL = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def normalizar_email(raw):
    """Limpia y valida un email. Devuelve el email en minusculas o None."""
    if not raw:
        return None
    email = str(raw).strip().lower()
    if len(email) > 120:
        return None
    return email if RE_EMAIL.match(email) else None


def enmascarar_email(email):
    """Muestra j***@gmail.com para no exponer el correo completo."""
    if not email or '@' not in email:
        return '****'
    local, dominio = email.split('@', 1)
    return (local[:1] + '***') + '@' + dominio


def generar_codigo():
    """Codigo numerico de 6 digitos criptograficamente seguro."""
    return f'{secrets.randbelow(900000) + 100000}'


def smtp_configurado(host='', user='', password=''):
    return bool(host and user and password)


def enviar_email(destino, asunto, cuerpo,
                 host='', port=587, user='', password='', from_addr=''):
    """Envia un email generico. Devuelve (ok, error).

    Sin SMTP configurado: registra el mensaje en el log (modo desarrollo).
    """
    if not smtp_configurado(host, user, password):
        log.info('[EMAIL-DEV] Para: %s | Asunto: %s | %s', destino, asunto, cuerpo)
        return True, None
    try:
        msg = EmailMessage()
        msg['Subject'] = asunto
        msg['From'] = from_addr or user
        msg['To'] = destino
        msg.set_content(cuerpo)
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
        return True, None
    except Exception as exc:  # noqa: BLE001 - fallos de red/auth SMTP
        log.error(f'Error enviando email a {destino}: {exc}')
        return False, 'No se pudo enviar el correo. Revisa tu email e intenta de nuevo.'


def enviar_enlace_recuperacion(destino, enlace, minutos,
                               host='', port=587, user='', password='', from_addr=''):
    """Envia el enlace de restablecimiento de contrasena (un solo uso)."""
    cuerpo = (
        'Hola,\n\n'
        'Recibimos una solicitud para restablecer la contrasena de tu cuenta SecureScan.\n\n'
        f'Enlace (valido por {minutos} minutos, de un solo uso):\n{enlace}\n\n'
        'Si no solicitaste este cambio, ignora este mensaje: tu contrasena seguira igual.\n'
    )
    return enviar_email(
        destino, 'Restablecer contrasena - SecureScan', cuerpo,
        host, port, user, password, from_addr,
    )


def enviar_codigo_email(destino, codigo, minutos,
                        host='', port=587, user='', password='', from_addr=''):
    """Envia el codigo 2FA por email. Devuelve (ok, error)."""
    cuerpo = (
        f'Hola,\n\nTu codigo de verificacion SecureScan es: {codigo}\n\n'
        f'Vence en {minutos} minutos. No lo compartas con nadie.\n\n'
        'Si no solicitaste este codigo, ignora este mensaje.'
    )
    return enviar_email(
        destino, 'Tu codigo de verificacion SecureScan', cuerpo,
        host, port, user, password, from_addr,
    )


def iniciar_desafio(usuario, minutos=CODIGO_MINUTOS_DEFAULT,
                    host='', port=587, user='', password='', from_addr=''):
    """Genera un codigo, lo guarda hasheado en el usuario y lo envia por email.

    Devuelve (ok, error). Requiere que usuario.email este configurado.
    """
    from werkzeug.security import generate_password_hash
    from models import db

    if not usuario.email:
        return False, 'No tienes un correo registrado.'
    codigo = generar_codigo()
    usuario.tfa_codigo_hash = generate_password_hash(codigo)
    usuario.tfa_expira_en = datetime.utcnow() + timedelta(minutes=minutos)
    usuario.tfa_intentos = 0
    db.session.commit()

    ok, error = enviar_codigo_email(
        usuario.email, codigo, minutos, host, port, user, password, from_addr,
    )
    if not ok:
        limpiar_desafio(usuario)
        return False, error
    return True, None


def verificar_codigo(usuario, codigo, max_intentos=MAX_INTENTOS_DEFAULT):
    """Valida el codigo ingresado. Devuelve (ok, error).

    Un solo uso: al acertar o agotar intentos/expiracion se limpia el desafio.
    """
    from werkzeug.security import check_password_hash
    from models import db

    if not usuario.tfa_codigo_hash or not usuario.tfa_expira_en:
        return False, 'No hay un codigo pendiente. Inicia sesion de nuevo.'
    if datetime.utcnow() > usuario.tfa_expira_en:
        limpiar_desafio(usuario)
        return False, 'El codigo vencio. Inicia sesion de nuevo.'
    if usuario.tfa_intentos >= max_intentos:
        limpiar_desafio(usuario)
        return False, 'Demasiados intentos. Inicia sesion de nuevo.'

    if check_password_hash(usuario.tfa_codigo_hash, (codigo or '').strip()):
        limpiar_desafio(usuario)
        return True, None

    usuario.tfa_intentos = (usuario.tfa_intentos or 0) + 1
    restantes = max_intentos - usuario.tfa_intentos
    db.session.commit()
    if restantes <= 0:
        limpiar_desafio(usuario)
        return False, 'Demasiados intentos. Inicia sesion de nuevo.'
    return False, f'Codigo incorrecto. Te quedan {restantes} intentos.'


def limpiar_desafio(usuario):
    """Borra el codigo pendiente (un solo uso / vencido / intentos agotados)."""
    from models import db

    usuario.tfa_codigo_hash = None
    usuario.tfa_expira_en = None
    usuario.tfa_intentos = 0
    db.session.commit()
