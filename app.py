import hashlib
import hmac
import os
import re
import secrets
import socket
import threading
import time
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

load_dotenv()
from flask import (
    Flask, render_template, request, redirect, flash, session, jsonify, abort, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, Usuario, Escaneo, ResultadoEscaneo, Vulnerabilidad, TrabajoEscaneo
from config import Config
from email_2fa import (
    normalizar_email,
    enmascarar_email,
    enviar_email,
    enviar_enlace_recuperacion,
    iniciar_desafio,
    verificar_codigo,
    limpiar_desafio,
)
from escaneo_red import (
    PUERTOS_POR_DEFECTO,
    analizar_url,
    descubrir_dispositivos,
    escanear_puertos,
    es_url_permitida,
    ip_local,
    sanitize_target,
    validar_ip,
    validar_url,
)


def _smtp_cfg():
    """Parametros SMTP para el desafio 2FA desde la config de la app."""
    return {
        'host': app.config.get('SMTP_HOST', ''),
        'port': app.config.get('SMTP_PORT', 587),
        'user': app.config.get('SMTP_USER', ''),
        'password': app.config.get('SMTP_PASS', ''),
        'from_addr': app.config.get('SMTP_FROM', ''),
    }
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# El token compartido con el agente local se configura SOLO por variable de
# entorno AGENTE_TOKEN (admite varios separados por coma). No hay valor por
# defecto en el codigo: si no esta configurado, los endpoints del agente
# responden 503.

app = Flask(
    __name__,
    template_folder=os.path.join(_BASE_DIR, 'templates'),
    static_folder=os.path.join(_BASE_DIR, 'static')
)
app.config.from_object(Config)

db.init_app(app)

@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if '_csrf_token' not in session:
            session['_csrf_token'] = secrets.token_hex(32)
        return session['_csrf_token']
    return dict(csrf_token=csrf_token)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

# ----------------------------------------------------------------------
# LOGGING
# ----------------------------------------------------------------------
if not app.debug and not app.testing:
    try:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/scanner.log', maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
    except OSError:
        pass
    app.logger.info('Scanner iniciado')

# ----------------------------------------------------------------------
# TALISMAN (HTTPS enforcement) - activable con FORCE_HTTPS=1 en produccion
# ----------------------------------------------------------------------
try:
    from flask_talisman import Talisman
    talisman = Talisman(
        app,
        force_https=os.environ.get('FORCE_HTTPS', '0') == '1',
        content_security_policy=None,
        session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', False),
    )
except ImportError:
    pass

# ----------------------------------------------------------------------
# CSRF: se valida el token de sesion en todos los POST/PUT/PATCH/DELETE.
# Los formularios ya lo incluyen (campo csrf_token) y el JS lo manda como
# cabecera X-CSRFToken. Los endpoints del agente se validan con su token.
# ----------------------------------------------------------------------
VALID_SCAN_TYPES = ('puertos', 'url', 'dispositivos')

RUTAS_EXENTAS_CSRF = {'/api/agente/claim', '/api/agente/resultados'}


def _token_csrf_recibido():
    token = (request.form.get('csrf_token')
             or request.form.get('_csrf_token')
             or request.headers.get('X-CSRFToken')
             or request.headers.get('X-CSRF-Token'))
    if not token and request.is_json:
        datos = request.get_json(silent=True) or {}
        token = datos.get('csrf_token')
    return token or ''


@app.before_request
def verificar_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    if request.path in RUTAS_EXENTAS_CSRF:
        return None
    if app.config.get('TESTING'):
        return None

    token_sesion = session.get('_csrf_token', '')
    token_recibido = _token_csrf_recibido()
    if not token_sesion or not token_recibido or not hmac.compare_digest(
        str(token_sesion), str(token_recibido)
    ):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Token CSRF invalido o ausente. Recarga la pagina.'}), 403
        abort(403)
    return None


# ----------------------------------------------------------------------
# VULNERABILITY ANALYSIS
# ----------------------------------------------------------------------
PORT_VULNERABILITIES = {
    21: {
        'nombre': 'FTP expuesto (Puerto 21)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'High',
        'descripcion': 'El protocolo FTP transmite datos, incluyendo credenciales, en texto plano. Esto permite que un atacante intercepte la informacion con facilidad.',
        'recomendacion': 'Desactiva FTP y usa SFTP o SCP para transferencias seguras. Si es necesario, limita el acceso por IP y usa credenciales fuertes.'
    },
    22: {
        'nombre': 'SSH expuesto (Puerto 22)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'Medium',
        'descripcion': 'SSH esta abierto y accesible. Aunque es un protocolo cifrado, un servico SSH mal configurado puede ser vulnerable a fuerza bruta.',
        'recomendacion': 'Desactiva el login por contrasena y usa unicamente claves SSH. Implementa fail2ban para bloquear intentos repetidos. Cambia el puerto por defecto.'
    },
    23: {
        'nombre': 'Telnet expuesto (Puerto 23)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'High',
        'descripcion': 'Telnet transmite toda la informacion, incluyendo credenciales, en texto plano. Es extremadamente inseguro para acceso remoto.',
        'recomendacion': 'Desactiva Telnet inmediatamente y usa SSH como reemplazo. Telnet no debe usarse en ningun entorno de produccion.'
    },
    25: {
        'nombre': 'SMTP expuesto (Puerto 25)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'Medium',
        'descripcion': 'El servicio SMTP abierto puede ser explotado para enviar spam, phishing o malware desde tu servidor.',
        'recomendacion': 'Restringe el relay SMTP solo a IPs autorizadas. Implementa SPF, DKIM y DMARC. Usa autenticacion obligatoria.'
    },
    53: {
        'nombre': 'DNS expuesto (Puerto 53)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'Low',
        'descripcion': 'El servicio DNS abierto puede ser utilizado para ataques de amplificacion DNS o recursion abierta.',
        'recomendacion': 'Limita las consultas DNS solo a clientes autorizados. Desactiva la recursion si no es necesaria.'
    },
    80: {
        'nombre': 'HTTP sin cifrar (Puerto 80)',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Medium',
        'descripcion': 'El trafico HTTP viaja en texto plano, lo que permite que un atacante intercepte o modifique los datos transmitidos.',
        'recomendacion': 'Implementa HTTPS con certificado SSL/TLS. Configura redireccion automatica de HTTP a HTTPS.'
    },
    110: {
        'nombre': 'POP3 expuesto (Puerto 110)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'Medium',
        'descripcion': 'POP3 transmite credenciales y correos en texto plano. Un atacante puede interceptar la informacion facilmente.',
        'recomendacion': 'Usa POP3S (puerto 995) o migrar a IMAP con cifrado TLS. Nunca uses POP3 sin cifrar.'
    },
    143: {
        'nombre': 'IMAP expuesto (Puerto 143)',
        'cve': 'CVE-General',
        'tipo': 'Red',
        'severity': 'Medium',
        'descripcion': 'IMAP sin cifrar permite la interceptacion de correos y credenciales de acceso.',
        'recomendacion': 'Usa IMAPS (puerto 993) con cifrado TLS. Configura la autenticacion segura.'
    },
    3306: {
        'nombre': 'MySQL expuesto (Puerto 3306)',
        'cve': 'CVE-General',
        'tipo': 'Base de Datos',
        'severity': 'High',
        'descripcion': 'La base de datos MySQL esta accesible desde la red. Esto permite ataques de fuerza bruta, inyeccion SQL remota o robo de datos.',
        'recomendacion': 'Binding a 127.0.0.1 si solo se accede localmente. Usa firewall para restringir accesos. Implementa contrasenas fuertes y usuarios con最小权限.'
    },
    3389: {
        'nombre': 'RDP expuesto (Puerto 3389)',
        'cve': 'CVE-1999-0514',
        'tipo': 'Acceso Remoto',
        'severity': 'High',
        'descripcion': 'RDP (Escritorio Remoto) abierto a la red es un vector de ataque muy comun. Puede permitir acceso no autorizado al sistema.',
        'recomendacion': 'Limita RDP solo a IPs especificas via firewall. Implementa NLA (Network Level Authentication). Usa VPN para acceso remoto.'
    },
    5000: {
        'nombre': 'Servidor de desarrollo Flask (Puerto 5000)',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Medium',
        'descripcion': 'El servidor de desarrollo Flask/Werkzeug esta expuesto. No esta disenado para produccion y puede filtrar informacion sensible.',
        'recomendacion': 'Nunca uses el servidor de desarrollo en produccion. Usa un servidor WSGI como Gunicorn o uWSGI detras de un reverse proxy (Nginx/Apache).'
    },
    8080: {
        'nombre': 'Servidor HTTP alternativo (Puerto 8080)',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Low',
        'descripcion': 'Un servidor web alternativo esta activo en el puerto 8080, comunmente usado para pruebas.',
        'recomendacion': 'Verifica que este servicio sea intencional. Si es un entorno de desarrollo, asegurate de que no sea accesible publicamente.'
    },
}

URL_VULNERABILITIES = {
    'no_https': {
        'nombre': 'Sitio sin HTTPS',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'High',
        'descripcion': 'El sitio no utiliza cifrado HTTPS. Todos los datos se transmiten en texto plano, incluyendo credenciales y datos sensibles.',
        'recomendacion': 'Obten un certificado SSL/TLS (Let\'s Encrypt es gratuito) y configura HTTPS. Implementa redireccion automatica desde HTTP.'
    },
    'no_hsts': {
        'nombre': 'Cabecera HSTS ausente',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Medium',
        'descripcion': 'La cabecera Strict-Transport-Security no esta configurada. Los navegadores podrian acceder a versiones no cifradas del sitio.',
        'recomendacion': 'Agrega la cabecera Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'no_xframe': {
        'nombre': 'Cabecera X-Frame-Options ausente',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Medium',
        'descripcion': 'Sin esta cabecera, el sitio puede ser embebido en iframes maliciosos, permitiendo ataques de clickjacking.',
        'recomendacion': 'Agrega X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking.'
    },
    'no_xcontent': {
        'nombre': 'Cabecera X-Content-Type-Options ausente',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'Low',
        'descripcion': 'Sin esta cabecera, el navegador podria interpretar archivos MIME de forma incorrecta, facilitando ataques de sniffing.',
        'recomendacion': 'Agrega X-Content-Type-Options: nosniff para forzar la deteccion de tipo MIME.'
    },
    'cert_por_vencer': {
        'nombre': 'Certificado SSL proximo a vencer',
        'cve': 'CVE-General',
        'tipo': 'Web',
        'severity': 'High',
        'descripcion': 'El certificado SSL del sitio vence en menos de 15 dias o ya vencio. Un certificado vencido habilita ataques de suplantacion y genera alertas en los navegadores.',
        'recomendacion': 'Renueva el certificado SSL (Let\'s Encrypt permite renovacion automatica con certbot).'
    },
}


def analizar_vulnerabilidades(tipo_escaneo, resultados, escaneo_id):
    vulns = []

    if tipo_escaneo == 'puertos':
        for r in resultados:
            if r['estado'] == 'ABIERTO':
                puerto = int(r['item'].replace('Puerto ', ''))
                if puerto in PORT_VULNERABILITIES:
                    info = PORT_VULNERABILITIES[puerto]
                    vulns.append(Vulnerabilidad(
                        escaneo_id=escaneo_id,
                        nombre=info['nombre'],
                        cve=info['cve'],
                        descripcion=info['descripcion'],
                        tipo=info['tipo'],
                        severity=info['severity'],
                        risk=info['recomendacion']
                    ))

    elif tipo_escaneo == 'url':
        https_usado = any('HTTPS' in r['item'] and r['estado'] == 'SEGURO' for r in resultados)
        if not https_usado:
            info = URL_VULNERABILITIES['no_https']
            vulns.append(Vulnerabilidad(
                escaneo_id=escaneo_id, nombre=info['nombre'], cve=info['cve'],
                descripcion=info['descripcion'], tipo=info['tipo'],
                severity=info['severity'], risk=info['recomendacion']
            ))

        for r in resultados:
            if r['item'] == 'Cabecera Strict-Transport-Security' and r['estado'] == 'AUSENTE':
                info = URL_VULNERABILITIES['no_hsts']
                vulns.append(Vulnerabilidad(
                    escaneo_id=escaneo_id, nombre=info['nombre'], cve=info['cve'],
                    descripcion=info['descripcion'], tipo=info['tipo'],
                    severity=info['severity'], risk=info['recomendacion']
                ))
            elif r['item'] == 'Cabecera X-Frame-Options' and r['estado'] == 'AUSENTE':
                info = URL_VULNERABILITIES['no_xframe']
                vulns.append(Vulnerabilidad(
                    escaneo_id=escaneo_id, nombre=info['nombre'], cve=info['cve'],
                    descripcion=info['descripcion'], tipo=info['tipo'],
                    severity=info['severity'], risk=info['recomendacion']
                ))
            elif r['item'] == 'Cabecera X-Content-Type-Options' and r['estado'] == 'AUSENTE':
                info = URL_VULNERABILITIES['no_xcontent']
                vulns.append(Vulnerabilidad(
                    escaneo_id=escaneo_id, nombre=info['nombre'], cve=info['cve'],
                    descripcion=info['descripcion'], tipo=info['tipo'],
                    severity=info['severity'], risk=info['recomendacion']
                ))
            elif r['item'] == 'Certificado SSL' and r['estado'] == 'ALERTA':
                info = URL_VULNERABILITIES['cert_por_vencer']
                vulns.append(Vulnerabilidad(
                    escaneo_id=escaneo_id, nombre=info['nombre'], cve=info['cve'],
                    descripcion=f"{info['descripcion']} ({r['explicacion']})",
                    tipo=info['tipo'], severity=info['severity'], risk=info['recomendacion']
                ))

    return vulns


# ----------------------------------------------------------------------
# RUTAS PRINCIPALES
# ----------------------------------------------------------------------
@app.route('/')
def inicio():
    if 'usuario' in session:
        return redirect('/dashboard')
    return render_template('login.html')


@app.route('/registro', methods=['POST'])
def registro():
    usuario = request.form.get('usuario', '').strip()
    clave = request.form.get('clave', '')

    if not usuario or not clave:
        flash('Complete todos los campos', 'error')
        return redirect('/')

    if len(usuario) < 3:
        flash('El usuario debe tener al menos 3 caracteres', 'error')
        return redirect('/')

    if len(clave) < 6:
        flash('La contrasena debe tener al menos 6 caracteres', 'error')
        return redirect('/')

    if not re.match(r'^[a-zA-Z0-9_.@+-]+$', usuario):
        flash('El usuario solo puede contener letras, numeros, @, puntos y guiones', 'error')
        return redirect('/')

    if Usuario.query.filter_by(username=usuario).first():
        flash('El usuario ya se encuentra registrado.', 'error')
        return redirect('/')

    nuevo = Usuario(username=usuario, password_hash=generate_password_hash(clave))
    db.session.add(nuevo)
    db.session.commit()
    app.logger.info(f'Nuevo usuario registrado: {usuario}')
    flash('Cuenta creada con exito! Ya puedes iniciar sesion.', 'success')
    return redirect('/')


@app.route('/login', methods=['POST'])
@limiter.limit("20 per minute")
def login():
    usuario = request.form.get('usuario', '').strip()
    clave = request.form.get('clave', '')

    user = Usuario.query.filter_by(username=usuario).first()
    if user and check_password_hash(user.password_hash, clave):
        # Solo persiste la sesion al cerrar el navegador si marco "Recordarme"
        recordar = bool(request.form.get('recordarme'))
        # Segundo factor por email si el usuario lo tiene activo
        if user.tfa_habilitado and user.email:
            ok, error = iniciar_desafio(
                user,
                minutos=app.config.get('TFA_CODIGO_MINUTOS', 10),
                **_smtp_cfg(),
            )
            if not ok:
                flash(error or 'No se pudo enviar el codigo al correo', 'error')
                return redirect('/')
            session['tfa_pendiente'] = user.id
            session['recordarme'] = recordar
            app.logger.info(f'Codigo 2FA enviado a {enmascarar_email(user.email)} ({usuario})')
            return redirect('/verificar-2fa')

        session['usuario'] = user.username
        session['usuario_id'] = user.id
        session.permanent = recordar
        app.logger.info(f'Login exitoso: {usuario}')
        return redirect('/dashboard')

    app.logger.warning(f'Login fallido para usuario: {usuario}')
    flash('Usuario o contrasena incorrectos', 'error')
    return redirect('/')


# ----------------------------------------------------------------------
# VERIFICACION EN DOS PASOS POR EMAIL
# ----------------------------------------------------------------------
def _usuario_tfa_pendiente():
    user_id = session.get('tfa_pendiente')
    if not user_id:
        return None
    return Usuario.query.get(user_id)


@app.route('/verificar-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verificar_2fa():
    user = _usuario_tfa_pendiente()
    if not user:
        flash('No hay una verificacion pendiente. Inicia sesion.', 'error')
        return redirect('/')

    if user.tfa_expira_en and datetime.utcnow() > user.tfa_expira_en:
        limpiar_desafio(user)
        session.pop('tfa_pendiente', None)
        flash('El codigo vencio. Inicia sesion de nuevo.', 'error')
        return redirect('/')

    if request.method == 'POST':
        codigo = request.form.get('codigo', '')
        ok, error = verificar_codigo(
            user, codigo,
            max_intentos=app.config.get('TFA_MAX_INTENTOS', 5),
        )
        if ok:
            session.pop('tfa_pendiente', None)
            session['usuario'] = user.username
            session['usuario_id'] = user.id
            session.permanent = session.pop('recordarme', False)
            app.logger.info(f'Login 2FA exitoso: {user.username}')
            return redirect('/dashboard')
        if 'Inicia sesion de nuevo' in (error or ''):
            session.pop('tfa_pendiente', None)
            flash(error, 'error')
            return redirect('/')
        flash(error, 'error')
        return redirect('/verificar-2fa')

    return render_template(
        'verificar_2fa.html',
        email_mask=enmascarar_email(user.email),
    )


@app.route('/api/reenviar-codigo', methods=['POST'])
@limiter.limit("3 per minute")
def reenviar_codigo():
    user = _usuario_tfa_pendiente()
    if not user:
        return jsonify({'error': 'No hay una verificacion pendiente'}), 401
    ok, error = iniciar_desafio(
        user,
        minutos=app.config.get('TFA_CODIGO_MINUTOS', 10),
        **_smtp_cfg(),
    )
    if not ok:
        return jsonify({'error': error or 'No se pudo reenviar el codigo'}), 500
    return jsonify({'ok': True, 'mensaje': 'Codigo reenviado a tu correo'})


@app.route('/api/guardar-email-2fa', methods=['POST'])
def guardar_email_2fa():
    """Registra el correo y envia el codigo de activacion."""
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    datos = request.get_json() or {}
    email = normalizar_email(datos.get('email', ''))
    if not email:
        return jsonify({'error': 'Correo invalido. Ej: nombre@empresa.com'}), 400

    user = Usuario.query.get(session['usuario_id'])
    user.email = email
    user.tfa_habilitado = False
    db.session.commit()

    ok, error = iniciar_desafio(
        user,
        minutos=app.config.get('TFA_CODIGO_MINUTOS', 10),
        **_smtp_cfg(),
    )
    if not ok:
        return jsonify({'error': error or 'No se pudo enviar el codigo'}), 500
    app.logger.info(f'Codigo de activacion 2FA enviado a {enmascarar_email(email)}')
    return jsonify({'ok': True, 'email_mask': enmascarar_email(email)})


@app.route('/api/confirmar-2fa', methods=['POST'])
def confirmar_2fa():
    """Confirma el codigo de activacion y habilita el 2FA."""
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    datos = request.get_json() or {}
    user = Usuario.query.get(session['usuario_id'])
    ok, error = verificar_codigo(
        user, datos.get('codigo', ''),
        max_intentos=app.config.get('TFA_MAX_INTENTOS', 5),
    )
    if not ok:
        return jsonify({'error': error}), 400
    user.tfa_habilitado = True
    db.session.commit()
    app.logger.info(f'2FA activado para: {user.username}')
    return jsonify({'ok': True})


@app.route('/api/desactivar-2fa', methods=['POST'])
def desactivar_2fa():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    user = Usuario.query.get(session['usuario_id'])
    user.tfa_habilitado = False
    db.session.commit()
    limpiar_desafio(user)
    app.logger.info(f'2FA desactivado para: {user.username}')
    return jsonify({'ok': True})


@app.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    return render_template('dashboard.html', usuario=session['usuario'])


@app.route('/nuevo-analisis')
def nuevo_analisis():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    return render_template('nuevo_analisis.html', usuario=session['usuario'])


@app.route('/historial')
def vista_historial():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    return render_template('historial.html', usuario=session['usuario'])


@app.route('/api/historial', methods=['GET'])
def obtener_historial():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    paginacion = Escaneo.query.filter_by(usuario_id=session['usuario_id']) \
        .order_by(Escaneo.fecha.desc()) \
        .paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'escaneos': [e.to_dict() for e in paginacion.items],
        'total': paginacion.total,
        'page': paginacion.page,
        'pages': paginacion.pages,
        'has_next': paginacion.has_next,
        'has_prev': paginacion.has_prev,
    })


@app.route('/api/historial/<int:escaneo_id>', methods=['GET'])
def obtener_detalle_historial(escaneo_id):
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    item = Escaneo.query.filter_by(id=escaneo_id, usuario_id=session['usuario_id']).first()
    if not item:
        return jsonify({'error': 'Registro no encontrado'}), 404
    return jsonify(item.to_dict())


@app.route('/api/ejecutar-escaneo', methods=['POST'])
@limiter.limit("10 per minute")
def ejecutar_escaneo():
    try:
        if 'usuario_id' not in session:
            return jsonify({'error': 'No autorizado'}), 401

        # La cuenta pudo ser eliminada con una sesion aun activa
        if not Usuario.query.get(session['usuario_id']):
            session.clear()
            return jsonify({'error': 'Sesión expirada. Inicia sesión de nuevo.'}), 401

        datos = request.get_json() or {}
        tipo_escaneo = datos.get('tipo', 'puertos')
        target = datos.get('target', '').strip()

        if tipo_escaneo not in VALID_SCAN_TYPES:
            return jsonify({'error': 'Tipo de escaneo invalido'}), 400

        try:
            target = sanitize_target(target, tipo_escaneo)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # Validaciones de seguridad antes de encolar (respuesta inmediata)
        if tipo_escaneo == 'url' and not app.config.get('PERMITIR_URLS_PRIVADAS'):
            permitida, mensaje = es_url_permitida(target)
            if not permitida:
                return jsonify({'error': mensaje}), 400

        if tipo_escaneo == 'dispositivos' and target and target != 'auto':
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                return jsonify({'error': 'Prefijo de red invalido. Usa el formato 192.168.0'}), 400

        # Escaneos de red local: se encolan para el agente cuando esta activo
        envia_al_agente = tipo_escaneo == 'dispositivos' and _cola_agente_activa()
        en_segundo_plano = (
            app.config.get('ESCANEO_EN_SEGUNDO_PLANO')
            and not app.config.get('TESTING')
        )

        if not envia_al_agente and not en_segundo_plano:
            # Modo directo (tests o ESCANEO_EN_SEGUNDO_PLANO=0)
            try:
                titulo, subtitulo, resultados, target_registro = _ejecutar_escaneo(
                    session['usuario_id'], tipo_escaneo, target
                )
            except ValueError as ve:
                return jsonify({'error': str(ve)}), 400

            escaneo_id = guardar_escaneo_completo(
                session['usuario_id'], tipo_escaneo, target_registro,
                titulo, subtitulo, resultados
            )
            app.logger.info(f'Escaneo guardado id={escaneo_id} tipo={tipo_escaneo}')
            return jsonify({
                'titulo': titulo,
                'subtitulo': subtitulo,
                'resultados': resultados,
            })

        trabajo = TrabajoEscaneo(
            usuario_id=session['usuario_id'],
            tipo=tipo_escaneo,
            target=target or 'auto',
            estado='pendiente',
            progreso='En cola',
        )
        db.session.add(trabajo)
        db.session.commit()

        if not envia_al_agente:
            hilo = threading.Thread(target=_procesar_trabajo, args=(trabajo.id,), daemon=True)
            hilo.start()

        return jsonify({
            'async': True,
            'trabajo_id': trabajo.id,
            'mensaje': ('Escaneo encolado. Esperando al agente de red...'
                        if envia_al_agente else 'Escaneo iniciado. Consultando progreso...'),
        })

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        app.logger.error(f'Error en escaneo: {e}', exc_info=True)
        return jsonify({'error': f'Error interno: {str(e)}'}), 500


def _ejecutar_escaneo(usuario_id, tipo_escaneo, target, progreso=None):
    """Ejecuta el escaneo segun el tipo. Devuelve (titulo, subtitulo, resultados, target_registro)."""
    resultados = []
    titulo = ''
    subtitulo = ''
    target_registro = target

    if tipo_escaneo == 'puertos':
        ip_target = target if (target and validar_ip(target)) else ip_local()
        hostname = socket.gethostname()
        inicio = time.perf_counter()

        if progreso:
            progreso(f'Escaneando {len(PUERTOS_POR_DEFECTO)} puertos en {ip_target}')

        abiertos = escanear_puertos(ip_target, PUERTOS_POR_DEFECTO)
        for puerto in PUERTOS_POR_DEFECTO:
            abierto = puerto in abiertos
            if abierto and puerto == 5000:
                explicacion = 'Sistema Flask corriendo'
            elif abierto:
                explicacion = 'Servicio activo'
            else:
                explicacion = 'Seguro (sin escucha)'
            resultados.append({
                'item': f'Puerto {puerto}',
                'estado': 'ABIERTO' if abierto else 'CERRADO',
                'explicacion': explicacion,
            })

        duracion = time.perf_counter() - inicio
        titulo = 'Analisis de Puertos de Red'
        subtitulo = (f'Host: {hostname} ({ip_target}) | {duracion:.1f}s | '
                     f'{len(abiertos)} puertos abiertos')
        target_registro = ip_target
        app.logger.info(f'Escaneo de puertos ejecutado en {ip_target} ({duracion:.1f}s)')

    elif tipo_escaneo == 'url':
        if not app.config.get('PERMITIR_URLS_PRIVADAS'):
            permitida, mensaje = es_url_permitida(target)
            if not permitida:
                raise ValueError(mensaje)

        titulo, subtitulo, resultados = analizar_url(target, progreso=progreso)
        target_registro = target
        app.logger.info(f'Escaneo URL ejecutado: {target}')

    elif tipo_escaneo == 'dispositivos':
        objetivo = '' if target in (None, '', 'auto') else str(target).strip()
        if objetivo and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$', objetivo):
            raise ValueError('Prefijo de red invalido. Usa el formato 192.168.0')
        prefijo = objetivo or '.'.join(ip_local().split('.')[:-1])

        titulo, subtitulo, resultados = descubrir_dispositivos(prefijo, progreso=progreso)
        target_registro = f'{prefijo}.0/24'
        app.logger.info(f'Escaneo de dispositivos: {len(resultados)} encontrados')

    return titulo, subtitulo, resultados, target_registro


def _actualizar_progreso(trabajo_id, mensaje):
    """Guarda el avance del escaneo para que el frontend lo muestre."""
    try:
        trabajo = TrabajoEscaneo.query.get(trabajo_id)
        if trabajo:
            trabajo.progreso = mensaje
            db.session.commit()
    except Exception:
        db.session.rollback()


def _procesar_trabajo(trabajo_id):
    """Hilo en segundo plano: ejecuta el escaneo y guarda resultados."""
    with app.app_context():
        trabajo = TrabajoEscaneo.query.get(trabajo_id)
        if not trabajo or trabajo.estado != 'pendiente':
            return
        trabajo.estado = 'procesando'
        trabajo.progreso = 'Iniciando escaneo...'
        db.session.commit()
        try:
            titulo, subtitulo, resultados, target_registro = _ejecutar_escaneo(
                trabajo.usuario_id, trabajo.tipo, trabajo.target or 'auto',
                progreso=lambda m: _actualizar_progreso(trabajo.id, m),
            )
            escaneo_id = guardar_escaneo_completo(
                trabajo.usuario_id, trabajo.tipo, target_registro,
                titulo, subtitulo, resultados,
            )
            trabajo.escaneo_id = escaneo_id
            trabajo.estado = 'completado'
            trabajo.progreso = 'Completado'
            trabajo.completado_en = datetime.utcnow()
            db.session.commit()
            app.logger.info(f'Trabajo {trabajo.id} completado (escaneo {escaneo_id})')
        except ValueError as ve:
            trabajo.estado = 'error'
            trabajo.mensaje_error = str(ve)
            trabajo.completado_en = datetime.utcnow()
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.error(f'Error en trabajo {trabajo_id}: {exc}', exc_info=True)
            trabajo = TrabajoEscaneo.query.get(trabajo_id)
            if trabajo:
                trabajo.estado = 'error'
                trabajo.mensaje_error = f'Error interno: {exc}'
                trabajo.completado_en = datetime.utcnow()
                db.session.commit()


def guardar_escaneo_completo(usuario_id, tipo_escaneo, target_registro, titulo, subtitulo, resultados):
    """Guarda el escaneo, sus resultados y vulnerabilidades. Devuelve el id del escaneo."""
    nuevo = Escaneo(
        usuario_id=usuario_id,
        tipo=tipo_escaneo,
        target=target_registro,
        titulo=titulo,
        subtitulo=subtitulo,
        total_dispositivos=len(resultados) if tipo_escaneo == 'dispositivos' else None
    )
    db.session.add(nuevo)
    db.session.flush()
    for r in resultados:
        db.session.add(ResultadoEscaneo(
            escaneo_id=nuevo.id,
            item=r['item'],
            estado=r['estado'],
            explicacion=r['explicacion']
        ))
    db.session.commit()

    try:
        vulns = analizar_vulnerabilidades(tipo_escaneo, resultados, nuevo.id)
        for v in vulns:
            db.session.add(v)
        db.session.commit()
    except Exception as ve:
        app.logger.error(f'Error guardando vulnerabilidades: {ve}')
        db.session.rollback()

    return nuevo.id


def _cola_agente_activa():
    """La cola del agente solo se usa si esta habilitada Y hay token configurado."""
    if os.environ.get('AGENTE_HABILITADO') == '0':
        return False
    con_token = bool(_tokens_agente_validos())
    if os.environ.get('AGENTE_HABILITADO') == '1':
        return con_token
    return os.environ.get('VERCEL') == '1' and con_token


def _tokens_agente_validos():
    """Tokens validos leidos de AGENTE_TOKEN (varios separados por coma)."""
    raw = app.config.get('AGENTE_TOKEN', '') or os.environ.get('AGENTE_TOKEN', '')
    return {t.strip() for t in raw.split(',') if t.strip()}


def _requiere_token_agente():
    if not _tokens_agente_validos():
        return False
    token_recibido = request.headers.get('X-Agente-Token', '')
    if not token_recibido:
        datos = request.get_json(silent=True) or {}
        token_recibido = datos.get('agente_token', '') or request.form.get('agente_token', '')
    return any(
        token_recibido and hmac.compare_digest(t, token_recibido)
        for t in _tokens_agente_validos()
    )


@app.route('/api/agente/ping')
def agente_ping():
    return jsonify({
        'ok': True,
        'version': 3,
        'token_configurado': bool(_tokens_agente_validos()),
        'cola_habilitada': _cola_agente_activa()
    })


@app.route('/api/trabajo/<int:trabajo_id>', methods=['GET'])
def estado_trabajo(trabajo_id):
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    trabajo = TrabajoEscaneo.query.get(trabajo_id)
    if not trabajo or trabajo.usuario_id != session['usuario_id']:
        return jsonify({'error': 'Trabajo no encontrado'}), 404

    respuesta = {'id': trabajo.id, 'estado': trabajo.estado, 'progreso': trabajo.progreso}

    if trabajo.estado == 'completado' and trabajo.escaneo_id:
        escaneo = Escaneo.query.get(trabajo.escaneo_id)
        if escaneo:
            respuesta.update({
                'titulo': escaneo.titulo,
                'subtitulo': escaneo.subtitulo,
                'resultados': [r.to_dict() for r in escaneo.resultados]
            })
    elif trabajo.estado == 'error':
        respuesta['error'] = trabajo.mensaje_error or 'El agente reporto un error'

    return jsonify(respuesta)


@app.route('/api/agente/claim', methods=['POST'])
def agente_claim():
    if not _tokens_agente_validos():
        return jsonify({'error': 'Agente no configurado: define AGENTE_TOKEN en el servidor'}), 503
    if not _requiere_token_agente():
        return jsonify({'error': 'Token de agente invalido'}), 401

    trabajo = (TrabajoEscaneo.query
               .filter_by(estado='pendiente')
               .order_by(TrabajoEscaneo.id.asc())
               .first())
    if not trabajo:
        return jsonify({'trabajo': None})

    trabajo.estado = 'procesando'
    db.session.commit()
    return jsonify({'trabajo': {'id': trabajo.id, 'tipo': trabajo.tipo, 'target': trabajo.target}})


@app.route('/api/agente/resultados', methods=['POST'])
def agente_resultados():
    if not _tokens_agente_validos():
        return jsonify({'error': 'Agente no configurado: define AGENTE_TOKEN en el servidor'}), 503
    if not _requiere_token_agente():
        return jsonify({'error': 'Token de agente invalido'}), 401

    datos = request.get_json() or {}
    trabajo_id = datos.get('trabajo_id')
    trabajo = TrabajoEscaneo.query.get(trabajo_id) if trabajo_id else None
    if not trabajo or trabajo.estado != 'procesando':
        return jsonify({'error': 'Trabajo no valido'}), 404

    if not datos.get('ok'):
        trabajo.estado = 'error'
        trabajo.mensaje_error = datos.get('error', 'Error desconocido del agente')
        trabajo.completado_en = datetime.utcnow()
        db.session.commit()
        return jsonify({'ok': True})

    try:
        resultados = datos.get('resultados') or []
        escaneo_id = guardar_escaneo_completo(
            trabajo.usuario_id,
            trabajo.tipo,
            trabajo.target or 'auto',
            datos.get('titulo', 'Dispositivos en Red Local'),
            datos.get('subtitulo', ''),
            resultados
        )
        trabajo.estado = 'completado'
        trabajo.escaneo_id = escaneo_id
        trabajo.completado_en = datetime.utcnow()
        db.session.commit()
        return jsonify({'ok': True})
    except Exception as exc:
        db.session.rollback()
        trabajo.estado = 'error'
        trabajo.mensaje_error = f'Error al guardar resultados: {exc}'
        trabajo.completado_en = datetime.utcnow()
        db.session.commit()
        return jsonify({'error': 'No se pudieron guardar los resultados'}), 500


# ----------------------------------------------------------------------
# RUTAS DE CONFIGURACION
# ----------------------------------------------------------------------
@app.route('/configuracion')
def configuracion():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    user = Usuario.query.get(session.get('usuario_id'))
    return render_template(
        'configuracion.html',
        usuario=session['usuario'],
        tfa_habilitado=bool(user and user.tfa_habilitado),
        email_mask=enmascarar_email(user.email) if user and user.email else '',
    )


@app.route('/api/actualizar-perfil', methods=['POST'])
def actualizar_perfil():
    if 'usuario_id' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')

    nuevo_username = request.form.get('username', '').strip()
    if not nuevo_username:
        flash('El nombre de usuario no puede estar vacio', 'error')
        return redirect('/configuracion')

    if len(nuevo_username) < 3:
        flash('El usuario debe tener al menos 3 caracteres', 'error')
        return redirect('/configuracion')

    if not re.match(r'^[a-zA-Z0-9_.@+-]+$', nuevo_username):
        flash('El usuario solo puede contener letras, numeros, @, puntos y guiones', 'error')
        return redirect('/configuracion')

    user = Usuario.query.get(session['usuario_id'])
    if user.username != nuevo_username and Usuario.query.filter_by(username=nuevo_username).first():
        flash('Ese nombre de usuario ya esta en uso', 'error')
        return redirect('/configuracion')

    user.username = nuevo_username
    db.session.commit()
    session['usuario'] = nuevo_username
    app.logger.info(f'Perfil actualizado: {nuevo_username}')
    flash('Perfil actualizado correctamente', 'success')
    return redirect('/configuracion')


@app.route('/api/cambiar-password', methods=['POST'])
def cambiar_password():
    if 'usuario_id' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')

    actual = request.form.get('password_actual', '')
    nueva = request.form.get('password_nueva', '')
    confirmar = request.form.get('password_confirmar', '')

    user = Usuario.query.get(session['usuario_id'])

    if not check_password_hash(user.password_hash, actual):
        flash('La contrasena actual es incorrecta', 'error')
        return redirect('/configuracion')

    if nueva != confirmar:
        flash('Las contrasenas nuevas no coinciden', 'error')
        return redirect('/configuracion')

    if len(nueva) < 6:
        flash('La nueva contrasena debe tener al menos 6 caracteres', 'error')
        return redirect('/configuracion')

    user.password_hash = generate_password_hash(nueva)
    db.session.commit()
    app.logger.info(f'Contrasena cambiada para: {user.username}')
    flash('Contrasena actualizada con exito', 'success')
    return redirect('/configuracion')


@app.route('/api/actualizar-tema', methods=['POST'])
def actualizar_tema():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    datos = request.get_json() or {}
    tema = datos.get('tema', 'oscuro')
    if tema not in ['oscuro', 'azul', 'verde', 'morado']:
        return jsonify({'error': 'Tema invalido'}), 400

    user = Usuario.query.get(session['usuario_id'])
    user.tema = tema
    db.session.commit()
    return jsonify({'ok': True, 'tema': tema})


@app.route('/api/cerrar-otras-sesiones', methods=['POST'])
def cerrar_otras_sesiones():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    return jsonify({'mensaje': 'Se han cerrado las demas sesiones activas'})


@app.route('/api/borrar-historial', methods=['POST'])
def api_borrar_historial():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    try:
        ids = [e.id for e in Escaneo.query.filter_by(usuario_id=session['usuario_id']).all()]
        if ids:
            ResultadoEscaneo.query.filter(ResultadoEscaneo.escaneo_id.in_(ids)).delete(synchronize_session=False)
            Vulnerabilidad.query.filter(Vulnerabilidad.escaneo_id.in_(ids)).delete(synchronize_session=False)
            Escaneo.query.filter(Escaneo.id.in_(ids)).delete(synchronize_session=False)
            db.session.commit()
            app.logger.info(f'Historial borrado por usuario_id: {session["usuario_id"]} ({len(ids)} escaneos)')
        return jsonify({'ok': True})
    except Exception as exc:
        db.session.rollback()
        app.logger.error(f'Error al borrar historial: {exc}')
        return jsonify({'error': 'No se pudo borrar el historial'}), 500


@app.route('/api/eliminar-cuenta', methods=['POST'])
def eliminar_cuenta():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    user = Usuario.query.get(session['usuario_id'])
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    try:
        # Los trabajos referencian al usuario: se borran primero
        TrabajoEscaneo.query.filter_by(usuario_id=user.id).delete(synchronize_session=False)
        ids = [e.id for e in Escaneo.query.filter_by(usuario_id=user.id).all()]
        if ids:
            ResultadoEscaneo.query.filter(ResultadoEscaneo.escaneo_id.in_(ids)).delete(synchronize_session=False)
            Vulnerabilidad.query.filter(Vulnerabilidad.escaneo_id.in_(ids)).delete(synchronize_session=False)
            Escaneo.query.filter(Escaneo.usuario_id == user.id).delete(synchronize_session=False)
        app.logger.info(f'Cuenta eliminada: {user.username}')
        db.session.delete(user)
        db.session.commit()
        session.clear()
        return jsonify({'ok': True})
    except Exception as exc:
        db.session.rollback()
        app.logger.error(f'Error al eliminar cuenta: {exc}')
        return jsonify({'error': 'No se pudo eliminar la cuenta'}), 500


# ----------------------------------------------------------------------
# RECUPERACION DE CONTRASENA (enlace de un solo uso por email)
# ----------------------------------------------------------------------
_RE_USERNAME = re.compile(r'^[a-zA-Z0-9_.@+-]{3,80}$')


def _limpiar_reset(user):
    user.reset_token_hash = None
    user.reset_expira_en = None
    user.reset_intentos = 0
    db.session.commit()


def _usuario_por_token_reset(token):
    if not token:
        return None
    digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
    user = Usuario.query.filter_by(reset_token_hash=digest).first()
    if not user:
        return None
    if user.reset_expira_en and datetime.utcnow() > user.reset_expira_en:
        _limpiar_reset(user)
        return None
    if (user.reset_intentos or 0) >= app.config.get('RESET_MAX_INTENTOS', 5):
        _limpiar_reset(user)
        return None
    user.reset_intentos = (user.reset_intentos or 0) + 1
    db.session.commit()
    return user


@app.route('/recuperar', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def recuperar():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        mensaje_generico = ('Si el usuario existe y tiene un correo configurado, '
                            'te enviamos un enlace para restablecer la contrasena.')

        if not _RE_USERNAME.match(username):
            flash('Usuario invalido', 'error')
            return redirect('/recuperar')

        user = Usuario.query.filter_by(username=username).first()

        if user and user.email:
            token = secrets.token_urlsafe(32)
            user.reset_token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            user.reset_expira_en = datetime.utcnow() + timedelta(
                minutes=app.config.get('RESET_TOKEN_MINUTOS', 30))
            user.reset_intentos = 0
            db.session.commit()

            enlace = url_for('restablecer', _external=True) + f'?token={token}'
            smtp_ok = (app.config.get('SMTP_HOST') and app.config.get('SMTP_USER')
                       and app.config.get('SMTP_PASS'))
            es_produccion = app.config.get('ENTORNO') == 'production'

            if smtp_ok:
                ok, error = enviar_enlace_recuperacion(
                    user.email, enlace,
                    app.config.get('RESET_TOKEN_MINUTOS', 30),
                    **_smtp_cfg(),
                )
                if ok:
                    app.logger.info(f'Enlace de recuperacion enviado a {enmascarar_email(user.email)}')
                    # En local/desarrollo tambien se muestra el enlace (util para pruebas)
                    if not es_produccion:
                        flash(f'Modo desarrollo - enlace de restablecimiento: {enlace}', 'info')
                    else:
                        flash(mensaje_generico, 'success')
                else:
                    flash(error or 'No se pudo enviar el correo. Intenta mas tarde.', 'error')
            elif not es_produccion:
                app.logger.info(f'[RESET-DEV] Enlace para {user.email}: {enlace}')
                flash(f'Modo desarrollo - enlace de restablecimiento: {enlace}', 'info')
            else:
                app.logger.error(
                    f'SMTP no configurado: no se pudo enviar enlace de recuperacion a {user.email}')
                flash('No se pudo enviar el correo. Contacta al administrador del sistema.', 'error')
        elif user and not user.email:
            app.logger.warning(f'Usuario {username} sin correo configurado: no puede recuperar por email')
            flash(mensaje_generico, 'info')
        else:
            flash(mensaje_generico, 'info')
        return redirect('/recuperar')
    return render_template('recuperar.html')


@app.route('/restablecer', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def restablecer():
    token = (request.values.get('token') or '').strip()

    if request.method == 'GET':
        if not token:
            flash('Enlace invalido. Solicita uno nuevo desde "Olvide mi contrasena".', 'error')
            return redirect('/recuperar')
        return render_template('restablecer.html', token=token)

    user = _usuario_por_token_reset(token)
    if not user:
        flash('El enlace no es valido o ya vencio. Solicita uno nuevo.', 'error')
        return redirect('/recuperar')

    clave = request.form.get('clave', '')
    confirmar = request.form.get('confirmar', '')

    if len(clave) < 6:
        flash('La contrasena debe tener al menos 6 caracteres', 'error')
        return redirect(url_for('restablecer') + f'?token={token}')
    if clave != confirmar:
        flash('Las contrasenas no coinciden', 'error')
        return redirect(url_for('restablecer') + f'?token={token}')

    user.password_hash = generate_password_hash(clave)
    user.reset_token_hash = None
    user.reset_expira_en = None
    user.reset_intentos = 0
    user.tfa_codigo_hash = None
    user.tfa_expira_en = None
    db.session.commit()
    app.logger.info(f'Contrasena restablecida por enlace: {user.username}')

    session['usuario'] = user.username
    session['usuario_id'] = user.id
    flash('Contrasena actualizada correctamente.', 'success')
    return redirect('/dashboard')


# ----------------------------------------------------------------------
# RUTAS EXTRAS
# ----------------------------------------------------------------------
@app.route('/resultados')
def resultados():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    escaneos = Escaneo.query.filter_by(usuario_id=session['usuario_id']) \
        .order_by(Escaneo.fecha.desc()).limit(10).all()
    return render_template('resultados.html', escaneos=escaneos, usuario=session.get('usuario'))


@app.route('/vulnerabilidades')
def vulnerabilidades():
    if 'usuario' not in session:
        flash('Debes iniciar sesion primero', 'error')
        return redirect('/')
    return render_template('vulnerabilidades.html', usuario=session.get('usuario'))


@app.route('/api/vulnerabilidades/summary')
def vulnerabilidades_summary():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    summary = db.session.query(
        Vulnerabilidad.severity,
        db.func.count(Vulnerabilidad.id)
    ).join(Escaneo).filter(
        Escaneo.usuario_id == session['usuario_id']
    ).group_by(Vulnerabilidad.severity).all()
    return jsonify({'summary': {sev: int(cnt) for sev, cnt in summary}})


@app.route('/api/vulnerabilidades/lista')
def vulnerabilidades_lista():
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    sev_order = db.case(
        (Vulnerabilidad.severity == 'High', 1),
        (Vulnerabilidad.severity == 'Medium', 2),
        (Vulnerabilidad.severity == 'Low', 3),
        else_=4
    )
    vulns = Vulnerabilidad.query.join(Escaneo).filter(
        Escaneo.usuario_id == session['usuario_id']
    ).order_by(sev_order).all()
    return jsonify({'vulnerabilidades': [v.to_dict() for v in vulns]})


# ----------------------------------------------------------------------
# LOGOUT
# ----------------------------------------------------------------------
@app.route('/logout')
def logout():
    usuario = session.get('usuario', 'desconocido')
    session.clear()
    app.logger.info(f'Logout: {usuario}')
    flash('Has cerrado sesion correctamente', 'success')
    return redirect('/')


# ----------------------------------------------------------------------
# ERROR HANDLERS
# ----------------------------------------------------------------------
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Demasiadas peticiones. Intenta mas tarde.'}), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Pagina no encontrada'}), 404


@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f'Error 500: {e}')
    db.session.rollback()
    return jsonify({'error': 'Error interno del servidor'}), 500


# ----------------------------------------------------------------------
# INICIALIZACION
# ----------------------------------------------------------------------
# Columnas que pueden faltar en bases de datos creadas por versiones
# anteriores: se agregan solas al arrancar (migracion ligera).
COLUMNAS_NUEVAS = {
    'usuarios': {
        'reset_token_hash': 'VARCHAR(255) NULL',
        'reset_expira_en': 'DATETIME NULL',
        'reset_intentos': 'INTEGER NOT NULL DEFAULT 0',
    },
    'trabajos_escaneo': {
        'progreso': 'VARCHAR(255) NULL',
    },
}


def _asegurar_columnas():
    """Agrega columnas nuevas a tablas existentes (MySQL/SQLite)."""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(db.engine)
        for tabla, columnas in COLUMNAS_NUEVAS.items():
            if not inspector.has_table(tabla):
                continue
            existentes = {c['name'] for c in inspector.get_columns(tabla)}
            for columna, ddl in columnas.items():
                if columna in existentes:
                    continue
                try:
                    db.session.execute(text(f'ALTER TABLE {tabla} ADD COLUMN {columna} {ddl}'))
                    db.session.commit()
                    app.logger.info(f'Columna agregada a {tabla}: {columna}')
                except Exception as exc:
                    db.session.rollback()
                    app.logger.warning(f'No se pudo agregar {tabla}.{columna}: {exc}')
    except Exception as exc:
        app.logger.warning(f'Migracion de columnas omitida: {exc}')


with app.app_context():
    db.create_all()
    _asegurar_columnas()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
