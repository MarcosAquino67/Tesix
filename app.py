import socket
import os
import platform
import subprocess
import re
import secrets
import logging
import urllib.request
import ssl
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, flash, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, Usuario, Escaneo, ResultadoEscaneo, Vulnerabilidad, TrabajoEscaneo
from config import Config

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(_BASE_DIR, 'templates'),
    static_folder=os.path.join(_BASE_DIR, 'static')
)
app.config.from_object(Config)

db.init_app(app)

import secrets as _secrets

@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if '_csrf_token' not in session:
            session['_csrf_token'] = _secrets.token_hex(32)
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
# TALISMAN (HTTPS enforcement) - solo en produccion
# ----------------------------------------------------------------------
try:
    from flask_talisman import Talisman
    talisman = Talisman(
        app,
        force_https=False,
        content_security_policy=None,
        session_cookie_secure=False,
    )
except ImportError:
    pass

# ----------------------------------------------------------------------
# SANITIZACION DE INPUTS
# ----------------------------------------------------------------------
IP_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
URL_REGEX = re.compile(
    r'^https?://[a-zA-Z0-9\-\.]+(\.[a-zA-Z]{2,})(:\d{1,5})?(/[^\s]*)?$'
)

VALID_SCAN_TYPES = ('puertos', 'url', 'dispositivos')


def validar_ip(ip):
    return bool(IP_REGEX.match(ip))


def validar_url(url):
    if not URL_REGEX.match(url):
        return False
    parsed = urllib.request.url2pathname(url)
    if any(c in parsed for c in [';', '|', '&', '$', '`', '(', ')']):
        return False
    return True


def sanitize_target(target, tipo):
    target = target.strip()
    if tipo == 'puertos':
        if not target or target == '':
            return target
        if not validar_ip(target):
            raise ValueError(f'IP invalida: {target}')
        return target
    elif tipo == 'url':
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        if not validar_url(target):
            raise ValueError(f'URL invalida: {target}')
        return target
    elif tipo == 'dispositivos':
        return target
    raise ValueError(f'Tipo de escaneo invalido: {tipo}')


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

    return vulns


# ----------------------------------------------------------------------
# MAC VENDORS
# ----------------------------------------------------------------------
MAC_VENDORS = {
    '00:26:08': 'Apple', '3c:15:c2': 'Apple', 'a4:5e:60': 'Apple', 'f8:ff:c2': 'Apple',
    'ec:1f:72': 'Samsung', '84:25:db': 'Samsung', '28:39:26': 'Samsung', 'cc:07:ab': 'Samsung',
    '34:80:b3': 'Xiaomi', '64:09:80': 'Xiaomi', 'd8:18:d6': 'Xiaomi',
    '84:c7:ea': 'Motorola', '00:0c:e7': 'Motorola',
    '00:11:32': 'Synology / Router', '50:c7:bf': 'TP-Link', 'e8:48:b8': 'TP-Link',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
    '00:50:56': 'VMware', '08:00:27': 'VirtualBox'
}

CACHE_VENDORS = {}


def obtener_tabla_arp_completa():
    tabla = {}
    try:
        salida = subprocess.check_output(
            ['arp', '-a'], stderr=subprocess.STDOUT, timeout=3
        ).decode('latin-1')
        for linea in salida.splitlines():
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', linea)
            mac_match = re.search(
                r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})',
                linea
            )
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1).lower().replace('-', ':')
                tabla[ip] = mac.upper()
    except Exception:
        pass
    return tabla


def es_mac_aleatoria(mac):
    segundo_digito = mac.split(':')[0][1].upper()
    return segundo_digito in ('2', '6', 'A', 'E')


def consultar_marca_online(mac):
    if mac in CACHE_VENDORS:
        return CACHE_VENDORS[mac]
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{mac}")
        with urllib.request.urlopen(req, timeout=2) as resp:
            marca = resp.read().decode('utf-8').strip()
            CACHE_VENDORS[mac] = marca
            return marca
    except Exception:
        CACHE_VENDORS[mac] = None
        return None


def identificar_marca(mac):
    prefix = mac[:8].lower()
    if prefix in MAC_VENDORS:
        return MAC_VENDORS[prefix]
    if es_mac_aleatoria(mac):
        return "MAC aleatoria (privacidad) - posible iPhone/Android reciente"
    marca_online = consultar_marca_online(mac)
    return marca_online if marca_online else "Dispositivo Conectado"


def hacer_ping(ip_test):
    if not validar_ip(ip_test):
        return None
    es_windows = platform.system().lower() == 'windows'
    try:
        param_cantidad = '-n' if es_windows else '-c'
        destino_nulo = 'NUL' if es_windows else '/dev/null'
        tiempo_espera = '-w' if es_windows else '-W'
        tiempo_valor = '1000' if es_windows else '2'
        comando = [
            'ping', param_cantidad, '1', tiempo_espera, tiempo_valor, ip_test
        ]
        resultado = subprocess.run(
            comando,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        return ip_test if resultado.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def escanear_puertos_rapido(ip, puertos=None):
    if puertos is None:
        puertos = [80, 443, 8080, 5000, 22, 3389, 53, 554, 1900, 50000]
    abiertos = []
    for puerto in puertos:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, puerto)) == 0:
                abiertos.append(puerto)
            sock.close()
        except Exception:
            pass
    return abiertos


def inferir_tipo_dispositivo(ip, mac, puertos_abiertos, hostname):
    hostname_lower = hostname.lower() if hostname else ''
    ip_last = int(ip.split('.')[-1])

    if ip_last == 1 or 'router' in hostname_lower or 'gateway' in hostname_lower:
        return 'Router / Modem Wi-Fi'

    if not puertos_abiertos:
        if mac and es_mac_aleatoria(mac):
            return 'Smartphone (iPhone/Android)'
        return 'Dispositivo IoT / Smart'

    servicios = set()
    for p in puertos_abiertos:
        if p == 22: servicios.add('ssh')
        elif p == 80 or p == 8080: servicios.add('web')
        elif p == 443: servicios.add('https')
        elif p == 3389: servicios.add('windows')
        elif p == 5000: servicios.add('flask')
        elif p == 53: servicios.add('dns')
        elif p == 554: servicios.add('camera')
        elif p == 1900: servicios.add('upnp')

    if 'windows' in servicios:
        return 'PC Windows'
    if 'ssh' in servicios and 'web' not in servicios:
        return 'Servidor / Linux'
    if 'camera' in servicios or 'upnp' in servicios:
        return 'Camara IP / Smart TV'
    if 'flask' in servicios or ('web' in servicios and 'https' not in servicios):
        return 'Servidor / Raspberry Pi'
    if 'web' in servicios and 'https' in servicios:
        return 'PC / Laptop'

    if mac:
        marca = identificar_marca(mac)
        if marca and marca != 'Dispositivo Conectado':
            return f'{marca} (dispositivo)'

    return 'Dispositivo de red'


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
        session['usuario'] = user.username
        session['usuario_id'] = user.id
        session.permanent = True
        app.logger.info(f'Login exitoso: {usuario}')
        return redirect('/dashboard')

    app.logger.warning(f'Login fallido para usuario: {usuario}')
    flash('Usuario o contrasena incorrectos', 'error')
    return redirect('/')


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

        datos = request.get_json() or {}
        tipo_escaneo = datos.get('tipo', 'puertos')
        target = datos.get('target', '').strip()

        if tipo_escaneo not in VALID_SCAN_TYPES:
            return jsonify({'error': 'Tipo de escaneo invalido'}), 400

        # Escaneos de red local: se encolan para el agente si esta habilitado
        if tipo_escaneo == 'dispositivos' and os.environ.get('AGENTE_HABILITADO') == '1':
            trabajo = TrabajoEscaneo(
                usuario_id=session['usuario_id'],
                tipo='dispositivos',
                target=target or 'auto',
                estado='pendiente'
            )
            db.session.add(trabajo)
            db.session.commit()
            return jsonify({
                'async': True,
                'trabajo_id': trabajo.id,
                'mensaje': 'Escaneo encolado. Esperando al agente de red...'
            })

        try:
            target = sanitize_target(target, tipo_escaneo)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        resultados = []
        titulo = ""
        subtitulo = ""
        target_registro = target

        if tipo_escaneo == 'puertos':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_target = s.getsockname()[0]
                s.close()
                hostname = socket.gethostname()
            except Exception:
                ip_target = "127.0.0.1"
                hostname = "localhost"

            puertos = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8080]
            for puerto in puertos:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                res = sock.connect_ex((ip_target, puerto))
                estado = "ABIERTO" if res == 0 else "CERRADO"
                if puerto == 5000 and res == 0:
                    explicacion = "Sistema Flask corriendo"
                elif res == 0:
                    explicacion = "Servicio activo"
                else:
                    explicacion = "Seguro (sin escucha)"
                resultados.append({'item': f"Puerto {puerto}", 'estado': estado, 'explicacion': explicacion})
                sock.close()

            titulo = 'Analisis de Puertos de Red'
            subtitulo = f"Host: {hostname} ({ip_target})"
            target_registro = ip_target
            app.logger.info(f'Escaneo de puertos ejecutado en {ip_target}')

        elif tipo_escaneo == 'url':
            target_registro = target
            try:
                req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                contexto = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=3, context=contexto) as response:
                    status = response.getcode()
                    resultados.append({
                        'item': 'Estado HTTP',
                        'estado': 'OK' if status == 200 else 'ALERTA',
                        'explicacion': f"Codigo de respuesta {status}"
                    })
                    resultados.append({
                        'item': 'HTTPS / SSL',
                        'estado': 'SEGURO' if target.startswith('https') else 'RIESGO',
                        'explicacion': 'Trafico cifrado activado' if target.startswith('https') else 'Sitio no usa HTTPS'
                    })

                    headers = dict(response.info())
                    h_seguridad = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
                    for h in h_seguridad:
                        esta = h in headers
                        resultados.append({
                            'item': f"Cabecera {h}",
                            'estado': 'OK' if esta else 'AUSENTE',
                            'explicacion': 'Cabecera de proteccion detectada' if esta else 'Se recomienda agregar esta cabecera'
                        })
            except Exception as e:
                resultados.append({
                    'item': 'Conexion Web',
                    'estado': 'FALLO',
                    'explicacion': f"No se pudo acceder a la URL ({str(e)})"
                })

            titulo = 'Analisis Web y SSL'
            subtitulo = f"Objetivo: {target}"
            app.logger.info(f'Escaneo URL ejecutado: {target}')

        elif tipo_escaneo == 'dispositivos':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_base = ".".join(s.getsockname()[0].split('.')[:-1])
                ip_propia = s.getsockname()[0]
                s.close()
            except Exception:
                ip_base = "192.168.0"
                ip_propia = "127.0.0.1"

            target_registro = f"{ip_base}.0/24"

            ips_a_probar = [f"{ip_base}.{i}" for i in range(1, 255)]
            with ThreadPoolExecutor(max_workers=60) as executor:
                resultados_ping = list(executor.map(hacer_ping, ips_a_probar))
            ips_activas = [ip for ip in resultados_ping if ip]

            tabla_arp = obtener_tabla_arp_completa()

            for ip_arp in tabla_arp:
                if ip_arp not in ips_activas and ip_arp.startswith(ip_base):
                    ips_activas.append(ip_arp)

            macs_vistas = set()
            for ip_test in sorted(ips_activas, key=lambda ip: int(ip.split('.')[-1])):
                mac = tabla_arp.get(ip_test, "Desconocida")

                if mac != "Desconocida" and mac in macs_vistas:
                    continue
                macs_vistas.add(mac)

                marca = identificar_marca(mac) if mac != "Desconocida" else "Dispositivo Conectado"

                puertos_abiertos = escanear_puertos_rapido(ip_test)

                try:
                    hostname = socket.gethostbyaddr(ip_test)[0]
                except Exception:
                    hostname = None

                if ip_test == ip_propia:
                    nombre_dispositivo = f"Este Equipo ({socket.gethostname()})"
                else:
                    nombre_dispositivo = inferir_tipo_dispositivo(ip_test, mac, puertos_abiertos, hostname)

                puertos_str = ', '.join(str(p) for p in puertos_abiertos) if puertos_abiertos else 'Ninguno detectado'
                detalle = f"MAC: {mac} | Marca: {marca} | Puertos: {puertos_str}"
                if hostname and ip_test != ip_propia:
                    detalle += f" | Host: {hostname}"

                resultados.append({
                    'item': f"IP {ip_test} - {nombre_dispositivo}",
                    'estado': 'ACTIVO',
                    'explicacion': detalle
                })

            titulo = 'Dispositivos en Red Local'
            subtitulo = f"Rango analizado: {ip_base}.1 - {ip_base}.254 ({len(resultados)} dispositivos activos)"
            app.logger.info(f'Escaneo de dispositivos: {len(resultados)} encontrados')

        escaneo_id = guardar_escaneo_completo(
            session['usuario_id'], tipo_escaneo, target_registro, titulo, subtitulo, resultados
        )
        app.logger.info(f'Escaneo guardado id={escaneo_id} tipo={tipo_escaneo}')

        return jsonify({
            'titulo': titulo,
            'subtitulo': subtitulo,
            'resultados': resultados
        })

    except Exception as e:
        app.logger.error(f'Error en escaneo: {e}', exc_info=True)
        return jsonify({'error': f'Error interno: {str(e)}'}), 500


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


def _requiere_token_agente():
    token_esperado = os.environ.get('AGENTE_TOKEN', '')
    if not token_esperado:
        return False
    token_recibido = request.headers.get('X-Agente-Token', '')
    if not token_recibido:
        datos = request.get_json(silent=True) or {}
        token_recibido = datos.get('agente_token', '') or request.form.get('agente_token', '')
    return token_recibido == token_esperado


@app.route('/api/agente/ping')
def agente_ping():
    return jsonify({
        'ok': True,
        'token_configurado': bool(os.environ.get('AGENTE_TOKEN')),
        'cola_habilitada': os.environ.get('AGENTE_HABILITADO') == '1'
    })


@app.route('/api/trabajo/<int:trabajo_id>', methods=['GET'])
def estado_trabajo(trabajo_id):
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401

    trabajo = TrabajoEscaneo.query.get(trabajo_id)
    if not trabajo or trabajo.usuario_id != session['usuario_id']:
        return jsonify({'error': 'Trabajo no encontrado'}), 404

    respuesta = {'id': trabajo.id, 'estado': trabajo.estado}

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
    return render_template('configuracion.html', usuario=session['usuario'])


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
# RECUPERACION DE CONTRASENA
# ----------------------------------------------------------------------
@app.route('/recuperar', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def recuperar():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = Usuario.query.filter_by(username=username).first()
        if user:
            nueva_temporal = secrets.token_urlsafe(8)
            user.password_hash = generate_password_hash(nueva_temporal)
            db.session.commit()
            app.logger.info(f'Contrasena temporal generada para: {username}')
            flash(f'Contrasena temporal: {nueva_temporal} ( cambiala al iniciar sesion)', 'success')
        else:
            flash('Usuario no encontrado', 'error')
        return redirect('/recuperar')
    return render_template('recuperar.html')


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
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
