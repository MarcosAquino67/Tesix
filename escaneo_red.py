"""
Escaneo de red: puertos, dispositivos LAN y analisis web.
Modulo puro compartido por la app Flask (app.py) y por agente_local.py.
No importa Flask: puede correr standalone en la PC de la red a escanear.
"""

import ipaddress
import platform
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# ----------------------------------------------------------------------
# CONSTANTES
# ----------------------------------------------------------------------
PUERTOS_POR_DEFECTO = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8080]
PUERTOS_DESCUBRIMIENTO = [80, 443, 8080, 5000, 22, 3389, 53, 554, 1900, 50000]
PING_TIMEOUT_MS = 800
PING_WORKERS = 128
DNS_TIMEOUT = 1.0
PUERTO_TIMEOUT = 0.4

IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
URL_RE = re.compile(r'^https?://[a-zA-Z0-9\-\.]+(:\d{1,5})?(/[^\s]*)?$')

_DNS_EXECUTOR = ThreadPoolExecutor(max_workers=16)

# ----------------------------------------------------------------------
# VALIDACION DE OBJETIVOS
# ----------------------------------------------------------------------


def es_ip_valida(ip):
    if not IPV4_RE.match(ip or ''):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validar_ip(ip):
    if not es_ip_valida(ip):
        return False
    partes = ip.split('.')
    return all(0 <= int(p) <= 255 for p in partes)


def validar_url(url):
    return bool(URL_RE.match(url or ''))


def sanitize_target(target, tipo):
    """Normaliza y valida el objetivo. Igual que la logica original de app.py."""
    target = (target or '').strip()
    if tipo == 'puertos':
        if not target:
            return target
        if not validar_ip(target):
            raise ValueError(f'IP invalida: {target}')
        return target
    elif tipo == 'url':
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        if not validar_url(target):
            raise ValueError(f'URL invalida: {target}')
        partes = urllib.request.urlparse(target)
        texto = partes.netloc + partes.path + partes.query
        if any(c in texto for c in [';', '|', '&', '$', '`', '(', ')', '<', '>', ' ', '\\']):
            raise ValueError(f'URL invalida: {target}')
        return target
    elif tipo == 'dispositivos':
        return target
    raise ValueError(f'Tipo de escaneo invalido: {tipo}')


def es_url_permitida(url):
    """Anti-SSRF: rechaza URLs que apunten a IPs privadas, loopback o reservadas.

    Devuelve (permitida, mensaje).
    """
    try:
        host = urllib.request.urlparse(url).hostname or ''
    except Exception:
        return False, 'URL invalida.'

    if not host:
        return False, 'La URL no tiene host.'

    if host.lower() in ('localhost', 'ip6-localhost', 'ip6-loopback'):
        return False, 'No se permiten URLs locales o privadas.'

    try:
        if es_ip_valida(host):
            ips = [ipaddress.ip_address(host)]
        else:
            ips = [ipaddress.ip_address(d[4][0]) for d in socket.getaddrinfo(host, None)]
    except Exception:
        return False, 'No se pudo resolver el host de la URL.'

    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, 'No se pudo resolver el host de la URL.'
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False, 'No se permiten URLs que apunten a redes privadas o locales.'
    return True, ''


# ----------------------------------------------------------------------
# RED LOCAL
# ----------------------------------------------------------------------


def ip_local():
    """IP de esta PC en la red local (truco del socket UDP, no envia datos)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def prefijo_red_local():
    ip = ip_local()
    return '.'.join(ip.split('.')[:-1]), ip


def hacer_ping(ip, timeout_ms=PING_TIMEOUT_MS):
    """Ping a una IP. Devuelve la IP si responde, si no None."""
    if not validar_ip(ip):
        return None
    es_windows = platform.system().lower() == 'windows'
    try:
        if es_windows:
            comando = ['ping', '-n', '1', '-w', str(timeout_ms), ip]
        else:
            comando = ['ping', '-c', '1', '-W', str(max(1, timeout_ms // 1000)), ip]
        resultado = subprocess.run(
            comando,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, (timeout_ms / 1000) + 2),
        )
        return ip if resultado.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def ping_barredo(ip_base, progreso=None, timeout_ms=PING_TIMEOUT_MS):
    """Ping a toda la subred /24 en paralelo."""
    ips = [f'{ip_base}.{i}' for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
        resultados = list(executor.map(lambda ip: hacer_ping(ip, timeout_ms), ips))
    activas = [ip for ip in resultados if ip]
    if progreso:
        progreso(f'{len(activas)} dispositivos respondieron al ping')
    return activas


def escanear_puertos(ip, puertos=None, timeout=PUERTO_TIMEOUT, workers=None):
    """Escaneo TCP de puertos en paralelo. Devuelve lista ordenada de abiertos."""
    if puertos is None:
        puertos = PUERTOS_POR_DEFECTO
    abiertos = []
    lock = threading.Lock()

    def _verificar(puerto):
        try:
            with socket.create_connection((ip, puerto), timeout=timeout):
                with lock:
                    abiertos.append(puerto)
        except Exception:
            pass

    workers = workers or min(64, max(1, len(puertos)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(_verificar, puertos))
    return sorted(abiertos)


# ----------------------------------------------------------------------
# MAC / FABRICANTES
# ----------------------------------------------------------------------
MAC_VENDORS = {
    '00:26:08': 'Apple', '3c:15:c2': 'Apple', 'a4:5e:60': 'Apple', 'f8:ff:c2': 'Apple',
    'ec:1f:72': 'Samsung', '84:25:db': 'Samsung', '28:39:26': 'Samsung', 'cc:07:ab': 'Samsung',
    '34:80:b3': 'Xiaomi', '64:09:80': 'Xiaomi', 'd8:18:d6': 'Xiaomi',
    '84:c7:ea': 'Motorola', '00:0c:e7': 'Motorola',
    '00:11:32': 'Synology / Router', '50:c7:bf': 'TP-Link', 'e8:48:b8': 'TP-Link',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
    '00:50:56': 'VMware', '08:00:27': 'VirtualBox',
}

CACHE_VENDORS = {}


def obtener_tabla_arp():
    """Tabla ARP del sistema: {ip: mac}."""
    tabla = {}
    try:
        salida = subprocess.check_output(['arp', '-a'], stderr=subprocess.STDOUT, timeout=3).decode('latin-1')
        for linea in salida.splitlines():
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', linea)
            mac_match = re.search(
                r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})',
                linea,
            )
            if ip_match and mac_match:
                tabla[ip_match.group(1)] = mac_match.group(1).lower().replace('-', ':').upper()
    except Exception:
        pass
    return tabla


def es_mac_aleatoria(mac):
    segundo = mac.split(':')[0][1].upper()
    return segundo in ('2', '6', 'A', 'E')


def consultar_marca_online(mac):
    if mac in CACHE_VENDORS:
        return CACHE_VENDORS[mac]
    try:
        req = urllib.request.Request(f'https://api.macvendors.com/{mac}')
        with urllib.request.urlopen(req, timeout=2) as resp:
            marca = resp.read().decode('utf-8').strip()
        CACHE_VENDORS[mac] = marca
        return marca
    except Exception:
        CACHE_VENDORS[mac] = None
        return None


def identificar_marca(mac):
    prefix = (mac or '')[:8].lower()
    if prefix in MAC_VENDORS:
        return MAC_VENDORS[prefix]
    if len(mac) == 17 and es_mac_aleatoria(mac):
        return 'MAC aleatoria (privacidad) - posible iPhone/Android reciente'
    marca_online = consultar_marca_online(mac)
    return marca_online if marca_online else 'Dispositivo Conectado'


# ----------------------------------------------------------------------
# DESCUBRIMIENTO DE DISPOSITIVOS
# ----------------------------------------------------------------------


def dns_inverso(ip, timeout=DNS_TIMEOUT):
    """Hostname por DNS inverso con timeout (sin colgar el escaneo)."""
    try:
        fut = _DNS_EXECUTOR.submit(socket.gethostbyaddr, ip)
        return fut.result(timeout=timeout)[0]
    except Exception:
        return None


def inferir_tipo_dispositivo(ip, mac, puertos_abiertos, hostname):
    hostname_lower = (hostname or '').lower()
    ip_last = int(ip.split('.')[-1]) if es_ip_valida(ip) else 0

    if ip_last == 1 or 'router' in hostname_lower or 'gateway' in hostname_lower:
        return 'Router / Modem Wi-Fi'

    if not puertos_abiertos:
        if mac and mac != 'Desconocida' and es_mac_aleatoria(mac):
            return 'Smartphone (iPhone/Android)'
        return 'Dispositivo IoT / Smart'

    servicios = set()
    for p in puertos_abiertos:
        if p == 22:
            servicios.add('ssh')
        elif p in (80, 8080):
            servicios.add('web')
        elif p == 443:
            servicios.add('https')
        elif p == 3389:
            servicios.add('windows')
        elif p == 5000:
            servicios.add('flask')
        elif p == 53:
            servicios.add('dns')
        elif p == 554:
            servicios.add('camera')
        elif p == 1900:
            servicios.add('upnp')

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

    if mac and mac != 'Desconocida':
        marca = identificar_marca(mac)
        if marca and marca != 'Dispositivo Conectado':
            return f'{marca} (dispositivo)'
    return 'Dispositivo de red'


def descubrir_dispositivos(ip_base=None, progreso=None):
    """Descubre dispositivos activos en la red local.

    Devuelve (titulo, subtitulo, resultados) con el mismo formato que usa la app.
    """
    inicio = time.perf_counter()

    if not ip_base:
        ip_base, ip_propia = prefijo_red_local()
    else:
        _, ip_propia = prefijo_red_local()

    if progreso:
        progreso(f'Ping a {ip_base}.1 - {ip_base}.254')

    ips_activas = ping_barredo(ip_base, progreso=progreso)

    tabla_arp = obtener_tabla_arp()
    for ip_arp in tabla_arp:
        if ip_arp not in ips_activas and ip_arp.startswith(ip_base):
            ips_activas.append(ip_arp)

    ips_ordenadas = sorted(set(ips_activas), key=lambda ip: int(ip.split('.')[-1]))

    def _analizar(ip_test):
        mac = tabla_arp.get(ip_test, 'Desconocida')
        marca = identificar_marca(mac) if mac != 'Desconocida' else 'Dispositivo Conectado'
        puertos = escanear_puertos(ip_test, PUERTOS_DESCUBRIMIENTO, timeout=0.3)
        hostname = dns_inverso(ip_test)

        if ip_test == ip_propia:
            nombre = f'Este Equipo ({socket.gethostname()})'
        else:
            nombre = inferir_tipo_dispositivo(ip_test, mac, puertos, hostname)

        puertos_str = ', '.join(str(p) for p in puertos) if puertos else 'Ninguno detectado'
        detalle = f'MAC: {mac} | Marca: {marca} | Puertos: {puertos_str}'
        if hostname and ip_test != ip_propia:
            detalle += f' | Host: {hostname}'

        return {
            'item': f'IP {ip_test} - {nombre}',
            'estado': 'ACTIVO',
            'explicacion': detalle,
        }

    resultados = []
    total = len(ips_ordenadas)
    if total:
        with ThreadPoolExecutor(max_workers=32) as executor:
            for indice, resultado in enumerate(executor.map(_analizar, ips_ordenadas), start=1):
                resultados.append(resultado)
                if progreso and indice % 5 == 0:
                    progreso(f'Analizando dispositivos {indice}/{total}')

    duracion = time.perf_counter() - inicio
    titulo = 'Dispositivos en Red Local'
    subtitulo = (
        f'Rango analizado: {ip_base}.1 - {ip_base}.254 | '
        f'{len(resultados)} dispositivos activos | {duracion:.1f}s'
    )
    return titulo, subtitulo, resultados


# ----------------------------------------------------------------------
# ANALISIS WEB / SSL
# ----------------------------------------------------------------------


def _dias_hasta_caducidad_cert(hostname, timeout=4):
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        no_despues = cert.get('notAfter')
        if not no_despues:
            return None
        vence = datetime.strptime(no_despues, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        return (vence - datetime.now(timezone.utc)).days
    except Exception:
        return None


def analizar_url(url, progreso=None):
    """Analiza una URL: estado HTTP, HTTPS, cabeceras de seguridad y certificado.

    Devuelve (titulo, subtitulo, resultados).
    """
    inicio = time.perf_counter()
    resultados = []
    hostname = urllib.request.urlparse(url).hostname or ''

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.getcode()
            resultados.append({
                'item': 'Estado HTTP',
                'estado': 'OK' if status == 200 else 'ALERTA',
                'explicacion': f'Codigo de respuesta {status}',
            })
            resultados.append({
                'item': 'HTTPS / SSL',
                'estado': 'SEGURO' if url.startswith('https') else 'RIESGO',
                'explicacion': 'Trafico cifrado activado' if url.startswith('https') else 'Sitio no usa HTTPS',
            })

            headers = {k.lower(): v for k, v in response.info().items()}
            for cabecera in ('Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options'):
                presente = cabecera.lower() in headers
                resultados.append({
                    'item': f'Cabecera {cabecera}',
                    'estado': 'OK' if presente else 'AUSENTE',
                    'explicacion': 'Cabecera de proteccion detectada' if presente else 'Se recomienda agregar esta cabecera',
                })

        if url.startswith('https'):
            dias = _dias_hasta_caducidad_cert(hostname)
            if dias is not None:
                if dias < 0:
                    estado, explicacion = 'ALERTA', 'El certificado SSL esta vencido'
                elif dias < 15:
                    estado, explicacion = 'ALERTA', f'El certificado vence en {dias} dias'
                else:
                    estado, explicacion = 'OK', f'Certificado valido, vence en {dias} dias'
                resultados.append({
                    'item': 'Certificado SSL',
                    'estado': estado,
                    'explicacion': explicacion,
                })
    except Exception as e:
        resultados.append({
            'item': 'Conexion Web',
            'estado': 'FALLO',
            'explicacion': f'No se pudo acceder a la URL ({str(e)})',
        })

    duracion = time.perf_counter() - inicio
    subtitulo = f'Objetivo: {url} | {duracion:.1f}s'
    return 'Analisis Web y SSL', subtitulo, resultados
