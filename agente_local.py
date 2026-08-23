"""
Agente local de SecureScan / Tesix
==================================
Corre en la PC que esta conectada a la red WiFi/LAN que se quiere escanear.
Consulta a la aplicacion web cada pocos segundos si hay trabajos pendientes,
los ejecuta localmente (arp, ping, puertos) y sube los resultados.

Uso:
    python agente_local.py

Variables opcionales:
    AGENTE_URL    URL de la app (default: https://tesix-five.vercel.app)
    AGENTE_TOKEN  token secreto (debe coincidir con la variable AGENTE_TOKEN del servidor)
"""

import os
import time
import sys

try:
    import requests
except ImportError:
    print("Falta 'requests'. Instalalo con: pip install requests")
    sys.exit(1)

BASE = os.environ.get('AGENTE_URL', 'https://tesix-five.vercel.app').rstrip('/')
TOKEN = os.environ.get('AGENTE_TOKEN', '')

HEADERS = {'X-Agente-Token': TOKEN}


def ejecutar_escaneo_dispositivos():
    """Importa las funciones de escaneo de app.py y ejecuta el analisis LAN real."""
    # Forzar sqlite para no depender de MySQL local: el agente solo usa funciones puras
    for var in ('DATABASE_URL', 'DB_USER', 'DB_PASS'):
        os.environ.pop(var, None)
    os.environ['FLASK_ENV'] = 'development'

    from app import (
        hacer_ping,
        obtener_tabla_arp_completa,
        identificar_marca,
        escanear_puertos_rapido,
        inferir_tipo_dispositivo,
    )
    import socket
    from concurrent.futures import ThreadPoolExecutor

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_base = ".".join(s.getsockname()[0].split('.')[:-1])
        ip_propia = s.getsockname()[0]
        s.close()
    except Exception:
        ip_base = "192.168.0"
        ip_propia = "127.0.0.1"

    ips_a_probar = [f"{ip_base}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=60) as executor:
        resultados_ping = list(executor.map(hacer_ping, ips_a_probar))
    ips_activas = [ip for ip in resultados_ping if ip]

    tabla_arp = obtener_tabla_arp_completa()
    for ip_arp in tabla_arp:
        if ip_arp not in ips_activas and ip_arp.startswith(ip_base):
            ips_activas.append(ip_arp)

    macs_vistas = set()
    resultados = []
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
    return titulo, subtitulo, resultados


def _post(url, **kwargs):
    kwargs.setdefault('timeout', 20)
    r = requests.post(url, headers=HEADERS, **kwargs)
    try:
        datos = r.json()
    except ValueError:
        datos = None
    return r.status_code, datos


def claim_trabajo():
    codigo, datos = _post(f'{BASE}/api/agente/claim', json={'agente_token': TOKEN})
    if codigo == 401:
        print('[!] Token invalido. Revisa AGENTE_TOKEN.')
        sys.exit(1)
    if codigo == 200 and isinstance(datos, dict):
        return datos.get('trabajo')
    print(f'[!] Respuesta inesperada del servidor ({codigo}). Reintentando...')
    return None


def enviar_resultados(trabajo_id, payload):
    payload['trabajo_id'] = trabajo_id
    payload['agente_token'] = TOKEN
    codigo, _ = _post(f'{BASE}/api/agente/resultados', json=payload)
    if codigo != 200:
        print(f'[!] El servidor rechazo los resultados (HTTP {codigo}).')
    return codigo == 200


def main():
    if not TOKEN:
        print('[!] Define AGENTE_TOKEN (el mismo configurado en el servidor).')
        print('    Ejemplo Windows:  set AGENTE_TOKEN=tu_token && python agente_local.py')
        sys.exit(1)

    print(f'[*] Agente SecureScan iniciado')
    print(f'[*] Servidor: {BASE}')
    print(f'[*] Esperando trabajos de escaneo... (Ctrl+C para salir)')
    while True:
        try:
            trabajo = claim_trabajo()
            if not trabajo:
                time.sleep(5)
                continue

            print(f'[+] Trabajo #{trabajo["id"]} recibido (tipo: {trabajo["tipo"]}). Escaneando red...')
            try:
                titulo, subtitulo, resultados = ejecutar_escaneo_dispositivos()
                ok = enviar_resultados(trabajo['id'], {
                    'ok': True,
                    'titulo': titulo,
                    'subtitulo': subtitulo,
                    'resultados': resultados,
                })
                print(f'[{ "+" if ok else "-" }] {len(resultados)} dispositivos enviados al servidor.' if ok
                      else '[!] El servidor rechazo los resultados.')
            except Exception as exc:
                print(f'[!] Error durante el escaneo: {exc}')
                enviar_resultados(trabajo['id'], {'ok': False, 'error': str(exc)})

        except KeyboardInterrupt:
            print('\n[*] Agente detenido.')
            break
        except requests.RequestException as exc:
            print(f'[!] Sin conexion con el servidor: {exc}')
            time.sleep(10)


if __name__ == '__main__':
    main()
