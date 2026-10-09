"""
Agente local de SecureScan
==========================
Corre en la PC que esta conectada a la red WiFi/LAN que se quiere escanear.
Consulta a la aplicacion web cada pocos segundos si hay trabajos pendientes,
los ejecuta localmente (arp, ping, puertos) y sube los resultados.

Uso:
    python agente_local.py

Variables opcionales:
    AGENTE_URL    URL de la app (default: https://tesix-five.vercel.app)
    AGENTE_TOKEN  token secreto (OBLIGATORIO: debe coincidir con AGENTE_TOKEN del servidor)
"""

import os
import sys
import time

import requests

from escaneo_red import descubrir_dispositivos

BASE = os.environ.get('AGENTE_URL', 'https://tesix-five.vercel.app').rstrip('/')
TOKEN = os.environ.get('AGENTE_TOKEN', '')

HEADERS = {'X-Agente-Token': TOKEN}


def _verificar_config():
    if not TOKEN:
        print('[!] Falta AGENTE_TOKEN. Defini la variable de entorno con el mismo')
        print('    token que esta configurado en el servidor (AGENTE_TOKEN).')
        sys.exit(1)


def claim_trabajo():
    r = requests.post(f'{BASE}/api/agente/claim', headers=HEADERS, timeout=20)
    if r.status_code == 503:
        print('[!] El servidor no tiene AGENTE_TOKEN configurado. No se puede usar el agente.')
        sys.exit(1)
    if r.status_code == 401:
        print('[!] Token invalido. Revisa AGENTE_TOKEN.')
        sys.exit(1)
    if r.status_code == 200:
        return r.json().get('trabajo')
    print(f'[!] Respuesta inesperada del servidor ({r.status_code}). Reintentando...')
    return None


def enviar_resultados(trabajo_id, payload):
    payload['trabajo_id'] = trabajo_id
    payload['agente_token'] = TOKEN
    r = requests.post(f'{BASE}/api/agente/resultados', headers=HEADERS, json=payload, timeout=30)
    return r.status_code == 200


def main():
    _verificar_config()
    print('[*] Agente SecureScan iniciado')
    print(f'[*] Servidor: {BASE}')
    print('[*] Esperando trabajos de escaneo... (Ctrl+C para salir)')
    while True:
        try:
            trabajo = claim_trabajo()
            if not trabajo:
                time.sleep(5)
                continue

            print(f'[+] Trabajo #{trabajo["id"]} recibido (tipo: {trabajo["tipo"]}). Escaneando red...')

            def _progreso(mensaje):
                print(f'    ... {mensaje}')

            try:
                target = trabajo.get('target') or 'auto'
                ip_base = target if target and target != 'auto' else None
                titulo, subtitulo, resultados = descubrir_dispositivos(ip_base, progreso=_progreso)
                ok = enviar_resultados(trabajo['id'], {
                    'ok': True,
                    'titulo': titulo,
                    'subtitulo': subtitulo,
                    'resultados': resultados,
                })
                print(f'[{"+" if ok else "-"}] {len(resultados)} dispositivos enviados al servidor.'
                      if ok else '[!] El servidor rechazo los resultados.')
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
