import socket
import time

print("🔍 ANÁLISIS DE VULNERABILIDADES EN RED")
print("Sistema de Seguridad para Servidores Web con Análisis de Vulnerabilidades")
print("=" * 85)

# Detectar IP automáticamente (funciona en casa y en el colegio)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_local = s.getsockname()[0]
    s.close()
    hostname = socket.gethostname()
    
    print(f"Computadora          : {hostname}")
    print(f"IP de la red         : {ip_local}")
except:
    ip_local = "127.0.0.1"

print("-" * 85)

puertos = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8080]

print(f"Escaneando puertos en {ip_local} ...\n")
print(f"{'Puerto':<6} {'Estado':<12} {'Explicación'}")
print("-" * 85)

for puerto in puertos:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    
    resultado = sock.connect_ex((ip_local, puerto))
    
    if resultado == 0:
        if puerto == 5000:
            print(f"{puerto:<6} ABIERTO      → Sistema de Login Seguro (Flask) funcionando")
        else:
            print(f"{puerto:<6} ABIERTO      → Servicio activo - Posible punto de entrada")
    else:
        print(f"{puerto:<6} CERRADO      → Seguro (no hay servicio escuchando)")
    
    sock.close()
    time.sleep(0.12)

print("\n" + "=" * 85)
print("CONCLUSIONES:")
print("• La mayoría de los puertos cerrados = Alto nivel de seguridad básica")
print("• El puerto 5000 abierto = Nuestro sistema web está activo y escuchando")
print("• Esto demuestra la relación entre servicio web y puertos de red")
print("• En servidores reales es importante controlar y proteger los puertos abiertos")
print("• Esta herramienta funciona en cualquier red (casa, colegio, etc.)")