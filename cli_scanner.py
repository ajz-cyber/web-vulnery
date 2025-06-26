#!/usr/bin/env python3
"""
Escáner de puertos por línea de comandos
Versión independiente sin interfaz web
"""

import os
import nmap
import argparse
from datetime import datetime

# Configuración
CARPETA_REPORTES = "reportes_cli"

def crear_estructura_directorios():
    """Crea las carpetas necesarias"""
    os.makedirs(CARPETA_REPORTES, exist_ok=True)

def ejecutar_escaneo_cli(host, puertos="1-1000", scripts="default", output_format="detailed"):
    """
    Ejecuta el escaneo por línea de comandos
    
    Args:
        host (str): Host objetivo
        puertos (str): Puertos a escanear
        scripts (str): Scripts NSE a ejecutar
        output_format (str): Formato de salida (detailed, simple, json)
    """
    try:
        print(f"[+] Iniciando escaneo al host {host}...")
        print(f"[+] Puertos: {puertos}")
        print(f"[+] Scripts: {scripts}")
        
        # Inicializar el escáner Nmap
        escaner = nmap.PortScanner()
        
        # Configurar argumentos del escaneo
        if scripts == "default":
            argumentos = f"-sV -p {puertos} -T4"
        elif scripts == "none":
            argumentos = f"-sV -p {puertos} -T4"
        else:
            argumentos = f"-sV -p {puertos} --script {scripts} -T4"
        
        print(f"[+] Ejecutando: nmap {argumentos} {host}")
        escaner.scan(hosts=host, arguments=argumentos)
        
        # Generar nombre del reporte
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nombre_reporte = f"escaneo_cli_{timestamp}.txt"
        ruta_reporte = os.path.join(CARPETA_REPORTES, nombre_reporte)
        
        print(f"[+] Generando reporte...")
        
        # Generar reporte según el formato
        with open(ruta_reporte, "w", encoding="utf-8") as archivo:
            if output_format == "simple":
                generar_reporte_simple(archivo, escaner, host, puertos, scripts)
            elif output_format == "json":
                import json
                archivo.write(json.dumps(escaner._scan_result, indent=2))
            else:  # detailed
                generar_reporte_detallado(archivo, escaner, host, puertos, scripts)
        
        print(f"[✓] Escaneo completado. Reporte guardado en: {ruta_reporte}")
        
        # Mostrar resumen en consola
        mostrar_resumen_consola(escaner)
        
        return ruta_reporte
        
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")
        return None

def generar_reporte_detallado(archivo, escaner, host, puertos, scripts):
    """Genera un reporte detallado"""
    archivo.write(f"=== REPORTE DE ESCANEO DETALLADO ===\n")
    archivo.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    archivo.write(f"Host objetivo: {host}\n")
    archivo.write(f"Puerto(s): {puertos}\n")
    archivo.write(f"Scripts: {scripts}\n")
    archivo.write("=" * 50 + "\n\n")
    
    for host_escaneado in escaner.all_hosts():
        archivo.write(f"Host: {host_escaneado} ({escaner[host_escaneado].state()})\n")
        
        # Información del host
        if 'hostnames' in escaner[host_escaneado]:
            hostnames = escaner[host_escaneado]['hostnames']
            if hostnames:
                archivo.write(f"Hostnames: {', '.join([h['name'] for h in hostnames])}\n")
        
        archivo.write("-" * 40 + "\n")
        
        for protocolo in escaner[host_escaneado].all_protocols():
            archivo.write(f"Protocolo: {protocolo}\n")
            puertos_encontrados = escaner[host_escaneado][protocolo].keys()
            
            for puerto in sorted(puertos_encontrados):
                info = escaner[host_escaneado][protocolo][puerto]
                archivo.write(f"  Puerto {puerto}: {info['state']}")
                
                if info.get('name'):
                    archivo.write(f" - Servicio: {info['name']}")
                if info.get('version'):
                    archivo.write(f" - Versión: {info['version']}")
                if info.get('product'):
                    archivo.write(f" - Producto: {info['product']}")
                
                archivo.write("\n")
                
                # Mostrar resultados de scripts NSE
                if 'script' in info:
                    archivo.write("    Scripts NSE:\n")
                    for nombre_script, salida_script in info['script'].items():
                        archivo.write(f"      [{nombre_script}]:\n")
                        lineas_script = salida_script.strip().split('\n')
                        for linea in lineas_script:
                            archivo.write(f"        {linea}\n")
                    archivo.write("\n")
        
        archivo.write("\n")

def generar_reporte_simple(archivo, escaner, host, puertos, scripts):
    """Genera un reporte simple"""
    archivo.write(f"=== REPORTE DE ESCANEO SIMPLE ===\n")
    archivo.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    archivo.write(f"Host: {host}\n")
    archivo.write(f"Puertos: {puertos}\n\n")
    
    for host_escaneado in escaner.all_hosts():
        archivo.write(f"Host: {host_escaneado} - {escaner[host_escaneado].state()}\n")
        
        puertos_abiertos = []
        for protocolo in escaner[host_escaneado].all_protocols():
            for puerto in sorted(escaner[host_escaneado][protocolo].keys()):
                info = escaner[host_escaneado][protocolo][puerto]
                if info['state'] == 'open':
                    servicio = info.get('name', 'unknown')
                    puertos_abiertos.append(f"{puerto}/{protocolo} ({servicio})")
        
        if puertos_abiertos:
            archivo.write("Puertos abiertos:\n")
            for puerto in puertos_abiertos:
                archivo.write(f"  - {puerto}\n")
        else:
            archivo.write("No se encontraron puertos abiertos.\n")
        
        archivo.write("\n")

def mostrar_resumen_consola(escaner):
    """Muestra un resumen del escaneo en consola"""
    print("\n" + "="*50)
    print("RESUMEN DEL ESCANEO")
    print("="*50)
    
    for host in escaner.all_hosts():
        print(f"Host: {host} ({escaner[host].state()})")
        
        puertos_abiertos = 0
        for protocolo in escaner[host].all_protocols():
            for puerto in escaner[host][protocolo].keys():
                if escaner[host][protocolo][puerto]['state'] == 'open':
                    puertos_abiertos += 1
                    info = escaner[host][protocolo][puerto]
                    servicio = info.get('name', 'unknown')
                    version = info.get('version', '')
                    print(f"  {puerto}/{protocolo}: {servicio} {version}")
        
        if puertos_abiertos == 0:
            print("  No se encontraron puertos abiertos")
        
        print()

def listar_reportes():
    """Lista todos los reportes generados"""
    if not os.path.exists(CARPETA_REPORTES):
        print("No hay reportes disponibles.")
        return
    
    archivos = sorted([f for f in os.listdir(CARPETA_REPORTES) if f.endswith('.txt')])
    
    if not archivos:
        print("No hay reportes disponibles.")
        return
    
    print("\nReportes disponibles:")
    print("-" * 40)
    
    for i, archivo in enumerate(archivos, 1):
        ruta_completa = os.path.join(CARPETA_REPORTES, archivo)
        fecha_mod = datetime.fromtimestamp(os.path.getmtime(ruta_completa))
        tamaño = os.path.getsize(ruta_completa)
        
        print(f"{i:2d}. {archivo}")
        print(f"    Fecha: {fecha_mod.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Tamaño: {tamaño:,} bytes")
        print()

def mostrar_reporte(numero_reporte):
    """Muestra el contenido de un reporte específico"""
    if not os.path.exists(CARPETA_REPORTES):
        print("No hay reportes disponibles.")
        return
    
    archivos = sorted([f for f in os.listdir(CARPETA_REPORTES) if f.endswith('.txt')])
    
    if not archivos or numero_reporte < 1 or numero_reporte > len(archivos):
        print("Número de reporte inválido.")
        return
    
    archivo_seleccionado = archivos[numero_reporte - 1]
    ruta_completa = os.path.join(CARPETA_REPORTES, archivo_seleccionado)
    
    print(f"\n=== CONTENIDO DE: {archivo_seleccionado} ===")
    print("="*60)
    
    try:
        with open(ruta_completa, 'r', encoding='utf-8') as f:
            print(f.read())
    except Exception as e:
        print(f"Error al leer el archivo: {e}")

def main():
    """Función principal del CLI"""
    parser = argparse.ArgumentParser(
        description="Escáner de puertos con Nmap - Versión CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -t 192.168.1.1                    # Escaneo básico
  %(prog)s -t 192.168.1.1 -p 80,443          # Puertos específicos
  %(prog)s -t 192.168.1.1 -p 1-1000          # Rango de puertos
  %(prog)s -t example.com --scripts vuln     # Escaneo de vulnerabilidades
  %(prog)s --list                            # Listar reportes
  %(prog)s --show 1                          # Mostrar reporte #1
        """
    )
    
    parser.add_argument('-t', '--target', 
                       help='Host objetivo a escanear')
    
    parser.add_argument('-p', '--ports', 
                       default='1-1000',
                       help='Puertos a escanear (default: 1-1000)')
    
    parser.add_argument('-s', '--scripts', 
                       default='default',
                       choices=['default', 'none', 'vuln', 'http-headers,http-title', 
                               'ssh-hostkey', 'smb-os-discovery', 'ftp-anon'],
                       help='Scripts NSE a ejecutar (default: default)')
    
    parser.add_argument('-f', '--format', 
                       default='detailed',
                       choices=['detailed', 'simple', 'json'],
                       help='Formato de salida (default: detailed)')
    
    parser.add_argument('--list', 
                       action='store_true',
                       help='Listar reportes disponibles')
    
    parser.add_argument('--show', 
                       type=int,
                       metavar='N',
                       help='Mostrar contenido del reporte número N')
    
    args = parser.parse_args()
    
    # Crear estructura de directorios
    crear_estructura_directorios()
    
    if args.list:
        listar_reportes()
        return
    
    if args.show:
        mostrar_reporte(args.show)
        return
    
    if not args.target:
        parser.error("Debe especificar un objetivo con -t/--target")
    
    print("=== ESCÁNER DE PUERTOS CLI ===")
    print(f"Objetivo: {args.target}")
    print(f"Puertos: {args.ports}")
    print(f"Scripts: {args.scripts}")
    print(f"Formato: {args.format}")
    print()
    
    # Ejecutar escaneo
    resultado = ejecutar_escaneo_cli(
        host=args.target,
        puertos=args.ports,
        scripts=args.scripts,
        output_format=args.format
    )
    
    if resultado:
        print(f"\n[✓] Reporte guardado en: {resultado}")
        print("\nUse --list para ver todos los reportes")
        print("Use --show N para mostrar un reporte específico")

if __name__ == "__main__":
    main()