import os
import nmap
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import threading
import uuid
import signal
import sys

app = Flask(__name__)
CORS(app)  # Permitir CORS para el frontend

# Estado global del escaneo
estado_escaneo = {
    "en_progreso": False,
    "ultimo_reporte": None,
    "mensaje": "",
    "proceso_actual": None,
}

# Almacenamiento en memoria de los reportes
reportes_memoria = {}

# Variable para controlar el hilo de escaneo
hilo_escaneo_actual = None


def generar_argumentos_nmap(tipo_escaneo, puerto, scripts, argumentos_extra=None):
    """Genera los argumentos de Nmap según el tipo de escaneo"""
    args = []

    # Configuración básica según el tipo
    if tipo_escaneo == "basico":
        args.extend(["-sT"])  # TCP Connect scan

    elif tipo_escaneo == "stealth":
        args.extend(["-sS"])  # SYN Stealth scan

    elif tipo_escaneo == "udp":
        args.extend(["-sU"])  # UDP scan
        if puerto == "5000":  # Puerto por defecto, cambiar a puertos UDP comunes
            puerto = "53,67,68,69,123,161,162,500,514,520,631,1434,1900,4500,5353"

    elif tipo_escaneo == "completo":
        args.extend(["-sS", "-sU"])  # TCP + UDP scan

    elif tipo_escaneo == "rapido":
        args.extend(["-sS", "--top-ports", "1000"])  # Top 1000 puertos

    elif tipo_escaneo == "intensivo":
        args.extend(
            ["-sS", "-A"]
        )  # Aggressive scan (OS detection, version detection, script scanning, traceroute)

    elif tipo_escaneo == "vuln":
        args.extend(["-sS", "-sV"])  # TCP SYN + version detection para vulnerabilidades

    else:  # personalizado o por defecto
        args.extend(["-sS"])  # Por defecto SYN scan

    # Agregar puertos
    if "--top-ports" not in args:
        args.extend(["-p", puerto])

    # Agregar scripts NSE
    if scripts and scripts != "default":
        if scripts == "vuln":
            args.extend(["--script", "vuln"])
        elif scripts == "discovery":
            args.extend(["--script", "discovery"])
        elif scripts == "safe":
            args.extend(["--script", "safe"])
        elif scripts == "intrusive":
            args.extend(["--script", "intrusive"])
        elif scripts == "http-*":
            args.extend(["--script", "http-*"])
        elif scripts == "ssl-*":
            args.extend(["--script", "ssl-*"])
        elif scripts == "smb-*":
            args.extend(["--script", "smb-*"])
        elif scripts == "dns-*":
            args.extend(["--script", "dns-*"])
        elif scripts == "ftp-*":
            args.extend(["--script", "ftp-*"])
        elif scripts == "ssh-*":
            args.extend(["--script", "ssh-*"])
        else:
            args.extend(["--script", scripts])

    # Velocidad por defecto
    if not any(arg.startswith("-T") for arg in args):
        args.append("-T4")

    # Agregar argumentos extra si se proporcionan
    if argumentos_extra:
        if isinstance(argumentos_extra, str):
            args.extend(argumentos_extra.split())
        elif isinstance(argumentos_extra, list):
            args.extend(argumentos_extra)

    return args


def ejecutar_escaneo(
    host,
    puerto="5000",
    scripts="http-headers,http-title",
    tipo_escaneo="basico",
    argumentos_extra=None,
):
    """Ejecuta el escaneo en un hilo separado"""
    global estado_escaneo, reportes_memoria

    try:
        estado_escaneo["en_progreso"] = True
        estado_escaneo["mensaje"] = (
            f"Iniciando escaneo {tipo_escaneo} a {host}:{puerto}..."
        )

        print(f"[+] Iniciando escaneo {tipo_escaneo} al host {host}...")

        # Inicializar el escáner Nmap
        escaner = nmap.PortScanner()

        # Generar argumentos específicos según el tipo de escaneo
        args_nmap = generar_argumentos_nmap(
            tipo_escaneo, puerto, scripts, argumentos_extra
        )
        argumentos_str = " ".join(args_nmap)

        estado_escaneo["mensaje"] = f"Ejecutando escaneo {tipo_escaneo}..."
        print(f"[+] Ejecutando: nmap {argumentos_str} {host}")

        # Ejecutar el escaneo
        escaner.scan(hosts=host, arguments=argumentos_str)

        # Generar ID único para el reporte
        reporte_id = str(uuid.uuid4())
        timestamp = datetime.now()
        nombre_reporte = f"escaneo_{tipo_escaneo}_{timestamp.strftime('%Y%m%d_%H%M%S')}"

        estado_escaneo["mensaje"] = "Generando reporte..."

        # Generar contenido del reporte
        contenido_reporte = []
        contenido_reporte.append("=== REPORTE DE ESCANEO ===")
        contenido_reporte.append(f"Fecha: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        contenido_reporte.append(f"Host objetivo: {host}")
        contenido_reporte.append(f"Puerto(s): {puerto}")
        contenido_reporte.append(f"Tipo de escaneo: {tipo_escaneo.upper()}")
        contenido_reporte.append(f"Scripts: {scripts}")
        contenido_reporte.append(f"Argumentos Nmap: {argumentos_str}")
        contenido_reporte.append("=" * 50)
        contenido_reporte.append("")

        # Verificar si hay hosts encontrados
        if not escaner.all_hosts():
            contenido_reporte.append(
                "⚠️  No se encontraron hosts o no se pudo acceder al objetivo."
            )
            contenido_reporte.append("Posibles causas:")
            contenido_reporte.append("- El host no está accesible")
            contenido_reporte.append("- Firewall bloqueando el escaneo")
            contenido_reporte.append("- Dirección IP incorrecta")
            contenido_reporte.append("")
        else:
            for host_escaneado in escaner.all_hosts():
                estado_host = escaner[host_escaneado].state()
                contenido_reporte.append(f"Host: {host_escaneado} ({estado_host})")
                contenido_reporte.append("-" * 40)

                # Información del host
                if "hostnames" in escaner[host_escaneado]:
                    hostnames = escaner[host_escaneado]["hostnames"]
                    if hostnames:
                        contenido_reporte.append(
                            f"Hostnames: {', '.join([h['name'] for h in hostnames])}"
                        )

                # Información de protocolos
                for protocolo in escaner[host_escaneado].all_protocols():
                    contenido_reporte.append(f"Protocolo: {protocolo.upper()}")
                    puertos = escaner[host_escaneado][protocolo].keys()
                    puertos_ordenados = sorted(puertos)

                    if not puertos_ordenados:
                        contenido_reporte.append("  No se encontraron puertos abiertos")
                        continue

                    for puerto_encontrado in puertos_ordenados:
                        info = escaner[host_escaneado][protocolo][puerto_encontrado]
                        estado_puerto = info["state"]

                        # Formatear información del puerto
                        linea_puerto = (
                            f"  Puerto {puerto_encontrado}/{protocolo}: {estado_puerto}"
                        )

                        if info.get("name"):
                            linea_puerto += f" - Servicio: {info['name']}"
                        if info.get("product"):
                            linea_puerto += f" - Producto: {info['product']}"
                        if info.get("version"):
                            linea_puerto += f" - Versión: {info['version']}"
                        if info.get("extrainfo"):
                            linea_puerto += f" - Extra: {info['extrainfo']}"

                        contenido_reporte.append(linea_puerto)

                        # Mostrar resultados de scripts NSE
                        if "script" in info:
                            contenido_reporte.append("    Scripts NSE:")
                            for nombre_script, salida_script in info["script"].items():
                                contenido_reporte.append(f"      [{nombre_script}]:")
                                # Formatear la salida del script
                                lineas_script = salida_script.strip().split("\n")
                                for linea in lineas_script:
                                    contenido_reporte.append(f"        {linea}")
                            contenido_reporte.append("")

                # Información adicional para escaneos intensivos
                if tipo_escaneo == "intensivo":
                    if "osmatch" in escaner[host_escaneado]:
                        os_matches = escaner[host_escaneado]["osmatch"]
                        if os_matches:
                            contenido_reporte.append("Detección de Sistema Operativo:")
                            for os_match in os_matches[:3]:  # Top 3 matches
                                contenido_reporte.append(
                                    f"  - {os_match['name']} (Precisión: {os_match['accuracy']}%)"
                                )
                            contenido_reporte.append("")

                contenido_reporte.append("")

        # Estadísticas del escaneo
        contenido_reporte.append("=== ESTADÍSTICAS DEL ESCANEO ===")
        contenido_reporte.append(f"Comando ejecutado: nmap {argumentos_str} {host}")
        contenido_reporte.append(f"Duración: {escaner.scanstats()['timestr']}")
        contenido_reporte.append(f"Hosts totales: {escaner.scanstats()['totalhosts']}")
        contenido_reporte.append(f"Hosts activos: {escaner.scanstats()['uphosts']}")
        contenido_reporte.append(f"Hosts inactivos: {escaner.scanstats()['downhosts']}")

        # Almacenar reporte en memoria
        contenido_completo = "\n".join(contenido_reporte)
        reportes_memoria[reporte_id] = {
            "id": reporte_id,
            "nombre": nombre_reporte,
            "contenido": contenido_completo,
            "fecha": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": timestamp.isoformat(),
            "host": host,
            "puerto": puerto,
            "scripts": scripts,
            "tipo": tipo_escaneo,
            "argumentos": argumentos_str,
            "tamaño": len(contenido_completo.encode("utf-8")),
        }

        estado_escaneo["ultimo_reporte"] = reporte_id
        estado_escaneo["mensaje"] = (
            f"Escaneo {tipo_escaneo} completado. Reporte: {nombre_reporte}"
        )
        print(
            f"[✓] Escaneo completado. Reporte almacenado en memoria con ID: {reporte_id}"
        )

    except Exception as e:
        estado_escaneo["mensaje"] = f"Error durante el escaneo: {str(e)}"
        print(f"[!] Error: {e}")

    finally:
        estado_escaneo["en_progreso"] = False
        estado_escaneo["proceso_actual"] = None


# === RUTAS DE LA API ===


@app.route("/api/health", methods=["GET"])
def health_check():
    """Endpoint para verificar que la API está funcionando"""
    return jsonify(
        {
            "status": "ok",
            "message": "API funcionando correctamente",
            "timestamp": datetime.now().isoformat(),
            "reportes_en_memoria": len(reportes_memoria),
            "escaneo_en_progreso": estado_escaneo["en_progreso"],
        }
    )


@app.route("/api/escanear", methods=["POST"])
def iniciar_escaneo():
    """Inicia un nuevo escaneo"""
    if estado_escaneo["en_progreso"]:
        return (
            jsonify({"success": False, "message": "Ya hay un escaneo en progreso"}),
            400,
        )

    datos = request.get_json()
    if not datos:
        return (
            jsonify({"success": False, "message": "No se recibieron datos JSON"}),
            400,
        )

    host = datos.get("host", "127.0.0.1")
    puerto = datos.get("puerto", "5000")
    scripts = datos.get("scripts", "http-headers,http-title")
    tipo_escaneo = datos.get("tipo", "basico")
    argumentos_extra = datos.get("argumentos", None)

    # Validar entrada
    if not host:
        return jsonify({"success": False, "message": "Debe especificar un host"}), 400

    # Validar tipo de escaneo
    tipos_validos = [
        "basico",
        "stealth",
        "udp",
        "completo",
        "rapido",
        "intensivo",
        "vuln",
        "personalizado",
    ]
    if tipo_escaneo not in tipos_validos:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Tipo de escaneo inválido. Tipos válidos: {', '.join(tipos_validos)}",
                }
            ),
            400,
        )

    # Iniciar escaneo en hilo separado
    global hilo_escaneo_actual
    hilo_escaneo_actual = threading.Thread(
        target=ejecutar_escaneo,
        args=(host, puerto, scripts, tipo_escaneo, argumentos_extra),
    )
    hilo_escaneo_actual.daemon = True
    hilo_escaneo_actual.start()

    return jsonify(
        {
            "success": True,
            "message": f"Escaneo {tipo_escaneo} iniciado",
            "host": host,
            "puerto": puerto,
            "scripts": scripts,
            "tipo": tipo_escaneo,
        }
    )


@app.route("/api/detener", methods=["POST"])
def detener_escaneo():
    """Detiene el escaneo actual"""
    global hilo_escaneo_actual

    if not estado_escaneo["en_progreso"]:
        return jsonify({"success": False, "message": "No hay escaneo en progreso"}), 400

    try:
        # Marcar como detenido
        estado_escaneo["en_progreso"] = False
        estado_escaneo["mensaje"] = "Escaneo detenido por el usuario"

        # Nota: Nmap no se puede detener fácilmente una vez iniciado
        # Este endpoint sirve para marcar el estado como detenido
        return jsonify({"success": True, "message": "Escaneo marcado como detenido"})

    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al detener escaneo: {str(e)}"}
            ),
            500,
        )


@app.route("/api/estado", methods=["GET"])
def obtener_estado():
    """Obtiene el estado actual del escaneo"""
    return jsonify(estado_escaneo)


@app.route("/api/reportes", methods=["GET"])
def listar_reportes():
    """Lista todos los reportes disponibles en memoria"""
    try:
        reportes = []
        for reporte_id, datos in sorted(
            reportes_memoria.items(), key=lambda x: x[1]["timestamp"], reverse=True
        ):
            reportes.append(
                {
                    "id": reporte_id,
                    "nombre": datos["nombre"],
                    "fecha": datos["fecha"],
                    "tamaño": datos["tamaño"],
                    "host": datos["host"],
                    "puerto": datos["puerto"],
                    "scripts": datos["scripts"],
                    "tipo": datos.get("tipo", "no especificado"),
                    "argumentos": datos.get("argumentos", ""),
                }
            )

        return jsonify({"success": True, "reportes": reportes, "total": len(reportes)})
    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al listar reportes: {str(e)}"}
            ),
            500,
        )


@app.route("/api/reportes/<reporte_id>/contenido", methods=["GET"])
def obtener_contenido_reporte(reporte_id):
    """Obtiene el contenido de un reporte específico"""
    try:
        if reporte_id not in reportes_memoria:
            return jsonify({"success": False, "message": "Reporte no encontrado"}), 404

        datos_reporte = reportes_memoria[reporte_id]

        return jsonify(
            {
                "success": True,
                "contenido": datos_reporte["contenido"],
                "nombre": datos_reporte["nombre"],
                "fecha": datos_reporte["fecha"],
                "id": reporte_id,
                "host": datos_reporte["host"],
                "puerto": datos_reporte["puerto"],
                "scripts": datos_reporte["scripts"],
                "tipo": datos_reporte.get("tipo", "no especificado"),
                "argumentos": datos_reporte.get("argumentos", ""),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al obtener reporte: {str(e)}"}
            ),
            500,
        )


@app.route("/api/reportes/<reporte_id>/descargar", methods=["GET"])
def descargar_reporte(reporte_id):
    """Genera y descarga un reporte como archivo de texto"""
    try:
        if reporte_id not in reportes_memoria:
            return jsonify({"success": False, "message": "Reporte no encontrado"}), 404

        datos_reporte = reportes_memoria[reporte_id]

        # Crear respuesta con el contenido como archivo
        response = Response(
            datos_reporte["contenido"],
            mimetype="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{datos_reporte["nombre"]}.txt"'
            },
        )

        return response

    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al descargar reporte: {str(e)}"}
            ),
            500,
        )


@app.route("/api/reportes/<reporte_id>", methods=["DELETE"])
def eliminar_reporte(reporte_id):
    """Elimina un reporte específico de la memoria"""
    try:
        if reporte_id not in reportes_memoria:
            return jsonify({"success": False, "message": "Reporte no encontrado"}), 404

        nombre_reporte = reportes_memoria[reporte_id]["nombre"]
        del reportes_memoria[reporte_id]

        return jsonify(
            {
                "success": True,
                "message": f"Reporte {nombre_reporte} eliminado correctamente",
            }
        )
    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al eliminar reporte: {str(e)}"}
            ),
            500,
        )


@app.route("/api/reportes/limpiar", methods=["DELETE"])
def limpiar_reportes():
    """Elimina todos los reportes de la memoria"""
    try:
        cantidad = len(reportes_memoria)
        reportes_memoria.clear()

        return jsonify(
            {
                "success": True,
                "message": f"Se eliminaron {cantidad} reportes de la memoria",
            }
        )
    except Exception as e:
        return (
            jsonify(
                {"success": False, "message": f"Error al limpiar reportes: {str(e)}"}
            ),
            500,
        )


# === MANEJO DE ERRORES ===


@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "message": "Endpoint no encontrado"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "message": "Error interno del servidor"}), 500


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {
            "message": "Bienvenido a la API de escaneo con Nmap",
            "reportes_en_memoria": len(reportes_memoria),
            "escaneo_en_progreso": estado_escaneo["en_progreso"],
            "tipos_escaneo_disponibles": [
                "basico",
                "stealth",
                "udp",
                "completo",
                "rapido",
                "intensivo",
                "vuln",
                "personalizado",
            ],
            "endpoints_disponibles": [
                "/api/health",
                "/api/escanear",
                "/api/detener",
                "/api/estado",
                "/api/reportes",
                "/api/reportes/<id>/contenido",
                "/api/reportes/<id>/descargar",
                "/api/reportes/<id> (DELETE)",
                "/api/reportes/limpiar (DELETE)",
            ],
        }
    )


def signal_handler(sig, frame):
    """Maneja la señal de interrupción"""
    print(f"\n[!] Señal {sig} recibida, cerrando servidor...")
    if len(reportes_memoria) > 0:
        print(
            f"[!] Se perderán {len(reportes_memoria)} reportes almacenados en memoria"
        )
    sys.exit(0)


def main():
    """Función principal para iniciar el servidor backend"""
    # Configurar manejo de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=== BACKEND - ESCÁNER DE PUERTOS ===")
    print("[+] Iniciando servidor API...")
    print("[+] API disponible en: http://localhost:5000")
    print("[+] Los reportes se almacenan en memoria (no se generan archivos)")
    print("[+] Tipos de escaneo disponibles:")
    print("    - basico: TCP Connect scan")
    print("    - stealth: SYN Stealth scan")
    print("    - udp: UDP scan")
    print("    - completo: TCP + UDP scan")
    print("    - rapido: Top 1000 puertos")
    print("    - intensivo: Detección OS + servicios")
    print("    - vuln: Escaneo de vulnerabilidades")
    print("    - personalizado: Argumentos personalizados")
    print("[+] Documentación de endpoints:")
    print("    GET  /api/health - Estado de la API")
    print("    POST /api/escanear - Iniciar escaneo")
    print("    POST /api/detener - Detener escaneo")
    print("    GET  /api/estado - Estado del escaneo")
    print("    GET  /api/reportes - Listar reportes")
    print("    GET  /api/reportes/<id>/contenido - Contenido del reporte")
    print("    GET  /api/reportes/<id>/descargar - Descargar reporte")
    print("    DELETE /api/reportes/<id> - Eliminar reporte")
    print("    DELETE /api/reportes/limpiar - Eliminar todos los reportes")
    print("[+] Presiona Ctrl+C para detener el servidor")

    try:
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido")
        if len(reportes_memoria) > 0:
            print(
                f"[!] Se perdieron {len(reportes_memoria)} reportes almacenados en memoria"
            )
    except Exception as e:
        print(f"[!] Error al iniciar servidor: {e}")


if __name__ == "__main__":
    main()
