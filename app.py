import os
import nmap
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import uuid

app = Flask(__name__)
CORS(app)  # Permitir CORS para el frontend

# Estado global del escaneo
estado_escaneo = {"en_progreso": False, "ultimo_reporte": None, "mensaje": ""}

# Almacenamiento en memoria de los reportes
reportes_memoria = {}


def ejecutar_escaneo(host, puerto="5000", scripts="http-headers,http-title"):
    """Ejecuta el escaneo en un hilo separado"""
    global estado_escaneo, reportes_memoria

    try:
        estado_escaneo["en_progreso"] = True
        estado_escaneo["mensaje"] = f"Iniciando escaneo a {host}:{puerto}..."

        print(f"[+] Iniciando escaneo al host {host}...")

        # Inicializar el escáner Nmap
        escaner = nmap.PortScanner()

        # Configurar argumentos del escaneo
        argumentos = f"-sV -p {puerto} --script {scripts} -T4"

        estado_escaneo["mensaje"] = "Ejecutando escaneo..."
        escaner.scan(hosts=host, arguments=argumentos)

        # Generar ID único para el reporte
        reporte_id = str(uuid.uuid4())
        timestamp = datetime.now()
        nombre_reporte = f"escaneo_{timestamp.strftime('%Y%m%d_%H%M%S')}"

        estado_escaneo["mensaje"] = "Generando reporte..."

        # Generar contenido del reporte
        contenido_reporte = []
        contenido_reporte.append("=== REPORTE DE ESCANEO ===")
        contenido_reporte.append(f"Fecha: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        contenido_reporte.append(f"Host objetivo: {host}")
        contenido_reporte.append(f"Puerto(s): {puerto}")
        contenido_reporte.append(f"Scripts: {scripts}")
        contenido_reporte.append("=" * 50)
        contenido_reporte.append("")

        for host_escaneado in escaner.all_hosts():
            contenido_reporte.append(
                f"Host: {host_escaneado} ({escaner[host_escaneado].state()})"
            )
            contenido_reporte.append("-" * 40)

            for protocolo in escaner[host_escaneado].all_protocols():
                contenido_reporte.append(f"Protocolo: {protocolo}")
                puertos = escaner[host_escaneado][protocolo].keys()

                for puerto_encontrado in sorted(puertos):
                    info = escaner[host_escaneado][protocolo][puerto_encontrado]
                    linea_puerto = f"  Puerto {puerto_encontrado}: {info['state']}"

                    if info.get("name"):
                        linea_puerto += f" - Servicio: {info['name']}"
                    if info.get("version"):
                        linea_puerto += f" - Versión: {info['version']}"

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

            contenido_reporte.append("")

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
            "tamaño": len(contenido_completo.encode("utf-8")),
        }

        estado_escaneo["ultimo_reporte"] = reporte_id
        estado_escaneo["mensaje"] = f"Escaneo completado. Reporte: {nombre_reporte}"
        print(
            f"[✓] Escaneo completado. Reporte almacenado en memoria con ID: {reporte_id}"
        )

    except Exception as e:
        estado_escaneo["mensaje"] = f"Error durante el escaneo: {str(e)}"
        print(f"[!] Error: {e}")

    finally:
        estado_escaneo["en_progreso"] = False


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

    # Validar entrada
    if not host:
        return jsonify({"success": False, "message": "Debe especificar un host"}), 400

    # Iniciar escaneo en hilo separado
    hilo_escaneo = threading.Thread(
        target=ejecutar_escaneo, args=(host, puerto, scripts)
    )
    hilo_escaneo.daemon = True
    hilo_escaneo.start()

    return jsonify(
        {
            "success": True,
            "message": "Escaneo iniciado",
            "host": host,
            "puerto": puerto,
            "scripts": scripts,
        }
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
        from flask import Response

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
            "endpoints_disponibles": [
                "/api/health",
                "/api/escanear",
                "/api/estado",
                "/api/reportes",
                "/api/reportes/<id>/contenido",
                "/api/reportes/<id>/descargar",
                "/api/reportes/<id> (DELETE)",
                "/api/reportes/limpiar (DELETE)",
            ],
        }
    )


def main():
    """Función principal para iniciar el servidor backend"""
    print("=== BACKEND - ESCÁNER DE PUERTOS ===")
    print("[+] Iniciando servidor API...")
    print("[+] API disponible en: http://localhost:5001")
    print("[+] Los reportes se almacenan en memoria (no se generan archivos)")
    print("[+] Documentación de endpoints:")
    print("    GET  /api/health - Estado de la API")
    print("    POST /api/escanear - Iniciar escaneo")
    print("    GET  /api/estado - Estado del escaneo")
    print("    GET  /api/reportes - Listar reportes")
    print("    GET  /api/reportes/<id>/contenido - Contenido del reporte")
    print("    GET  /api/reportes/<id>/descargar - Descargar reporte")
    print("    DELETE /api/reportes/<id> - Eliminar reporte")
    print("    DELETE /api/reportes/limpiar - Eliminar todos los reportes")
    print("[+] Presiona Ctrl+C para detener el servidor")

    try:
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=False)
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido")
        print(
            f"[!] Se perdieron {len(reportes_memoria)} reportes almacenados en memoria"
        )


if __name__ == "__main__":
    main()
