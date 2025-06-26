import os
import nmap
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import threading
import glob

app = Flask(__name__)
CORS(app)  # Permitir CORS para el frontend

# Configuración
CARPETA_REPORTES = "reportes"

# Estado global del escaneo
estado_escaneo = {
    "en_progreso": False,
    "ultimo_reporte": None,
    "mensaje": ""
}

def crear_estructura_directorios():
    """Crea las carpetas necesarias"""
    os.makedirs(CARPETA_REPORTES, exist_ok=True)

def ejecutar_escaneo(host, puerto="5000", scripts="http-headers,http-title"):
    """Ejecuta el escaneo en un hilo separado"""
    global estado_escaneo
    
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
        
        # Generar nombre del reporte
        nombre_reporte = f"escaneo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        ruta_reporte = os.path.join(CARPETA_REPORTES, nombre_reporte)
        
        estado_escaneo["mensaje"] = "Generando reporte..."
        
        # Generar reporte
        with open(ruta_reporte, "w", encoding="utf-8") as archivo:
            archivo.write(f"=== REPORTE DE ESCANEO ===\n")
            archivo.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            archivo.write(f"Host objetivo: {host}\n")
            archivo.write(f"Puerto(s): {puerto}\n")
            archivo.write(f"Scripts: {scripts}\n")
            archivo.write("=" * 50 + "\n\n")
            
            for host_escaneado in escaner.all_hosts():
                archivo.write(f"Host: {host_escaneado} ({escaner[host_escaneado].state()})\n")
                archivo.write("-" * 40 + "\n")
                
                for protocolo in escaner[host_escaneado].all_protocols():
                    archivo.write(f"Protocolo: {protocolo}\n")
                    puertos = escaner[host_escaneado][protocolo].keys()
                    
                    for puerto_encontrado in sorted(puertos):
                        info = escaner[host_escaneado][protocolo][puerto_encontrado]
                        archivo.write(f"  Puerto {puerto_encontrado}: {info['state']}")
                        
                        if info.get('name'):
                            archivo.write(f" - Servicio: {info['name']}")
                        if info.get('version'):
                            archivo.write(f" - Versión: {info['version']}")
                        
                        archivo.write("\n")
                        
                        # Mostrar resultados de scripts NSE
                        if 'script' in info:
                            archivo.write("    Scripts NSE:\n")
                            for nombre_script, salida_script in info['script'].items():
                                archivo.write(f"      [{nombre_script}]:\n")
                                # Formatear la salida del script
                                lineas_script = salida_script.strip().split('\n')
                                for linea in lineas_script:
                                    archivo.write(f"        {linea}\n")
                            archivo.write("\n")
                
                archivo.write("\n")
        
        estado_escaneo["ultimo_reporte"] = nombre_reporte
        estado_escaneo["mensaje"] = f"Escaneo completado. Reporte: {nombre_reporte}"
        print(f"[✓] Escaneo completado. Reporte guardado en: {ruta_reporte}")
        
    except Exception as e:
        estado_escaneo["mensaje"] = f"Error durante el escaneo: {str(e)}"
        print(f"[!] Error: {e}")
    
    finally:
        estado_escaneo["en_progreso"] = False

# === RUTAS DE LA API ===

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar que la API está funcionando"""
    return jsonify({
        "status": "ok",
        "message": "API funcionando correctamente",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/escanear', methods=['POST'])
def iniciar_escaneo():
    """Inicia un nuevo escaneo"""
    if estado_escaneo["en_progreso"]:
        return jsonify({
            "success": False,
            "message": "Ya hay un escaneo en progreso"
        }), 400
    
    datos = request.get_json()
    if not datos:
        return jsonify({
            "success": False,
            "message": "No se recibieron datos JSON"
        }), 400
    
    host = datos.get('host', '127.0.0.1')
    puerto = datos.get('puerto', '5000')
    scripts = datos.get('scripts', 'http-headers,http-title')
    
    # Validar entrada
    if not host:
        return jsonify({
            "success": False,
            "message": "Debe especificar un host"
        }), 400
    
    # Iniciar escaneo en hilo separado
    hilo_escaneo = threading.Thread(
        target=ejecutar_escaneo,
        args=(host, puerto, scripts)
    )
    hilo_escaneo.daemon = True
    hilo_escaneo.start()
    
    return jsonify({
        "success": True,
        "message": "Escaneo iniciado",
        "host": host,
        "puerto": puerto,
        "scripts": scripts
    })

@app.route('/api/estado', methods=['GET'])
def obtener_estado():
    """Obtiene el estado actual del escaneo"""
    return jsonify(estado_escaneo)

@app.route('/api/reportes', methods=['GET'])
def listar_reportes():
    """Lista todos los reportes disponibles"""
    try:
        archivos = glob.glob(os.path.join(CARPETA_REPORTES, "*.txt"))
        reportes = []
        
        for archivo in sorted(archivos, reverse=True):
            nombre = os.path.basename(archivo)
            fecha_modificacion = datetime.fromtimestamp(
                os.path.getmtime(archivo)
            ).strftime('%Y-%m-%d %H:%M:%S')
            
            reportes.append({
                "nombre": nombre,
                "fecha": fecha_modificacion,
                "tamaño": os.path.getsize(archivo)
            })
        
        return jsonify({
            "success": True,
            "reportes": reportes,
            "total": len(reportes)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al listar reportes: {str(e)}"
        }), 500

@app.route('/api/reportes/<nombre_archivo>/descargar', methods=['GET'])
def descargar_reporte(nombre_archivo):
    """Descarga un reporte específico"""
    try:
        return send_from_directory(CARPETA_REPORTES, nombre_archivo, as_attachment=True)
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al descargar reporte: {str(e)}"
        }), 500

@app.route('/api/reportes/<nombre_archivo>/contenido', methods=['GET'])
def obtener_contenido_reporte(nombre_archivo):
    """Obtiene el contenido de un reporte"""
    try:
        ruta_archivo = os.path.join(CARPETA_REPORTES, nombre_archivo)
        if not os.path.exists(ruta_archivo):
            return jsonify({
                "success": False,
                "message": "Reporte no encontrado"
            }), 404
            
        with open(ruta_archivo, 'r', encoding='utf-8') as archivo:
            contenido = archivo.read()
        
        return jsonify({
            "success": True,
            "contenido": contenido,
            "nombre": nombre_archivo
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al leer reporte: {str(e)}"
        }), 500

@app.route('/api/reportes/<nombre_archivo>', methods=['DELETE'])
def eliminar_reporte(nombre_archivo):
    """Elimina un reporte específico"""
    try:
        ruta_archivo = os.path.join(CARPETA_REPORTES, nombre_archivo)
        if not os.path.exists(ruta_archivo):
            return jsonify({
                "success": False,
                "message": "Reporte no encontrado"
            }), 404
            
        os.remove(ruta_archivo)
        return jsonify({
            "success": True,
            "message": f"Reporte {nombre_archivo} eliminado correctamente"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar reporte: {str(e)}"
        }), 500

# === MANEJO DE ERRORES ===

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Endpoint no encontrado"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "message": "Error interno del servidor"
    }), 500

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Bienvenido a la API de escaneo con Nmap",
        "endpoints_disponibles": [
            "/api/health",
            "/api/escanear",
            "/api/estado",
            "/api/reportes",
            "/api/reportes/<nombre>/contenido",
            "/api/reportes/<nombre>/descargar",
            "/api/reportes/<nombre> (DELETE)"
        ]
    })


def main():
    """Función principal para iniciar el servidor backend"""
    crear_estructura_directorios()
    
    print("=== BACKEND - ESCÁNER DE PUERTOS ===")
    print("[+] Iniciando servidor API...")
    print("[+] API disponible en: http://localhost:5001")
    print("[+] Documentación de endpoints:")
    print("    GET  /api/health - Estado de la API")
    print("    POST /api/escanear - Iniciar escaneo")
    print("    GET  /api/estado - Estado del escaneo")
    print("    GET  /api/reportes - Listar reportes")
    print("    GET  /api/reportes/<nombre>/contenido - Contenido del reporte")
    print("    GET  /api/reportes/<nombre>/descargar - Descargar reporte")
    print("    DELETE /api/reportes/<nombre> - Eliminar reporte")
    print("[+] Presiona Ctrl+C para detener el servidor")
    
    try:
        port = int(os.environ.get("PORT", 5000))  # Render asigna el puerto por variable de entorno
        app.run(host='0.0.0.0', port=port, debug=False)

    except KeyboardInterrupt:
        print("\n[!] Servidor detenido")

if __name__ == "__main__":
    main()