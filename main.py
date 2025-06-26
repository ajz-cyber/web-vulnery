import os
import nmap
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
import threading
import glob

app = Flask(__name__)

# Configuración
CARPETA_REPORTES = "reportes"
CARPETA_TEMPLATES = "templates"

# Estado global del escaneo
estado_escaneo = {
    "en_progreso": False,
    "ultimo_reporte": None,
    "mensaje": ""
}

def crear_estructura_directorios():
    """Crea las carpetas necesarias"""
    os.makedirs(CARPETA_REPORTES, exist_ok=True)
    os.makedirs(CARPETA_TEMPLATES, exist_ok=True)

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

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/escanear', methods=['POST'])
def iniciar_escaneo():
    """Inicia un nuevo escaneo"""
    if estado_escaneo["en_progreso"]:
        return jsonify({
            "success": False,
            "message": "Ya hay un escaneo en progreso"
        })
    
    datos = request.get_json()
    host = datos.get('host', '127.0.0.1')
    puerto = datos.get('puerto', '5000')
    scripts = datos.get('scripts', 'http-headers,http-title')
    
    # Validar entrada
    if not host:
        return jsonify({
            "success": False,
            "message": "Debe especificar un host"
        })
    
    # Iniciar escaneo en hilo separado
    hilo_escaneo = threading.Thread(
        target=ejecutar_escaneo,
        args=(host, puerto, scripts)
    )
    hilo_escaneo.daemon = True
    hilo_escaneo.start()
    
    return jsonify({
        "success": True,
        "message": "Escaneo iniciado"
    })

@app.route('/estado')
def obtener_estado():
    """Obtiene el estado actual del escaneo"""
    return jsonify(estado_escaneo)

@app.route('/reportes')
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
            "reportes": reportes
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al listar reportes: {str(e)}"
        })

@app.route('/reportes/<nombre_archivo>')
def descargar_reporte(nombre_archivo):
    """Descarga un reporte específico"""
    try:
        return send_from_directory(CARPETA_REPORTES, nombre_archivo, as_attachment=True)
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al descargar reporte: {str(e)}"
        })

@app.route('/reporte/<nombre_archivo>')
def ver_reporte(nombre_archivo):
    """Muestra el contenido de un reporte"""
    try:
        ruta_archivo = os.path.join(CARPETA_REPORTES, nombre_archivo)
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
        })

def crear_template_html():
    """Crea el archivo HTML de la interfaz"""
    html_content = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Escáner de Puertos - Interfaz Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .scan-form {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 2px solid #e9ecef;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:disabled {
            background: #95a5a6;
            cursor: not-allowed;
            transform: none;
        }
        
        .status {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .status.scanning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #8a6d3b;
        }
        
        .status.completed {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .status.error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .reports-section {
            margin-top: 30px;
        }
        
        .reports-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .reports-header h2 {
            color: #2c3e50;
        }
        
        .reports-list {
            background: #f8f9fa;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .report-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .report-item:last-child {
            border-bottom: none;
        }
        
        .report-info h4 {
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .report-info small {
            color: #6c757d;
        }
        
        .report-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-small {
            padding: 8px 15px;
            font-size: 14px;
            border-radius: 5px;
            text-decoration: none;
            color: white;
            transition: opacity 0.2s;
        }
        
        .btn-view {
            background: #17a2b8;
        }
        
        .btn-download {
            background: #28a745;
        }
        
        .btn-small:hover {
            opacity: 0.8;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .report-content {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            display: none;
        }
        
        .report-content pre {
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            color: #2c3e50;
        }
        
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .content {
                padding: 20px;
            }
            
            .report-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .report-actions {
                width: 100%;
                justify-content: flex-end;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Escáner de Puertos</h1>
            <p>Herramienta de escaneo de puertos con Nmap</p>
        </div>
        
        <div class="content">
            <!-- Formulario de escaneo -->
            <div class="scan-form">
                <h2 style="margin-bottom: 20px; color: #2c3e50;">Configurar Escaneo</h2>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="host">Host objetivo:</label>
                        <input type="text" id="host" value="127.0.0.1" placeholder="Ej: 192.168.1.1">
                    </div>
                    
                    <div class="form-group">
                        <label for="puerto">Puerto(s):</label>
                        <input type="text" id="puerto" value="5000" placeholder="Ej: 80,443 o 1-1000">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="scripts">Scripts NSE:</label>
                    <select id="scripts">
                        <option value="http-headers,http-title">HTTP básico (headers, title)</option>
                        <option value="http-headers,http-title,http-methods">HTTP completo</option>
                        <option value="ssh-hostkey,ssh2-enum-algos">SSH</option>
                        <option value="smb-os-discovery,smb-security-mode">SMB</option>
                        <option value="ftp-anon,ftp-bounce">FTP</option>
                        <option value="default">Scripts por defecto</option>
                        <option value="vuln">Vulnerabilidades</option>
                    </select>
                </div>
                
                <button class="btn" onclick="iniciarEscaneo()" id="btnEscanear">
                    🚀 Iniciar Escaneo
                </button>
            </div>
            
            <!-- Estado del escaneo -->
            <div id="estado" style="display: none;"></div>
            
            <!-- Contenido del reporte actual -->
            <div id="reporteActual" class="report-content"></div>
            
            <!-- Lista de reportes -->
            <div class="reports-section">
                <div class="reports-header">
                    <h2>📊 Reportes Generados</h2>
                    <button class="btn" onclick="actualizarReportes()">🔄 Actualizar</button>
                </div>
                
                <div id="listaReportes" class="reports-list">
                    <div class="report-item">
                        <div class="report-info">
                            <p style="color: #6c757d;">Cargando reportes...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let intervaloBusqueda = null;
        
        function iniciarEscaneo() {
            const host = document.getElementById('host').value.trim();
            const puerto = document.getElementById('puerto').value.trim();
            const scripts = document.getElementById('scripts').value;
            
            if (!host) {
                alert('Por favor, ingresa un host válido');
                return;
            }
            
            const datos = {
                host: host,
                puerto: puerto,
                scripts: scripts
            };
            
            fetch('/escanear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(datos)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    iniciarMonitoreo();
                } else {
                    mostrarEstado('error', data.message);
                }
            })
            .catch(error => {
                mostrarEstado('error', 'Error de conexión: ' + error.message);
            });
        }
        
        function iniciarMonitoreo() {
            if (intervaloBusqueda) {
                clearInterval(intervaloBusqueda);
            }
            
            intervaloBusqueda = setInterval(verificarEstado, 1000);
            verificarEstado();
        }
        
        function verificarEstado() {
            fetch('/estado')
            .then(response => response.json())
            .then(data => {
                const btnEscanear = document.getElementById('btnEscanear');
                
                if (data.en_progreso) {
                    mostrarEstado('scanning', data.mensaje);
                    btnEscanear.disabled = true;
                    btnEscanear.innerHTML = '<div class="loading"></div>Escaneando...';
                } else {
                    if (intervaloBusqueda) {
                        clearInterval(intervaloBusqueda);
                        intervaloBusqueda = null;
                    }
                    
                    btnEscanear.disabled = false;
                    btnEscanear.innerHTML = '🚀 Iniciar Escaneo';
                    
                    if (data.ultimo_reporte) {
                        mostrarEstado('completed', data.mensaje);
                        mostrarReporte(data.ultimo_reporte);
                        actualizarReportes();
                    } else if (data.mensaje) {
                        mostrarEstado('error', data.mensaje);
                    }
                }
            })
            .catch(error => {
                console.error('Error al verificar estado:', error);
                if (intervaloBusqueda) {
                    clearInterval(intervaloBusqueda);
                    intervaloBusqueda = null;
                }
            });
        }
        
        function mostrarEstado(tipo, mensaje) {
            const estadoDiv = document.getElementById('estado');
            estadoDiv.className = 'status ' + tipo;
            estadoDiv.textContent = mensaje;
            estadoDiv.style.display = 'block';
        }
        
        function mostrarReporte(nombreArchivo) {
            fetch('/reporte/' + nombreArchivo)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const reporteDiv = document.getElementById('reporteActual');
                    reporteDiv.innerHTML = '<h3>📄 Último Reporte: ' + data.nombre + '</h3><pre>' + data.contenido + '</pre>';
                    reporteDiv.style.display = 'block';
                }
            });
        }
        
        function actualizarReportes() {
            fetch('/reportes')
            .then(response => response.json())
            .then(data => {
                const listaDiv = document.getElementById('listaReportes');
                
                if (data.success && data.reportes.length > 0) {
                    listaDiv.innerHTML = data.reportes.map(reporte => `
                        <div class="report-item">
                            <div class="report-info">
                                <h4>${reporte.nombre}</h4>
                                <small>📅 ${reporte.fecha} | 📊 ${(reporte.tamaño / 1024).toFixed(1)} KB</small>
                            </div>
                            <div class="report-actions">
                                <a href="#" class="btn-small btn-view" onclick="verReporte('${reporte.nombre}')">👁️ Ver</a>
                                <a href="/reportes/${reporte.nombre}" class="btn-small btn-download">💾 Descargar</a>
                            </div>
                        </div>
                    `).join('');
                } else {
                    listaDiv.innerHTML = `
                        <div class="report-item">
                            <div class="report-info">
                                <p style="color: #6c757d;">No hay reportes disponibles</p>
                            </div>
                        </div>
                    `;
                }
            });
        }
        
        function verReporte(nombreArchivo) {
            fetch('/reporte/' + nombreArchivo)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const reporteDiv = document.getElementById('reporteActual');
                    reporteDiv.innerHTML = '<h3>📄 Reporte: ' + data.nombre + '</h3><pre>' + data.contenido + '</pre>';
                    reporteDiv.style.display = 'block';
                    reporteDiv.scrollIntoView({ behavior: 'smooth' });
                }
            });
        }
        
        // Cargar reportes al iniciar la página
        document.addEventListener('DOMContentLoaded', actualizarReportes);
    </script>
</body>
</html>'''
    
    ruta_template = os.path.join(CARPETA_TEMPLATES, 'index.html')
    with open(ruta_template, 'w', encoding='utf-8') as archivo:
        archivo.write(html_content)
    
    print(f"[✓] Template HTML creado en: {ruta_template}")

def main():
    """Función principal que puede ejecutar el escáner original o la interfaz web"""
    print("=== ESCÁNER DE PUERTOS ===")
    print("1. Ejecutar escáner web (interfaz gráfica)")
    print("2. Ejecutar escáner original (línea de comandos)")
    
    opcion = input("\nSelecciona una opción (1 o 2): ").strip()
    
    if opcion == "1":
        # Crear estructura de directorios y template
        crear_estructura_directorios()
        crear_template_html()
        
        print("\n[+] Iniciando servidor web...")
        print("[+] Accede a: http://localhost:5001")
        print("[+] Presiona Ctrl+C para detener el servidor")
        
        try:
            app.run(host='0.0.0.0', port=5001, debug=False)
        except KeyboardInterrupt:
            print("\n[!] Servidor detenido")
    
    elif opcion == "2":
        # Ejecutar escáner original
        print(f"[+] Iniciando escaneo al host 127.0.0.1...")
        
        os.makedirs(CARPETA_REPORTES, exist_ok=True)
        escaner = nmap.PortScanner()
        
        escaner.scan(
            hosts="127.0.0.1",
            arguments="-sV -p 5000 --script http-headers,http-title -T4"
        )
        
        nombre_reporte = f"escaneo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        ruta_reporte = os.path.join(CARPETA_REPORTES, nombre_reporte)
        
        with open(ruta_reporte, "w", encoding="utf-8") as archivo:
            for host in escaner.all_hosts():
                archivo.write(f"\nHost: {host} ({escaner[host].state()})\n")
                for protocolo in escaner[host].all_protocols():
                    archivo.write(f" Protocolo: {protocolo}\n")
                    puertos = escaner[host][protocolo].keys()
                    for puerto in sorted(puertos):
                        info = escaner[host][protocolo][puerto]
                        linea = f"  Puerto {puerto}: {info['state']} - {info.get('name', '')} {info.get('version', '')}\n"
                        archivo.write(linea)
                        
                        if 'script' in info:
                            for nombre_script, salida_script in info['script'].items():
                                archivo.write(f"    [{nombre_script}]: {salida_script.strip()}\n")
        
        print(f"[✓] Escaneo completado. Reporte guardado en: {ruta_reporte}")
    
    else:
        print("[!] Opción no válida")

if __name__ == "__main__":
    main()dccdscvdsvvs
