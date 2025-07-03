const API_BASE_URL = 'https://web-vulnery.onrender.com';
let intervaloBusqueda = null;
let apiOnline = false;

function verificarAPI() {
    fetch(`${API_BASE_URL}/api/health`)
        .then(res => res.json())
        .then(data => {
            apiOnline = true;
            document.getElementById('apiStatusText').textContent = 'Conectado';
            if (data.reportes_en_memoria !== undefined) {
                document.getElementById('apiStatusText').textContent = 
                    `Conectado (${data.reportes_en_memoria} reportes en memoria)`;
            }
        })
        .catch(() => {
            apiOnline = false;
            document.getElementById('apiStatusText').textContent = 'Desconectado';
        });
}

function actualizarOpciones() {
    const tipo = document.getElementById('tipoEscaneo').value;
    const scriptsSelect = document.getElementById('scripts');
    const puertoInput = document.getElementById('puerto');
    
    // Configurar puertos y scripts según el tipo
    switch(tipo) {
        case 'basico':
            scriptsSelect.value = 'http-headers,http-title';
            break;
        case 'stealth':
            scriptsSelect.value = 'default';
            break;
        case 'udp':
            scriptsSelect.value = 'discovery';
            if (puertoInput.value === '5000') {
                puertoInput.value = '53,67,68,69,123,161,162,500,514,520,631,1434,1900,4500,5353';
            }
            break;
        case 'completo':
            scriptsSelect.value = 'default';
            break;
        case 'rapido':
            scriptsSelect.value = 'default';
            puertoInput.value = '--top-ports 1000';
            break;
        case 'intensivo':
            scriptsSelect.value = 'default';
            document.getElementById('deteccionOS').checked = true;
            document.getElementById('deteccionVersion').checked = true;
            break;
        case 'vuln':
            scriptsSelect.value = 'vuln';
            break;
        case 'personalizado':
            mostrarOpcionesAvanzadas();
            break;
    }
}

function mostrarOpcionesAvanzadas() {
    const opciones = document.getElementById('opcionesAvanzadas');
    opciones.style.display = opciones.style.display === 'none' ? 'block' : 'none';
}

function generarArgumentosEscaneo() {
    const tipo = document.getElementById('tipoEscaneo').value;
    const velocidad = document.getElementById('velocidad').value;
    const deteccionOS = document.getElementById('deteccionOS').checked;
    const deteccionVersion = document.getElementById('deteccionVersion').checked;
    const fragmentacion = document.getElementById('fragmentacion').checked;
    const evasionFirewall = document.getElementById('evasionFirewall').checked;
    const argumentosPersonalizados = document.getElementById('argumentosPersonalizados').value;
    
    let argumentos = [];
    
    // Tipo de escaneo
    switch(tipo) {
        case 'basico':
            argumentos.push('-sT'); // TCP Connect
            break;
        case 'stealth':
            argumentos.push('-sS'); // SYN Stealth
            break;
        case 'udp':
            argumentos.push('-sU'); // UDP
            break;
        case 'completo':
            argumentos.push('-sS', '-sU'); // TCP + UDP
            break;
        case 'rapido':
            argumentos.push('-sS', '--top-ports', '1000');
            break;
        case 'intensivo':
            argumentos.push('-sS', '-A'); // Aggressive scan
            break;
        case 'vuln':
            argumentos.push('-sS');
            break;
    }
    
    // Velocidad
    argumentos.push(`-${velocidad}`);
    
    // Detección de OS
    if (deteccionOS) {
        argumentos.push('-O');
    }
    
    // Detección de versión
    if (deteccionVersion) {
        argumentos.push('-sV');
    }
    
    // Fragmentación
    if (fragmentacion) {
        argumentos.push('-f');
    }
    
    // Evasión de firewall
    if (evasionFirewall) {
        argumentos.push('-D', 'RND:10'); // Decoy scan
    }
    
    // Argumentos personalizados
    if (argumentosPersonalizados) {
        argumentos.push(...argumentosPersonalizados.split(' '));
    }
    
    return argumentos.join(' ');
}

function iniciarEscaneo() {
    if (!apiOnline) {
        alert('API no disponible');
        return;
    }

    const host = document.getElementById('host').value.trim();
    const puerto = document.getElementById('puerto').value.trim();
    const scripts = document.getElementById('scripts').value;
    const tipo = document.getElementById('tipoEscaneo').value;
    const argumentos = generarArgumentosEscaneo();

    if (!host) {
        alert('Ingresa un host válido');
        return;
    }

    fetch(`${API_BASE_URL}/api/escanear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            host, 
            puerto, 
            scripts, 
            tipo,
            argumentos
        })
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                iniciarMonitoreo();
                mostrarEstado('info', 'Escaneo iniciado correctamente');
                document.getElementById('btnEscanear').disabled = true;
                document.getElementById('btnDetener').disabled = false;
            } else {
                mostrarEstado('error', data.message);
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al iniciar escaneo: ' + err.message);
        });
}

function detenerEscaneo() {
    fetch(`${API_BASE_URL}/api/detener`, {
        method: 'POST'
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                mostrarEstado('info', 'Escaneo detenido');
                document.getElementById('btnEscanear').disabled = false;
                document.getElementById('btnDetener').disabled = true;
                if (intervaloBusqueda) {
                    clearInterval(intervaloBusqueda);
                    intervaloBusqueda = null;
                }
            } else {
                mostrarEstado('error', data.message);
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al detener escaneo: ' + err.message);
        });
}

function exportarReportes() {
    fetch(`${API_BASE_URL}/api/reportes/exportar`)
        .then(res => {
            if (res.ok) {
                return res.blob();
            }
            throw new Error('Error al exportar');
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `reportes_${new Date().toISOString().split('T')[0]}.zip`;
            a.click();
            window.URL.revokeObjectURL(url);
        })
        .catch(err => {
            mostrarEstado('error', 'Error al exportar: ' + err.message);
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
    if (!apiOnline) return;

    fetch(`${API_BASE_URL}/api/estado`)
        .then(res => res.json())
        .then(data => {
            const btn = document.getElementById('btnEscanear');
            const btnDetener = document.getElementById('btnDetener');

            if (data.en_progreso) {
                mostrarEstado('scanning', data.mensaje);
                btn.disabled = true;
                btn.textContent = 'Escaneando...';
                btnDetener.disabled = false;
            } else {
                clearInterval(intervaloBusqueda);
                intervaloBusqueda = null;
                btn.disabled = false;
                btn.textContent = 'Iniciar Escaneo';
                btnDetener.disabled = true;

                if (data.ultimo_reporte) {
                    mostrarEstado('completed', data.mensaje);
                    mostrarReporte(data.ultimo_reporte);
                    actualizarReportes();
                } else if (data.mensaje) {
                    mostrarEstado('error', data.mensaje);
                }
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al verificar estado: ' + err.message);
        });
}

function mostrarEstado(tipo, mensaje) {
    const div = document.getElementById('estado');
    div.className = tipo;
    div.textContent = mensaje;
    div.style.display = 'block';
    
    if (tipo === 'info' || tipo === 'completed') {
        setTimeout(() => {
            if (div.textContent === mensaje) {
                div.style.display = 'none';
            }
        }, 5000);
    }
}

function mostrarReporte(reporteId) {
    fetch(`${API_BASE_URL}/api/reportes/${reporteId}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const div = document.getElementById('reporteActual');
                div.innerHTML = `
                    <h4>Último Reporte: ${data.nombre}</h4>
                    <p><strong>Fecha:</strong> ${data.fecha}</p>
                    <p><strong>Host:</strong> ${data.host} | <strong>Puerto:</strong> ${data.puerto}</p>
                    <p><strong>Tipo:</strong> ${data.tipo || 'No especificado'}</p>
                    <pre>${data.contenido}</pre>
                `;
                div.style.display = 'block';
            } else {
                mostrarEstado('error', 'Error al cargar el reporte: ' + data.message);
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al obtener reporte: ' + err.message);
        });
}

function actualizarReportes() {
    fetch(`${API_BASE_URL}/api/reportes`)
        .then(res => res.json())
        .then(data => {
            const lista = document.getElementById('listaReportes');
            if (data.success && data.reportes.length > 0) {
                lista.innerHTML = data.reportes.map(r => `
                    <div style="border: 1px solid #ccc; margin: 10px 0; padding: 10px; border-radius: 5px;">
                        <div style="margin-bottom: 10px;">
                            <strong>${r.nombre}</strong><br>
                            <small>
                                <strong>Fecha:</strong> ${r.fecha}<br>
                                <strong>Host:</strong> ${r.host} | <strong>Puerto:</strong> ${r.puerto}<br>
                                <strong>Tipo:</strong> ${r.tipo || 'No especificado'}<br>
                                <strong>Tamaño:</strong> ${(r.tamaño / 1024).toFixed(1)} KB
                            </small>
                        </div>
                        <div style="display: flex; gap: 5px;">
                            <button onclick="verReporteModal('${r.id}')">Ver</button>
                            <button onclick="descargarReporte('${r.id}')">Descargar</button>
                            <button onclick="eliminarReporte('${r.id}', '${r.nombre}')" style="background-color: #ff4444; color: white;">Eliminar</button>
                        </div>
                    </div>
                `).join('');
                
                if (data.reportes.length > 1) {
                    lista.innerHTML += `
                        <div style="margin-top: 20px; padding: 10px; text-align: center;">
                            <button onclick="limpiarTodosReportes()" style="background-color: #ff6666; color: white; padding: 10px 20px;">
                                Eliminar todos los reportes (${data.reportes.length})
                            </button>
                        </div>
                    `;
                }
            } else {
                lista.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No hay reportes disponibles</div>';
            }
        })
        .catch(err => {
            document.getElementById('listaReportes').innerHTML = 
                '<div style="padding: 20px; text-align: center; color: #red;">Error al cargar reportes: ' + err.message + '</div>';
        });
}

function verReporteModal(reporteId) {
    fetch(`${API_BASE_URL}/api/reportes/${reporteId}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('modalContent').innerHTML = `
                    <h3>${data.nombre}</h3>
                    <p><strong>Fecha:</strong> ${data.fecha}</p>
                    <p><strong>Host:</strong> ${data.host} | <strong>Puerto:</strong> ${data.puerto}</p>
                    <p><strong>Scripts:</strong> ${data.scripts}</p>
                    <p><strong>Tipo:</strong> ${data.tipo || 'No especificado'}</p>
                    <hr>
                    <pre style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto;">${data.contenido}</pre>
                `;
                document.getElementById('reportModal').style.display = 'block';
            } else {
                mostrarEstado('error', 'Error al cargar el reporte: ' + data.message);
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al obtener reporte: ' + err.message);
        });
}

function descargarReporte(reporteId) {
    window.open(`${API_BASE_URL}/api/reportes/${reporteId}/descargar`, '_blank');
}

function eliminarReporte(reporteId, nombreReporte) {
    if (confirm(`¿Estás seguro de que quieres eliminar el reporte "${nombreReporte}"?`)) {
        fetch(`${API_BASE_URL}/api/reportes/${reporteId}`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    actualizarReportes();
                    mostrarEstado('completed', data.message);
                    
                    const reporteActual = document.getElementById('reporteActual');
                    if (reporteActual.innerHTML.includes(nombreReporte)) {
                        reporteActual.style.display = 'none';
                    }
                } else {
                    mostrarEstado('error', data.message);
                }
            })
            .catch(err => {
                mostrarEstado('error', 'Error al eliminar reporte: ' + err.message);
            });
    }
}

function limpiarTodosReportes() {
    if (confirm('¿Estás seguro de que quieres eliminar TODOS los reportes? Esta acción no se puede deshacer.')) {
        fetch(`${API_BASE_URL}/api/reportes/limpiar`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    actualizarReportes();
                    mostrarEstado('completed', data.message);
                    document.getElementById('reporteActual').style.display = 'none';
                } else {
                    mostrarEstado('error', data.message);
                }
            })
            .catch(err => {
                mostrarEstado('error', 'Error al limpiar reportes: ' + err.message);
            });
    }
}

function cerrarModal() {
    document.getElementById('reportModal').style.display = 'none';
}

window.onclick = function (e) {
    const modal = document.getElementById('reportModal');
    if (e.target === modal) {
        modal.style.display = 'none';
    }
};

document.addEventListener('DOMContentLoaded', () => {
    verificarAPI();
    actualizarReportes();
    setInterval(verificarAPI, 30000);
});

function refrescarReportes() {
    mostrarEstado('info', 'Actualizando lista de reportes...');
    actualizarReportes();
}