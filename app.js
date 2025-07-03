const API_BASE_URL = 'https://web-vulnery.onrender.com/api';
let intervaloBusqueda = null;
let apiOnline = false;

function verificarAPI() {
    fetch(`${API_BASE_URL}/health`)
        .then(res => res.json())
        .then(data => {
            apiOnline = true;
            document.getElementById('apiStatusText').textContent = 'Conectado';
            // Mostrar información adicional si está disponible
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

function iniciarEscaneo() {
    if (!apiOnline) {
        alert('API no disponible');
        return;
    }

    const host = document.getElementById('host').value.trim();
    const puerto = document.getElementById('puerto').value.trim();
    const scripts = document.getElementById('scripts').value;

    if (!host) {
        alert('Ingresa un host válido');
        return;
    }

    fetch(`${API_BASE_URL}/escanear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, puerto, scripts })
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                iniciarMonitoreo();
                mostrarEstado('info', 'Escaneo iniciado correctamente');
            } else {
                mostrarEstado('error', data.message);
            }
        })
        .catch(err => {
            mostrarEstado('error', 'Error al iniciar escaneo: ' + err.message);
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

    fetch(`${API_BASE_URL}/estado`)
        .then(res => res.json())
        .then(data => {
            const btn = document.getElementById('btnEscanear');

            if (data.en_progreso) {
                mostrarEstado('scanning', data.mensaje);
                btn.disabled = true;
                btn.textContent = 'Escaneando...';
            } else {
                clearInterval(intervaloBusqueda);
                intervaloBusqueda = null;
                btn.disabled = false;
                btn.textContent = 'Iniciar Escaneo';

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
    
    // Auto-ocultar después de 5 segundos para mensajes de info
    if (tipo === 'info' || tipo === 'completed') {
        setTimeout(() => {
            if (div.textContent === mensaje) {
                div.style.display = 'none';
            }
        }, 5000);
    }
}

function mostrarReporte(reporteId) {
    fetch(`${API_BASE_URL}/reportes/${reporteId}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const div = document.getElementById('reporteActual');
                div.innerHTML = `
                    <h4>Último Reporte: ${data.nombre}</h4>
                    <p><strong>Fecha:</strong> ${data.fecha}</p>
                    <p><strong>Host:</strong> ${data.host} | <strong>Puerto:</strong> ${data.puerto}</p>
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
    fetch(`${API_BASE_URL}/reportes`)
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
                
                // Agregar botón para limpiar todos los reportes
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
    fetch(`${API_BASE_URL}/reportes/${reporteId}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('modalContent').innerHTML = `
                    <h3>${data.nombre}</h3>
                    <p><strong>Fecha:</strong> ${data.fecha}</p>
                    <p><strong>Host:</strong> ${data.host} | <strong>Puerto:</strong> ${data.puerto}</p>
                    <p><strong>Scripts:</strong> ${data.scripts}</p>
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
    window.open(`${API_BASE_URL}/reportes/${reporteId}/descargar`, '_blank');
}

function eliminarReporte(reporteId, nombreReporte) {
    if (confirm(`¿Estás seguro de que quieres eliminar el reporte "${nombreReporte}"?`)) {
        fetch(`${API_BASE_URL}/reportes/${reporteId}`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    actualizarReportes();
                    mostrarEstado('completed', data.message);
                    
                    // Limpiar el reporte actual si es el que se eliminó
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
        fetch(`${API_BASE_URL}/reportes/limpiar`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    actualizarReportes();
                    mostrarEstado('completed', data.message);
                    
                    // Limpiar el reporte actual
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

// Cerrar modal al hacer clic fuera de él
window.onclick = function (e) {
    const modal = document.getElementById('reportModal');
    if (e.target === modal) {
        modal.style.display = 'none';
    }
};

// Inicialización cuando se carga la página
document.addEventListener('DOMContentLoaded', () => {
    verificarAPI();
    actualizarReportes();
    
    // Verificar estado de la API cada 30 segundos
    setInterval(verificarAPI, 30000);
});

// Función para refrescar reportes manualmente
function refrescarReportes() {
    mostrarEstado('info', 'Actualizando lista de reportes...');
    actualizarReportes();
}