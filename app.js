const API_BASE_URL = 'https://web-vulnery.onrender.com/api';
let intervaloBusqueda = null;
let apiOnline = false;

function verificarAPI() {
    fetch(`${API_BASE_URL}/health`)
        .then(res => res.json())
        .then(() => {
            apiOnline = true;
            document.getElementById('apiStatusText').textContent = 'Conectado';
        })
        .catch(() => {
            apiOnline = false;
            document.getElementById('apiStatusText').textContent = 'Desconectado';
        });
}

function iniciarEscaneo() {
    if (!apiOnline) return alert('API no disponible');

    const host = document.getElementById('host').value.trim();
    const puerto = document.getElementById('puerto').value.trim();
    const scripts = document.getElementById('scripts').value;

    if (!host) return alert('Ingresa un host válido');

    fetch(`${API_BASE_URL}/escanear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, puerto, scripts })
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) iniciarMonitoreo();
            else mostrarEstado('error', data.message);
        })
        .catch(err => mostrarEstado('error', 'Error: ' + err.message));
}

function iniciarMonitoreo() {
    if (intervaloBusqueda) clearInterval(intervaloBusqueda);
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
        });
}

function mostrarEstado(tipo, mensaje) {
    const div = document.getElementById('estado');
    div.className = tipo;
    div.textContent = mensaje;
    div.style.display = 'block';
}

function mostrarReporte(nombre) {
    fetch(`${API_BASE_URL}/reportes/${nombre}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const div = document.getElementById('reporteActual');
                div.innerHTML = `<h4>Último Reporte: ${data.nombre}</h4><pre>${data.contenido}</pre>`;
                div.style.display = 'block';
            }
        });
}

function actualizarReportes() {
    fetch(`${API_BASE_URL}/reportes`)
        .then(res => res.json())
        .then(data => {
            const lista = document.getElementById('listaReportes');
            if (data.success && data.reportes.length > 0) {
                lista.innerHTML = data.reportes.map(r => `
                    <div>
                        <div>
                            <strong>${r.nombre}</strong><br>
                            <small>${r.fecha} | ${(r.tamaño / 1024).toFixed(1)} KB</small>
                        </div>
                        <div>
                            <button onclick="verReporteModal('${r.nombre}')">Ver</button>
                            <button onclick="descargarReporte('${r.nombre}')">Descargar</button>
                            <button onclick="eliminarReporte('${r.nombre}')">Eliminar</button>
                        </div>
                    </div>
                `).join('');
            } else {
                lista.innerHTML = '<div>No hay reportes disponibles</div>';
            }
        })
        .catch(() => {
            document.getElementById('listaReportes').innerHTML = '<div>Error al cargar reportes</div>';
        });
}

function verReporteModal(nombre) {
    fetch(`${API_BASE_URL}/reportes/${nombre}/contenido`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('modalContent').innerHTML = `<h3>${data.nombre}</h3><pre>${data.contenido}</pre>`;
                document.getElementById('reportModal').style.display = 'block';
            }
        });
}

function descargarReporte(nombre) {
    window.open(`${API_BASE_URL}/reportes/${nombre}/descargar`, '_blank');
}

function eliminarReporte(nombre) {
    if (confirm(`¿Eliminar "${nombre}"?`)) {
        fetch(`${API_BASE_URL}/reportes/${nombre}`, { method: 'DELETE' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    actualizarReportes();
                    mostrarEstado('completed', data.message);
                } else {
                    mostrarEstado('error', data.message);
                }
            });
    }
}

function cerrarModal() {
    document.getElementById('reportModal').style.display = 'none';
}

window.onclick = function (e) {
    const modal = document.getElementById('reportModal');
    if (e.target === modal) modal.style.display = 'none';
};

document.addEventListener('DOMContentLoaded', () => {
    verificarAPI();
    actualizarReportes();
    setInterval(verificarAPI, 30000);
});
