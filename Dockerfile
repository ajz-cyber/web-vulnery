# Usa una imagen base de Python
FROM python:3.11-slim

# Instala Nmap y algunas dependencias del sistema necesarias
RUN apt-get update && apt-get install -y \
    nmap \
    gcc \
    libffi-dev \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Establece el directorio de trabajo
WORKDIR /app

# Copia todo el código al contenedor
COPY . .

# Instala dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Expone el puerto 5000
EXPOSE 5000

# Comando de inicio de la app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
