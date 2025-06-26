# Imagen base de Python
FROM python:3.11-slim

# Instala Nmap
RUN apt-get update && apt-get install -y nmap && apt-get clean

# Directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos al contenedor
COPY . .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Expone el puerto que usa Flask o Gunicorn
EXPOSE 5000

# Comando que ejecuta la app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
