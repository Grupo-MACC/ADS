FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependencias Python
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY src/app.py .
COPY src/model_handler.py .
COPY src/models.py .
COPY src/crud.py .

# Variables de entorno por defecto para la base de datos
# RDS_HOST se resuelve automáticamente via Consul (servicio "rds")
ENV DB_NAME=ads_db
ENV DB_USER=admin
ENV DB_PASSWORD=maccadmin
ENV RDS_PORT=3306

# Consul Service Discovery (HTTPS)
ENV CONSUL_HOST=10.1.11.40
ENV CONSUL_PORT=8501
ENV CONSUL_SCHEME=https

# Certificados TLS (el chassis hace verify=False, pero se pueden usar)
ENV CONSUL_CA_FILE=/certs/ca.pem

# Crear directorio para certificados
RUN mkdir -p /certs

# Crear directorio para el modelo
RUN mkdir -p /app/models

# Copiar modelo (si existe)
COPY models/ /app/models/

# Exponer puerto
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Ejecutar
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
