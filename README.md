# 🛡️ ADS - Attack Detection System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.104+-green?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/ML-Isolation_Forest-orange?logo=scikit-learn&logoColor=white" alt="ML">
  <img src="https://img.shields.io/badge/Docker-Ready-blue?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Database-MySQL_RDS-blue?logo=mysql&logoColor=white" alt="MySQL">
</p>

**Sistema de detección de ataques de Consul Poisoning mediante Machine Learning.**

El ADS Server recibe ventanas de tráfico procesadas desde el Merger, las analiza con un modelo de Isolation Forest combinado con heurísticas, y detecta patrones de ataque en tiempo real. Cuando detecta un ataque con alta confianza, puede desregistrar automáticamente los servicios maliciosos de Consul.

---

## 📁 Estructura del Repositorio

```
ADS/
├── 📄 Dockerfile              # Imagen Docker del servidor
├── 📄 docker-compose.yaml     # Configuración de despliegue
├── 📄 .env.example            # Variables de entorno (ejemplo)
├── 📄 README.md               # Este archivo
│
├── 📂 src/                    # Código fuente principal
│   ├── app.py                 # API FastAPI con todos los endpoints
│   ├── model_handler.py       # Carga y predicción del modelo ML
│   ├── models.py              # Modelos SQLAlchemy (tabla predictions)
│   ├── crud.py                # Operaciones de base de datos
│   └── requirements.txt       # Dependencias Python
│
├── 📂 models/                 # Modelos ML entrenados
│   ├── isolation_forest_model_new.joblib   # Modelo principal (recomendado)
│   └── isolation_forest_model.joblib       # Modelo anterior
│
└── 📂 scripts/                # Scripts de utilidad
    └── init_db.py             # Crear tablas en MySQL/RDS
```

---

## 📚 Descripción de Archivos

### 🔹 `src/app.py` - API Principal

**Propósito:** Servidor FastAPI que expone la API REST del sistema ADS.

**Funcionalidades:**
- Recibe ventanas de tráfico del Merger (`POST /predict`)
- Ejecuta el modelo de ML para detectar ataques
- Dispara respuesta automática (desregistro) si confianza ≥ 75%
- Guarda predicciones en MySQL/RDS para Grafana
- Mantiene historial en memoria para consultas rápidas

**Dependencias del Chassis:**
```python
from microservice_chassis_grupo2.sql import database
from microservice_chassis_grupo2.core.dependencies import get_db
```

**Endpoints principales:**
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `POST` | `/predict` | Recibe ventana y retorna predicción |
| `GET` | `/health` | Health check del servicio |
| `GET` | `/stats` | Estadísticas del servidor |
| `GET` | `/predictions` | Predicciones de la BD (para Grafana) |
| `GET` | `/model/info` | Información del modelo cargado |

---

### 🔹 `src/model_handler.py` - Handler del Modelo ML

**Propósito:** Gestiona la carga y ejecución del modelo de detección.

**Funcionalidades:**
- Carga el modelo Isolation Forest desde archivo `.joblib`
- Combina predicción ML con heurísticas de ataque
- Normaliza scores a rango [0, 1]
- Valida que las ventanas tengan las features necesarias

**Modelo utilizado:** Isolation Forest con 74 features de red.

**Heurísticas de ataque:**
```python
# Patrón de Consul Poisoning
conn_count >= 6              # Burst de conexiones
recon_pattern_score >= 0.7   # Patrón de reconocimiento
burst_score >= 0.8           # Conexiones muy rápidas
```

**Score final:** Combina score ML (60%) + score heurístico (40%)

---

### 🔹 `src/models.py` - Modelos de Base de Datos

**Propósito:** Define la estructura de tablas usando SQLAlchemy.

**Tabla `predictions`:**
| Columna | Tipo | Descripción |
|---------|------|-------------|
| `id` | INT | Primary key |
| `timestamp` | DATETIME | Momento de la predicción |
| `source_ip` | VARCHAR(45) | IP origen del tráfico |
| `anomaly_score` | FLOAT | Score normalizado [0-1] |
| `anomaly_score_raw` | FLOAT | Score raw del modelo |
| `attack_detected` | INT | 1 si ataque, 0 si normal |
| `confidence` | FLOAT | Confianza de la predicción |
| `method` | VARCHAR(50) | Método: ml, heuristic, combined |
| `n_connections` | INT | Conexiones en la ventana |
| `window_data` | JSON | Datos completos de la ventana |

**Hereda del Chassis:**
```python
from microservice_chassis_grupo2.sql.models import BaseModel

class Prediction(BaseModel):
    __tablename__ = "predictions"
    # ... columnas
```

---

### 🔹 `src/crud.py` - Operaciones de Base de Datos

**Propósito:** Funciones CRUD asíncronas para la tabla predictions.

**Funciones:**
```python
async def save_prediction(db, prediction_data: dict) -> Prediction
async def get_recent_predictions(db, limit: int = 100) -> List[Prediction]
async def count_predictions(db) -> dict
```

---

### 🔹 `src/requirements.txt` - Dependencias

**Dependencias principales:**
```
microservice-chassis-grupo2_cc_prod   # Chassis del proyecto
fastapi>=0.104.0                      # Framework API
uvicorn>=0.24.0                       # Servidor ASGI
scikit-learn>=1.3.0                   # Modelo ML
aiomysql>=0.2.0                       # MySQL async
```

---

### 🔹 `scripts/init_db.py` - Inicialización de BD

**Propósito:** Script para crear las tablas en MySQL/RDS.

**Uso:**
```bash
export RDS_HOST=tu-rds-endpoint.amazonaws.com
export DB_NAME=ads
export DB_USER=admin
export DB_PASSWORD=tu-password

python scripts/init_db.py
```

**Crea:**
- Tabla `predictions` con índices optimizados
- Vista `predictions_summary` para Grafana
- Vista `recent_attacks` con últimos ataques

---

### 🔹 `Dockerfile` - Imagen Docker

**Base:** `python:3.11-slim`

**Estructura:**
```dockerfile
WORKDIR /app
COPY src/requirements.txt .
RUN pip install -r requirements.txt
COPY src/ .
COPY models/ /app/models/
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
```

---

### 🔹 `docker-compose.yaml` - Orquestación

**Servicio:** `ads-server`
- Puerto: `8083:8080`
- Volumen: `./models:/app/models:ro`
- Variables de entorno para RDS y respuesta automática

---

### 🔹 `.env.example` - Variables de Entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `RDS_HOST` | - | Endpoint de MySQL/RDS |
| `RDS_PORT` | `3306` | Puerto MySQL |
| `DB_NAME` | `ads` | Nombre de la base de datos |
| `DB_USER` | `admin` | Usuario de BD |
| `DB_PASSWORD` | - | Contraseña de BD |
| `ATTACK_THRESHOLD` | `0.5` | Umbral para clasificar ataque |
| `AUTO_DEREGISTER_ENABLED` | `true` | Respuesta automática |
| `AUTO_DEREGISTER_THRESHOLD` | `0.75` | Confianza mínima para desregistrar |
| `MERGER_URL` | `http://merger:8082` | URL del Merger |

---

## 🚀 Despliegue Rápido

### 1. Configurar variables de entorno

```bash
cp .env.example .env
nano .env  # Rellenar con datos de RDS
```

### 2. Crear tablas en RDS (primera vez)

```bash
# Con las variables exportadas:
python scripts/init_db.py
```

### 3. Construir y ejecutar

```bash
docker-compose up -d --build
```

### 4. Verificar funcionamiento

```bash
# Health check
curl http://localhost:8083/health

# Info del modelo
curl http://localhost:8083/model/info
```

---

## 🧠 Algoritmo de Detección

### Flujo de Predicción

```
┌──────────────────────────────────────────────────────────────┐
│                     VENTANA DE TRÁFICO                       │
│  (74 features: conn_count, burst_score, pattern_score...)    │
└────────────────────────────┬─────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌─────────────────────────┐    ┌─────────────────────────┐
│   ISOLATION FOREST      │    │      HEURÍSTICAS        │
│   (Modelo ML)           │    │   (Patrones conocidos)  │
│                         │    │                         │
│   score_ml = predict()  │    │   conn >= 6 → +0.3      │
│   Normalizado [0,1]     │    │   burst >= 0.8 → +0.3   │
└───────────┬─────────────┘    │   recon >= 0.7 → +0.4   │
            │                  └───────────┬─────────────┘
            │                              │
            ▼                              ▼
┌──────────────────────────────────────────────────────────────┐
│              SCORE COMBINADO                                  │
│                                                               │
│   final_score = 0.6 × score_ml + 0.4 × score_heuristic       │
│                                                               │
│   Si final_score >= 0.5 → ATAQUE DETECTADO                   │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
         ┌───────────────────────────────────────┐
         │  Si confianza >= 75%                  │
         │  → Desregistro automático de la IP    │
         └───────────────────────────────────────┘
```

### Patrón de Ataque (Consul Poisoning)

```
Tiempo ──────────────────────────────────────────▶

[RECON]     GET /v1/catalog/services      ─┐
    ↓       GET /v1/catalog/service/X      │
    ↓       GET /v1/catalog/service/Y      ├── 4 GETs rápidos (~0.3s cada uno)
    ↓       GET /v1/health/service/Z      ─┘

[INJECT]    PUT /v1/agent/service/register  ── Registro malicioso

[VERIFY]    GET /v1/catalog/service/mal     ── Verificación
```

---

## 🔄 Respuesta Automática

Cuando el ADS detecta un ataque con **confianza ≥ 75%**:

1. 🎯 Envía `POST /deregister/{ip}` al Merger
2. 🗑️ El Merger desregistra todos los servicios de esa IP en Consul
3. 📝 Se registra la acción en el historial

```bash
# Ver historial de desregistros
curl http://localhost:8083/deregistrations
```

---

## 🏗️ Arquitectura del Sistema

```
                                    EC2-Consul
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ┌─────────┐    ┌──────────┐    ┌─────────┐                 │
│  │  Zeek   │───▶│ Shipper  │───▶│ Merger  │◀───────────┐    │
│  └─────────┘    └──────────┘    └────┬────┘            │    │
│                                      │                  │    │
│                                      │ POST /predict    │    │
│                                      ▼                  │    │
└──────────────────────────────────────┼──────────────────┼────┘
                                       │                  │
                                       │                  │ POST /deregister/{ip}
                                       ▼                  │
                                    EC2-ADS               │
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    ADS SERVER                         │   │
│  │                                                       │   │
│  │   ┌───────────┐    ┌─────────────┐    ┌──────────┐   │   │
│  │   │  FastAPI  │───▶│ ModelHandler│───▶│ Predicción│──┼───┘
│  │   └───────────┘    └─────────────┘    └────┬─────┘   │
│  │                                            │         │
│  └────────────────────────────────────────────┼─────────┘   │
│                                               │              │
│                                               ▼              │
│                                    ┌──────────────────┐      │
│                                    │   MySQL (RDS)    │      │
│                                    │  predictions DB  │      │
│                                    └────────┬─────────┘      │
│                                             │                │
└─────────────────────────────────────────────┼────────────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │     Grafana      │
                                    │   Dashboards     │
                                    └──────────────────┘
```

---

## 📊 Ejemplo de Uso

### Request (enviado por el Merger)

```bash
curl -X POST http://localhost:8083/predict \
  -H "Content-Type: application/json" \
  -d '{
    "window": {
      "burst_score_max": 1.0,
      "conn_count_10s_max": 8,
      "recon_pattern_score_max": 0.85,
      "n_connections": 6
    },
    "source_ip": "10.0.0.50",
    "timestamp": 1737450000
  }'
```

### Response

```json
{
  "attack_detected": true,
  "attack_probability": 0.95,
  "attack_score": 0.95,
  "confidence": 0.80,
  "method": "combined",
  "ip": "10.0.0.50",
  "timestamp": "2026-01-21T10:30:00",
  "window_connections": 6,
  "auto_deregister_triggered": true
}
```

---

## 🔧 Desarrollo Local

```bash
# Clonar repositorio
git clone <repo-url>
cd ADS

# Crear entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r src/requirements.txt

# Ejecutar en desarrollo
cd src
uvicorn app:app --reload --port 8083
```


<p align="center">
  <i>Desarrollado como parte del sistema de detección de ataques a Consul</i>
</p>
