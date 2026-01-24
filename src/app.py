"""
ADS Server - Attack Detection System API
=========================================

API que recibe ventanas del Merger y las pasa al modelo de ML
para detectar ataques de Consul Poisoning.

Endpoints:
- POST /predict: Recibe ventana y retorna predicción
- GET /health: Health check
- GET /stats: Estadísticas del servidor
- POST /model/load: Carga un modelo desde archivo
- GET /model/info: Información del modelo cargado
- GET /predictions: Predicciones guardadas en RDS
"""

import os
import time
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import numpy as np
import httpx

from microservice_chassis_grupo2.sql import database
from microservice_chassis_grupo2.core.dependencies import get_db
import models
import crud
from model_handler import ModelHandler, validate_window_data, MODEL_FEATURES

# ============================================
# CONFIGURACIÓN
# ============================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MODEL_PATH = os.getenv("MODEL_PATH", "/app/models/isolation_forest_model_new.joblib")
ATTACK_THRESHOLD = float(os.getenv("ATTACK_THRESHOLD", "0.5"))

# Respuesta automática a ataques
MERGER_URL = os.getenv("MERGER_URL", "http://merger:8082")
AUTO_DEREGISTER_ENABLED = os.getenv("AUTO_DEREGISTER_ENABLED", "true").lower() == "true"
AUTO_DEREGISTER_THRESHOLD = float(os.getenv("AUTO_DEREGISTER_THRESHOLD", "0.75"))

# Logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ads-server")

# Model handler (global)
model_handler = ModelHandler()

# Historial de predicciones (para visualización en memoria)
PREDICTION_HISTORY = deque(maxlen=500)

# Alertas activas
ACTIVE_ALERTS = deque(maxlen=100)

# Historial de respuestas automáticas (desregistros)
DEREGISTER_HISTORY = deque(maxlen=100)

# Estado de conexión a BD
db_connected = False

# ============================================
# FUNCIONES DE RESPUESTA AUTOMÁTICA
# ============================================

async def trigger_auto_deregister(ip: str, anomaly_score: float, attack_score: float):
    """
    Dispara el desregistro automático de servicios de una IP atacante.
    """
    if not AUTO_DEREGISTER_ENABLED:
        logger.debug(f"Auto-deregister deshabilitado, ignorando IP {ip}")
        return
    
    if anomaly_score < AUTO_DEREGISTER_THRESHOLD:
        logger.info(f"Score {anomaly_score:.2%} < umbral {AUTO_DEREGISTER_THRESHOLD:.2%}, no se desregistra IP {ip}")
        return
    
    logger.warning(f"🚨 RESPUESTA AUTOMÁTICA: Score {anomaly_score:.2%} >= {AUTO_DEREGISTER_THRESHOLD:.2%}")
    logger.warning(f"🎯 Iniciando desregistro de servicios de IP: {ip}")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{MERGER_URL}/deregister/{ip}")
            
            if response.status_code == 200:
                result = response.json()
                deregistered_count = result.get('deregistered_count', 0)
                
                history_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'ip': ip,
                    'anomaly_score': anomaly_score,
                    'attack_score': attack_score,
                    'deregistered_count': deregistered_count,
                    'deregistered_services': result.get('deregistered_services', []),
                    'status': 'success'
                }
                DEREGISTER_HISTORY.append(history_entry)
                
                logger.warning(f"✅ RESPUESTA COMPLETADA: {deregistered_count} servicios desregistrados de IP {ip}")
            else:
                logger.error(f"❌ Error en respuesta automática: HTTP {response.status_code}")
                DEREGISTER_HISTORY.append({
                    'timestamp': datetime.now().isoformat(),
                    'ip': ip,
                    'anomaly_score': anomaly_score,
                    'status': 'error',
                    'error': f"HTTP {response.status_code}"
                })
                
    except httpx.RequestError as e:
        logger.error(f"❌ Error conectando con Merger para desregistro: {e}")
        DEREGISTER_HISTORY.append({
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'anomaly_score': anomaly_score,
            'status': 'error',
            'error': str(e)
        })
    except Exception as e:
        logger.error(f"❌ Error inesperado en auto-deregister: {e}")

# ============================================
# MODELOS PYDANTIC
# ============================================

class WindowData(BaseModel):
    """Datos de una ventana del Merger"""
    window: Dict[str, Any] = Field(..., description="Diccionario con features de la ventana")
    timestamp: Optional[float] = Field(None, description="Timestamp de la ventana")
    source_ip: Optional[str] = Field(None, description="IP origen")

class PredictionResponse(BaseModel):
    """Respuesta de predicción"""
    is_attack: int
    anomaly_score_raw: float
    anomaly_score_normalized: float
    attack_detected: bool  # Mantener por compatibilidad
    method: str
    ip: Optional[str] = None
    timestamp: str
    window_connections: Optional[int] = None

class BatchWindowData(BaseModel):
    """Múltiples ventanas para predicción en batch"""
    windows: List[Dict[str, Any]]
    timestamp: Optional[float] = None

class ModelLoadRequest(BaseModel):
    """Request para cargar modelo"""
    model_path: str = Field(..., description="Ruta al archivo del modelo")

class ThresholdRequest(BaseModel):
    """Request para ajustar threshold"""
    threshold: float = Field(..., ge=0.0, le=1.0)

# ============================================
# LIFESPAN (inicialización y cierre)
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager - inicializa BD y modelo"""
    global db_connected
    
    logger.info("=" * 50)
    logger.info("ADS Server iniciando...")
    logger.info(f"Model path: {MODEL_PATH}")
    logger.info(f"Attack threshold: {ATTACK_THRESHOLD}")
    logger.info(f"Auto-deregister: {AUTO_DEREGISTER_ENABLED} (threshold: {AUTO_DEREGISTER_THRESHOLD})")
    logger.info("=" * 50)
    
    # Inicializar base de datos
    try:
        logger.info("Inicializando conexión a base de datos...")
        await database.init_database()
        logger.info("✅ Conexión a base de datos inicializada")
        db_connected = True
    except Exception as e:
        logger.error(f"❌ No se pudo inicializar la base de datos: {e}")
        db_connected = False
    
    # Crear tablas si no existen
    if db_connected:
        try:
            logger.info("Creando tablas si no existen...")
            async with database.engine.begin() as conn:
                await conn.run_sync(database.Base.metadata.create_all)
            logger.info("✅ Tablas verificadas/creadas")
        except Exception as e:
            logger.error(f"❌ No se pudieron crear las tablas: {e}")
    
    # Cargar modelo ML
    if Path(MODEL_PATH).exists():
        success = model_handler.load_model(MODEL_PATH)
        if success:
            logger.info(f"✅ Modelo cargado desde {MODEL_PATH}")
        else:
            logger.warning(f"⚠️  No se pudo cargar modelo desde {MODEL_PATH}")
    else:
        logger.warning(f"⚠️  Modelo no encontrado en {MODEL_PATH}")
        logger.error("No se puede realizar predicción sin modelo")
    
    # Configurar threshold
    model_handler.set_threshold(ATTACK_THRESHOLD)
    
    yield
    
    # Cleanup
    logger.info("Cerrando ADS Server...")
    if db_connected:
        await database.engine.dispose()
        logger.info("Conexión a base de datos cerrada")

# ============================================
# APP
# ============================================

app = FastAPI(
    title="ADS Server",
    description="Attack Detection System - Consul Poisoning Detection API",
    version="1.0.0",
    lifespan=lifespan
)

# ============================================
# ENDPOINTS DE PREDICCIÓN
# ============================================

@app.get("/health/liveness", include_in_schema=False)
async def health_simple() -> dict:
    """Healthcheck LIVENESS (para Consul / balanceadores)."""
    return {"detail": "OK"}


@app.post("/predict", response_model=PredictionResponse)
async def predict(
    data: WindowData,
    db: AsyncSession = Depends(get_db)
):
    """
    Recibe una ventana y retorna predicción de ataque.
    """
    try:
        window = data.window
        
        # Extraer IP (priorizar source_ip del payload)
        ip = data.source_ip or window.get('id.orig_h') or window.get('ip') or 'unknown'
        
        # Extraer timestamp (del payload o actual)
        request_timestamp = data.timestamp or time.time()
        
        # Validar datos mínimos
        is_valid, missing = validate_window_data(window)
        if not is_valid:
            logger.warning(f"Ventana con features faltantes: {missing[:5]}...")
        
        # Hacer predicción
        result = model_handler.predict(window)
        
        # Extraer valores del resultado
        anomaly_score_raw = result.get('anomaly_score_raw', 0.0)
        anomaly_score_normalized = result.get('anomaly_score_normalized', 0.0)
        is_attack = result.get('is_attack', 0)
        
        # Crear respuesta
        response = PredictionResponse(
            is_attack=is_attack,
            anomaly_score_raw=anomaly_score_raw,
            anomaly_score_normalized=anomaly_score_normalized,
            attack_detected=bool(is_attack),
            method=result['method'],
            ip=ip,
            timestamp=datetime.now().isoformat(),
            window_connections=window.get('n_connections')
        )
        
        # Guardar en historial local
        history_entry = {
            'timestamp': response.timestamp,
            'ip': ip,
            'is_attack': is_attack,
            'anomaly_score_raw': anomaly_score_raw,
            'anomaly_score_normalized': anomaly_score_normalized,
            'method': result['method'],
            'n_connections': window.get('n_connections', 0)
        }
        PREDICTION_HISTORY.append(history_entry)
        
        # Loguear SIEMPRE (ataque o tráfico normal)
        if is_attack:
            logger.warning(
                f"🚨 ATAQUE DETECTADO - IP: {ip}, "
                f"anomaly_score_raw: {anomaly_score_raw:.4f}, "
                f"anomaly_score_normalized: {anomaly_score_normalized:.4f}, "
                f"is_attack: {is_attack}"
            )
        else:
            logger.info(
                f"✅ TRÁFICO NORMAL - IP: {ip}, "
                f"anomaly_score_raw: {anomaly_score_raw:.4f}, "
                f"anomaly_score_normalized: {anomaly_score_normalized:.4f}, "
                f"is_attack: {is_attack}"
            )
        
        # Guardar en RDS
        if db_connected:
            await crud.save_prediction(
                db=db,
                source_ip=ip,
                timestamp=request_timestamp,
                anomaly_score_raw=anomaly_score_raw,
                anomaly_score_normalized=anomaly_score_normalized,
                is_attack=is_attack,
                method=result['method'],
                n_connections=window.get('n_connections'),
                window_data=window
            )
        
        # Si se detecta ataque, crear alerta y respuesta automática
        if is_attack:
            alert = {
                'timestamp': response.timestamp,
                'ip': ip,
                'anomaly_score_raw': anomaly_score_raw,
                'anomaly_score_normalized': anomaly_score_normalized,
                'n_connections': window.get('n_connections', 0)
            }
            ACTIVE_ALERTS.append(alert)
            
            # RESPUESTA AUTOMÁTICA
            asyncio.create_task(trigger_auto_deregister(
                ip=ip,
                anomaly_score=anomaly_score_raw,
                attack_score=anomaly_score_raw
            ))
        
        return response
        
    except Exception as e:
        logger.error(f"Error en predicción: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
async def predict_batch(
    data: BatchWindowData,
    db: AsyncSession = Depends(get_db)
):
    """Predicción en batch para múltiples ventanas."""
    results = []
    
    for window in data.windows:
        try:
            result = model_handler.predict(window)
            ip = window.get('id.orig_h') or window.get('ip') or 'unknown'
            
            results.append({
                'ip': ip,
                'is_attack': result['is_attack'],
                'attack_detected': result['attack_detected'],
                'anomaly_score_raw': result['anomaly_score_raw'],
                'anomaly_score_normalized': result['anomaly_score_normalized'],
                'method': result['method']
            })
            
            if result['attack_detected']:
                logger.warning(f"🚨 ATAQUE DETECTADO (batch) - IP: {ip}")
                
        except Exception as e:
            results.append({
                'ip': window.get('id.orig_h', 'unknown'),
                'error': str(e)
            })
    
    return {
        'predictions': results,
        'total': len(results),
        'attacks_detected': sum(1 for r in results if r.get('attack_detected', False))
    }

# ============================================
# ENDPOINTS DE MODELO
# ============================================

@app.post("/model/load")
async def load_model(request: ModelLoadRequest):
    """Carga un modelo desde archivo"""
    success = model_handler.load_model(request.model_path)
    
    if success:
        return {
            'status': 'ok',
            'message': f'Modelo cargado desde {request.model_path}',
            'model_info': model_handler.get_stats()
        }
    else:
        raise HTTPException(
            status_code=400, 
            detail=f'No se pudo cargar modelo desde {request.model_path}'
        )


@app.get("/model/info")
async def model_info():
    """Información del modelo cargado"""
    return {
        'model_stats': model_handler.get_stats(),
        'feature_count': len(model_handler.get_feature_names()),
        'features_sample': model_handler.get_feature_names()[:20]
    }


@app.post("/model/threshold")
async def set_threshold(request: ThresholdRequest):
    """Ajusta el threshold de detección"""
    model_handler.set_threshold(request.threshold)
    return {
        'status': 'ok',
        'new_threshold': model_handler.attack_threshold
    }


@app.get("/model/features")
async def get_features():
    """Lista de features que espera el modelo"""
    return {
        'features': model_handler.get_feature_names(),
        'count': len(model_handler.get_feature_names())
    }

# ============================================
# ENDPOINTS DE ESTADO
# ============================================

@app.get("/health")
async def health():
    """Health check completo"""
    return {
        'status': 'healthy',
        'model_loaded': model_handler.is_loaded,
        'model_type': model_handler.model_type or 'none',
        'rds_connected': db_connected,
        'timestamp': datetime.now().isoformat()
    }


@app.get("/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    """Estadísticas del servidor"""
    db_stats = {}
    if db_connected:
        db_stats = await crud.count_predictions(db)
    
    return {
        'model_stats': model_handler.get_stats(),
        'predictions_in_memory': len(PREDICTION_HISTORY),
        'active_alerts': len(ACTIVE_ALERTS),
        'recent_attacks': sum(1 for p in list(PREDICTION_HISTORY)[-100:] 
                             if p.get('attack_detected', False)),
        'db_stats': db_stats,
        'auto_response': {
            'enabled': AUTO_DEREGISTER_ENABLED,
            'threshold': AUTO_DEREGISTER_THRESHOLD,
            'merger_url': MERGER_URL,
            'deregistrations_total': len(DEREGISTER_HISTORY),
            'successful_deregistrations': sum(1 for d in DEREGISTER_HISTORY if d.get('status') == 'success')
        }
    }


@app.get("/deregistrations")
async def get_deregistrations(limit: int = 50):
    """Obtiene historial de desregistros automáticos."""
    deregistrations = list(DEREGISTER_HISTORY)[-limit:]
    return {
        'deregistrations': deregistrations,
        'count': len(deregistrations),
        'config': {
            'enabled': AUTO_DEREGISTER_ENABLED,
            'threshold': AUTO_DEREGISTER_THRESHOLD
        }
    }

# ============================================
# ENDPOINTS DE RDS / GRAFANA
# ============================================

@app.get("/predictions")
async def get_predictions(
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """Obtiene predicciones guardadas en RDS."""
    if not db_connected:
        return {
            'error': 'RDS no conectado',
            'predictions': [],
            'count': 0
        }
    
    predictions = await crud.get_recent_predictions(db, limit=limit)
    return {
        'predictions': predictions,
        'count': len(predictions)
    }


@app.get("/predictions/stats")
async def get_prediction_stats(db: AsyncSession = Depends(get_db)):
    """Estadísticas de predicciones en RDS"""
    if not db_connected:
        return {'connected': False}
    return await crud.count_predictions(db)


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    """Obtiene alertas recientes (en memoria)"""
    alerts = list(ACTIVE_ALERTS)[-limit:]
    return {
        'alerts': alerts,
        'count': len(alerts),
        'total_alerts': len(ACTIVE_ALERTS)
    }


@app.get("/history")
async def get_history(limit: int = 100, attacks_only: bool = False):
    """Obtiene historial de predicciones (en memoria)"""
    history = list(PREDICTION_HISTORY)
    
    if attacks_only:
        history = [h for h in history if h.get('attack_detected', False)]
    
    return {
        'history': history[-limit:],
        'count': len(history[-limit:]),
        'total': len(PREDICTION_HISTORY)
    }


@app.delete("/alerts/clear")
async def clear_alerts():
    """Limpia alertas"""
    ACTIVE_ALERTS.clear()
    return {'status': 'ok', 'message': 'Alertas limpiadas'}

# ============================================
# ENDPOINT DE TEST
# ============================================

@app.post("/test/predict")
async def test_predict(db: AsyncSession = Depends(get_db)):
    """
    Endpoint de prueba que genera una ventana sintética
    y hace predicción.
    """
    test_window = {
        'id.orig_h': '10.0.0.99',
        'n_connections': 25,
        'window_duration': 30.0,
        'burst_score_mean': 0.8,
        'burst_score_std': 0.15,
        'burst_score_max': 1.0,
        'bytes_ratio_mean': 0.3,
        'bytes_ratio_std': 0.1,
        'bytes_ratio_max': 0.5,
        'conn_count_10s_mean': 8.0,
        'conn_count_10s_std': 2.0,
        'conn_count_10s_max': 12.0,
        'conn_count_300s_mean': 20.0,
        'conn_count_300s_std': 5.0,
        'conn_count_300s_max': 25.0,
        'conn_count_60s_mean': 15.0,
        'conn_count_60s_std': 3.0,
        'conn_count_60s_max': 20.0,
        'recon_pattern_score_mean': 0.7,
        'recon_pattern_score_std': 0.15,
        'recon_pattern_score_max': 0.9,
    }
    
    result = model_handler.predict(test_window)
    
    return {
        'test_window_features': len([k for k in test_window.keys() if k not in ['id.orig_h', 'window_duration']]),
        'model_features': len(model_handler.get_feature_names()),
        'prediction': result,
        'info': 'Test window simulates attack pattern with high burst_score, recon, and unknown IP'
    }


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
