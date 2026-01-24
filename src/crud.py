"""
CRUD operations para ADS Server
================================

Operaciones de base de datos para predicciones.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from models import Prediction

logger = logging.getLogger("ads-server.crud")


def normalize_score(raw_score: float, min_val: float = 0.35, max_val: float = 0.8) -> float:
    """
    Normaliza el anomaly score del rango [0.35, 0.8] a [0, 1]
    
    Args:
        raw_score: Score del modelo (típicamente entre 0.35 y 0.8)
        min_val: Valor mínimo esperado (default 0.35)
        max_val: Valor máximo esperado (default 0.8)
    
    Returns:
        Score normalizado entre 0 y 1
    """
    if max_val == min_val:
        return 0.5
    # Normalizar: (valor - min) / (max - min)
    normalized = (raw_score - min_val) / (max_val - min_val)
    # Clampear entre 0 y 1
    return round(max(0.0, min(1.0, normalized)), 4)


async def save_prediction(
    db: AsyncSession,
    source_ip: str,
    timestamp: float,
    anomaly_score_raw: float,
    anomaly_score_normalized: float,
    is_attack: int,
    method: str = None,
    n_connections: int = None,
    window_data: Dict = None
) -> Optional[Prediction]:
    """
    Guarda una predicción en la base de datos.
    
    Args:
        db: Sesión de base de datos
        source_ip: IP origen de la conexión
        timestamp: Timestamp Unix de la ventana
        anomaly_score_raw: Score crudo del modelo
        anomaly_score_normalized: Score normalizado (0-1) desde rango [0.35, 0.8]
        is_attack: 1 si es ataque (anomaly_score_raw > 0.65), 0 si no
        method: Método usado ('model')
        n_connections: Número de conexiones en la ventana
        window_data: Diccionario completo de la ventana
    
    Returns:
        Prediction creada o None si hay error
    """
    try:
        # Convertir timestamp a datetime
        ts_datetime = datetime.fromtimestamp(timestamp) if timestamp else datetime.utcnow()
        
        # Crear registro
        prediction = Prediction(
            timestamp=ts_datetime,
            source_ip=source_ip or "unknown",
            anomaly_score=anomaly_score_normalized,
            anomaly_score_raw=anomaly_score_raw,
            attack_detected=is_attack,
            method=method,
            n_connections=n_connections,
            window_data=window_data
        )
        
        db.add(prediction)
        await db.commit()
        await db.refresh(prediction)
        
        logger.debug(f"Predicción guardada: IP={source_ip}, raw={anomaly_score_raw:.4f}, normalized={anomaly_score_normalized:.4f}, is_attack={is_attack}")
        return prediction
        
    except Exception as e:
        logger.error(f"Error guardando predicción: {e}")
        await db.rollback()
        return None


async def get_recent_predictions(db: AsyncSession, limit: int = 100) -> List[Dict]:
    """
    Obtiene las predicciones más recientes.
    
    Args:
        db: Sesión de base de datos
        limit: Número máximo de predicciones
    
    Returns:
        Lista de predicciones como diccionarios
    """
    try:
        result = await db.execute(
            select(Prediction)
            .order_by(desc(Prediction.timestamp))
            .limit(limit)
        )
        predictions = result.scalars().all()
        
        return [
            {
                "id": p.id,
                "timestamp": p.timestamp.isoformat(),
                "source_ip": p.source_ip,
                "anomaly_score": p.anomaly_score,
                "anomaly_score_raw": p.anomaly_score_raw,
                "is_attack": p.attack_detected,
                "method": p.method,
                "n_connections": p.n_connections
            }
            for p in predictions
        ]
        
    except Exception as e:
        logger.error(f"Error obteniendo predicciones: {e}")
        return []


async def get_attacks_by_ip(db: AsyncSession, source_ip: str, limit: int = 50) -> List[Dict]:
    """
    Obtiene ataques detectados de una IP específica.
    """
    try:
        result = await db.execute(
            select(Prediction)
            .where(Prediction.source_ip == source_ip)
            .where(Prediction.attack_detected == 1)
            .order_by(desc(Prediction.timestamp))
            .limit(limit)
        )
        predictions = result.scalars().all()
        
        return [
            {
                "id": p.id,
                "timestamp": p.timestamp.isoformat(),
                "anomaly_score": p.anomaly_score,
                "anomaly_score_raw": p.anomaly_score_raw,
                "is_attack": p.attack_detected,
                "method": p.method,
                "n_connections": p.n_connections
            }
            for p in predictions
        ]
        
    except Exception as e:
        logger.error(f"Error obteniendo ataques por IP: {e}")
        return []


async def count_predictions(db: AsyncSession) -> Dict:
    """
    Cuenta total de predicciones y ataques.
    """
    try:
        # Total predicciones
        result_total = await db.execute(select(Prediction))
        total = len(result_total.scalars().all())
        
        # Total ataques
        result_attacks = await db.execute(
            select(Prediction).where(Prediction.attack_detected == 1)
        )
        attacks = len(result_attacks.scalars().all())
        
        return {
            "total_predictions": total,
            "total_attacks": attacks,
            "attack_rate": attacks / total if total > 0 else 0
        }
        
    except Exception as e:
        logger.error(f"Error contando predicciones: {e}")
        return {"total_predictions": 0, "total_attacks": 0, "attack_rate": 0}
