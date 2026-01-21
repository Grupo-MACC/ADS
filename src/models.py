"""
Modelos SQLAlchemy para ADS Server
==================================

Define las tablas de la base de datos.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, Float, String, DateTime, JSON
from microservice_chassis_grupo2.sql.models import BaseModel


class Prediction(BaseModel):
    """Tabla de predicciones para Grafana"""
    __tablename__ = "predictions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)  # Soporta IPv6
    anomaly_score = Column(Float, nullable=False)  # Score normalizado 0-1
    anomaly_score_raw = Column(Float, nullable=False)  # Score original del modelo
    attack_detected = Column(Integer, nullable=False, index=True)  # 0 o 1
    confidence = Column(Float, nullable=True)
    method = Column(String(50), nullable=True)  # 'model', 'heuristic' o 'combined'
    n_connections = Column(Integer, nullable=True)
    window_data = Column(JSON, nullable=True)  # Window completa como JSON
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Prediction(id={self.id}, ip={self.source_ip}, score={self.anomaly_score:.3f}, attack={self.attack_detected})>"
