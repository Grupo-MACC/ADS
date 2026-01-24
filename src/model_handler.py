"""
Model Handler for Consul Poisoning Detection
=============================================

Este módulo maneja la carga y predicción del modelo de ML.
Diseñado para ser flexible y soportar diferentes tipos de modelo.

Uso:
    handler = ModelHandler()
    handler.load_model("/app/models/model.joblib")
    prediction = handler.predict(window_data)
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)


# =============================================================================
# Configuración de Features
# =============================================================================

# Features que el modelo Isolation Forest espera recibir (exactamente 74, en orden alfabético)
# IMPORTANTE: Este orden debe coincidir exactamente con el usado durante el entrenamiento

MODEL_FEATURES = [
    'burst_score_max', 'burst_score_mean', 'burst_score_std',
    'bytes_ratio_max', 'bytes_ratio_mean', 'bytes_ratio_std',
    'conn_count_10s_max', 'conn_count_10s_mean', 'conn_count_10s_std',
    'conn_count_300s_max', 'conn_count_300s_mean', 'conn_count_300s_std',
    'conn_count_60s_max', 'conn_count_60s_mean', 'conn_count_60s_std',
    'conn_interval_max', 'conn_interval_mean', 'conn_interval_std',
    'conn_state_encoded_max', 'conn_state_encoded_mean', 'conn_state_encoded_std',
    'duration_max', 'duration_mean', 'duration_std',
    'duration_zscore_max', 'duration_zscore_mean', 'duration_zscore_std',
    'hour_of_day_max', 'hour_of_day_mean', 'hour_of_day_std',
    'id.orig_p_max', 'id.orig_p_mean', 'id.orig_p_std',
    'id.resp_p_std',
    'interval_stddev_max', 'interval_stddev_mean', 'interval_stddev_std',
    'ip_first_seen_hours_ago_max', 'ip_first_seen_hours_ago_mean', 'ip_first_seen_hours_ago_std',
    'is_known_ip_max', 'is_known_ip_mean', 'is_known_ip_std',
    'ja3_behavior_score_std',
    'ja3_frequency_max', 'ja3_frequency_mean', 'ja3_frequency_std',
    'ja3_is_known_std',
    'n_connections',
    'orig_bytes_max', 'orig_bytes_mean', 'orig_bytes_std',
    'recent_activity_score_max', 'recent_activity_score_mean', 'recent_activity_score_std',
    'recent_docker_event_max', 'recent_docker_event_mean', 'recent_docker_event_std',
    'recon_pattern_score_max', 'recon_pattern_score_mean', 'recon_pattern_score_std',
    'resp_bytes_max', 'resp_bytes_mean', 'resp_bytes_std',
    'time_since_container_start_max', 'time_since_container_start_mean', 'time_since_container_start_std',
    'time_since_last_conn_max', 'time_since_last_conn_mean', 'time_since_last_conn_std',
    'total_conn_from_ip_max', 'total_conn_from_ip_mean', 'total_conn_from_ip_std',
    'unique_ja3_from_ip_std'
]


class ModelHandler:
    """
    Manejador del modelo de ML para detección de Consul Poisoning.
    
    Usa el modelo Isolation Forest para detectar anomalías.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path
        self.model_type = None
        self.feature_names = MODEL_FEATURES.copy()
        self.is_loaded = False
        
        # Estadísticas
        self.stats = {
            'predictions_made': 0,
            'attacks_detected': 0,
            'errors': 0
        }
        
        # Threshold para clasificación
        self.attack_threshold = 0.5
        
        # Cargar modelo si se especifica path
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str) -> bool:
        """
        Carga el modelo desde un archivo.
        
        Soporta:
        - .joblib: sklearn models
        - .pkl: pickle models
        - .h5: keras models (requiere tensorflow)
        
        Args:
            model_path: Ruta al archivo del modelo
            
        Returns:
            True si se cargó correctamente, False en caso contrario
        """
        try:
            path = Path(model_path)
            
            if not path.exists():
                logger.warning(f"Modelo no encontrado en {model_path}")
                return False
            
            ext = path.suffix.lower()
            
            if ext in ['.joblib', '.pkl']:
                import joblib
                self.model = joblib.load(model_path)
                self.model_type = 'sklearn'
                logger.info(f"Modelo sklearn cargado desde {model_path}")
                
            elif ext == '.h5':
                # Para modelos Keras/TensorFlow
                try:
                    from tensorflow import keras
                    self.model = keras.models.load_model(model_path)
                    self.model_type = 'keras'
                    logger.info(f"Modelo Keras cargado desde {model_path}")
                except ImportError:
                    logger.error("TensorFlow no instalado, no se puede cargar modelo .h5")
                    return False
                    
            else:
                logger.error(f"Extensión de modelo no soportada: {ext}")
                return False
            
            self.model_path = model_path
            self.is_loaded = True
            
            # Intentar obtener feature names del modelo
            self._extract_feature_names()
            
            return True
            
        except Exception as e:
            logger.error(f"Error cargando modelo: {e}")
            self.stats['errors'] += 1
            return False
    
    def _extract_feature_names(self):
        """Intenta extraer los nombres de features del modelo"""
        if self.model is None:
            return
        
        # sklearn models
        if hasattr(self.model, 'feature_names_in_'):
            self.feature_names = list(self.model.feature_names_in_)
            logger.info(f"Features extraídas del modelo: {len(self.feature_names)}")
        elif hasattr(self.model, 'feature_names'):
            self.feature_names = list(self.model.feature_names)
            logger.info(f"Features extraídas del modelo: {len(self.feature_names)}")
    
    def prepare_input(self, window_data: Dict) -> np.ndarray:
        """
        Prepara los datos de entrada para el modelo.
        
        Args:
            window_data: Diccionario con features de la ventana
            
        Returns:
            Array numpy con shape (1, n_features)
        """
        features = []
        missing_features = []
        non_zero_features = []
        
        for feature_name in self.feature_names:
            value = window_data.get(feature_name, 0.0)
            
            # Rastrear features faltantes
            if feature_name not in window_data:
                missing_features.append(feature_name)
            
            # Manejar valores None o NaN
            if value is None or (isinstance(value, float) and np.isnan(value)):
                value = 0.0
            
            # Convertir a float
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = 0.0
            
            # Rastrear features con valor
            if value != 0.0:
                non_zero_features.append((feature_name, value))
            
            features.append(value)
        
        # LOGS DE DEBUG
        logger.info(f"=== DEBUG prepare_input ===")
        logger.info(f"Total features esperadas: {len(self.feature_names)}")
        logger.info(f"Features en window_data: {len(window_data)}")
        logger.info(f"Features FALTANTES: {len(missing_features)}")
        if missing_features:
            logger.info(f"Primeras 10 faltantes: {missing_features[:10]}")
        logger.info(f"Features con valor != 0: {len(non_zero_features)}")
        if non_zero_features:
            logger.info(f"Primeras 10 con valor: {non_zero_features[:10]}")
        
        return np.array(features).reshape(1, -1)
    
    def _normalize_anomaly_score(self, raw_score: float) -> float:
        """
        Normaliza el anomaly score del rango [0.35, 0.8] a [0, 1].
        
        Args:
            raw_score: Score crudo del modelo (típicamente entre 0.35 y 0.8)
            
        Returns:
            Score normalizado entre 0 y 1
        """
        min_score = 0.35
        max_score = 0.8
        
        # Normalizar: (valor - min) / (max - min)
        normalized = (raw_score - min_score) / (max_score - min_score)
        
        # Clampear entre 0 y 1
        return max(0.0, min(1.0, normalized))
    
    def predict(self, window_data: Dict) -> Dict:
        """
        Realiza predicción sobre una ventana usando SOLO el modelo ML.
        
        Args:
            window_data: Diccionario con features de la ventana
            
        Returns:
            Diccionario con:
            - is_attack: int (1 si ataque, 0 si no)
            - anomaly_score_raw: float (score crudo del modelo)
            - anomaly_score_normalized: float (0-1, normalizado desde rango 0.35-0.8)
            - method: str (model)
        """
        logger.info("=" * 60)
        logger.info("=== INICIO PREDICCIÓN ===")
        logger.info(f"Modelo cargado: {self.is_loaded}")
        logger.info(f"Tipo de modelo: {self.model_type}")
        logger.info(f"Path del modelo: {self.model_path}")
        if self.model:
            logger.info(f"Clase del modelo: {type(self.model).__name__}")
        
        try:
            if self.model is not None and self.is_loaded:
                model_result = self._predict_with_model(window_data)
                
                anomaly_score_raw = model_result['anomaly_score_raw']
                anomaly_score_normalized = self._normalize_anomaly_score(anomaly_score_raw)
                
                # Detectar ataque si el score RAW es mayor a 0.65
                is_attack = 1 if anomaly_score_raw > 0.65 else 0
                
                # Loguear siempre (ataque o no)
                logger.info(
                    f"Predicción ML - anomaly_score_raw: {anomaly_score_raw:.4f}, "
                    f"anomaly_score_normalized: {anomaly_score_normalized:.4f}, "
                    f"is_attack: {is_attack}"
                )
                
                self.stats['predictions_made'] += 1
                if is_attack:
                    self.stats['attacks_detected'] += 1
                
                return {
                    'is_attack': is_attack,
                    'attack_detected': bool(is_attack),
                    'anomaly_score_raw': anomaly_score_raw,
                    'anomaly_score_normalized': anomaly_score_normalized,
                    'method': 'model',
                    'model_type': self.model_type
                }
            else:
                logger.warning("Modelo no cargado, no se puede realizar predicción")
                return {
                    'is_attack': 0,
                    'attack_detected': False,
                    'anomaly_score_raw': 0.0,
                    'anomaly_score_normalized': 0.0,
                    'method': 'no_model',
                    'error': 'Modelo no cargado'
                }
                
        except Exception as e:
            logger.error(f"Error en predicción: {e}")
            self.stats['errors'] += 1
            return {
                'is_attack': 0,
                'attack_detected': False,
                'anomaly_score_raw': 0.0,
                'anomaly_score_normalized': 0.0,
                'method': 'error',
                'error': str(e)
            }
    
    def _predict_with_model(self, window_data: Dict) -> Dict:
        """
        Predicción usando el modelo ML.
        
        Soporta:
        - Isolation Forest: predict() devuelve -1 (anomalía) o 1 (normal)
        - Otros clasificadores: predict_proba()
        
        Returns:
            Diccionario con anomaly_score_raw (valor crudo del modelo)
        """
        X = self.prepare_input(window_data)
        
        # Verificar tipo de modelo
        model_class = type(self.model).__name__
        logger.info(f"Modelo detectado: {model_class}, shape input: {X.shape}")
        
        # Si es un Pipeline, necesitamos manejarlo diferente
        if model_class == 'Pipeline':
            # El Pipeline tiene scaler + IsolationForest
            # Usamos score_samples del pipeline directamente
            if hasattr(self.model, 'score_samples'):
                anomaly_score_raw = float(-self.model.score_samples(X)[0])
                logger.info(f"Pipeline score_samples (negado): {anomaly_score_raw}")
            elif hasattr(self.model, 'decision_function'):
                anomaly_score_raw = float(-self.model.decision_function(X)[0])
                logger.info(f"Pipeline decision_function (negado): {anomaly_score_raw}")
            else:
                # Intentar acceder al último paso del pipeline (IsolationForest)
                try:
                    # Primero transformamos los datos con los pasos previos
                    X_transformed = X
                    for name, step in self.model.steps[:-1]:
                        X_transformed = step.transform(X_transformed)
                        logger.info(f"Pipeline paso '{name}' aplicado, shape: {X_transformed.shape}")
                    
                    # Ahora usamos el último paso (IsolationForest)
                    final_step = self.model.steps[-1][1]
                    logger.info(f"Pipeline último paso: {type(final_step).__name__}")
                    
                    if hasattr(final_step, 'score_samples'):
                        anomaly_score_raw = float(-final_step.score_samples(X_transformed)[0])
                        logger.info(f"IsolationForest score_samples (negado): {anomaly_score_raw}")
                    elif hasattr(final_step, 'decision_function'):
                        anomaly_score_raw = float(-final_step.decision_function(X_transformed)[0])
                        logger.info(f"IsolationForest decision_function (negado): {anomaly_score_raw}")
                    else:
                        prediction = final_step.predict(X_transformed)[0]
                        anomaly_score_raw = 1.0 if prediction == -1 else 0.0
                        logger.info(f"IsolationForest predict: {prediction}")
                except Exception as e:
                    logger.error(f"Error accediendo al Pipeline: {e}")
                    anomaly_score_raw = 0.5
        
        elif model_class == 'IsolationForest':
            # Isolation Forest: usar score_samples (como en el entrenamiento)
            # -score_samples da valores entre 0.35 y 0.8 donde más alto = más anómalo
            if hasattr(self.model, 'score_samples'):
                # Usar -score_samples como en el entrenamiento
                anomaly_score_raw = float(-self.model.score_samples(X)[0])
                logger.info(f"score_samples (negado): {anomaly_score_raw}")
            elif hasattr(self.model, 'decision_function'):
                # Fallback a decision_function si no hay score_samples
                # decision_function = -score_samples, así que negamos
                anomaly_score_raw = float(-self.model.decision_function(X)[0])
                logger.info(f"decision_function (negado): {anomaly_score_raw}")
            else:
                prediction = self.model.predict(X)[0]
                anomaly_score_raw = 1.0 if prediction == -1 else 0.0
                logger.info(f"predict: {prediction} -> anomaly_score_raw: {anomaly_score_raw}")
        
        elif hasattr(self.model, 'predict_proba'):
            # Clasificadores con probabilidades
            proba = self.model.predict_proba(X)[0]
            # Asumimos que clase 1 = ataque
            anomaly_score_raw = float(proba[1]) if len(proba) > 1 else float(proba[0])
        
        else:
            # Modelo genérico con predict
            pred = self.model.predict(X)[0]
            anomaly_score_raw = float(pred) if isinstance(pred, (int, float)) else 0.5
        
        return {
            'anomaly_score_raw': anomaly_score_raw,
            'model_type': self.model_type,
            'model_class': model_class
        }
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del handler"""
        return {
            **self.stats,
            'model_loaded': self.is_loaded,
            'model_type': self.model_type,
            'model_path': self.model_path,
            'n_features': len(self.feature_names),
            'attack_threshold': self.attack_threshold
        }
    
    def set_threshold(self, threshold: float):
        """Ajusta el threshold de detección"""
        self.attack_threshold = max(0.0, min(1.0, threshold))
        logger.info(f"Threshold ajustado a {self.attack_threshold}")
    
    def get_feature_names(self) -> List[str]:
        """Retorna lista de features que espera el modelo"""
        return self.feature_names.copy()


# =============================================================================
# Funciones de utilidad
# =============================================================================

def validate_window_data(window_data: Dict, required_features: Optional[List[str]] = None) -> Tuple[bool, List[str]]:
    """
    Valida que los datos de ventana tengan las features necesarias.
    
    Args:
        window_data: Diccionario con features
        required_features: Lista de features requeridas (default: MODEL_FEATURES)
        
    Returns:
        Tupla (es_valido, lista_de_features_faltantes)
    """
    if required_features is None:
        required_features = MODEL_FEATURES
    
    missing = [f for f in required_features if f not in window_data]
    
    return len(missing) == 0, missing


def create_dummy_model():
    """
    Crea un modelo dummy para testing.
    Retorna un RandomForestClassifier pre-entrenado con datos sintéticos.
    """
    from sklearn.ensemble import RandomForestClassifier
    
    # Crear datos sintéticos
    n_samples = 1000
    n_features = len(MODEL_FEATURES)
    
    np.random.seed(42)
    X = np.random.randn(n_samples, n_features)
    
    # Simular labels basados en algunas features
    # burst_score_mean es feature índice 11, burst_score_max índice 53
    y = ((X[:, 11] > 0.5) | (X[:, 53] > 0.7)).astype(int)
    
    # Entrenar modelo
    model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    model.fit(X, y)
    
    # Guardar feature names
    model.feature_names_in_ = np.array(MODEL_FEATURES)
    
    return model
