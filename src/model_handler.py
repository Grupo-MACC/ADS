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

# Features más importantes para heurísticas (cuando no hay modelo)
HEURISTIC_FEATURES = [
    'burst_score_max', 'burst_score_mean',
    'conn_count_10s_mean', 'conn_count_60s_mean', 'conn_count_300s_mean',
    'recon_pattern_score_mean', 'recent_activity_score_mean',
    'ja3_frequency_mean',
    'n_connections'
]


class ModelHandler:
    """
    Manejador del modelo de ML para detección de Consul Poisoning.
    
    Soporta:
    - Modelos sklearn (RandomForest, XGBoost, etc.) via joblib
    - Modelos custom con interfaz predict()
    - Modo fallback con heurísticas cuando no hay modelo
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
        
        for feature_name in self.feature_names:
            value = window_data.get(feature_name, 0.0)
            
            # Manejar valores None o NaN
            if value is None or (isinstance(value, float) and np.isnan(value)):
                value = 0.0
            
            # Convertir a float
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = 0.0
            
            features.append(value)
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, window_data: Dict) -> Dict:
        """
        Realiza predicción sobre una ventana.
        
        IMPORTANTE: Combina modelo ML con heurísticas del patrón Consul Poisoning.
        El patrón de ataque tiene 3 fases en ~2 segundos:
        - RECON: 4 GETs rápidos (cada 0.3s)
        - INJECT: 1 PUT (registro malicioso)
        - VERIFY: 1 GET (verificación)
        
        Args:
            window_data: Diccionario con features de la ventana
            
        Returns:
            Diccionario con:
            - attack_detected: bool
            - attack_probability: float (0-1)
            - attack_score: float (0-1)
            - confidence: float (0-1)
            - method: str (model|heuristic|combined)
        """
        try:
            # SIEMPRE calcular heurísticas (patrón específico Consul Poisoning)
            heuristic_result = self._detect_consul_poisoning_pattern(window_data)
            
            # IMPORTANTE: Si la heurística detecta tráfico normal espaciado,
            # NO consultar el modelo ML (evita falsos positivos)
            if heuristic_result.get('indicators') == ['spaced_normal_traffic']:
                logger.info("Heurística override: tráfico normal espaciado, ignorando modelo ML")
                return heuristic_result
            
            if self.model is not None and self.is_loaded:
                model_result = self._predict_with_model(window_data)
                
                # Combinar: Si la heurística detecta ataque, usar su score
                # Si no, usar el máximo entre modelo y heurística
                if len(heuristic_result.get('indicators', [])) >= 2:
                    # Heurística tiene indicadores fuertes, darle prioridad
                    combined_score = max(
                        model_result['attack_probability'],
                        heuristic_result['attack_probability']
                    )
                else:
                    # Sin indicadores fuertes de heurística, confiar más en modelo
                    # pero ajustar a la baja si heurística dice normal
                    if heuristic_result['attack_probability'] < 0.3:
                        combined_score = min(model_result['attack_probability'] * 0.5, 0.4)
                    else:
                        combined_score = max(
                            model_result['attack_probability'],
                            heuristic_result['attack_probability']
                        )
                
                return {
                    'attack_detected': combined_score >= self.attack_threshold,
                    'attack_probability': combined_score,
                    'attack_score': combined_score,
                    'confidence': max(model_result['confidence'], heuristic_result['confidence']),
                    'method': 'combined',
                    'model_score': model_result['attack_probability'],
                    'heuristic_score': heuristic_result['attack_probability'],
                    'pattern_indicators': heuristic_result.get('indicators', [])
                }
            else:
                return heuristic_result
                
        except Exception as e:
            logger.error(f"Error en predicción: {e}")
            self.stats['errors'] += 1
            return {
                'attack_detected': False,
                'attack_probability': 0.0,
                'attack_score': 0.0,
                'confidence': 0.0,
                'method': 'error',
                'error': str(e)
            }
    
    def _predict_with_model(self, window_data: Dict) -> Dict:
        """
        Predicción usando el modelo ML.
        
        Soporta:
        - Isolation Forest: predict() devuelve -1 (anomalía) o 1 (normal)
        - Otros clasificadores: predict_proba()
        """
        X = self.prepare_input(window_data)
        
        # Verificar tipo de modelo
        model_class = type(self.model).__name__
        
        if model_class == 'IsolationForest':
            # Isolation Forest: -1 = anomalía (ataque), 1 = normal
            prediction = self.model.predict(X)[0]
            attack_detected = bool(prediction == -1)  # Convertir a bool nativo
            
            # Usar decision_function para score (más negativo = más anómalo)
            if hasattr(self.model, 'decision_function'):
                score = float(self.model.decision_function(X)[0])
                # Convertir a probabilidad (0-1): score negativo = mayor probabilidad de ataque
                # El score típicamente va de -0.5 a 0.5, normalizamos
                attack_proba = 1 / (1 + np.exp(score * 5))  # Sigmoid transformation
            else:
                attack_proba = 1.0 if attack_detected else 0.0
        
        elif hasattr(self.model, 'predict_proba'):
            # Clasificadores con probabilidades
            proba = self.model.predict_proba(X)[0]
            # Asumimos que clase 1 = ataque
            attack_proba = float(proba[1]) if len(proba) > 1 else float(proba[0])
            attack_detected = bool(attack_proba >= self.attack_threshold)
        
        else:
            # Modelo genérico con predict
            pred = self.model.predict(X)[0]
            attack_proba = float(pred) if isinstance(pred, (int, float)) else 0.5
            attack_detected = bool(attack_proba >= self.attack_threshold)
        
        self.stats['predictions_made'] += 1
        if attack_detected:
            self.stats['attacks_detected'] += 1
        
        return {
            'attack_detected': bool(attack_detected),  # Asegurar bool nativo
            'attack_probability': float(attack_proba),
            'attack_score': float(attack_proba),
            'confidence': float(abs(attack_proba - 0.5) * 2),  # 0-1 escala de confianza
            'method': 'model',
            'model_type': self.model_type,
            'model_class': model_class
        }
    
    def _detect_consul_poisoning_pattern(self, window_data: Dict) -> Dict:
        """
        Detecta el patrón específico de Consul Poisoning.
        
        El ataque tiene 6 conexiones en ~2 segundos:
        - 4 GETs de reconocimiento (cada 0.3s)
        - 1 PUT de inyección
        - 1 GET de verificación
        
        Características clave del dataset de entrenamiento:
        - conn_count_10s: ~4 para ataques (media), ~1.25 para normal
        - recon_pattern_score: ~0.81 para ataques, ~0.28 para normal
        - burst_score: ~1.0 para ataques (muchas conexiones rápidas)
        
        IMPORTANTE: Para evitar falsos positivos, requerimos:
        - O burst_score alto (conexiones muy rápidas)
        - O muchas conexiones + patrón de reconocimiento
        """
        indicators = []
        
        # Extraer features con fallback a 0
        n_connections = window_data.get('n_connections', 0)
        conn_count_10s_max = window_data.get('conn_count_10s_max', 
                                              window_data.get('conn_count_10s', 0))
        conn_count_10s_mean = window_data.get('conn_count_10s_mean', 0)
        recon_score_max = window_data.get('recon_pattern_score_max',
                                          window_data.get('recon_pattern_score', 0))
        recon_score_mean = window_data.get('recon_pattern_score_mean', 0)
        burst_score_max = window_data.get('burst_score_max', 
                                          window_data.get('burst_score', 0))
        burst_score_mean = window_data.get('burst_score_mean', 0)
        
        # Features adicionales - tiempo entre conexiones
        time_since_last_max = window_data.get('time_since_last_conn_max', float('inf'))
        time_since_last_min = window_data.get('time_since_last_conn_min', 
                                               window_data.get('time_since_last_conn', float('inf')))
        time_since_last_mean = window_data.get('time_since_last_conn_mean', float('inf'))
        
        # Heuristic intensity del burst
        burst_intensity = window_data.get('burst_intensity', 0)
        
        # =========================================
        # DETECTOR DE FALSOS POSITIVOS
        # =========================================
        # Si las conexiones están MUY espaciadas (> 5s entre ellas en promedio),
        # NO es un ataque de Consul Poisoning (que hace 6 conexiones en 2s)
        
        is_spaced_traffic = False
        if time_since_last_mean is not None and time_since_last_mean > 5.0:
            is_spaced_traffic = True
            logger.debug(f"Tráfico espaciado detectado: time_since_last_mean={time_since_last_mean}")
        
        # Si burst_score es muy bajo y las conexiones están espaciadas, NO es ataque
        # PERO: Si hay muchas conexiones (>=4), es sospechoso aunque el burst_score sea bajo
        # (puede pasar si Zeek loguea con delay)
        if burst_score_max < 0.1 and is_spaced_traffic and n_connections < 4:
            logger.info(f"Tráfico normal: burst_score={burst_score_max}, espaciado={is_spaced_traffic}, conns={n_connections}")
            return {
                'attack_detected': False,
                'attack_probability': 0.1,
                'attack_score': 0.1,
                'confidence': 0.8,
                'method': 'heuristic',
                'indicators': ['spaced_normal_traffic'],
                'indicators_triggered': 0
            }
        
        # =========================================
        # Indicadores del patrón Consul Poisoning
        # =========================================
        
        # 1. BURST DE CONEXIONES: 4+ conexiones en 10 segundos es sospechoso
        # El ataque tiene 6 conexiones en ~2 segundos
        if conn_count_10s_max >= 6:
            indicators.append(('high_burst', 0.35))
        elif conn_count_10s_max >= 4:
            indicators.append(('medium_burst', 0.25))
        elif conn_count_10s_max >= 3 and burst_score_max > 0.3:  # Solo si hay burst
            indicators.append(('low_burst', 0.15))
        
        # 2. PATRÓN DE RECONOCIMIENTO alto
        # Dataset: ataque tiene recon_score ~0.81, normal ~0.28
        if recon_score_max >= 0.7:
            indicators.append(('high_recon', 0.30))
        elif recon_score_max >= 0.5:
            indicators.append(('medium_recon', 0.20))
        elif recon_score_max >= 0.3 and burst_score_max > 0.3:  # Solo si hay burst
            indicators.append(('low_recon', 0.10))
        
        # 3. BURST SCORE alto (conexiones muy rápidas) - MUY IMPORTANTE
        if burst_score_max >= 0.8:
            indicators.append(('high_burst_score', 0.25))
        elif burst_score_max >= 0.5:
            indicators.append(('medium_burst_score', 0.15))
        elif burst_score_max >= 0.3:
            indicators.append(('low_burst_score', 0.10))
        
        # 4. CONEXIONES MUY CERCANAS (< 1 segundo entre ellas)
        if time_since_last_min is not None and time_since_last_min < 1.0:
            indicators.append(('rapid_connections', 0.20))
        elif time_since_last_min is not None and time_since_last_min < 2.0:
            indicators.append(('quick_connections', 0.10))
        
        # 5. MUCHAS CONEXIONES en la ventana (ataque genera 6+ en 2s)
        # Cuenta aunque burst_score sea bajo (Zeek puede tener delay)
        if n_connections >= 6:
            indicators.append(('many_connections', 0.25))
        elif n_connections >= 5:
            indicators.append(('suspicious_conn_count', 0.20))
        elif n_connections >= 4:
            indicators.append(('elevated_conn_count', 0.15))
        
        # Calcular score total
        total_score = sum(weight for _, weight in indicators)
        attack_score = min(total_score, 1.0)
        
        # Umbral de confianza:
        # - Si el score es alto (>= 0.7), confianza alta también
        # - Si no, basado en número de indicadores
        if attack_score >= 0.7:
            confidence = 0.8  # Alta confianza para ataques claros
        elif attack_score >= 0.5:
            confidence = 0.6
        else:
            confidence = min(len(indicators) * 0.2, 0.4)
        
        attack_detected = attack_score >= self.attack_threshold
        
        self.stats['predictions_made'] += 1
        if attack_detected:
            self.stats['attacks_detected'] += 1
        
        return {
            'attack_detected': attack_detected,
            'attack_probability': attack_score,
            'attack_score': attack_score,
            'confidence': confidence,
            'method': 'heuristic',
            'indicators': [name for name, _ in indicators],
            'indicators_triggered': len(indicators)
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
        required_features: Lista de features requeridas (default: HEURISTIC_FEATURES)
        
    Returns:
        Tupla (es_valido, lista_de_features_faltantes)
    """
    if required_features is None:
        required_features = HEURISTIC_FEATURES
    
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
