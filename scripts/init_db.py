"""
Script de inicialización de la base de datos RDS (MySQL)
========================================================

Este script crea las tablas necesarias en MySQL (RDS) para
almacenar las predicciones del sistema ADS.

Uso:
    python init_db.py
    
Variables de entorno:
    - RDS_HOST: Host de la base de datos (requerido, obtener de Consul)
    - RDS_PORT: Puerto (default: 3306)
    - DB_NAME: Nombre de la base de datos (default: ads_db)
    - DB_USER: Usuario (default: admin)
    - DB_PASSWORD: Contraseña (default: maccadmin)

Ejemplo:
    export RDS_HOST=tu-rds.amazonaws.com
    python init_db.py
"""

import os
import sys

# Configuración desde variables de entorno
RDS_HOST = os.getenv("RDS_HOST")  # Requerido - obtener de Consul
RDS_PORT = os.getenv("RDS_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "ads_db")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "maccadmin")

# SQL para crear la tabla de predicciones (MySQL)
CREATE_PREDICTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    anomaly_score FLOAT NOT NULL,
    anomaly_score_raw FLOAT NOT NULL,
    attack_detected INT NOT NULL,
    confidence FLOAT,
    method VARCHAR(50),
    n_connections INT,
    window_data JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    creation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    update_date DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_attack (attack_detected),
    INDEX idx_timestamp_attack (timestamp, attack_detected)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def init_database():
    """Inicializa la base de datos con las tablas necesarias"""
    try:
        import pymysql
    except ImportError:
        print("❌ Error: pymysql no instalado")
        print("   pip install pymysql")
        sys.exit(1)
    
    if not RDS_HOST:
        print("❌ Error: RDS_HOST no configurado")
        print("   El host de RDS se obtiene del servicio 'rds' en Consul.")
        print("   ")
        print("   Puedes obtenerlo con:")
        print("   curl http://consul:8500/v1/catalog/service/rds | jq")
        print("   ")
        print("   Luego exporta:")
        print("   export RDS_HOST=tu-rds-host.amazonaws.com")
        print("   python init_db.py")
        sys.exit(1)
    
    print(f"🔌 Conectando a: {RDS_HOST}:{RDS_PORT}/{DB_NAME}")
    print(f"   Usuario: {DB_USER}")
    
    try:
        conn = pymysql.connect(
            host=RDS_HOST,
            port=int(RDS_PORT),
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset='utf8mb4'
        )
        
        with conn.cursor() as cursor:
            # Test conexión
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            print(f"✅ Conectado a MySQL: {version}")
            
            # Crear tabla de predicciones
            print("\n📦 Creando tabla 'predictions'...")
            cursor.execute(CREATE_PREDICTIONS_TABLE)
            conn.commit()
            print("   ✅ Tabla creada/verificada")
            
            # Verificar estructura
            print("\n🔍 Verificando estructura...")
            cursor.execute("""
                SELECT COLUMN_NAME, DATA_TYPE 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'predictions'
                ORDER BY ORDINAL_POSITION
            """, (DB_NAME,))
            columns = cursor.fetchall()
            print("   Columnas de 'predictions':")
            for col_name, col_type in columns:
                print(f"      - {col_name}: {col_type}")
        
        conn.close()
        
        print("\n" + "="*50)
        print("✅ Base de datos inicializada correctamente")
        print("="*50)
        print("\nPuedes conectar Grafana con:")
        print(f"   Host: {RDS_HOST}")
        print(f"   Port: {RDS_PORT}")
        print(f"   Database: {DB_NAME}")
        print(f"   User: {DB_USER}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def drop_tables():
    """Elimina las tablas (usar con cuidado)"""
    try:
        import pymysql
    except ImportError:
        print("❌ Error: pymysql no instalado")
        sys.exit(1)
    
    if not RDS_HOST:
        print("❌ Error: RDS_HOST no configurado")
        sys.exit(1)
    
    confirm = input("⚠️  ¿Estás seguro de eliminar todas las tablas? (escribe 'SI'): ")
    if confirm != 'SI':
        print("Operación cancelada")
        return
    
    try:
        conn = pymysql.connect(
            host=RDS_HOST,
            port=int(RDS_PORT),
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        with conn.cursor() as cursor:
            cursor.execute("DROP TABLE IF EXISTS predictions")
            conn.commit()
        conn.close()
        print("✅ Tablas eliminadas")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--drop":
        drop_tables()
    else:
        init_database()
