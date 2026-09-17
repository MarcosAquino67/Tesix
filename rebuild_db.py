import os
from dotenv import load_dotenv
load_dotenv()
import pymysql
from werkzeug.security import generate_password_hash

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASS = os.environ.get('DB_PASS', '')
DB_NAME = os.environ.get('DB_NAME', 'scanner_db')

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
cursor = conn.cursor()

sql = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(80) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    creado_en DATETIME NULL DEFAULT NULL,
    tema VARCHAR(20) NULL DEFAULT 'oscuro',
    PRIMARY KEY (id),
    UNIQUE INDEX ix_usuarios_username (username ASC)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci
"""
cursor.execute(sql)

sql = """
CREATE TABLE IF NOT EXISTS escaneos (
    id INT NOT NULL AUTO_INCREMENT,
    usuario_id INT NOT NULL,
    tipo VARCHAR(30) NOT NULL,
    target VARCHAR(255) NOT NULL,
    titulo VARCHAR(150) NULL DEFAULT NULL,
    subtitulo VARCHAR(255) NULL DEFAULT NULL,
    total_dispositivos INT NULL DEFAULT NULL,
    fecha DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX ix_escaneos_fecha (fecha ASC),
    INDEX ix_escaneos_usuario_id (usuario_id ASC),
    CONSTRAINT escaneos_ibfk_1 FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci
"""
cursor.execute(sql)

sql = """
CREATE TABLE IF NOT EXISTS resultados_escaneo (
    id INT NOT NULL AUTO_INCREMENT,
    escaneo_id INT NOT NULL,
    item VARCHAR(255) NOT NULL,
    estado VARCHAR(30) NOT NULL,
    explicacion TEXT NULL DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX ix_resultados_escaneo_escaneo_id (escaneo_id ASC),
    CONSTRAINT resultados_escaneo_ibfk_1 FOREIGN KEY (escaneo_id) REFERENCES escaneos (id)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci
"""
cursor.execute(sql)

sql = """
CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id INT NOT NULL AUTO_INCREMENT,
    escaneo_id INT NOT NULL,
    id_malware VARCHAR(100) NULL DEFAULT NULL,
    cve VARCHAR(100) NULL DEFAULT NULL,
    nombre VARCHAR(250) NULL DEFAULT NULL,
    descripcion TEXT NULL DEFAULT NULL,
    tipo VARCHAR(50) NULL DEFAULT NULL,
    severity VARCHAR(20) NULL DEFAULT NULL,
    risk TEXT NULL DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX fk_vul_escaneo (escaneo_id ASC),
    CONSTRAINT fk_vul_escaneo FOREIGN KEY (escaneo_id) REFERENCES escaneos (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci
"""
cursor.execute(sql)

hashed = generate_password_hash('admin123')
cursor.execute("INSERT INTO usuarios (username, password_hash, tema) VALUES (%s, %s, %s)", ('admin', hashed, 'oscuro'))
conn.commit()

print('Tablas recreadas y usuario admin creado')
cursor.execute('SHOW TABLES')
for t in cursor.fetchall():
    print(f'  - {t[0]}')

conn.close()
