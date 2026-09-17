CREATE DATABASE IF NOT EXISTS scanner_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE scanner_db;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(80) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    creado_en DATETIME NULL DEFAULT NULL,
    tema VARCHAR(20) NULL DEFAULT 'oscuro',
    telefono VARCHAR(20) NULL DEFAULT NULL,
    tfa_habilitado TINYINT(1) NOT NULL DEFAULT 0,
    tfa_codigo_hash VARCHAR(255) NULL DEFAULT NULL,
    tfa_expira_en DATETIME NULL DEFAULT NULL,
    tfa_intentos INT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE INDEX ix_usuarios_username (username ASC) VISIBLE
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

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
    INDEX ix_escaneos_fecha (fecha ASC) VISIBLE,
    INDEX ix_escaneos_usuario_id (usuario_id ASC) VISIBLE,
    CONSTRAINT escaneos_ibfk_1 FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS resultados_escaneo (
    id INT NOT NULL AUTO_INCREMENT,
    escaneo_id INT NOT NULL,
    item VARCHAR(255) NOT NULL,
    estado VARCHAR(30) NOT NULL,
    explicacion TEXT NULL DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX ix_resultados_escaneo_escaneo_id (escaneo_id ASC) VISIBLE,
    CONSTRAINT resultados_escaneo_ibfk_1 FOREIGN KEY (escaneo_id) REFERENCES escaneos (id)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

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
    INDEX fk_vul_escaneo (escaneo_id ASC) VISIBLE,
    CONSTRAINT fk_vul_escaneo FOREIGN KEY (escaneo_id) REFERENCES escaneos (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
