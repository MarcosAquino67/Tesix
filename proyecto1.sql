-- MySQL dump 10.13  Distrib 8.0.46, for Win64 (x86_64)
--
-- Host: localhost    Database: scanner_db
-- ------------------------------------------------------
-- Server version	8.0.46

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `escaneos`
--

DROP TABLE IF EXISTS `escaneos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `escaneos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` int NOT NULL,
  `tipo` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL,
  `target` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `titulo` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `subtitulo` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `total_dispositivos` int DEFAULT NULL,
  `fecha` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_escaneos_fecha` (`fecha`),
  KEY `ix_escaneos_usuario_id` (`usuario_id`),
  CONSTRAINT `escaneos_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `escaneos`
--

LOCK TABLES `escaneos` WRITE;
/*!40000 ALTER TABLE `escaneos` DISABLE KEYS */;
INSERT INTO `escaneos` VALUES (1,2,'puertos','192.168.0.7','Analisis de Puertos de Red','Host: DESKTOP-THK8QHF (192.168.0.7)',NULL,'2026-08-17 00:23:57'),(2,2,'dispositivos','192.168.0.0/24','Dispositivos en Red Local','Rango analizado: 192.168.0.1 - 192.168.0.254 (11 dispositivos activos)',11,'2026-08-17 00:26:12'),(3,2,'url','https://www.youtube.com/','Analisis Web y SSL','Objetivo: https://www.youtube.com/',NULL,'2026-08-17 00:27:39'),(4,2,'url','https://hubcapmanifest.com/api-keys/stats','Analisis Web y SSL','Objetivo: https://hubcapmanifest.com/api-keys/stats',NULL,'2026-08-17 00:27:48'),(5,2,'url','https://github.com/MarcosAbue15/Tesix','Analisis Web y SSL','Objetivo: https://github.com/MarcosAbue15/Tesix',NULL,'2026-08-17 00:28:02'),(6,2,'url','https://www.youtube.com/','Analisis Web y SSL','Objetivo: https://www.youtube.com/',NULL,'2026-08-17 00:28:26'),(7,2,'url','https://hardwaretester.com/gamepad','Analisis Web y SSL','Objetivo: https://hardwaretester.com/gamepad',NULL,'2026-08-17 00:28:40');
/*!40000 ALTER TABLE `escaneos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_escaneo`
--

DROP TABLE IF EXISTS `resultados_escaneo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `resultados_escaneo` (
  `id` int NOT NULL AUTO_INCREMENT,
  `escaneo_id` int NOT NULL,
  `item` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `estado` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL,
  `explicacion` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `ix_resultados_escaneo_escaneo_id` (`escaneo_id`),
  CONSTRAINT `resultados_escaneo_ibfk_1` FOREIGN KEY (`escaneo_id`) REFERENCES `escaneos` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_escaneo`
--

LOCK TABLES `resultados_escaneo` WRITE;
/*!40000 ALTER TABLE `resultados_escaneo` DISABLE KEYS */;
INSERT INTO `resultados_escaneo` VALUES (1,1,'Puerto 21','CERRADO','Seguro (sin escucha)'),(2,1,'Puerto 22','CERRADO','Seguro (sin escucha)'),(3,1,'Puerto 23','CERRADO','Seguro (sin escucha)'),(4,1,'Puerto 25','CERRADO','Seguro (sin escucha)'),(5,1,'Puerto 53','CERRADO','Seguro (sin escucha)'),(6,1,'Puerto 80','CERRADO','Seguro (sin escucha)'),(7,1,'Puerto 110','CERRADO','Seguro (sin escucha)'),(8,1,'Puerto 143','CERRADO','Seguro (sin escucha)'),(9,1,'Puerto 443','CERRADO','Seguro (sin escucha)'),(10,1,'Puerto 3306','ABIERTO','Servicio activo'),(11,1,'Puerto 3389','CERRADO','Seguro (sin escucha)'),(12,1,'Puerto 5000','ABIERTO','Sistema Flask corriendo'),(13,1,'Puerto 8080','CERRADO','Seguro (sin escucha)'),(14,2,'IP 192.168.0.1 - Router / Modem Wi-Fi','ACTIVO','MAC: 94:8F:CF:C2:9C:F8 | Marca: Commscope | Puertos: 80, 443, 5000'),(15,2,'IP 192.168.0.3 - Dispositivo IoT / Smart','ACTIVO','MAC: 1C:79:2D:88:83:92 | Marca: CHINA DRAGON TECHNOLOGY LIMITED | Puertos: Ninguno detectado'),(16,2,'IP 192.168.0.5 - Smartphone (iPhone/Android)','ACTIVO','MAC: FA:9E:6C:36:23:ED | Marca: MAC aleatoria (privacidad) - posible iPhone/Android reciente | Puertos: Ninguno detectado'),(17,2,'IP 192.168.0.6 - Smartphone (iPhone/Android)','ACTIVO','MAC: D2:E0:96:C2:FB:D7 | Marca: MAC aleatoria (privacidad) - posible iPhone/Android reciente | Puertos: Ninguno detectado'),(18,2,'IP 192.168.0.7 - Este Equipo (DESKTOP-THK8QHF)','ACTIVO','MAC: Desconocida | Marca: Dispositivo Conectado | Puertos: 5000'),(19,2,'IP 192.168.0.8 - Smartphone (iPhone/Android)','ACTIVO','MAC: D6:C6:1E:C7:78:13 | Marca: MAC aleatoria (privacidad) - posible iPhone/Android reciente | Puertos: Ninguno detectado'),(20,2,'IP 192.168.0.9 - Dispositivo IoT / Smart','ACTIVO','MAC: 30:BD:5A:F6:AE:57 | Marca: Dispositivo Conectado | Puertos: Ninguno detectado'),(21,2,'IP 192.168.0.10 - Servidor / Raspberry Pi','ACTIVO','MAC: 8C:79:F5:81:98:E8 | Marca: Samsung Electronics Co.,Ltd | Puertos: 8080'),(22,2,'IP 192.168.0.21 - Smartphone (iPhone/Android)','ACTIVO','MAC: BA:77:4B:74:05:85 | Marca: MAC aleatoria (privacidad) - posible iPhone/Android reciente | Puertos: Ninguno detectado'),(23,2,'IP 192.168.0.22 - Smartphone (iPhone/Android)','ACTIVO','MAC: 2A:F0:C3:E5:88:CE | Marca: MAC aleatoria (privacidad) - posible iPhone/Android reciente | Puertos: Ninguno detectado'),(24,2,'IP 192.168.0.252 - Dispositivo IoT / Smart','ACTIVO','MAC: 00:00:CA:01:02:03 | Marca: Commscope | Puertos: Ninguno detectado'),(25,3,'Estado HTTP','OK','Codigo de respuesta 200'),(26,3,'HTTPS / SSL','SEGURO','Trafico cifrado activado'),(27,3,'Cabecera Strict-Transport-Security','OK','Cabecera de proteccion detectada'),(28,3,'Cabecera X-Frame-Options','OK','Cabecera de proteccion detectada'),(29,3,'Cabecera X-Content-Type-Options','OK','Cabecera de proteccion detectada'),(30,4,'Conexion Web','FALLO','No se pudo acceder a la URL (<urlopen error _ssl.c:1015: The handshake operation timed out>)'),(31,5,'Conexion Web','FALLO','No se pudo acceder a la URL (HTTP Error 404: Not Found)'),(32,6,'Estado HTTP','OK','Codigo de respuesta 200'),(33,6,'HTTPS / SSL','SEGURO','Trafico cifrado activado'),(34,6,'Cabecera Strict-Transport-Security','OK','Cabecera de proteccion detectada'),(35,6,'Cabecera X-Frame-Options','OK','Cabecera de proteccion detectada'),(36,6,'Cabecera X-Content-Type-Options','OK','Cabecera de proteccion detectada'),(37,7,'Estado HTTP','OK','Codigo de respuesta 200'),(38,7,'HTTPS / SSL','SEGURO','Trafico cifrado activado'),(39,7,'Cabecera Strict-Transport-Security','OK','Cabecera de proteccion detectada'),(40,7,'Cabecera X-Frame-Options','AUSENTE','Se recomienda agregar esta cabecera'),(41,7,'Cabecera X-Content-Type-Options','AUSENTE','Se recomienda agregar esta cabecera');
/*!40000 ALTER TABLE `resultados_escaneo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuarios`
--

DROP TABLE IF EXISTS `usuarios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `creado_en` datetime DEFAULT NULL,
  `tema` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'oscuro',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_usuarios_username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuarios`
--

LOCK TABLES `usuarios` WRITE;
/*!40000 ALTER TABLE `usuarios` DISABLE KEYS */;
INSERT INTO `usuarios` VALUES (1,'admin','scrypt:32768:8:1$P1I1GFuINumxOkGd$2cdb3650da5b8512c1a7379c67811ea725ee5d2c0d631eb42944e3049399740eac8b062218a4002e992e10f3ca5b0b1f3f246069564a3f9c14996cd635ee737e',NULL,'oscuro'),(2,'aurelio@gmail.com','scrypt:32768:8:1$cYFkvyCOoZHL1tsW$d8617ae2e4cce809989453a7af2a17207c8d6e4b76df865f16f24099845c1f586bcee39bc8880460cf0e96612b8a1db74b63ea55c779f52f991a989d8c2d49c7',NULL,'azul');
/*!40000 ALTER TABLE `usuarios` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vulnerabilidades`
--

DROP TABLE IF EXISTS `vulnerabilidades`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerabilidades` (
  `id` int NOT NULL AUTO_INCREMENT,
  `escaneo_id` int NOT NULL,
  `id_malware` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cve` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nombre` varchar(250) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `descripcion` text COLLATE utf8mb4_unicode_ci,
  `tipo` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `severity` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `risk` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `fk_vul_escaneo` (`escaneo_id`),
  CONSTRAINT `fk_vul_escaneo` FOREIGN KEY (`escaneo_id`) REFERENCES `escaneos` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vulnerabilidades`
--

LOCK TABLES `vulnerabilidades` WRITE;
/*!40000 ALTER TABLE `vulnerabilidades` DISABLE KEYS */;
INSERT INTO `vulnerabilidades` VALUES (1,1,NULL,'CVE-General','MySQL expuesto (Puerto 3306)','La base de datos MySQL esta accesible desde la red. Esto permite ataques de fuerza bruta, inyeccion SQL remota o robo de datos.','Base de Datos','High','Binding a 127.0.0.1 si solo se accede localmente. Usa firewall para restringir accesos. Implementa contrasenas fuertes y usuarios con最小权限.'),(2,1,NULL,'CVE-General','Servidor de desarrollo Flask (Puerto 5000)','El servidor de desarrollo Flask/Werkzeug esta expuesto. No esta disenado para produccion y puede filtrar informacion sensible.','Web','Medium','Nunca uses el servidor de desarrollo en produccion. Usa un servidor WSGI como Gunicorn o uWSGI detras de un reverse proxy (Nginx/Apache).'),(3,4,NULL,'CVE-General','Sitio sin HTTPS','El sitio no utiliza cifrado HTTPS. Todos los datos se transmiten en texto plano, incluyendo credenciales y datos sensibles.','Web','High','Obten un certificado SSL/TLS (Let\'s Encrypt es gratuito) y configura HTTPS. Implementa redireccion automatica desde HTTP.'),(4,5,NULL,'CVE-General','Sitio sin HTTPS','El sitio no utiliza cifrado HTTPS. Todos los datos se transmiten en texto plano, incluyendo credenciales y datos sensibles.','Web','High','Obten un certificado SSL/TLS (Let\'s Encrypt es gratuito) y configura HTTPS. Implementa redireccion automatica desde HTTP.'),(5,7,NULL,'CVE-General','Cabecera X-Frame-Options ausente','Sin esta cabecera, el sitio puede ser embebido en iframes maliciosos, permitiendo ataques de clickjacking.','Web','Medium','Agrega X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking.'),(6,7,NULL,'CVE-General','Cabecera X-Content-Type-Options ausente','Sin esta cabecera, el navegador podria interpretar archivos MIME de forma incorrecta, facilitando ataques de sniffing.','Web','Low','Agrega X-Content-Type-Options: nosniff para forzar la deteccion de tipo MIME.');
/*!40000 ALTER TABLE `vulnerabilidades` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping events for database 'scanner_db'
--

--
-- Dumping routines for database 'scanner_db'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-08-16 21:36:41
