# ScanSecure - Escáner de Vulnerabilidades de Red

Aplicación web Flask para escanear puertos, analizar URLs y descubrir dispositivos en red local con detección de vulnerabilidades.

## 🚀 Inicio rápido con Docker (recomendado)

**Requisitos:** Docker Desktop / Docker Engine + Compose

```bash
# 1. Clonar repositorio
git clone <url-del-repo>
cd Proyecto/Proyecto

# 2. Configurar variables de entorno
cp .env.example .env
# Edita .env si quieres cambiar contraseñas (opcional, valores por defecto son seguros para desarrollo)

# 3. Levantar todo
docker-compose up -d --build

# 4. Verificar estado
docker-compose ps
# db   -> healthy
# app  -> running

# 5. Acceder a la app
# http://localhost:5000
```

### Credenciales por defecto (solo desarrollo)
- **MySQL:** `scanner_user` / `admin123` en `localhost:3306`, db `scanner_db`
- **App:** Regístrate en `/` (primer usuario se crea al registrarse)

---

## 📦 Qué incluye Docker

| Servicio | Puerto | Descripción |
|----------|--------|-------------|
| `db` (MySQL 8.0) | 3306 | Base de datos persistente en volume `mysql_data` |
| `app` (Flask + Gunicorn) | 5000 | Aplicación web, auto-migra tablas al inicio |

**Init automático:** `init.sql` crea tablas al iniciar MySQL por primera vez (montado en `/docker-entrypoint-initdb.d/`).

---

## 🛠 Desarrollo local sin Docker

```bash
cd Proyecto/Proyecto

# Entorno virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Dependencias
pip install -r requirements.txt

# Variables (usa SQLite local si no configuras MySQL)
cp .env.example .env
# Edita .env o déjalo vacío para SQLite

# Ejecutar
python app.py
# http://localhost:5000
```

> **Nota:** Sin `DB_USER`/`DB_PASS` en `.env`, `config.py` usa SQLite (`scanner_dev.db`) automáticamente.

---

## 📁 Estructura del proyecto

```
Proyecto/
├── docker-compose.yml      # Orquestación Docker (db + app)
├── Dockerfile              # Imagen Python 3.13 slim
├── init.sql                # Schema MySQL (auto-ejecutado)
├── requirements.txt        # Dependencias Python
├── .env.example            # Template variables entorno
├── app.py                  # App Flask principal
├── config.py               # Configuración (lee .env)
├── models.py               # Modelos SQLAlchemy
├── agente_local.py         # Agente escaneo red local (opcional)
├── scanner.py              # Lógica escaneo puertos/URL
├── rebuild_db.py           # Utilidad reset DB
├── templates/              # Jinja2 templates
├── static/                 # CSS/JS
└── tests/                  # Pytest
```

---

## 🔧 Comandos Docker útiles

```bash
# Ver logs en tiempo real
docker-compose logs -f app

# Parar servicios (datos persisten)
docker-compose down

# Parar y BORRAR base de datos (¡cuidado!)
docker-compose down -v

# Rebuild tras cambios de código
docker-compose up -d --build

# Shell en contenedor app
docker-compose exec app bash

# Shell en MySQL
docker-compose exec db mysql -u scanner_user -p scanner_db

# Ejecutar tests
docker-compose exec app pytest
```

---

## 🔐 Variables de entorno importantes

| Variable | Descripción | Por defecto |
|----------|-------------|-------------|
| `SECRET_KEY` | Clave secreta Flask (obligatoria en prod) | aleatoria por proceso |
| `DB_USER` / `DB_PASS` | Usuario/contraseña MySQL app | `scanner_user` / `admin123` |
| `DB_HOST` | Host MySQL (en Docker = nombre servicio `db`) | `db` |
| `DB_NAME` | Nombre base de datos | `scanner_db` |
| `MYSQL_ROOT_PASSWORD` | Root password MySQL | `rootpass123` |
| `FLASK_ENV` | `production` \| `development` | `production` |
| `SESSION_COOKIE_SECURE` | Cookie de sesión solo por HTTPS (`1`/`0`) | `0` |
| `FORCE_HTTPS` | Redirigir HTTP→HTTPS con Talisman (`1`/`0`) | `0` |
| `ESCANEO_EN_SEGUNDO_PLANO` | Escaneos en hilo aparte con progreso (`1`/`0`) | `1` |
| `PERMITIR_URLS_PRIVADAS` | Permitir analizar URLs privadas/locales (`1`/`0`) | `0` |
| `AGENTE_HABILITADO` | Habilitar cola agente local (`1`/`0`) | auto (Vercel) |
| `AGENTE_TOKEN` | Token compartido agente-servidor (**obligatorio** si el agente está activo) | vacío |

---

## 🛡️ Seguridad implementada

- **CSRF**: todos los POST validan el token de sesión (campo oculto en formularios, cabecera `X-CSRFToken` en el JS).
- **Recuperación de contraseña por email**: enlace de un solo uso con vencimiento (30 min) y límite de intentos. Nunca se muestra una contraseña en pantalla.
- **Anti-SSRF**: el análisis de URLs rechaza destinos privados, loopback, link-local y reservados (falta que defina `PERMITIR_URLS_PRIVADAS=1`).
- **Rate limiting**: login 20/min, escaneos 10/min, recuperación 5/min, reenvío 2FA 3/min.
- **Contraseñas**: hash scrypt (Werkzeug). Códigos 2FA hasheados, de un solo uso, con expiración e intentos máximos.
- **Agente local**: autenticado por token leído **solo** de la variable de entorno (sin valores por defecto en el código).
- **Sesiones**: `HttpOnly`, `SameSite=Lax`, `Secure` configurable para HTTPS.

---

## ⚡ Rendimiento

- Escaneo de puertos en paralelo (`ThreadPoolExecutor`), timeouts de 0.4s por puerto.
- Descubrimiento de dispositivos: ping a la /24 con 128 workers en paralelo, análisis por host en paralelo (puertos + DNS inverso con timeout de 1s).
- Consulta de fabricantes MAC con caché en memoria (no repite llamadas a la API).
- Análisis web con timeout de 5s + verificación de vencimiento del certificado SSL.
- Los escaneos corren en segundo plano: la API responde al instante con el id del trabajo y el frontend muestra el avance consultando `/api/trabajo/<id>`.
- Cada resultado muestra su duración (útil como métrica: "13 puertos en 0.4s", "N dispositivos en Xs").

---

## 🌐 Despliegue en producción

1. **Genera SECRET_KEY fuerte:**
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Usa contraseñas seguras** en `.env` (no los defaults)

3. **Reverse proxy** (Nginx/Traefik) con HTTPS delante de Gunicorn

4. **Variables críticas en prod:**
   ```env
   FLASK_ENV=production
   SECRET_KEY=clave_muy_larga_y_aleatoria
   DB_PASS=contraseña_fuerte_mysql
   MYSQL_ROOT_PASSWORD=otra_contraseña_fuerte
   SESSION_COOKIE_SECURE=True  # solo con HTTPS
   ```

5. **Docker Compose prod** (ejemplo):
   ```yaml
   # docker-compose.prod.yml
   version: '3.8'
   services:
     app:
       build: .
       environment:
         - FLASK_ENV=production
         - SESSION_COOKIE_SECURE=True
       # ...resto igual
   ```

---

## 🔐 Verificación en dos pasos (por email, gratis)

Cada usuario puede activarla desde **Configuración → Seguridad**:

1. Ingresa tu correo electrónico
2. Recibes un código de 6 dígitos por email y lo confirmas
3. Desde entonces, cada login pide contraseña + código del correo

### Configurar el correo (Gmail, gratis)

1. En tu cuenta Google activa la **verificación en 2 pasos**
2. Genera una **Contraseña de aplicación** en [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) (16 letras, gratis)
3. En `.env`:
   ```env
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=tu_correo@gmail.com
   SMTP_PASS=xxxx_xxxx_xxxx_xxxx
   SMTP_FROM=tu_correo@gmail.com
   ```
   > Usa la contraseña de aplicación como `SMTP_PASS`, NO tu contraseña normal.
4. Reconstruye: `docker-compose up -d --build`

> Sin SMTP configurado, el código se escribe en el log (`logs/scanner.log`) para desarrollo.

### Migrar base de datos existente

Si actualizás una instalación anterior, la app agrega las columnas nuevas automáticamente al arrancar (`ALTER TABLE usuarios ADD COLUMN ...`). Si preferís hacerlo manual:

```sql
ALTER TABLE usuarios
  ADD COLUMN reset_token_hash VARCHAR(255) NULL,
  ADD COLUMN reset_expira_en DATETIME NULL,
  ADD COLUMN reset_intentos INT NOT NULL DEFAULT 0;
```

También se necesita la tabla de trabajos (la crea `db.create_all()` al iniciar):

```sql
CREATE TABLE IF NOT EXISTS trabajos_escaneo (
    id INT NOT NULL AUTO_INCREMENT,
    usuario_id INT NOT NULL,
    tipo VARCHAR(30) NOT NULL DEFAULT 'dispositivos',
    target VARCHAR(255) NULL DEFAULT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
    escaneo_id INT NULL DEFAULT NULL,
    mensaje_error TEXT NULL DEFAULT NULL,
    progreso VARCHAR(255) NULL DEFAULT NULL,
    creado_en DATETIME NULL DEFAULT NULL,
    completado_en DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

---

## 🔑 Recuperación de contraseña

Ya no se generan contraseñas temporales en pantalla. El flujo actual:

1. El usuario ingresa su usuario en **/recuperar**.
2. Si el usuario existe **y tiene correo configurado**, se envía un enlace de un solo uso (vence en 30 minutos).
3. En **/restablecer** define la contraseña nueva y queda logueado.
4. Sin correo configurado, el sistema muestra el mismo mensaje genérico (no revela si el usuario existe) y el intento queda registrado en el log.

Para que funcione hay que configurar SMTP (ver sección de variables). Sin SMTP, en desarrollo el enlace se escribe en `logs/scanner.log`.

---

## 🌐 Despliegue en producción (Vercel / Docker)

1. **Generá SECRET_KEY y AGENTE_TOKEN fuertes:**
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"   # SECRET_KEY
   python -c "import secrets; print(secrets.token_hex(24))"   # AGENTE_TOKEN
   ```

2. **Variables críticas en prod** (Vercel → Project → Settings → Environment Variables):
   ```env
   FLASK_ENV=production
   SECRET_KEY=clave_muy_larga_y_aleatoria
   DATABASE_URL=mysql://usuario:password@host:3306/scanner_db
   SESSION_COOKIE_SECURE=True
   AGENTE_HABILITADO=1          # solo si usás el agente local
   AGENTE_TOKEN=el_mismo_token_del_agente
   SMTP_HOST=smtp.gmail.com
   SMTP_USER=...
   SMTP_PASS=...                # contraseña de aplicación de Google
   ```

3. **Agente local** (PC dentro de la red a escanear):
   ```bash
   export AGENTE_URL=https://tu-app.vercel.app
   export AGENTE_TOKEN=el_mismo_token_del_servidor
   python agente_local.py
   ```

4. **Reverse proxy** (Nginx/Traefik) con HTTPS delante de la app. Con HTTPS activo poné `SESSION_COOKIE_SECURE=True` y `FORCE_HTTPS=1`.

---

## 🧪 Tests

```bash
# Con Docker
docker-compose exec app pytest -v

# Local
pytest -v
```

---

## 📄 Licencia

MIT - Úsalo libremente.

---

## ❓ Problemas comunes

| Problema | Solución |
|----------|----------|
| `db` unhealthy | Espera 30s; MySQL tarda en iniciar. `docker-compose logs db` |
| Puerto 5000 ocupado | Cambia `ports:` en docker-compose.yml (ej. `"5001:5000"`) |
| Error conexión DB | Verifica `DB_HOST=db` en `.env` (no `localhost` dentro de Docker) |
| Cambios en código no se ven | `docker-compose up -d --build` rebuilda la imagen |
| Quiero resetear BD | `docker-compose down -v && docker-compose up -d --build` |