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
| `SECRET_KEY` | Clave secreta Flask (¡cambia en prod!) | `cambia_esto...` |
| `DB_USER` / `DB_PASS` | Usuario/contraseña MySQL app | `scanner_user` / `admin123` |
| `DB_HOST` | Host MySQL (en Docker = nombre servicio `db`) | `db` |
| `DB_NAME` | Nombre base de datos | `scanner_db` |
| `MYSQL_ROOT_PASSWORD` | Root password MySQL | `rootpass123` |
| `FLASK_ENV` | `production` \| `development` | `production` |
| `AGENTE_HABILITADO` | Habilitar cola agente local (`1`/`0`) | `0` |
| `AGENTE_TOKEN` | Token compartido agente-servidor | (generado) |

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

Si ya tienes datos en MySQL, agrega las columnas 2FA:

```sql
ALTER TABLE usuarios
  ADD COLUMN email VARCHAR(120) NULL,
  ADD COLUMN telefono VARCHAR(20) NULL,
  ADD COLUMN tfa_habilitado TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN tfa_codigo_hash VARCHAR(255) NULL,
  ADD COLUMN tfa_expira_en DATETIME NULL,
  ADD COLUMN tfa_intentos INT NOT NULL DEFAULT 0;
```

(Instalaciones nuevas con Docker ya incluyen estas columnas vía `init.sql`. SQLite local se crea solo con `db.create_all()`.)

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