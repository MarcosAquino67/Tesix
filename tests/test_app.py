import os
import pytest

os.environ['FLASK_ENV'] = 'testing'
# AISLAMIENTO CRITICO: forzar SQLite en memoria ANTES de importar la app.
# Cambiar SQLALCHEMY_DATABASE_URI despues no sirve: Flask-SQLAlchemy cachea
# el engine creado al importar (MySQL) y el drop_all del fixture borraria
# las tablas de la base de datos real.
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

# Los tests no deben enviar emails reales: se vacian las variables SMTP del
# .env local (load_dotenv no pisa variables ya definidas), asi los
# codigos/enlaces se registran en el log (modo desarrollo).
for _var_smtp in ('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM'):
    os.environ[_var_smtp] = ''

from app import app, db, limiter


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    limiter.reset()

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()


@pytest.fixture
def logged_in_client(client):
    client.post('/registro', data={'usuario': 'testuser', 'clave': 'testpass123'})
    client.post('/login', data={'usuario': 'testuser', 'clave': 'testpass123'})
    return client


def test_inicio(client):
    response = client.get('/')
    assert response.status_code == 200


def test_registro(client):
    response = client.post('/registro', data={
        'usuario': 'newuser',
        'clave': 'newpass123'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_registro_usuario_duplicado(client):
    client.post('/registro', data={'usuario': 'dupuser', 'clave': 'pass123'})
    response = client.post('/registro', data={
        'usuario': 'dupuser',
        'clave': 'pass123'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_login(client):
    client.post('/registro', data={'usuario': 'loginuser', 'clave': 'pass123'})
    response = client.post('/login', data={
        'usuario': 'loginuser',
        'clave': 'pass123'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_login_fallido(client):
    response = client.post('/login', data={
        'usuario': 'wronguser',
        'clave': 'wrongpass'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_dashboard(logged_in_client):
    response = logged_in_client.get('/dashboard')
    assert response.status_code == 200


def test_dashboard_sin_login(client):
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200


def test_historial(logged_in_client):
    response = logged_in_client.get('/api/historial')
    assert response.status_code == 200
    data = response.get_json()
    assert 'escaneos' in data
    assert 'total' in data
    assert 'page' in data
    assert 'pages' in data


def test_historial_sin_login(client):
    response = client.get('/api/historial')
    assert response.status_code == 401


def test_historial_paginacion(logged_in_client):
    response = logged_in_client.get('/api/historial?page=1&per_page=5')
    assert response.status_code == 200
    data = response.get_json()
    assert data['page'] == 1


def test_ejecutar_escaneo_puertos(logged_in_client):
    response = logged_in_client.post('/api/ejecutar-escaneo',
        json={'tipo': 'puertos', 'target': ''},
        content_type='application/json'
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'resultados' in data
    assert 'titulo' in data


def test_ejecutar_escaneo_tipo_invalido(logged_in_client):
    response = logged_in_client.post('/api/ejecutar-escaneo',
        json={'tipo': 'invalido', 'target': ''},
        content_type='application/json'
    )
    assert response.status_code == 400


def test_ejecutar_escaneo_url(logged_in_client):
    response = logged_in_client.post('/api/ejecutar-escaneo',
        json={'tipo': 'url', 'target': 'https://httpbin.org'},
        content_type='application/json'
    )
    assert response.status_code == 200


def test_vulnerabilidades_summary(logged_in_client):
    response = logged_in_client.get('/api/vulnerabilidades/summary')
    assert response.status_code == 200
    data = response.get_json()
    assert 'summary' in data


def test_logout(logged_in_client):
    response = logged_in_client.get('/logout', follow_redirects=True)
    assert response.status_code == 200


def test_configuracion(logged_in_client):
    response = logged_in_client.get('/configuracion')
    assert response.status_code == 200


def test_cambiar_password(logged_in_client):
    response = logged_in_client.post('/api/cambiar-password', data={
        'password_actual': 'testpass123',
        'password_nueva': 'newpass123',
        'password_confirmar': 'newpass123'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_cambiar_password_no_coinciden(logged_in_client):
    response = logged_in_client.post('/api/cambiar-password', data={
        'password_actual': 'testpass123',
        'password_nueva': 'newpass123',
        'password_confirmar': 'differentpass'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_borrar_historial(logged_in_client):
    response = logged_in_client.post('/api/borrar-historial')
    assert response.status_code == 200
    data = response.get_json()
    assert data['ok'] is True


def test_eliminar_cuenta(logged_in_client):
    response = logged_in_client.post('/api/eliminar-cuenta')
    assert response.status_code == 200
    data = response.get_json()
    assert data['ok'] is True


# ----------------------------------------------------------------------
# VERIFICACION EN DOS PASOS (EMAIL)
# ----------------------------------------------------------------------
def test_normalizar_email():
    from email_2fa import normalizar_email
    assert normalizar_email('Usuario@Empresa.com ') == 'usuario@empresa.com'
    assert normalizar_email('nombre@empresa.com') == 'nombre@empresa.com'
    assert normalizar_email('no-es-email') is None
    assert normalizar_email('falta@arroba') is None
    assert normalizar_email('') is None


def test_guardar_email_invalido(logged_in_client):
    response = logged_in_client.post('/api/guardar-email-2fa',
        json={'email': 'no-es-email'})
    assert response.status_code == 400
    assert 'error' in response.get_json()


def test_guardar_email_sin_login(client):
    response = client.post('/api/guardar-email-2fa',
        json={'email': 'test@empresa.com'})
    assert response.status_code == 401


def test_activar_2fa_flujo_completo(logged_in_client, monkeypatch):
    import email_2fa
    monkeypatch.setattr(email_2fa, 'generar_codigo', lambda: '123456')

    response = logged_in_client.post('/api/guardar-email-2fa',
        json={'email': 'test@empresa.com'})
    assert response.status_code == 200
    assert response.get_json()['ok'] is True

    response = logged_in_client.post('/api/confirmar-2fa',
        json={'codigo': '123456'})
    assert response.status_code == 200
    assert response.get_json()['ok'] is True


def test_confirmar_2fa_codigo_mal(logged_in_client):
    logged_in_client.post('/api/guardar-email-2fa',
        json={'email': 'test@empresa.com'})
    response = logged_in_client.post('/api/confirmar-2fa',
        json={'codigo': '000000'})
    assert response.status_code == 400
    assert 'error' in response.get_json()


def test_desactivar_2fa(logged_in_client):
    logged_in_client.post('/api/guardar-email-2fa',
        json={'email': 'test@empresa.com'})
    response = logged_in_client.post('/api/desactivar-2fa')
    assert response.status_code == 200
    assert response.get_json()['ok'] is True


def test_login_con_2fa_redirige_a_verificacion(client):
    from models import Usuario
    client.post('/registro', data={'usuario': 'tfauser', 'clave': 'pass123'})
    with app.app_context():
        user = Usuario.query.filter_by(username='tfauser').first()
        user.email = 'tfauser@empresa.com'
        user.tfa_habilitado = True
        db.session.commit()

    response = client.post('/login', data={
        'usuario': 'tfauser', 'clave': 'pass123'
    })
    assert response.status_code == 302
    assert '/verificar-2fa' in response.headers['Location']


def test_verificar_2fa_sin_pendiente(client):
    response = client.get('/verificar-2fa', follow_redirects=True)
    assert response.status_code == 200


def test_verificar_2fa_codigo_mal(client, monkeypatch):
    import email_2fa
    monkeypatch.setattr(email_2fa, 'generar_codigo', lambda: '123456')

    client.post('/registro', data={'usuario': 'tfauser2', 'clave': 'pass123'})
    with app.app_context():
        from models import Usuario
        user = Usuario.query.filter_by(username='tfauser2').first()
        user.email = 'tfauser2@empresa.com'
        user.tfa_habilitado = True
        db.session.commit()
    client.post('/login', data={'usuario': 'tfauser2', 'clave': 'pass123'})

    response = client.post('/verificar-2fa', data={'codigo': '000000'})
    assert response.status_code == 302
    assert '/verificar-2fa' in response.headers['Location']


# ----------------------------------------------------------------------
# RECUPERACION DE CONTRASENA POR EMAIL
# ----------------------------------------------------------------------
def _token_de_respuesta(respuesta):
    import re as _re
    cuerpo = respuesta.get_data(as_text=True)
    match = _re.search(r'token=([A-Za-z0-9_\-]+)', cuerpo)
    assert match, 'No se encontro el enlace de restablecimiento en la respuesta'
    return match.group(1)


def test_recuperar_no_expone_contrasena(client):
    client.post('/registro', data={'usuario': 'victima', 'clave': 'pass123'})
    response = client.post('/recuperar', data={'username': 'victima'}, follow_redirects=True)
    assert response.status_code == 200
    cuerpo = response.get_data(as_text=True)
    assert 'Contrasena temporal' not in cuerpo


def test_recuperar_usuario_inexistente_no_revela(client):
    response = client.post('/recuperar', data={'username': 'fantasma'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'enlace' in response.data.lower()


def test_flujo_reset_completo(client):
    import re as _re
    from models import Usuario
    from werkzeug.security import check_password_hash

    with app.app_context():
        user = Usuario.query.filter_by(username='testuser').first() if Usuario.query.count() else None
    client.post('/registro', data={'usuario': 'resetuser', 'clave': 'pass123'})
    with app.app_context():
        usuario = Usuario.query.filter_by(username='resetuser').first()
        usuario.email = 'reset@empresa.com'
        db.session.commit()

    respuesta = client.post('/recuperar', data={'username': 'resetuser'}, follow_redirects=True)
    token = _token_de_respuesta(respuesta)

    respuesta = client.get(f'/restablecer?token={token}')
    assert respuesta.status_code == 200

    respuesta = client.post(f'/restablecer?token={token}', data={
        'clave': 'nuevaclave123',
        'confirmar': 'nuevaclave123',
    }, follow_redirects=True)
    assert respuesta.status_code == 200

    with app.app_context():
        usuario = Usuario.query.filter_by(username='resetuser').first()
        assert check_password_hash(usuario.password_hash, 'nuevaclave123')
        assert usuario.reset_token_hash is None

    # La nueva contrasena funciona para entrar
    client.get('/logout')
    respuesta = client.post('/login', data={
        'usuario': 'resetuser', 'clave': 'nuevaclave123'
    }, follow_redirects=True)
    assert respuesta.status_code == 200


def test_reset_token_invalido(client):
    respuesta = client.post('/restablecer?token=token-falso', data={
        'clave': 'nuevaclave123',
        'confirmar': 'nuevaclave123',
    }, follow_redirects=True)
    assert respuesta.status_code == 200
    assert b'no es valido' in respuesta.data.lower()


def test_reset_contrasenas_no_coinciden(client):
    import re as _re
    from models import Usuario
    client.post('/registro', data={'usuario': 'resetuser2', 'clave': 'pass123'})
    with app.app_context():
        usuario = Usuario.query.filter_by(username='resetuser2').first()
        usuario.email = 'reset2@empresa.com'
        db.session.commit()

    respuesta = client.post('/recuperar', data={'username': 'resetuser2'}, follow_redirects=True)
    token = _token_de_respuesta(respuesta)
    respuesta = client.post(f'/restablecer?token={token}', data={
        'clave': 'nuevaclave123',
        'confirmar': 'otraclave456',
    }, follow_redirects=True)
    assert respuesta.status_code == 200
    assert b'no coinciden' in respuesta.data.lower()


# ----------------------------------------------------------------------
# CSRF
# ----------------------------------------------------------------------
def test_post_sin_csrf_rechazado(client):
    client.get('/')
    app.config['TESTING'] = False
    try:
        respuesta = client.post('/login', data={'usuario': 'x', 'clave': 'y'})
        assert respuesta.status_code == 403
        respuesta = client.post('/api/borrar-historial')
        assert respuesta.status_code == 403
    finally:
        app.config['TESTING'] = True


# ----------------------------------------------------------------------
# ANTI-SSRF
# ----------------------------------------------------------------------
def test_url_privada_rechazada(logged_in_client):
    response = logged_in_client.post('/api/ejecutar-escaneo',
        json={'tipo': 'url', 'target': 'http://127.0.0.1:5000'},
        content_type='application/json'
    )
    assert response.status_code == 400
    data = response.get_json()
    assert 'privadas' in data['error'] or 'locales' in data['error']


def test_url_localhost_rechazada(logged_in_client):
    response = logged_in_client.post('/api/ejecutar-escaneo',
        json={'tipo': 'url', 'target': 'http://localhost'},
        content_type='application/json'
    )
    assert response.status_code == 400


# ----------------------------------------------------------------------
# AGENTE LOCAL (token solo por entorno)
# ----------------------------------------------------------------------
def test_agente_sin_token_configurado(client):
    app.config['AGENTE_TOKEN'] = ''
    response = client.post('/api/agente/claim')
    assert response.status_code == 503


def test_agente_token_invalido(client):
    app.config['AGENTE_TOKEN'] = 'secreto-de-prueba'
    response = client.post('/api/agente/claim', headers={'X-Agente-Token': 'otro'})
    assert response.status_code == 401


def test_agente_token_valido(client):
    from models import Usuario
    app.config['AGENTE_TOKEN'] = 'secreto-de-prueba'
    client.post('/registro', data={'usuario': 'agenteuser', 'clave': 'pass123'})
    with app.app_context():
        usuario = Usuario.query.filter_by(username='agenteuser').first()
        from models import TrabajoEscaneo
        trabajo = TrabajoEscaneo(usuario_id=usuario.id, tipo='dispositivos',
                                 target='auto', estado='pendiente')
        db.session.add(trabajo)
        db.session.commit()

    response = client.post('/api/agente/claim', headers={'X-Agente-Token': 'secreto-de-prueba'})
    assert response.status_code == 200
    assert response.get_json()['trabajo']['tipo'] == 'dispositivos'


def test_agente_ping_reporta_token(client):
    app.config['AGENTE_TOKEN'] = ''
    respuesta = client.get('/api/agente/ping').get_json()
    assert respuesta['token_configurado'] is False


# ----------------------------------------------------------------------
# MODULO ESCANEO_RED
# ----------------------------------------------------------------------
def test_validar_ip():
    from escaneo_red import validar_ip
    assert validar_ip('192.168.0.1')
    assert not validar_ip('256.1.1.1')
    assert not validar_ip('192.168.0')
    assert not validar_ip('')


def test_sanitize_target_url():
    from escaneo_red import sanitize_target
    assert sanitize_target('ejemplo.com', 'url') == 'https://ejemplo.com'
    try:
        sanitize_target('no es url', 'url')
        assert False, 'Debia fallar'
    except ValueError:
        pass
    try:
        sanitize_target('10.0.0.1', 'puertos')
        assert sanitize_target('10.0.0.1', 'puertos') == '10.0.0.1'
    except ValueError:
        assert False, 'IP valida no debia fallar'
    try:
        sanitize_target('999.1.1.1', 'puertos')
        assert False, 'Debia fallar'
    except ValueError:
        pass


def test_es_url_permitida():
    from escaneo_red import es_url_permitida
    ok, _ = es_url_permitida('http://127.0.0.1/x')
    assert ok is False
    ok, _ = es_url_permitida('http://localhost/x')
    assert ok is False
    ok, _ = es_url_permitida('http://192.168.0.5/x')
    assert ok is False
    ok, _ = es_url_permitida('http://10.0.0.3/x')
    assert ok is False
    ok, _ = es_url_permitida('http://169.254.169.254/latest/meta-data')
    assert ok is False


def test_escanear_puertos_detecta_puerto_abierto():
    import socket as s
    from escaneo_red import escanear_puertos
    servidor = s.socket(s.AF_INET, s.SOCK_STREAM)
    servidor.bind(('127.0.0.1', 0))
    servidor.listen(1)
    puerto = servidor.getsockname()[1]
    try:
        abiertos = escanear_puertos('127.0.0.1', [puerto, 65001], timeout=0.5)
        assert puerto in abiertos
        assert 65001 not in abiertos
    finally:
        servidor.close()


def test_ip_local():
    from escaneo_red import ip_local
    ip = ip_local()
    assert ip.count('.') == 3


def test_prefix_red():
    from escaneo_red import prefijo_red_local
    prefijo, propia = prefijo_red_local()
    assert prefijo.count('.') == 2
    assert propia.count('.') == 3
