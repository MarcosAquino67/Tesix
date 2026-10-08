import os
import pytest

os.environ['FLASK_ENV'] = 'testing'
# AISLAMIENTO CRITICO: forzar SQLite en memoria ANTES de importar la app.
# Cambiar SQLALCHEMY_DATABASE_URI despues no sirve: Flask-SQLAlchemy cachea
# el engine creado al importar (MySQL) y el drop_all del fixture borraria
# las tablas de la base de datos real.
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

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
