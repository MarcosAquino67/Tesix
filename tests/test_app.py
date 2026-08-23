import os
import pytest

os.environ['FLASK_ENV'] = 'testing'

from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False

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
