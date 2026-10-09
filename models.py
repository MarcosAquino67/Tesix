from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Usuario(db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    tema = db.Column(db.String(20), default='oscuro')

    # Verificacion en dos pasos por email (opcional por usuario)
    email = db.Column(db.String(120), nullable=True)
    telefono = db.Column(db.String(20), nullable=True)
    tfa_habilitado = db.Column(db.Boolean, default=False, nullable=False)
    tfa_codigo_hash = db.Column(db.String(255), nullable=True)
    tfa_expira_en = db.Column(db.DateTime, nullable=True)
    tfa_intentos = db.Column(db.Integer, default=0, nullable=False)

    # Recuperacion de contrasena por enlace de un solo uso
    reset_token_hash = db.Column(db.String(255), nullable=True)
    reset_expira_en = db.Column(db.DateTime, nullable=True)
    reset_intentos = db.Column(db.Integer, default=0, nullable=False)

    escaneos = db.relationship('Escaneo', backref='usuario', lazy=True,
                               cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Usuario {self.username}>'


class Escaneo(db.Model):
    __tablename__ = 'escaneos'

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'),
                           nullable=False, index=True)
    tipo = db.Column(db.String(30), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    titulo = db.Column(db.String(150))
    subtitulo = db.Column(db.String(255))
    total_dispositivos = db.Column(db.Integer)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    resultados = db.relationship('ResultadoEscaneo', backref='escaneo', lazy=True,
                                 cascade='all, delete-orphan',
                                 order_by='ResultadoEscaneo.id')

    def to_dict(self):
        return {
            'id': self.id,
            'tipo': self.tipo,
            'target': self.target,
            'titulo': self.titulo,
            'subtitulo': self.subtitulo,
            'total_dispositivos': self.total_dispositivos,
            'fecha': self.fecha.strftime('%Y-%m-%d %H:%M:%S'),
            'detalles': [r.to_dict() for r in self.resultados]
        }


class ResultadoEscaneo(db.Model):
    __tablename__ = 'resultados_escaneo'

    id = db.Column(db.Integer, primary_key=True)
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos.id'),
                           nullable=False, index=True)
    item = db.Column(db.String(255), nullable=False)
    estado = db.Column(db.String(30), nullable=False)
    explicacion = db.Column(db.Text)

    def to_dict(self):
        return {
            'item': self.item,
            'estado': self.estado,
            'explicacion': self.explicacion
        }


# --------------------------------------------------------------------
# Modelo que faltaba: Vulnerabilidad
# --------------------------------------------------------------------
class Vulnerabilidad(db.Model):
    __tablename__ = 'vulnerabilidades'

    id = db.Column(db.Integer, primary_key=True)
    escaneo_id = db.Column(db.Integer,
                           db.ForeignKey('escaneos.id'),
                           nullable=False, index=True)
    id_malware = db.Column(db.String(100))
    cve = db.Column(db.String(100))
    nombre = db.Column(db.String(250))
    descripcion = db.Column(db.Text)
    tipo = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    risk = db.Column(db.Text)

    # Vínculo bidireccional con Escaneo (borrar escaneo borra sus vulnerabilidades)
    escaneo = db.relationship("Escaneo", backref="vulnerabilidades", lazy=True,
                              cascade='all, delete-orphan', single_parent=True)

    def to_dict(self):
        return {
            'id': self.id,
            'escaneo_id': self.escaneo_id,
            'id_malware': self.id_malware,
            'cve': self.cve,
            'nombre': self.nombre,
            'descripcion': self.descripcion,
            'tipo': self.tipo,
            'severity': self.severity,
            'risk': self.risk,
        }


# --------------------------------------------------------------------
# Cola de trabajos para escaneos ejecutados por el agente local
# --------------------------------------------------------------------
class TrabajoEscaneo(db.Model):
    __tablename__ = 'trabajos_escaneo'

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'),
                           nullable=False, index=True)
    tipo = db.Column(db.String(30), nullable=False, default='dispositivos')
    target = db.Column(db.String(255))
    estado = db.Column(db.String(20), nullable=False, default='pendiente',
                       index=True)  # pendiente | procesando | completado | error
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos.id'))
    mensaje_error = db.Column(db.Text)
    progreso = db.Column(db.String(255))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    completado_en = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'tipo': self.tipo,
            'estado': self.estado,
            'creado_en': self.creado_en.strftime('%Y-%m-%d %H:%M:%S') if self.creado_en else None
        }