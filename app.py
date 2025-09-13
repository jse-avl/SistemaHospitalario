from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_muy_segura_aqui_2024'

# Agregar función de contexto para fechas
@app.context_processor
def utility_processor():
    def get_today():
        return datetime.now().strftime('%Y-%m-%d')
    return dict(get_today=get_today)

# Configuración de la base de datos
DATABASE = 'hospital.db'

def init_db():
    """Inicializa la base de datos con las tablas necesarias"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cedula TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            tipo TEXT NOT NULL,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de pacientes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pacientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cedula TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            fecha_nacimiento DATE,
            telefono TEXT,
            email TEXT,
            direccion TEXT,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de médicos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS medicos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cedula TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            especialidad TEXT NOT NULL,
            telefono TEXT,
            email TEXT,
            horario_inicio TIME,
            horario_fin TIME,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de citas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS citas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paciente_cedula TEXT NOT NULL,
            medico_cedula TEXT NOT NULL,
            fecha DATE NOT NULL,
            hora TIME NOT NULL,
            motivo TEXT,
            estado TEXT DEFAULT 'Programada',
            fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (paciente_cedula) REFERENCES pacientes (cedula),
            FOREIGN KEY (medico_cedula) REFERENCES medicos (cedula)
        )
    ''')
    
    # Crear usuario administrador por defecto
    admin_password = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO usuarios (cedula, nombre, apellido, email, password_hash, tipo)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('admin', 'Administrador', 'Sistema', 'admin@hospital.com', admin_password, 'admin'))
    
    # Crear algunos médicos de ejemplo
    medicos_ejemplo = [
        ('12345', 'Dr. Carlos', 'García', 'Cardiología', '555-1234', 'garcia@hospital.com', '08:00', '16:00'),
        ('67890', 'Dra. Ana', 'López', 'Pediatría', '555-5678', 'lopez@hospital.com', '09:00', '17:00'),
        ('54321', 'Dr. Luis', 'Martínez', 'Neurología', '555-9012', 'martinez@hospital.com', '07:00', '15:00')
    ]
    
    for medico in medicos_ejemplo:
        cursor.execute('''
            INSERT OR IGNORE INTO medicos (cedula, nombre, apellido, especialidad, telefono, email, horario_inicio, horario_fin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', medico)
        
        # Crear usuario para cada médico
        medico_password = generate_password_hash('123456')
        cursor.execute('''
            INSERT OR IGNORE INTO usuarios (cedula, nombre, apellido, email, password_hash, tipo)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (medico[0], medico[1], medico[2], medico[5], medico_password, 'medico'))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Obtiene una conexión a la base de datos"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Decorador para requerir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorador para requerir permisos de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'admin':
            flash('Acceso denegado. Se requieren permisos de administrador.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Página principal - redirige al login o dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        cedula = request.form['cedula']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM usuarios WHERE cedula = ?', (cedula,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_cedula'] = user['cedula']
            session['user_name'] = f"{user['nombre']} {user['apellido']}"
            session['user_type'] = user['tipo']
            flash(f'¡Bienvenido, {user["nombre"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Cédula o contraseña incorrecta', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session.clear()
    flash('Sesión cerrada exitosamente', 'info')
    return redirect(url_for('login'))

@app.route('/register_patient', methods=['POST'])
def register_patient():
    """Registro público de pacientes"""
    try:
        # Obtener datos del formulario
        cedula = request.form['cedula']
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        fecha_nacimiento = request.form['fecha_nacimiento']
        telefono = request.form.get('telefono', '')
        email = request.form['email']
        direccion = request.form.get('direccion', '')
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validaciones
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('login'))
        
        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres', 'error')
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        
        # Verificar si la cédula ya existe
        existing_user = conn.execute(
            'SELECT id FROM usuarios WHERE cedula = ?', (cedula,)
        ).fetchone()
        
        if existing_user:
            flash('Ya existe un usuario con esta cédula', 'error')
            conn.close()
            return redirect(url_for('login'))
        
        # Verificar si el email ya existe
        existing_email = conn.execute(
            'SELECT id FROM pacientes WHERE email = ?', (email,)
        ).fetchone()
        
        if existing_email:
            flash('Ya existe un paciente con este email', 'error')
            conn.close()
            return redirect(url_for('login'))
        
        # Crear hash de la contraseña
        password_hash = generate_password_hash(password)
        
        # Insertar usuario
        conn.execute(
            '''INSERT INTO usuarios (cedula, nombre, apellido, email, password_hash, tipo)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (cedula, nombre, apellido, email, password_hash, 'paciente')
        )
        
        # Insertar paciente
        conn.execute(
            '''INSERT INTO pacientes (cedula, nombre, apellido, fecha_nacimiento, telefono, email, direccion)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (cedula, nombre, apellido, fecha_nacimiento, telefono, email, direccion)
        )
        
        conn.commit()
        conn.close()
        
        flash('Registro exitoso. Ya puedes iniciar sesión', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        flash(f'Error en el registro: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal"""
    conn = get_db_connection()
    
    # Si es paciente, redirigir a dashboard específico
    if session.get('user_type') == 'paciente':
        return dashboard_paciente()
    
    # Estadísticas generales para admin y médicos
    stats = {
        'total_pacientes': conn.execute('SELECT COUNT(*) FROM pacientes').fetchone()[0],
        'total_medicos': conn.execute('SELECT COUNT(*) FROM medicos').fetchone()[0],
        'total_citas': conn.execute('SELECT COUNT(*) FROM citas').fetchone()[0],
        'citas_hoy': conn.execute(
            'SELECT COUNT(*) FROM citas WHERE fecha = DATE("now")'
        ).fetchone()[0]
    }
    
    # Próximas citas (solo para médicos y admin)
    proximas_citas = []
    if session['user_type'] in ['medico', 'admin']:
        if session['user_type'] == 'medico':
            proximas_citas = conn.execute('''
                SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                FROM citas c
                JOIN pacientes p ON c.paciente_cedula = p.cedula
                WHERE c.medico_cedula = ? AND c.fecha >= DATE('now')
                ORDER BY c.fecha, c.hora
                LIMIT 5
            ''', (session['user_cedula'],)).fetchall()
        else:
            proximas_citas = conn.execute('''
                SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido,
                       m.nombre as medico_nombre, m.apellido as medico_apellido
                FROM citas c
                JOIN pacientes p ON c.paciente_cedula = p.cedula
                JOIN medicos m ON c.medico_cedula = m.cedula
                WHERE c.fecha >= DATE('now')
                ORDER BY c.fecha, c.hora
                LIMIT 10
            ''').fetchall()
    
    conn.close()
    return render_template('dashboard.html', stats=stats, proximas_citas=proximas_citas)

def dashboard_paciente():
    """Dashboard específico para pacientes"""
    conn = get_db_connection()
    
    # Obtener ID del paciente
    paciente = conn.execute(
        'SELECT id, nombre FROM pacientes WHERE cedula = ?',
        (session['user_cedula'],)
    ).fetchone()
    
    if not paciente:
        flash('Paciente no encontrado', 'error')
        return redirect(url_for('login'))
    
    # Estadísticas del paciente
    citas_pendientes = conn.execute(
        'SELECT COUNT(*) FROM citas WHERE paciente_cedula = ? AND estado IN ("Programada", "pendiente")',
        (session['user_cedula'],)
    ).fetchone()[0]
    
    citas_completadas = conn.execute(
        'SELECT COUNT(*) FROM citas WHERE paciente_cedula = ? AND estado IN ("Completada", "completada")',
        (session['user_cedula'],)
    ).fetchone()[0]
    
    # Próxima cita
    proxima_cita_row = conn.execute(
        '''SELECT fecha, hora FROM citas 
           WHERE paciente_cedula = ? AND fecha >= DATE('now') AND estado != 'Cancelada'
           ORDER BY fecha, hora LIMIT 1''',
        (session['user_cedula'],)
    ).fetchone()
    
    proxima_cita = "Sin citas"
    if proxima_cita_row:
        proxima_cita = f"{proxima_cita_row['fecha']}"
    
    # Próximas citas para la tabla
    proximas_citas = conn.execute(
        '''SELECT c.*, m.nombre as medico_nombre, m.especialidad
           FROM citas c
           JOIN medicos m ON c.medico_cedula = m.cedula
           WHERE c.paciente_cedula = ? AND c.fecha >= DATE('now') AND c.estado != 'Cancelada'
           ORDER BY c.fecha, c.hora
           LIMIT 5''',
        (session['user_cedula'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard_paciente.html', 
                         citas_pendientes=citas_pendientes,
                         citas_completadas=citas_completadas,
                         proxima_cita=proxima_cita,
                         notificaciones=0,  # Por ahora 0, se puede implementar después
                         proximas_citas=proximas_citas)

@app.route('/pacientes')
@login_required
def pacientes():
    """Lista de pacientes"""
    conn = get_db_connection()
    pacientes = conn.execute(
        'SELECT * FROM pacientes ORDER BY apellido, nombre'
    ).fetchall()
    conn.close()
    return render_template('pacientes.html', pacientes=pacientes)

@app.route('/pacientes/nuevo', methods=['POST'])
@login_required
def nuevo_paciente():
    """Crear nuevo paciente"""
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO pacientes (cedula, nombre, apellido, fecha_nacimiento, telefono, email, direccion)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            request.form['cedula'],
            request.form['nombre'],
            request.form['apellido'],
            request.form['fecha_nacimiento'],
            request.form['telefono'],
            request.form['email'],
            request.form['direccion']
        ))
        
        # Crear usuario para el paciente
        password_hash = generate_password_hash('123456')  # Contraseña por defecto
        conn.execute('''
            INSERT INTO usuarios (cedula, nombre, apellido, email, password_hash, tipo)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            request.form['cedula'],
            request.form['nombre'],
            request.form['apellido'],
            request.form['email'],
            password_hash,
            'paciente'
        ))
        
        conn.commit()
        conn.close()
        flash('Paciente registrado exitosamente', 'success')
    except sqlite3.IntegrityError:
        flash('Error: Ya existe un paciente con esa cédula', 'error')
    except Exception as e:
        flash(f'Error al registrar paciente: {str(e)}', 'error')
    
    return redirect(url_for('pacientes'))

@app.route('/medicos')
@login_required
def medicos():
    """Lista de médicos"""
    conn = get_db_connection()
    medicos = conn.execute(
        'SELECT * FROM medicos ORDER BY apellido, nombre'
    ).fetchall()
    conn.close()
    return render_template('medicos.html', medicos=medicos)

@app.route('/citas')
@login_required
def citas():
    """Lista de citas con funcionalidades avanzadas"""
    conn = get_db_connection()
    
    if session['user_type'] == 'paciente':
        citas = conn.execute('''
            SELECT c.*, m.nombre as medico_nombre, m.apellido as medico_apellido, m.especialidad
            FROM citas c
            JOIN medicos m ON c.medico_cedula = m.cedula
            WHERE c.paciente_cedula = ?
            ORDER BY c.fecha DESC, c.hora DESC
        ''', (session['user_cedula'],)).fetchall()
    elif session['user_type'] == 'medico':
        citas = conn.execute('''
            SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
            FROM citas c
            JOIN pacientes p ON c.paciente_cedula = p.cedula
            WHERE c.medico_cedula = ?
            ORDER BY c.fecha DESC, c.hora DESC
        ''', (session['user_cedula'],)).fetchall()
    else:
        citas = conn.execute('''
            SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido,
                   m.nombre as medico_nombre, m.apellido as medico_apellido, m.especialidad
            FROM citas c
            JOIN pacientes p ON c.paciente_cedula = p.cedula
            JOIN medicos m ON c.medico_cedula = m.cedula
            ORDER BY c.fecha DESC, c.hora DESC
        ''').fetchall()
    
    # Obtener listas para filtros
    medicos_list = conn.execute('SELECT cedula, nombre, apellido, especialidad, horario_inicio, horario_fin FROM medicos').fetchall()
    pacientes_list = []
    
    if session['user_type'] == 'admin':
        pacientes_list = conn.execute('SELECT cedula, nombre, apellido FROM pacientes').fetchall()
    
    # Obtener especialidades únicas
    especialidades = conn.execute('SELECT DISTINCT especialidad FROM medicos ORDER BY especialidad').fetchall()
    especialidades = [esp['especialidad'] for esp in especialidades]
    
    conn.close()
    return render_template('citas.html', 
                         citas=citas, 
                         pacientes=pacientes_list, 
                         medicos=medicos_list,
                         especialidades=especialidades)

@app.route('/citas/nueva', methods=['POST'])
@login_required
def nueva_cita():
    """Crear una nueva cita"""
    try:
        paciente_cedula = request.form.get('paciente_cedula')
        medico_cedula = request.form.get('medico_cedula')
        fecha = request.form.get('fecha')
        hora = request.form.get('hora')
        motivo = request.form.get('motivo', '')
        
        # Validaciones
        if not all([paciente_cedula, medico_cedula, fecha, hora]):
            flash('Todos los campos obligatorios deben ser completados', 'error')
            return redirect(url_for('citas'))
        
        # Verificar que la fecha no sea en el pasado
        fecha_cita = datetime.strptime(fecha, '%Y-%m-%d').date()
        if fecha_cita < datetime.now().date():
            flash('No se puede agendar una cita en el pasado', 'error')
            return redirect(url_for('citas'))
        
        conn = get_db_connection()
        
        # Verificar disponibilidad del médico
        cita_existente = conn.execute(
            'SELECT id FROM citas WHERE medico_cedula = ? AND fecha = ? AND hora = ? AND estado != "Cancelada"',
            (medico_cedula, fecha, hora)
        ).fetchone()
        
        if cita_existente:
            flash('El médico no está disponible en esa fecha y hora', 'error')
            conn.close()
            return redirect(url_for('citas'))
        
        # Crear la nueva cita
        conn.execute(
            '''INSERT INTO citas (paciente_cedula, medico_cedula, fecha, hora, motivo, estado, fecha_creacion)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (paciente_cedula, medico_cedula, fecha, hora, motivo, 'Programada', datetime.now())
        )
        conn.commit()
        conn.close()
        
        flash('Cita agendada exitosamente', 'success')
        return redirect(url_for('citas'))
        
    except Exception as e:
        flash(f'Error al agendar la cita: {str(e)}', 'error')
        return redirect(url_for('citas'))

@app.route('/api/citas/disponibilidad')
@login_required
def verificar_disponibilidad():
    """API para verificar disponibilidad de horarios"""
    medico_cedula = request.args.get('medico')
    fecha = request.args.get('fecha')
    
    if not medico_cedula or not fecha:
        return jsonify({'error': 'Parámetros faltantes'}), 400
    
    conn = get_db_connection()
    
    # Obtener citas existentes
    citas_existentes = conn.execute('''
        SELECT hora FROM citas 
        WHERE medico_cedula = ? AND fecha = ? AND estado != 'Cancelada'
    ''', (medico_cedula, fecha)).fetchall()
    
    # Obtener horario del médico
    medico = conn.execute('''
        SELECT horario_inicio, horario_fin FROM medicos WHERE cedula = ?
    ''', (medico_cedula,)).fetchone()
    
    conn.close()
    
    if not medico:
        return jsonify({'error': 'Médico no encontrado'}), 404
    
    # Generar horarios disponibles
    horarios_ocupados = [cita['hora'] for cita in citas_existentes]
    horarios_disponibles = []
    
    hora_inicio = int(medico['horario_inicio'].split(':')[0])
    hora_fin = int(medico['horario_fin'].split(':')[0])
    
    for hora in range(hora_inicio, hora_fin):
        for minuto in ['00', '30']:
            horario = f"{hora:02d}:{minuto}"
            if horario not in horarios_ocupados:
                horarios_disponibles.append(horario)
    
    return jsonify({
        'disponibles': horarios_disponibles,
        'ocupados': horarios_ocupados
    })

@app.route('/citas/exportar/pdf')
@login_required
def exportar_citas_pdf():
    """Exportar citas a PDF"""
    # Implementar exportación a PDF
    # Requiere librerías como reportlab o weasyprint
    pass

@app.route('/citas/exportar/excel')
@login_required
def exportar_citas_excel():
    """Exportar citas a Excel"""
    # Implementar exportación a Excel
    # Requiere librería openpyxl o xlsxwriter
    pass

@app.route('/api/citas/buscar')
@login_required
def buscar_citas():
    """API para búsqueda avanzada de citas"""
    cedula = request.args.get('cedula', '')
    medico = request.args.get('medico', '')
    especialidad = request.args.get('especialidad', '')
    estado = request.args.get('estado', '')
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    
    conn = get_db_connection()
    
    query = '''
        SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido,
               m.nombre as medico_nombre, m.apellido as medico_apellido, m.especialidad
        FROM citas c
        JOIN pacientes p ON c.paciente_cedula = p.cedula
        JOIN medicos m ON c.medico_cedula = m.cedula
        WHERE 1=1
    '''
    
    params = []
    
    if cedula:
        query += ' AND p.cedula LIKE ?'
        params.append(f'%{cedula}%')
    
    if medico:
        query += ' AND m.cedula = ?'
        params.append(medico)
    
    if especialidad:
        query += ' AND m.especialidad = ?'
        params.append(especialidad)
    
    if estado:
        query += ' AND c.estado = ?'
        params.append(estado)
    
    if fecha_inicio:
        query += ' AND c.fecha >= ?'
        params.append(fecha_inicio)
    
    if fecha_fin:
        query += ' AND c.fecha <= ?'
        params.append(fecha_fin)
    
    # Aplicar filtros según tipo de usuario
    if session['user_type'] == 'paciente':
        query += ' AND c.paciente_cedula = ?'
        params.append(session['user_cedula'])
    elif session['user_type'] == 'medico':
        query += ' AND c.medico_cedula = ?'
        params.append(session['user_cedula'])
    
    query += ' ORDER BY c.fecha DESC, c.hora DESC'
    
    citas = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(cita) for cita in citas])

@app.route('/mis_citas')
@login_required
def mis_citas():
    """Página de citas del paciente"""
    if session.get('user_type') != 'paciente':
        flash('Acceso denegado', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    citas = conn.execute(
        '''SELECT c.*, m.nombre as medico_nombre, m.especialidad
           FROM citas c
           JOIN medicos m ON c.medico_cedula = m.cedula
           WHERE c.paciente_cedula = ?
           ORDER BY c.fecha DESC, c.hora DESC''',
        (session['user_cedula'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('mis_citas.html', citas=citas)

@app.route('/mi_perfil')
@login_required
def mi_perfil():
    """Página de perfil del paciente"""
    if session.get('user_type') != 'paciente':
        flash('Acceso denegado', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    paciente = conn.execute(
        'SELECT * FROM pacientes WHERE cedula = ?',
        (session['user_cedula'],)
    ).fetchone()
    
    conn.close()
    
    return render_template('mi_perfil.html', paciente=paciente)

@app.route('/mi_historial')
@login_required
def mi_historial():
    """Página de historial médico del paciente"""
    if session.get('user_type') != 'paciente':
        flash('Acceso denegado', 'error')
        return redirect(url_for('dashboard'))
    
    # Por ahora redirigir a mis_citas, se puede implementar después
    return redirect(url_for('mis_citas'))

@app.route('/agendar_cita_paciente', methods=['GET', 'POST'])
@login_required
def agendar_cita_paciente():
    """Permite a los pacientes agendar sus propias citas"""
    if session.get('user_type') != 'paciente':
        flash('Acceso denegado', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        medico_cedula = request.form['medico_cedula']
        fecha = request.form['fecha']
        hora = request.form['hora']
        motivo = request.form.get('motivo', '')
        
        conn = get_db_connection()
        
        # Obtener datos del paciente
        paciente = conn.execute(
            'SELECT email, nombre FROM pacientes WHERE cedula = ?',
            (session['user_cedula'],)
        ).fetchone()
        
        # Verificar disponibilidad
        cita_existente = conn.execute(
            'SELECT id FROM citas WHERE medico_cedula = ? AND fecha = ? AND hora = ? AND estado != "Cancelada"',
            (medico_cedula, fecha, hora)
        ).fetchone()
        
        if cita_existente:
            flash('El horario seleccionado no está disponible', 'error')
            conn.close()
            return redirect(url_for('agendar_cita_paciente'))
        
        # Crear la cita
        conn.execute(
            '''INSERT INTO citas (paciente_cedula, medico_cedula, fecha, hora, motivo, estado)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (session['user_cedula'], medico_cedula, fecha, hora, motivo, 'Programada')
        )
        
        # Obtener datos del médico para la notificación
        medico = conn.execute(
            'SELECT nombre FROM medicos WHERE cedula = ?', (medico_cedula,)
        ).fetchone()
        
        conn.commit()
        conn.close()
        
        # Enviar notificación de confirmación
        enviar_notificacion_cita(
            paciente['email'], 
            paciente['nombre'], 
            fecha, 
            hora, 
            medico['nombre'], 
            'confirmacion'
        )
        
        flash('Cita agendada exitosamente. Recibirás una confirmación por email.', 'success')
        return redirect(url_for('mis_citas'))
    
    # GET request - mostrar formulario
    conn = get_db_connection()
    medicos = conn.execute('SELECT * FROM medicos ORDER BY nombre').fetchall()
    conn.close()
    
    return render_template('agendar_cita_paciente.html', medicos=medicos)

@app.route('/confirmar_cita/<int:cita_id>', methods=['POST'])
@login_required
def confirmar_cita(cita_id):
    """Confirma una cita por parte del paciente"""
    if session.get('user_type') != 'paciente':
        return jsonify({'success': False, 'message': 'Acceso denegado'})
    
    conn = get_db_connection()
    
    # Verificar que la cita pertenece al paciente
    cita = conn.execute(
        '''SELECT c.*, p.cedula, p.email, p.nombre as paciente_nombre, m.nombre as medico_nombre
           FROM citas c
           JOIN pacientes p ON c.paciente_cedula = p.cedula
           JOIN medicos m ON c.medico_cedula = m.cedula
           WHERE c.id = ? AND p.cedula = ?''',
        (cita_id, session['user_cedula'])
    ).fetchone()
    
    if not cita:
        conn.close()
        return jsonify({'success': False, 'message': 'Cita no encontrada'})
    
    # Actualizar estado
    conn.execute(
        'UPDATE citas SET estado = ? WHERE id = ?',
        ('Confirmada', cita_id)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Cita confirmada'})

@app.route('/cancelar_cita/<int:cita_id>', methods=['POST'])
@login_required
def cancelar_cita(cita_id):
    """Cancela una cita por parte del paciente"""
    if session.get('user_type') != 'paciente':
        return jsonify({'success': False, 'message': 'Acceso denegado'})
    
    conn = get_db_connection()
    
    # Verificar que la cita pertenece al paciente
    cita = conn.execute(
        '''SELECT c.*, p.cedula FROM citas c
           JOIN pacientes p ON c.paciente_cedula = p.cedula
           WHERE c.id = ? AND p.cedula = ?''',
        (cita_id, session['user_cedula'])
    ).fetchone()
    
    if not cita:
        conn.close()
        return jsonify({'success': False, 'message': 'Cita no encontrada'})
    
    # Verificar que la cita no sea en las próximas 24 horas
    fecha_cita = datetime.strptime(f"{cita['fecha']} {cita['hora']}", '%Y-%m-%d %H:%M')
    if fecha_cita - datetime.now() < timedelta(hours=24):
        conn.close()
        return jsonify({'success': False, 'message': 'No se puede cancelar con menos de 24 horas de anticipación'})
    
    # Actualizar estado
    conn.execute(
        'UPDATE citas SET estado = ? WHERE id = ?',
        ('cancelada', cita_id)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Cita cancelada'})

# Configuración de email (agregar después de la configuración de la app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tu_email@gmail.com'  # Cambiar por tu email
app.config['MAIL_PASSWORD'] = 'tu_password'  # Cambiar por tu password

def enviar_email_async(app, destinatario, asunto, mensaje):
    """Envía email de forma asíncrona"""
    with app.app_context():
        try:
            msg = MIMEMultipart()
            msg['From'] = app.config['MAIL_USERNAME']
            msg['To'] = destinatario
            msg['Subject'] = asunto
            
            msg.attach(MIMEText(mensaje, 'html'))
            
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            print(f"Error enviando email: {e}")

def enviar_notificacion_cita(paciente_email, paciente_nombre, fecha, hora, medico, tipo='recordatorio'):
    """Envía notificación de cita por email"""
    if tipo == 'recordatorio':
        asunto = "Recordatorio de Cita Médica"
        mensaje = f"""
        <h3>Recordatorio de Cita Médica</h3>
        <p>Estimado/a {paciente_nombre},</p>
        <p>Le recordamos que tiene una cita médica programada:</p>
        <ul>
            <li><strong>Fecha:</strong> {fecha}</li>
            <li><strong>Hora:</strong> {hora}</li>
            <li><strong>Médico:</strong> Dr. {medico}</li>
        </ul>
        <p>Por favor, llegue 15 minutos antes de su cita.</p>
        <p>Si necesita cancelar o reprogramar, contáctenos con anticipación.</p>
        <br>
        <p>Saludos cordiales,<br>Sistema Hospitalario</p>
        """
    elif tipo == 'confirmacion':
        asunto = "Confirmación de Cita Médica"
        mensaje = f"""
        <h3>Cita Médica Confirmada</h3>
        <p>Estimado/a {paciente_nombre},</p>
        <p>Su cita médica ha sido confirmada exitosamente:</p>
        <ul>
            <li><strong>Fecha:</strong> {fecha}</li>
            <li><strong>Hora:</strong> {hora}</li>
            <li><strong>Médico:</strong> Dr. {medico}</li>
        </ul>
        <p>Gracias por confirmar su asistencia.</p>
        <br>
        <p>Saludos cordiales,<br>Sistema Hospitalario</p>
        """
    
    # Enviar email en un hilo separado
    thread = Thread(target=enviar_email_async, args=(app, paciente_email, asunto, mensaje))
    thread.start()

@app.route('/api/notificaciones')
@login_required
def get_notificaciones():
    """API para obtener notificaciones del paciente"""
    if session.get('user_type') != 'paciente':
        return jsonify({'notificaciones': []})
    
    conn = get_db_connection()
    
    # Obtener citas próximas (próximos 7 días)
    fecha_limite = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
    
    citas = conn.execute(
        '''SELECT c.*, p.nombre as paciente_nombre, m.nombre as medico_nombre, m.especialidad
           FROM citas c
           JOIN pacientes p ON c.paciente_cedula = p.cedula
           JOIN medicos m ON c.medico_cedula = m.cedula
           WHERE p.cedula = ? AND c.fecha >= ? AND c.fecha <= ? AND c.estado != 'cancelada'
           ORDER BY c.fecha, c.hora''',
        (session['user_cedula'], datetime.now().strftime('%Y-%m-%d'), fecha_limite)
    ).fetchall()
    
    conn.close()
    
    notificaciones = []
    for cita in citas:
        dias_restantes = (datetime.strptime(cita['fecha'], '%Y-%m-%d') - datetime.now()).days
        
        if dias_restantes == 0:
            mensaje = f"¡Hoy tienes cita con Dr. {cita['medico_nombre']} a las {cita['hora']}!"
        elif dias_restantes == 1:
            mensaje = f"Mañana tienes cita con Dr. {cita['medico_nombre']} a las {cita['hora']}"
        elif dias_restantes <= 3:
            mensaje = f"En {dias_restantes} días tienes cita con Dr. {cita['medico_nombre']}"
        else:
            continue
            
        notificaciones.append({
            'mensaje': mensaje,
            'fecha': cita['fecha'],
            'tipo': 'recordatorio'
        })
    
    return jsonify({'notificaciones': notificaciones})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)