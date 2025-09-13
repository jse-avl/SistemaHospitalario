
## Instalación

### Prerrequisitos
- Python 3.7 o superior
- pip (gestor de paquetes de Python)

### Pasos de Instalación

1. **Clonar o descargar el proyecto**
   ```bash
   git clone <url-del-repositorio>
   cd Hospital
   ```

2. **Crear entorno virtual (recomendado)**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

4. **Inicializar la base de datos**
   ```bash
   python app.py
   ```

## Configuración

### Base de Datos
El sistema utiliza SQLite y se inicializa automáticamente al ejecutar la aplicación por primera vez.

### Configuración de Email (Opcional)
Para habilitar notificaciones por email, editar las siguientes líneas en `app.py`:

```python
app.config['MAIL_USERNAME'] = 'tu_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'tu_password'
```

## Uso

### Ejecutar la Aplicación
```bash
python app.py
```

La aplicación estará disponible en: `http://localhost:5000`

### Usuarios por Defecto
El sistema se inicializa con usuarios de ejemplo:

**Administrador:**
- Usuario: admin
- Contraseña: admin123

**Médico:**
- Usuario: medico1
- Contraseña: medico123

**Paciente:**
- Usuario: paciente1
- Contraseña: paciente123

### Funcionalidades por Rol

#### Administrador
- Gestión completa de usuarios
- Visualización de todas las citas
- Creación de nuevos pacientes y médicos
- Acceso a estadísticas generales
- Exportación de reportes

#### Médico
- Visualización de sus citas programadas
- Confirmación y cancelación de citas
- Acceso al historial de pacientes
- Gestión de su perfil profesional

#### Paciente
- Agendar nuevas citas
- Visualizar sus citas programadas
- Cancelar citas propias
- Actualizar información personal
- Acceso a su historial médico

## API Endpoints

### Autenticación
- `POST /login` - Iniciar sesión
- `GET /logout` - Cerrar sesión
- `POST /register_patient` - Registro de pacientes

### Gestión de Citas
- `GET /citas` - Listar citas
- `POST /citas/nueva` - Crear nueva cita
- `POST /confirmar_cita/<id>` - Confirmar cita
- `POST /cancelar_cita/<id>` - Cancelar cita
- `GET /api/citas/disponibilidad` - Verificar disponibilidad

### Gestión de Usuarios
- `GET /pacientes` - Listar pacientes
- `POST /pacientes/nuevo` - Crear nuevo paciente
- `GET /medicos` - Listar médicos

### Exportación
- `GET /citas/exportar/pdf` - Exportar citas a PDF
- `GET /citas/exportar/excel` - Exportar citas a Excel

## Características de Seguridad

- Autenticación basada en sesiones
- Hash seguro de contraseñas con Werkzeug
- Validación de permisos por rol
- Protección CSRF en formularios
- Validación de datos de entrada
- Sanitización de consultas SQL

## Contribución

1. Fork del proyecto
2. Crear rama para nueva funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## Soporte

Para reportar bugs o solicitar nuevas funcionalidades, crear un issue en el repositorio del proyecto.

## Versión

Versión actual: 1.0.0

## Changelog

### v1.0.0
- Implementación inicial del sistema
- Gestión básica de usuarios y citas
- Dashboard personalizado por roles
- Sistema de notificaciones
- Exportación de datos
- Interfaz responsive