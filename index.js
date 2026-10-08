const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';

// ==========================================
// 1. AUTENTICACIÓN (REGISTRO Y LOGIN)
// ==========================================

app.post('/api/auth/registro', async (req, res) => {
    const { nombre, correo, contrasena, rol } = req.body;

    if (!nombre || !correo || !contrasena || !rol) {
        return res.status(400).json({ success: false, mensaje: 'Todos los campos son obligatorios' });
    }

    try {
        const [existe] = await db.query('SELECT id FROM usuarios WHERE correo = ?', [correo]);
        if (existe.length > 0) {
            return res.status(409).json({ success: false, mensaje: 'El correo ya se encuentra registrado' });
        }

        const salt = await bcrypt.genSalt(10);
        const passHash = await bcrypt.hash(contrasena, salt);

        const [resultado] = await db.query(
            'INSERT INTO usuarios (nombre, correo, contrasena, rol) VALUES (?, ?, ?, ?)',
            [nombre, correo, passHash, rol]
        );

        const token = jwt.sign(
            { id: resultado.insertId, rol: rol },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        return res.status(201).json({
            success: true,
            mensaje: 'Usuario registrado correctamente',
            token: token,
            usuario: { id: resultado.insertId, nombre, correo, rol }
        });
    } catch (error) {
        console.error('Error en registro:', error);
        return res.status(500).json({ success: false, mensaje: 'Error interno del servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ success: false, mensaje: 'Ingresa correo y contraseña' });
    }

    try {
        const [usuarios] = await db.query('SELECT * FROM usuarios WHERE correo = ?', [correo]);
        if (usuarios.length === 0) {
            return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
        }

        const usuario = usuarios[0];
        const coincide = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!coincide) {
            return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { id: usuario.id, rol: usuario.rol },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        return res.json({
            success: true,
            mensaje: 'Inicio de sesión exitoso',
            token: token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                correo: usuario.correo,
                rol: usuario.rol
            }
        });
    } catch (error) {
        console.error('Error en login:', error);
        return res.status(500).json({ success: false, mensaje: 'Error interno del servidor' });
    }
});

// ==========================================
// 2. VINCULACIÓN ENTRE CUIDADOR Y PACIENTE
// ==========================================

// El cuidador vincula a un paciente por su correo electrónico
app.post('/api/vinculos/enlazar', async (req, res) => {
    const { cuidador_id, correo_paciente } = req.body;

    if (!cuidador_id || !correo_paciente) {
        return res.status(400).json({ success: false, mensaje: 'Faltan datos de vinculación' });
    }

    try {
        const [pacientes] = await db.query(
            "SELECT id, nombre, correo FROM usuarios WHERE correo = ? AND rol = 'paciente'",
            [correo_paciente.trim()]
        );

        if (pacientes.length === 0) {
            return res.status(404).json({ success: false, mensaje: 'No existe un paciente con ese correo' });
        }

        const paciente = pacientes[0];

        // Guardar o actualizar la vinculación
        await db.query(`
            INSERT INTO vinculos (cuidador_id, paciente_id, estado)
            VALUES (?, ?, 'activo')
            ON DUPLICATE KEY UPDATE estado = 'activo'
        `, [cuidador_id, paciente.id]);

        return res.json({
            success: true,
            mensaje: `¡Vinculado exitosamente con ${paciente.nombre}!`,
            paciente: paciente
        });
    } catch (error) {
        console.error('Error en vinculación:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al vincular usuarios' });
    }
});

// Obtener el paciente asignado al cuidador
app.get('/api/vinculos/paciente-de/:cuidador_id', async (req, res) => {
    const { cuidador_id } = req.params;

    try {
        const [rows] = await db.query(`
            SELECT u.id, u.nombre, u.correo
            FROM vinculos v
            JOIN usuarios u ON v.paciente_id = u.id
            WHERE v.cuidador_id = ? AND v.estado = 'activo'
            LIMIT 1
        `, [cuidador_id]);

        if (rows.length === 0) {
            return res.json({ success: false, vinculado: false, mensaje: 'Sin paciente vinculado aún' });
        }

        return res.json({ success: true, vinculado: true, paciente: rows[0] });
    } catch (error) {
        console.error('Error al obtener paciente:', error);
        return res.status(500).json({ success: false, mensaje: 'Error de servidor' });
    }
});

// ==========================================
// 3. GESTIÓN DE MEDICAMENTOS
// ==========================================

// Agregar medicamento (acción realizada por el cuidador)
app.post('/api/medicamentos', async (req, res) => {
    const { paciente_id, cuidador_id, nombre, dosis, instrucciones, hora_programada } = req.body;

    if (!paciente_id || !cuidador_id || !nombre || !dosis || !hora_programada) {
        return res.status(400).json({ success: false, mensaje: 'Todos los campos obligatorios deben completarse' });
    }

    try {
        const [resultado] = await db.query(`
            INSERT INTO medicamentos (paciente_id, cuidador_id, nombre, dosis, instrucciones, hora_programada)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [paciente_id, cuidador_id, nombre, dosis, instrucciones || '', hora_programada]);

        return res.status(201).json({
            success: true,
            mensaje: 'Medicamento guardado con éxito',
            medicamento_id: resultado.insertId
        });
    } catch (error) {
        console.error('Error al guardar medicamento:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al registrar medicamento' });
    }
});

// Consultar medicamentos de un paciente con el estado de HOY
app.get('/api/medicamentos/hoy/:paciente_id', async (req, res) => {
    const { paciente_id } = req.params;
    const hoy = new Date().toISOString().slice(0, 10); // Formato YYYY-MM-DD

    try {
        const [medicamentos] = await db.query(`
            SELECT 
                m.id,
                m.nombre,
                m.dosis,
                m.instrucciones,
                TIME_FORMAT(m.hora_programada, '%H:%i') AS hora_programada,
                COALESCE(ht.estado, 'pendiente') AS estado_hoy,
                TIME_FORMAT(ht.hora_tomada, '%H:%i') AS hora_tomada
            FROM medicamentos m
            LEFT JOIN historial_tomas ht 
                ON m.id = ht.medicamento_id AND ht.fecha = ?
            WHERE m.paciente_id = ? AND m.activo = TRUE
            ORDER BY m.hora_programada ASC
        `, [hoy, paciente_id]);

        // Métricas rápidas
        const total = medicamentos.length;
        const tomadas = medicamentos.filter(m => m.estado_hoy === 'tomada').length;
        const cumplimiento = total > 0 ? Math.round((tomadas / total) * 100) : 0;
        
        // Última toma registrada hoy
        const ultimas = medicamentos.filter(m => m.hora_tomada !== null);
        const ultimaToma = ultimas.length > 0 ? ultimas[ultimas.length - 1].hora_tomada : null;

        return res.json({
            success: true,
            metricas: {
                total,
                tomadas,
                cumplimiento: `${cumplimiento}%`,
                ultima_toma: ultimaToma ? `${ultimaToma} hrs` : '--:--'
            },
            medicamentos
        });
    } catch (error) {
        console.error('Error al listar medicamentos:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al obtener medicamentos' });
    }
});

// ==========================================
// 4. CONFIRMAR TOMA (ACCIÓN DEL PACIENTE)
// ==========================================

app.post('/api/tomas/confirmar', async (req, res) => {
    const { medicamento_id, paciente_id } = req.body;

    if (!medicamento_id || !paciente_id) {
        return res.status(400).json({ success: false, mensaje: 'Faltan parámetros de toma' });
    }

    const hoy = new Date().toISOString().slice(0, 10);
    // Hora actual del servidor formateada como HH:MM:SS
    const ahora = new Date().toTimeString().split(' ')[0];

    try {
        // Verificar si ya existe registro de hoy o si se crea nuevo
        const [existe] = await db.query(
            'SELECT id FROM historial_tomas WHERE medicamento_id = ? AND fecha = ?',
            [medicamento_id, hoy]
        );

        if (existe.length > 0) {
            await db.query(`
                UPDATE historial_tomas
                SET estado = 'tomada', hora_tomada = ?
                WHERE id = ?
            `, [ahora, existe[0].id]);
        } else {
            // Obtenemos la hora programada original del medicamento
            const [med] = await db.query('SELECT hora_programada FROM medicamentos WHERE id = ?', [medicamento_id]);
            const horaProg = med.length > 0 ? med[0].hora_programada : ahora;

            await db.query(`
                INSERT INTO historial_tomas (medicamento_id, paciente_id, fecha, hora_programada, hora_tomada, estado)
                VALUES (?, ?, ?, ?, ?, 'tomada')
            `, [medicamento_id, paciente_id, hoy, horaProg, ahora]);
        }

        return res.json({
            success: true,
            mensaje: '¡Toma confirmada correctamente!',
            hora_tomada: ahora.slice(0, 5) // HH:MM
        });
    } catch (error) {
        console.error('Error al confirmar toma:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al registrar la toma' });
    }
});

// ==========================================
// INICIO DEL SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor de Florence corriendo en http://localhost:${PORT}`);
});