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
// 3. GESTIÓN DE MEDICAMENTOS Y ESTADOS
// ==========================================

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

// Consultar medicamentos de un paciente con cálculo dinámico de retraso
app.get('/api/medicamentos/hoy/:paciente_id', async (req, res) => {
    const { paciente_id } = req.params;

    // Fecha actual en formato YYYY-MM-DD según la hora local de México
    const fechaOpciones = { timeZone: 'America/Mexico_City', year: 'numeric', month: '2-digit', day: '2-digit' };
    const partesFecha = new Intl.DateTimeFormat('es-MX', fechaOpciones).formatToParts(new Date());
    const anio = partesFecha.find(p => p.type === 'year').value;
    const mes = partesFecha.find(p => p.type === 'month').value;
    const dia = partesFecha.find(p => p.type === 'day').value;
    const hoy = `${anio}-${mes}-${dia}`;

    try {
        const [medicamentos] = await db.query(`
            SELECT 
                m.id,
                m.nombre,
                m.dosis,
                m.instrucciones,
                TIME_FORMAT(m.hora_programada, '%H:%i') AS hora_programada,
                COALESCE(ht.estado, 'pendiente') AS estado_base,
                TIME_FORMAT(ht.hora_tomada, '%H:%i') AS hora_tomada
            FROM medicamentos m
            LEFT JOIN historial_tomas ht 
                ON m.id = ht.medicamento_id AND ht.fecha = ?
            WHERE m.paciente_id = ? AND m.activo = TRUE
            ORDER BY m.hora_programada ASC
        `, [hoy, paciente_id]);

        // Minutos transcurridos en el día actual (zona horaria CDMX)
        const ahora = new Date();
        const horaStr = ahora.toLocaleTimeString('es-MX', { timeZone: 'America/Mexico_City', hour12: false, hour: '2-digit', minute: '2-digit' });
        const [hActual, mActual] = horaStr.split(':').map(Number);
        const minutosActuales = hActual * 60 + mActual;

        const listaProcesada = medicamentos.map(med => {
            let estadoCalculado = med.estado_base;

            // Si está pendiente y ya transcurrieron más de 15 minutos de la hora programada
            if (estadoCalculado === 'pendiente') {
                const [hProg, mProg] = med.hora_programada.split(':').map(Number);
                const minutosProgramados = hProg * 60 + mProg;

                if (minutosActuales > minutosProgramados + 15) {
                    estadoCalculado = 'retrasada';
                }
            }

            return {
                id: med.id,
                nombre: med.nombre,
                dosis: med.dosis,
                instrucciones: med.instrucciones,
                hora_programada: med.hora_programada,
                estado_hoy: estadoCalculado,
                hora_tomada: med.hora_tomada
            };
        });

        const total = listaProcesada.length;
        const tomadas = listaProcesada.filter(m => m.estado_hoy === 'tomada').length;
        const retrasadas = listaProcesada.filter(m => m.estado_hoy === 'retrasada').length;
        const cumplimiento = total > 0 ? Math.round((tomadas / total) * 100) : 0;

        const ultimas = listaProcesada.filter(m => m.hora_tomada !== null);
        const ultimaToma = ultimas.length > 0 ? ultimas[ultimas.length - 1].hora_tomada : null;

        return res.json({
            success: true,
            metricas: {
                total,
                tomadas,
                retrasadas,
                cumplimiento: `${cumplimiento}%`,
                ultima_toma: ultimaToma ? `${ultimaToma} hrs` : '--:--'
            },
            medicamentos: listaProcesada
        });
    } catch (error) {
        console.error('Error al listar medicamentos:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al obtener medicamentos' });
    }
});

// Desactivar / Eliminar medicamento (Soft Delete)
app.delete('/api/medicamentos/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [resultado] = await db.query(
            'UPDATE medicamentos SET activo = FALSE WHERE id = ?',
            [id]
        );

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ success: false, mensaje: 'Medicamento no encontrado' });
        }

        return res.json({
            success: true,
            mensaje: 'Medicamento retirado del tratamiento con éxito'
        });
    } catch (error) {
        console.error('Error al retirar medicamento:', error);
        return res.status(500).json({ success: false, mensaje: 'Error interno al eliminar medicamento' });
    }
});

// Editar medicamento existente
app.put('/api/medicamentos/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, dosis, instrucciones, hora_programada } = req.body;

    if (!nombre || !dosis || !hora_programada) {
        return res.status(400).json({ success: false, mensaje: 'Nombre, dosis y horario son obligatorios' });
    }

    try {
        const [resultado] = await db.query(`
            UPDATE medicamentos 
            SET nombre = ?, dosis = ?, instrucciones = ?, hora_programada = ?
            WHERE id = ? AND activo = TRUE
        `, [nombre, dosis, instrucciones || '', hora_programada, id]);

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ success: false, mensaje: 'Medicamento no encontrado o inactivo' });
        }

        return res.json({
            success: true,
            mensaje: 'Tratamiento actualizado correctamente'
        });
    } catch (error) {
        console.error('Error al editar medicamento:', error);
        return res.status(500).json({ success: false, mensaje: 'Error al actualizar medicamento' });
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

    const fechaOpciones = { timeZone: 'America/Mexico_City', year: 'numeric', month: '2-digit', day: '2-digit' };
    const partesFecha = new Intl.DateTimeFormat('es-MX', fechaOpciones).formatToParts(new Date());
    const anio = partesFecha.find(p => p.type === 'year').value;
    const mes = partesFecha.find(p => p.type === 'month').value;
    const dia = partesFecha.find(p => p.type === 'day').value;
    const hoy = `${anio}-${mes}-${dia}`;

    const ahora = new Date().toLocaleTimeString('es-MX', { timeZone: 'America/Mexico_City', hour12: false });

    try {
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
            hora_tomada: ahora.slice(0, 5)
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