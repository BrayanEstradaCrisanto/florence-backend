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

// 1. ENDPOINT DE REGISTRO
app.post('/api/auth/registro', async (req, res) => {
    const { nombre, correo, contrasena, rol } = req.body;

    if (!nombre || !correo || !contrasena || !rol) {
        return res.status(400).json({ success: false, mensaje: 'Todos los campos son obligatorios' });
    }

    try {
        // Verificar si el correo ya existe
        const [existe] = await db.query('SELECT id FROM usuarios WHERE correo = ?', [correo]);
        if (existe.length > 0) {
            return res.status(409).json({ success: false, mensaje: 'El correo ya se encuentra registrado' });
        }

        // Cifrado de contraseña con bcrypt
        const salt = await bcrypt.genSalt(10);
        const passHash = await bcrypt.hash(contrasena, salt);

        // Insertar en la BD
        const [resultado] = await db.query(
            'INSERT INTO usuarios (nombre, correo, contrasena, rol) VALUES (?, ?, ?, ?)',
            [nombre, correo, passHash, rol]
        );

        // Generar Token JWT
        const token = jwt.sign(
            { id: resultado.insertId, rol: rol },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        return res.status(201).json({
            success: true,
            mensaje: 'Usuario registrado correctamente',
            token: token,
            usuario: {
                id: resultado.insertId,
                nombre,
                correo,
                rol
            }
        });
    } catch (error) {
        console.error('Error en registro:', error);
        return res.status(500).json({ success: false, mensaje: 'Error interno del servidor' });
    }
});

// 2. ENDPOINT DE LOGIN
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

        // Comparar contraseña con el hash
        const coincide = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!coincide) {
            return res.status(401).json({ success: false, mensaje: 'Credenciales inválidas' });
        }

        // Generar Token JWT
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor de Florence corriendo en http://localhost:${PORT}`);
});