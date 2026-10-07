const mysql = require('mysql2/promise');
require('dotenv').config();

async function probar() {
    console.log('Intentando conectar con Clever Cloud...');
    try {
        const conexion = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: Number(process.env.DB_PORT) || 3306,
            ssl: { rejectUnauthorized: false }
        });

        console.log('🟢 ¡CONEXIÓN EXITOSA A CLEVER CLOUD!');

        // Preguntamos qué tablas existen actualmente en la base de datos
        const [tablas] = await conexion.query('SHOW TABLES;');
        console.log('Tablas encontradas en la nube:', tablas);

        await conexion.end();
    } catch (error) {
        console.error('🔴 ERROR DE CONEXIÓN:', error.message);
    }
}

probar();