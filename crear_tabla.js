const mysql = require('mysql2/promise');

async function iniciarBD() {
    try {
        const conexion = await mysql.createConnection({
            host: 'b9ncuylw4snwe9n6vq3m-mysql.services.clever-cloud.com',
            user: 'uj8k9l533oacch9r',
            password: 'AQ92xGBNptTHDt5bFt1z',
            database: 'b9ncuylw4snwe9n6vq3m',
            port: 3306,
            ssl: { rejectUnauthorized: false }
        });

        console.log('Conectado a Clever Cloud con éxito.');

        const sql = `
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                correo VARCHAR(150) NOT NULL UNIQUE,
                contrasena VARCHAR(255) NOT NULL,
                rol ENUM('cuidador', 'paciente') NOT NULL,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        await conexion.query(sql);
        console.log('¡Tabla "usuarios" creada correctamente en la nube!');
        await conexion.end();
    } catch (error) {
        console.error('Error al crear tabla:', error);
    }
}

iniciarBD();