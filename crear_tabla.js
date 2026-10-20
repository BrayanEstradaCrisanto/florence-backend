const mysql = require('mysql2/promise');

async function crearEstructuraFlorence() {
    try {
        console.log('Conectando a Clever Cloud...');
        const conexion = await mysql.createConnection({
            host: 'b9ncuylw4snwe9n6vq3m-mysql.services.clever-cloud.com',
            user: 'uj8k9l533oacch9r',
            password: 'AQ92xGBNptTHDt5bFt1z',
            database: 'b9ncuylw4snwe9n6vq3m',
            port: 3306,
            ssl: { rejectUnauthorized: false }
        });

        console.log('Creando tablas necesarias...');

        // 1. Tabla de vinculación entre Cuidador y Paciente
        await conexion.query(`
            CREATE TABLE IF NOT EXISTS vinculos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cuidador_id INT NOT NULL,
                paciente_id INT NOT NULL,
                estado ENUM('activo', 'pendiente') DEFAULT 'activo',
                fecha_vinculacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cuidador_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                FOREIGN KEY (paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                UNIQUE KEY vinculo_unico (cuidador_id, paciente_id)
            );
        `);

        // 2. Tabla de Medicamentos registrados por el cuidador
        await conexion.query(`
            CREATE TABLE IF NOT EXISTS medicamentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                paciente_id INT NOT NULL,
                cuidador_id INT NOT NULL,
                nombre VARCHAR(120) NOT NULL,
                dosis VARCHAR(80) NOT NULL,
                instrucciones VARCHAR(255) NULL,
                hora_programada TIME NOT NULL,
                activo BOOLEAN DEFAULT TRUE,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                FOREIGN KEY (cuidador_id) REFERENCES usuarios(id) ON DELETE CASCADE
            );
        `);

        // 3. Historial de tomas (para métricas y alertas en tiempo real)
        await conexion.query(`
            CREATE TABLE IF NOT EXISTS historial_tomas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                medicamento_id INT NOT NULL,
                paciente_id INT NOT NULL,
                fecha DATE NOT NULL,
                hora_programada TIME NOT NULL,
                hora_tomada TIME NULL,
                estado ENUM('pendiente', 'tomada', 'omitida') DEFAULT 'pendiente',
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (medicamento_id) REFERENCES medicamentos(id) ON DELETE CASCADE,
                FOREIGN KEY (paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE
            );
        `);

        console.log('✅ ¡TABLAS VINCULOS, MEDICAMENTOS E HISTORIAL_TOMAS CREADAS!');
        const [tablas] = await conexion.query('SHOW TABLES;');
        console.log('Tablas en la BD:', tablas);

        await conexion.end();
    } catch (error) {
        console.error('❌ Error al crear tablas:', error);
    }
}

crearEstructuraFlorence();