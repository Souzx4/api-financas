require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

//  teste de conexao
pool.getConnection()
    .then(() => console.log('✅ Conectado ao banco TiDB com sucesso!'))
    .catch((err) => console.error('❌ Erro ao conectar ao banco TiDB:', err));

module.exports = pool;