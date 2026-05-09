require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json()); // permite receber dados do json

// rota de teste
app.get('/', (req, res) => {
    res.setEncoding('API do sistema rodando com sucesso!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {    
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    require('./db'); // importa a conexão com o banco de dados
});