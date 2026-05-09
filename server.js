require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db'); // Nosso arquivo de conexão com o banco

const app = express();

app.use(cors());
app.use(express.json());

// ==========================================
// ROTA 1: CADASTRAR UM NOVO USUÁRIO
// ==========================================
app.post('/registrar', async (req, res) => {
    const { login, senha } = req.body;

    try {
        // 1. Verifica se o usuário já existe no banco
        const [usuariosExistentes] = await pool.query('SELECT * FROM usuarios WHERE login = ?', [login]);
        if (usuariosExistentes.length > 0) {
            return res.status(400).json({ erro: 'Esse login já está em uso.' });
        }

        // 2. Criptografa a senha (ninguém vai ver a senha real no banco de dados)
        const salt = await bcrypt.genSalt(10);
        const senhaCriptografada = await bcrypt.hash(senha, salt);

        // 3. Salva no banco de dados TiDB
        const [resultado] = await pool.query(
            'INSERT INTO usuarios (login, senha) VALUES (?, ?)',
            [login, senhaCriptografada]
        );

        res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!', id: resultado.insertId });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro interno no servidor ao cadastrar.' });
    }
});

// ==========================================
// ROTA 2: FAZER LOGIN
// ==========================================
app.post('/login', async (req, res) => {
    const { login, senha } = req.body;

    try {
        // 1. Busca o usuário no banco
        const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE login = ?', [login]);

        if (usuarios.length === 0) {
            return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
        }

        const usuario = usuarios[0];

        // 2. Compara a senha digitada com a senha criptografada do banco
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        if (!senhaValida) {
            return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
        }

        // 3. Gera o Token de Acesso (JWT)
        const token = jwt.sign(
            { id: usuario.id, login: usuario.login },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } // O login dele vai durar 7 dias no celular
        );

        res.json({ mensagem: 'Login realizado com sucesso!', token });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro interno no servidor ao fazer login.' });
    }
});

// Inicializando o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});