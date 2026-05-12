require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const req = require('express/lib/request');

const app = express();

app.use(cors());
app.use(express.json());

// ==========================================
// MIDDLEWARE (O Segurança da Porta)
// ==========================================
function verificarToken(req, res, next) {
    // Pega o token que vem no cabeçalho da requisição
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Tira a palavra "Bearer " da frente

    if (!token) {
        return res.status(403).json({ erro: 'Acesso negado. Nenhum token fornecido.' });
    }

    // Verifica se o token é verdadeiro e não expirou
    jwt.verify(token, process.env.JWT_SECRET, (err, usuarioDecodificado) => {
        if (err) return res.status(401).json({ erro: 'Token inválido ou expirado.' });

        // Se deu tudo certo, guarda os dados do usuário (id) para usarmos na rota
        req.usuario = usuarioDecodificado;
        next(); // Libera a entrada!
    });
}

// ==========================================
// ROTA 1: CADASTRAR UM NOVO USUÁRIO
// ==========================================
app.post('/registrar', async (req, res) => {
    const { login, senha } = req.body;
    try {
        const [usuariosExistentes] = await pool.query('SELECT * FROM usuarios WHERE login = ?', [login]);
        if (usuariosExistentes.length > 0) {
            return res.status(400).json({ erro: 'Esse login já está em uso.' });
        }
        const salt = await bcrypt.genSalt(10);
        const senhaCriptografada = await bcrypt.hash(senha, salt);
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
        const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE login = ?', [login]);
        if (usuarios.length === 0) return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });

        const usuario = usuarios[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });

        const token = jwt.sign(
            { id: usuario.id, login: usuario.login },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ mensagem: 'Login realizado com sucesso!', token });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro interno no servidor ao fazer login.' });
    }
});

// ==========================================
// ROTA 3: CRIAR UM EMPRÉSTIMO (ROTA PROTEGIDA)
// ==========================================
app.post('/emprestimos', verificarToken, async (req, res) => {
    // Pegamos os dados do empréstimo que vieram do celular/Thunder Client
    const { nome_cliente, porcentagem_juros, valor_principal, valor_juros, data_inicial, data_vencimento } = req.body;

    // O pulo do gato: pegamos o ID do dono da conta direto do Token!
    const usuario_id = req.usuario.id;

    try {
        const [resultado] = await pool.query(
            `INSERT INTO emprestimos 
            (usuario_id, nome_cliente, porcentagem_juros, valor_principal, valor_juros, data_inicial, data_vencimento) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [usuario_id, nome_cliente, porcentagem_juros, valor_principal, valor_juros, data_inicial, data_vencimento]
        );

        res.status(201).json({ mensagem: 'Empréstimo registrado com sucesso!', id: resultado.insertId });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao criar empréstimo.' });
    }
});


// ==========================================
// ROTA 4: LISTAR OS EMPRÉSTIMOS DO USUÁRIO (GET)
// ==========================================
app.get('/emprestimos', verificarToken, async (req, res) => {
    const usuario_id = req.usuario.id;

    try {
        // busca todos os emprestimos do usuario logado e que estão ativos
        const [emprestimos] = await pool.query(
            'select * from emprestimos where usuario_id = ? and status = "ativo" order by data_vencimento asc', [usuario_id]
        );

        res.json(emprestimos);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao buscar os empréstimos.' });
    }
});

// ==========================================
// ROTA 5: QUITAR / FINALIZAR UM EMPRÉSTIMO (PUT)
// ==========================================
app.put('/emprestimos/:id/quitar', verificarToken, async (req, res) => {
    const emprestimo_id = req.params.id;
    const usuario_id = req.usuario.id;

    try {
        const [resultado] = await pool.query(
            'update emprestimos set status = "finalizado" where id = ? and usuario_id = ?', [emprestimo_id, usuario_id]
        );

        // verifica se ele tentou alterar algo que não existe ou não é dele
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ erro: 'Empréstimo não encontrado ou você não tem permissão.' });
        }
        res.json({ mensagem: 'Dinheiro na conta! Empréstimo quitado com sucesso.' });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao tentar finalizar o empréstimo.' });
    }
});

// ==========================================
// ROTA 6: ADICIONAR UMA NOVA TRANSAÇÃO (POST)
// ==========================================
app.post('/transacoes', verificarToken, async (req, res) => {
    const { tipo, valor, categoria, descricao, data_transacao, origem} = req.body;
    const usuario_id = req.usuario.id;

    try {
        const [resultado] = await pool.query(
            `insert into transacoes (usuario_id, tipo, valor, categoria, descricao, data_transacao, origem) values (?, ?, ?, ?, ?, ?, ?)`, [usuario_id, tipo, valor, categoria, descricao, data_transacao, origem]
        );
        res.status(201).json({ mensagem: 'Transação registrada com sucesso!', id: resultado.insertId });
    } catch (erro){
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao salvar a transação.' })
    }
});

// ==========================================
// ROTA 7: LISTAR TODAS AS TRANSAÇÕES (GET)
// ==========================================
app.get('/transacoes', verificarToken,async (req, res) => {
    const usuario_id = req.usuario.id;

    try {
        // busca os gastos e ganhos ordenados do mais recente
        const [transacoes] = await pool.query(
            'select * from transacoes where usuario_id = ? order by data_transacao desc', [usuario_id]
        );
        res.json(transacoes);
    } catch (erro){
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao buscar as transações.'})
    }
});

// ==========================================
// ROTA 8: RESUMO FINANCEIRO (DASHBOARD)
// ==========================================
app.get('/resumo', verificarToken, async (req, res) =>{
    const usuario_id = req.usuario.id;

    try {
        //soma todas as entradas (receitas)
        const [receitas] = await pool.query (
            'select sum(valor) as total_receitas from transacoes where usuario_id = ? and tipo = "receita"', [usuario_id]
        );

        // soma toas as saidas (despesas)
        const [despesas] = await pool.query (
            'select sum(valor) as total_despesas from transacoes where usuario_id = ? and tipo = "despesa"', [usuario_id]
        );

        // se não tiver nada, garante que o valor é 0
        const totalReceitas = receitas[0].total_receitas || 0;
        const totalDespesas = despesas[0].total_despesas || 0;

        // calcula o saldo
        const saldoCaixa = totalReceitas - totalDespesas;

        res.json({
            receitas: parseFloat(totalReceitas).toFixed(2),
            despesas: parseFloat(totalDespesas).toFixed(2),
            saldo: parseFloat(saldoCaixa).toFixed(2)
        });
    } catch (erro){
        console.error(erro);
        res.status(500).json({ erro: 'Erro ao gerar o resumo.'});
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});