// backend/index.js

// --- 1. IMPORTAÇÕES ---
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
require('dotenv').config();


// --- 2. CONFIGURAÇÕES E INICIALIZAÇÕES ---
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'seu-segredo-super-secreto';

// Conexão com o Banco de Dados
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Cliente OAuth2 do Google
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'http://localhost:3001/google/auth/callback' // Esta URL pode precisar de ser atualizada para produção mais tarde
);


// --- 3. MIDDLEWARES ---
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'https://catalogo-fc-frontend.vercel.app', // URL do frontend no Vercel
    // Adicione outras origens se necessário
  ],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

const verifyAdminToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token é necessário para autenticação.');
  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    req.admin = decoded;
  } catch (err) {
    return res.status(401).send('Token inválido.');
  }
  return next();
};


// --- 4. ROTAS DA API ---

// Rota de Login do Vendedor
app.post('/api/login/vendedor', async (req, res) => {
    // ... (o seu código desta rota permanece igual)
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json('Email e senha são obrigatórios.');
    try {
        const result = await pool.query('SELECT * FROM vendedores WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json('Credenciais inválidas.');
        const vendedor = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, vendedor.password_hash);
        if (!senhaValida) return res.status(401).json('Credenciais inválidas.');
        const hoje = new Date();
        const dataVencimento = new Date(vendedor.data_vencimento);
        dataVencimento.setUTCHours(23, 59, 59, 999);
        if (hoje > dataVencimento) {
            return res.status(403).json('Acesso bloqueado: sua mensalidade está vencida.');
        }
        res.json({ message: 'Login bem-sucedido!' });
    } catch (err) {
        res.status(500).send('Erro no servidor.');
    }
});

// Rota de Login do Admin
app.post('/api/admin/login', async (req, res) => {
    // ... (o seu código desta rota permanece igual, com os logs de depuração)
    try {
        const { email, senha } = req.body;
        const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json('Acesso negado.');
        const admin = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, admin.password_hash);
        if (!senhaValida) return res.status(401).json('Acesso negado.');
        const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token });
    } catch (err) {
        res.status(500).send('Erro no servidor.');
    }
});

// Rotas de gerenciamento do Admin (Vendedores e Times)
app.post('/api/admin/vendedores', verifyAdminToken, async (req, res) => {
    // ... (o seu código desta rota permanece igual)
    const { nome, email, senha } = req.body;
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(senha, salt);
    const data_vencimento = new Date();
    data_vencimento.setDate(data_vencimento.getDate() + 30);
    try {
        const novoVendedor = await pool.query('INSERT INTO vendedores (nome, email, password_hash, data_vencimento) VALUES ($1, $2, $3, $4) RETURNING *', [nome, email, password_hash, data_vencimento]);
        res.status(201).json(novoVendedor.rows[0]);
    } catch (err) {
        res.status(500).json('Erro ao cadastrar vendedor. O email já pode existir.');
    }
});

app.post('/api/admin/times', verifyAdminToken, async (req, res) => {
    // ... (o seu código desta rota permanece igual)
    const { nome_time, link_fotos, url_escudo } = req.body;
    try {
        const novoTime = await pool.query('INSERT INTO times (nome_time, link_fotos, url_escudo) VALUES ($1, $2, $3) RETURNING *', [nome_time, link_fotos, url_escudo]);
        res.status(201).json(novoTime.rows[0]);
    } catch (err) {
        res.status(500).json('Erro ao cadastrar time.');
    }
});

// Rota pública do Catálogo (para listar os times)
app.get('/api/times', async (req, res) => {
    // ... (o seu código desta rota permanece igual)
    try {
        const { rows } = await pool.query('SELECT id, nome_time, link_fotos, url_escudo FROM times ORDER BY nome_time ASC');
        res.json(rows);
    } catch (err) {
        res.status(500).send('Server error');
    }
});


// Rota de visualização
app.get('/api/visualizar/:timeId', async (req, res) => {
  try {
    const { timeId } = req.params;
    const timeResult = await pool.query('SELECT link_fotos FROM times WHERE id = $1', [timeId]);
    if (timeResult.rows.length === 0) {
      return res.status(404).send('Time não encontrado.');
    }
    const albumId = timeResult.rows[0].link_fotos;

    // Define as credenciais no cliente OAuth2
    oauth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
    
    // Passa o cliente autenticado diretamente ao criar o serviço
    const photos = google.photoslibrary({ version: 'v1', auth: oauth2Client });

    const response = await photos.mediaItems.search({
      albumId: albumId,
      pageSize: 100
    });
    
    if (!response.data.mediaItems) {
      return res.json([]);
    }

    const imageUrls = response.data.mediaItems.map(item => item.baseUrl);
    res.json(imageUrls);

  } catch (error) {
    console.error("Erro ao buscar imagens do Google Photos:", error.response ? error.response.data : error.message);
    res.status(500).send("Erro ao buscar imagens.");
  }
});


// --- 5. INICIA O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

