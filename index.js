// backend/index.js

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // Para criptografar senhas
const jwt = require('jsonwebtoken'); // Para autenticação
require('dotenv').config();

// --- CONFIGURAÇÕES ---
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'seu-segredo-super-secreto'; // Crie essa variável no seu .env

// CONEXÃO COM BANCO DE DADOS
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- MIDDLEWARES ---
// backend/index.js

// Configuração do CORS
const corsOptions = {
  origin: [
    'http://localhost:3000', // Permite seu front-end local
    // Adicione aqui a URL do seu Vercel quando fizer o deploy
    // Ex: 'https://catalogo-fc.vercel.app' 
  ],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Middleware para verificar o token de admin
const verifyAdminToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token é necessário para autenticação.');

  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET); // Remove 'Bearer '
    req.admin = decoded;
  } catch (err) {
    return res.status(401).send('Token inválido.');
  }
  return next();
};


// --- ROTAS DA API ---

// == ROTA DE LOGIN DO VENDEDOR ==
app.post('/api/login/vendedor', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json('Email e senha são obrigatórios.');

  try {
    const result = await pool.query('SELECT * FROM vendedores WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json('Credenciais inválidas.');
    
    const vendedor = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, vendedor.password_hash);
    if (!senhaValida) return res.status(401).json('Credenciais inválidas.');

    const hoje = new Date();
    // Ajuste para garantir que a comparação de datas funcione corretamente
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


// == ROTAS DE ADMIN ==

// Rota para o Admin fazer login (para obter o token)
// Substitua a sua rota de login de admin por esta:
app.post('/api/admin/login', async (req, res) => {
  console.log('\n--- NOVA TENTATIVA DE LOGIN ADMIN ---');
  try {
    const { email, senha } = req.body;
    console.log('1. Dados recebidos do formulário:');
    console.log(`   Email: '${email}'`);
    console.log(`   Senha: '${senha}'`);

    const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    console.log('2. Resultado da busca no banco de dados:');

    if (result.rows.length === 0) {
      console.log('   !!! ERRO: Nenhum usuário encontrado no banco com este email.');
      return res.status(401).json('Acesso negado.');
    }
    
    const admin = result.rows[0];
    console.log('   => Usuário encontrado:', admin);

    console.log('3. Comparando senhas agora...');
    console.log(`   Senha recebida do formulário: '${senha}'`);
    console.log(`   Hash salvo no banco de dados: '${admin.password_hash}'`);

    // A mágica do bcrypt acontece aqui
    const senhaValida = await bcrypt.compare(senha, admin.password_hash);
    
    console.log('4. Resultado da comparação (bcrypt.compare):', senhaValida); // << ESTE É O LOG MAIS IMPORTANTE

    if (!senhaValida) {
      console.log('   !!! ERRO: As senhas não batem. O bcrypt.compare retornou false.');
      return res.status(401).json('Acesso negado.');
    }

    console.log('5. Sucesso! Gerando o token de acesso.');
    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });

  } catch (err) {
    console.error('!!! ERRO GERAL NO BLOCO TRY/CATCH:', err);
    res.status(500).send('Erro no servidor.');
  }
});

// Rota para cadastrar um novo vendedor (protegida)
app.post('/api/admin/vendedores', verifyAdminToken, async (req, res) => {
  const { nome, email, senha } = req.body;
  
  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(senha, salt);
  
  // Define a data de vencimento para 30 dias a partir de hoje
  const data_vencimento = new Date();
  data_vencimento.setDate(data_vencimento.getDate() + 30);
  
  try {
    const novoVendedor = await pool.query(
      'INSERT INTO vendedores (nome, email, password_hash, data_vencimento) VALUES ($1, $2, $3, $4) RETURNING *',
      [nome, email, password_hash, data_vencimento]
    );
    res.status(201).json(novoVendedor.rows[0]);
  } catch (err) {
    res.status(500).json('Erro ao cadastrar vendedor. O email já pode existir.');
  }
});

// Rota para cadastrar um novo time (protegida)
app.post('/api/admin/times', verifyAdminToken, async (req, res) => {
    const { nome_time, link_fotos, url_escudo } = req.body;
    try {
        const novoTime = await pool.query(
            'INSERT INTO times (nome_time, link_fotos, url_escudo) VALUES ($1, $2, $3) RETURNING *',
            [nome_time, link_fotos, url_escudo]
        );
        res.status(201).json(novoTime.rows[0]);
    } catch (err) {
        res.status(500).json('Erro ao cadastrar time.');
    }
});

// ROTA PÚBLICA do Catálogo (já tínhamos feito)
app.get('/api/times', async (req, res) => {
  console.log('\n--- TENTATIVA DE BUSCAR TIMES PARA O CATÁLOGO ---');
  try {
    console.log('1. Buscando dados da tabela "times"...');
    const { rows } = await pool.query('SELECT id, nome_time, link_fotos, url_escudo FROM times ORDER BY nome_time ASC');
    console.log(`2. Sucesso! Encontrados ${rows.length} times.`);
    res.json(rows);
  } catch (err) {
    console.error('!!! ERRO AO BUSCAR TIMES NO BANCO:', err);
    res.status(500).send('Server error');
  }
});

// --- INICIA O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// backend/index.js (adicione este bloco)
const { google } = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'http://localhost:3001/google/auth/callback' // URI de redirecionamento
);

// backend/index.js
// backend/index.js

app.get('/api/visualizar/:timeId', async (req, res) => {
  try {
    const { timeId } = req.params;

    // 1. Encontra o ID do álbum no nosso banco de dados
    const timeResult = await pool.query('SELECT link_fotos FROM times WHERE id = $1', [timeId]);
    if (timeResult.rows.length === 0) {
      return res.status(404).send('Time não encontrado.');
    }
    const albumId = timeResult.rows[0].link_fotos;

    // --- INÍCIO DA CORREÇÃO ---

    // 2. Define as credenciais no nosso cliente OAuth2
    oauth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });

    // 3. Define este cliente como o padrão de autenticação para as próximas chamadas da API do Google
    google.options({ auth: oauth2Client });

    // 4. Agora sim, cria o serviço do Photos Library
    const photos = google.photoslibrary({ version: 'v1' });

    // 5. Busca todas as imagens do álbum
    const response = await photos.mediaItems.search({
      albumId: albumId,
      pageSize: 100
    });

    // --- FIM DA CORREÇÃO -

    // Verifica se mediaItems existe antes de mapear
    if (!response.data.mediaItems) {
      return res.json([]); // Retorna uma lista vazia se o álbum não tiver fotos
    }

    const imageUrls = response.data.mediaItems.map(item => item.baseUrl);
    res.json(imageUrls);

  } catch (error) {
    // Agora vamos logar o erro da API do Google de forma mais detalhada
    console.error("Erro ao buscar imagens do Google Photos:", error.response ? error.response.data : error.message);
    res.status(500).send("Erro ao buscar imagens.");
  }
});