require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();

// ---------- CONFIG BÁSICA ----------
app.use(cors());
app.use(express.json());

// ---------- ROTA DE TESTE ----------
app.get("/", (req, res) => {
  res.send("API online 🚀");
});

// ---------- CONEXÃO COM POSTGRES ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ---------- EMAIL (NODEMAILER) ----------
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),
  secure: false, // true para 465, false para outras portas
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

// ---------- FUNÇÕES AUXILIARES ----------
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
}

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------- MIDDLEWARE DE AUTENTICAÇÃO ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: "Token inválido." });
    req.user = user;
    next();
  });
}

// ================ ROTAS ================

// --------- REGISTER ---------
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ msg: "Preencha todos os campos." });

  try {
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ msg: "Email já cadastrado." });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hash]
    );

    return res.status(201).json({ msg: "Conta criada com sucesso.", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro no servidor." });
  }
});

// --------- LOGIN ---------
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ msg: "Preencha todos os campos." });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ msg: "Credenciais incorretas." });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ msg: "Credenciais incorretas." });

    const token = generateToken(user);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro no servidor." });
  }
});

// --------- FORGOT PASSWORD ---------
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ msg: "Informe o email." });

  try {
    const result = await pool.query("SELECT id, name FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ msg: "Email não encontrado." });

    const user = result.rows[0];
    const code = generateResetCode();
    // Ajuste de data para funcionar com timestamp do Postgres
    const expires = new Date(Date.now() + 15 * 60 * 1000); 

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3",
      [code, expires, user.id]
    );

    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "Redefinição de senha - Prof Smart",
      text: `Olá, ${user.name}!\n\nSeu código: ${code}\n\nVálido por 15 minutos.`
    });

    return res.json({ msg: "Código enviado para o email." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro ao enviar email." });
  }
});

// --------- RESET PASSWORD ---------
app.post("/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) return res.status(400).json({ msg: "Dados incompletos." });
  if (newPassword.length < 6) return res.status(400).json({ msg: "Senha curta demais." });

  try {
    const result = await pool.query("SELECT id, reset_token, reset_expires FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ msg: "Usuário não encontrado." });

    const user = result.rows[0];
    if (token !== user.reset_token) return res.status(400).json({ msg: "Código inválido." });
    
    const now = new Date();
    if (now > new Date(user.reset_expires)) return res.status(400).json({ msg: "Código expirado." });

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2",
      [newHash, user.id]
    );

    return res.json({ msg: "Senha alterada com sucesso." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro no servidor." });
  }
});

// ---------- STATS ROUTES ----------

// 1. ATUALIZAR ESTATÍSTICAS
app.post("/stats/update", authenticateToken, async (req, res) => {
  // gameType: 'matematica', 'computacao', 'portugues', 'historia'
  const { gameType, score, duration } = req.body;
  const userId = req.user.id;

  // Garantir que são números
  const numScore = parseInt(score, 10) || 0;
  const numDuration = parseFloat(duration) || 0;

  try {
    const check = await pool.query(
      "SELECT * FROM game_stats WHERE user_id = $1 AND game_type = $2",
      [userId, gameType]
    );

    if (check.rows.length === 0) {
      await pool.query(
        "INSERT INTO game_stats (user_id, game_type, total_hours, high_score, total_score) VALUES ($1, $2, $3, $4, $5)",
        [userId, gameType, numDuration, numScore, numScore]
      );
    } else {
      const current = check.rows[0];
      const newTotalHours = parseFloat(current.total_hours) + numDuration;
      const newTotalScore = parseInt(current.total_score, 10) + numScore;
      const newHighScore = numScore > current.high_score ? numScore : current.high_score;

      await pool.query(
        "UPDATE game_stats SET total_hours = $1, total_score = $2, high_score = $3 WHERE id = $4",
        [newTotalHours, newTotalScore, newHighScore, current.id]
      );
    }
    return res.json({ msg: "Stats updated" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro ao salvar stats." });
  }
});

// 2. BUSCAR DADOS DO USUÁRIO (PERFIL)
app.get("/stats/me", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      "SELECT game_type, total_hours, high_score, total_score FROM game_stats WHERE user_id = $1",
      [userId]
    );

    let stats = {
      scores: { matematica: 0, computacao: 0, portugues: 0, historia: 0 },
      highScores: { matematica: 0, computacao: 0, portugues: 0, historia: 0 },
      hours: { matematica: 0, computacao: 0, portugues: 0, historia: 0 }
    };

    result.rows.forEach(row => {
      const type = row.game_type;
      if (stats.scores[type] !== undefined) {
        stats.scores[type] = parseInt(row.total_score, 10);
        stats.highScores[type] = parseInt(row.high_score, 10);
        stats.hours[type] = parseFloat(row.total_hours);
      }
    });

    return res.json(stats);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro ao buscar perfil." });
  }
});

// 3. RANKING (TOP 1 de cada matéria)
app.get("/stats/ranking", async (req, res) => {
  try {
    const games = ['matematica', 'computacao', 'portugues', 'historia'];
    let ranking = {};

    for (const game of games) {
      const result = await pool.query(
        `SELECT u.name, gs.high_score 
         FROM game_stats gs
         JOIN users u ON gs.user_id = u.id
         WHERE gs.game_type = $1
         ORDER BY gs.high_score DESC
         LIMIT 1`,
        [game]
      );
      if (result.rows.length > 0) {
        ranking[game] = result.rows[0];
      } else {
        ranking[game] = { name: '---', high_score: 0 };
      }
    }
    return res.json(ranking);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Erro no ranking." });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));