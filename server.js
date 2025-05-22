// BACKEND (server.js unificado)

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const SECRET = process.env.JWT_SECRET || "segredo";

app.use(cors());
app.use(express.json());

// Conexão com MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Conectado ao MongoDB"))
  .catch((err) => console.error("Erro na conexão com MongoDB:", err));

// ========================== MODELOS ==========================
const usuarioSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Usuario = mongoose.model("Usuario", usuarioSchema);

const opiniaoSchema = new mongoose.Schema({
  empresa: String,
  comentario: String,
  aprovado: { type: Boolean, default: false },
  criadoEm: { type: Date, default: Date.now }
});
const Opiniao = mongoose.model("Opiniao", opiniaoSchema);

// ========================== MIDDLEWARE ==========================
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token não fornecido." });

  jwt.verify(token, SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ message: "Token inválido." });
    req.usuario = usuario;
    next();
  });
}

// ========================== ROTAS PÚBLICAS ==========================
app.get("/", (req, res) => {
  res.send("API Opina + online.");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const usuarioExistente = await Usuario.findOne({ username });
    if (usuarioExistente) return res.status(400).json({ message: "Usuário já existe." });

    const hash = await bcrypt.hash(password, 10);
    const novoUsuario = new Usuario({ username, password: hash });
    await novoUsuario.save();
    res.status(201).json({ message: "Usuário registrado com sucesso." });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar usuário." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const usuario = await Usuario.findOne({ username });
    if (!usuario) return res.status(401).json({ message: "Usuário não encontrado." });

    const senhaValida = await bcrypt.compare(password, usuario.password);
    if (!senhaValida) return res.status(401).json({ message: "Senha incorreta." });

    const token = jwt.sign({ id: usuario._id }, SECRET, { expiresIn: "2h" });
    res.status(200).json({ message: "Login bem-sucedido.", token });
  } catch (error) {
    res.status(500).json({ message: "Erro ao efetuar login." });
  }
});

// ========================== ROTAS PROTEGIDAS ==========================
app.get("/api/conteudo", autenticarToken, (req, res) => {
  res.json({ message: "Conteúdo restrito acessado." });
});

app.get("/api/opinioes", async (req, res) => {
  try {
    const opinioes = await Opiniao.find({ aprovado: true }).sort({ criadoEm: -1 });
    res.json(opinioes);
  } catch (err) {
    res.status(500).json({ message: "Erro ao buscar opiniões." });
  }
});

app.post("/api/opinioes", async (req, res) => {
  const { empresa, comentario } = req.body;
  if (!empresa || !comentario) return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const novaOpiniao = new Opiniao({ empresa, comentario });
    await novaOpiniao.save();
    res.status(201).json({ message: "Opinião registrada para moderação." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao salvar opinião." });
  }
});

app.get("/api/moderar", autenticarToken, async (req, res) => {
  try {
    const pendentes = await Opiniao.find({ aprovado: false }).sort({ criadoEm: -1 });
    res.json(pendentes);
  } catch (err) {
    res.status(500).json({ message: "Erro ao buscar opiniões pendentes." });
  }
});

app.put("/api/moderar/:id", autenticarToken, async (req, res) => {
  try {
    await Opiniao.findByIdAndUpdate(req.params.id, { aprovado: true });
    res.json({ message: "Opinião aprovada." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao aprovar opinião." });
  }
});

// ========================== INICIAR SERVIDOR ==========================
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});
