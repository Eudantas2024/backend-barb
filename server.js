require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "segredo";

app.use(cors());
app.use(express.json());

// ========================== CONEXÃO COM MONGODB ==========================
async function startDatabase() {
  const { DB_USER, DB_PASS, DB_NAME } = process.env;

  const uri = `mongodb+srv://${DB_USER}:${DB_PASS}@barbearia.zreebsk.mongodb.net/${DB_NAME}?retryWrites=true&w=majority&appName=barbearia`;

  try {
    await mongoose.connect(uri);
    console.log("✅ Conectado ao MongoDBAtlas");
  } catch (error) {
    console.error("❌ Erro ao conectar ao MongoDB:", error.message);
    process.exit(1); // Encerra o servidor se a conexão falhar
  }
}
startDatabase();

// ========================== MODELOS SCHEMAS MONGO DB==========================
// usuarios
const usuarioSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Usuario = mongoose.model("Usuario", usuarioSchema);


// empresas
const empresaSchema = new mongoose.Schema({
  empresa: String,
  comentario: String,
  aprovado: { type: Boolean, default: false }
}, { timestamps: true });

const Empresa = mongoose.model("Empresa", empresaSchema);


// consumidores
const consumidorSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  senha: { type: String, required: true },
  anotacoes: { type: String, default: "" } // <-- campo de anotações pessoais
});
const Consumidor = mongoose.model("Consumidor", consumidorSchema);


// ========================== MIDDLEWARE ==========================
// moderadores
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

//consumidores
function autenticarConsumidor(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token não fornecido." });

  jwt.verify(token, SECRET, (err, usuario) => {
    if (err || usuario.tipo !== "consumidor")
      return res.status(403).json({ message: "Acesso negado ao consumidor." });

    req.usuario = usuario;
    next();
  });
}


// ========================== ROTAS de login ==========================
app.get("/", (req, res) => {
  res.send("API Opina + online.");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const usuarioExistente = await Usuario.findOne({ username });
    if (usuarioExistente)
      return res.status(400).json({ message: "Usuário já existe." });

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

app.get("/api/empresas", async (req, res) => {
  try {
    const opinioes = await Empresa.find({ aprovado: true }).sort({ createdAt: -1 });
    res.json(opinioes);
  } catch (err) {
    console.error("Erro ao buscar opiniões:", err);
    res.status(500).json({ message: "Erro ao buscar opiniões." });
  }
});

app.post("/api/empresas", async (req, res) => {
  const { empresa, comentario } = req.body;
  if (!empresa || !comentario)
    return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const novaOpiniao = new Empresa({ empresa, comentario });
    await novaOpiniao.save();
    res.status(201).json({ message: "Opinião registrada para moderação." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao salvar opinião." });
  }
});

app.delete("/api/empresas/:id", autenticarToken, async (req, res) => {
  try {
    const opiniao = await Empresa.findOne({ _id: req.params.id, aprovado: true });

    if (!opiniao) {
      return res.status(404).json({ message: "Opinião aprovada não encontrada." });
    }

    await Empresa.findByIdAndDelete(req.params.id);
    res.json({ message: "Opinião aprovada excluída com sucesso." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao excluir opinião aprovada." });
  }
});


app.delete("/api/moderar/:id", autenticarToken, async (req, res) => {
  try {
    await Empresa.findByIdAndDelete(req.params.id);
    res.json({ message: "Opinião excluída com sucesso." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao excluir opinião." });
  }
});

// === CORREÇÃO AQUI: corrigido "criadoEm" para "createdAt"
app.get("/api/moderar", autenticarToken, async (req, res) => {
  try {
    const pendentes = await Empresa.find({ aprovado: false }).sort({ createdAt: -1 });
    res.json(pendentes);
  } catch (err) {
    res.status(500).json({ message: "Erro ao buscar opiniões pendentes." });
  }
});

app.put("/api/moderar/:id", autenticarToken, async (req, res) => {
  try {
    await Empresa.findByIdAndUpdate(req.params.id, { aprovado: true });
    res.json({ message: "Opinião aprovada." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao aprovar opinião." });
  }
});


// Registro de consumidor
app.post("/consumidor/register", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const existente = await Consumidor.findOne({ email });
    if (existente) return res.status(400).json({ message: "Consumidor já existe." });

    const hash = await bcrypt.hash(senha, 10);
    const novo = new Consumidor({ email, senha: hash });
    await novo.save();
    res.status(201).json({ message: "Consumidor registrado com sucesso." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao registrar consumidor." });
  }
});

// Login de consumidor
app.post("/consumidor/login", async (req, res) => {
  const { email, senha } = req.body;
  try {
    const consumidor = await Consumidor.findOne({ email });
    if (!consumidor) return res.status(401).json({ message: "Consumidor não encontrado." });

    const senhaValida = await bcrypt.compare(senha, consumidor.senha);
    if (!senhaValida) return res.status(401).json({ message: "Senha incorreta." });

    const token = jwt.sign({ id: consumidor._id, tipo: "consumidor" }, SECRET, { expiresIn: "2h" });
    res.status(200).json({ message: "Login bem-sucedido.", token });
  } catch {
    res.status(500).json({ message: "Erro ao efetuar login." });
  }
});

// Buscar anotações do consumidor autenticado
app.get("/consumidor/anotacoes", autenticarConsumidor, async (req, res) => {
  try {
    const consumidor = await Consumidor.findById(req.usuario.id);
    res.json({ anotacoes: consumidor.anotacoes });
  } catch (err) {
    res.status(500).json({ message: "Erro ao buscar anotações." });
  }
});

// Atualizar as anotações
app.put("/consumidor/anotacoes", autenticarConsumidor, async (req, res) => {
  try {
    const { anotacoes } = req.body;
    await Consumidor.findByIdAndUpdate(req.usuario.id, { anotacoes });
    res.json({ message: "Anotações salvas com sucesso." });
  } catch (err) {
    res.status(500).json({ message: "Erro ao salvar anotações." });
  }
});



// ========================== INICIAR SERVIDOR ==========================
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
