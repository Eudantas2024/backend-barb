require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const mongoURI = process.env.MONGO_URI;
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// 📦 Conexão com MongoDB
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Conectado ao MongoDB!"))
  .catch(err => console.error("❌ Erro na conexão:", err));

// 📄 Schema e Model - Usuário
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
}, { timestamps: true });

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("Usuarios", UserSchema);

// 📄 Schema e Model - Opinião
const OpiniaoSchema = new mongoose.Schema({
  nome: String,
  email: String,
  cep: String,
  logradouro: String,
  numero: String,
  complemento: String,
  bairro: String,
  cidade: String,
  uf: String,
  empresa: String,
  comentario: String,
  data: { type: Date, default: Date.now }
});

const Opiniao = mongoose.model("Clientes", OpiniaoSchema);

// 🔐 Middleware de autenticação JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "❌ Token não encontrado." });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: "❌ Token inválido!" });
        req.user = user;
        next();
    });
}

// ✅ Registro de Usuário
app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        const trimmedUsername = username.trim();
        const existingUser = await User.findOne({ username: trimmedUsername });

        if (existingUser) {
            return res.status(400).json({ message: "❌ Usuário já cadastrado." });
        }

        const newUser = new User({ username: trimmedUsername, password: password.trim() });
        await newUser.save();

        res.json({ message: "✅ Usuário registrado com sucesso!" });
    } catch (error) {
        console.error("❌ Erro ao registrar usuário:", error);
        res.status(500).json({ message: "❌ Erro interno no servidor." });
    }
});

// ✅ Login
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const trimmedUsername = username.trim();
        const user = await User.findOne({ username: trimmedUsername });

        if (!user) {
            return res.status(401).json({ message: "❌ Usuário não encontrado." });
        }

        const validPassword = await bcrypt.compare(password.trim(), user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "❌ Senha incorreta." });
        }

        const token = jwt.sign({ username: user.username, id: user._id }, jwtSecret, { expiresIn: "1h" });
        res.json({ message: "✅ Login bem-sucedido!", token });
    } catch (error) {
        console.error("❌ Erro ao realizar login:", error);
        res.status(500).json({ message: "❌ Erro interno no login." });
    }
});

// ✅ Rota protegida: perfil do usuário
app.get("/profile", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        if (!user) return res.status(404).json({ message: "❌ Usuário não encontrado." });

        res.json(user);
    } catch (error) {
        console.error("❌ Erro ao buscar perfil:", error);
        res.status(500).json({ message: "❌ Erro interno ao buscar perfil." });
    }
});

// ✅ CRUD de Opiniões (Clientes)

// Criar nova opinião
app.post('/api/opinioes', async (req, res) => {
  try {
    const novaOpiniao = new Opiniao(req.body);
    await novaOpiniao.save();
    res.status(201).json({ mensagem: '✅ Reclamação registrada com sucesso!' });
  } catch (err) {
    res.status(500).json({ erro: '❌ Erro ao registrar reclamação.' });
  }
});

// Listar opiniões
app.get('/api/opinioes', async (req, res) => {
  try {
    const opinioes = await Opiniao.find().sort({ data: -1 });
    res.json(opinioes);
  } catch (err) {
    res.status(500).json({ erro: '❌ Erro ao buscar opiniões.' });
  }
});

// Atualizar opinião por ID
app.put('/api/opinioes/:id', async (req, res) => {
  try {
    const opiniaoAtualizada = await Opiniao.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (opiniaoAtualizada) {
      res.status(200).json({ mensagem: '✅ Reclamação atualizada com sucesso!', opiniao: opiniaoAtualizada });
    } else {
      res.status(404).json({ erro: '❌ Reclamação não encontrada.' });
    }
  } catch (err) {
    res.status(500).json({ erro: '❌ Erro ao atualizar reclamação.' });
  }
});

// Deletar opinião por ID
app.delete('/api/opinioes/:id', async (req, res) => {
  try {
    const resultado = await Opiniao.findByIdAndDelete(req.params.id);
    if (resultado) {
      res.status(200).json({ mensagem: '✅ Reclamação excluída com sucesso!' });
    } else {
      res.status(404).json({ erro: '❌ Reclamação não encontrada.' });
    }
  } catch (err) {
    res.status(500).json({ erro: '❌ Erro ao excluir reclamação.' });
  }
});

// ✅ Iniciar servidor
app.listen(port, () => {
    console.log(`🚀 Servidor rodando na porta ${port}`);
});
