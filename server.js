const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("./models/User"); 
const Opiniao = require("./models/Opiniao"); 

const app = express();
app.use(cors());
app.use(bodyParser.json());

const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

mongoose.connect(mongoURI)
  .then(() => console.log("✅ Conectado ao MongoDB!"))
  .catch((err) => {
    console.error("❌ Erro na conexão:", err);
    process.exit(1);
  });

function authenticateToken(req, res, next) {
    const token = req.headers["authorization"]?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "❌ Token não encontrado." });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: "❌ Token inválido!" });
        req.user = user;
        next();
    });
}

const userRoutes = require("./routes/userRoutes");
app.use("/api/users", userRoutes);

const opinioesRoute = require("./routes/opinioes");
app.use("/api/opinioes", opinioesRoute);

app.get("/api/conteudo", authenticateToken, (req, res) => {
    res.json({ message: "✅ Conteúdo carregado com sucesso!" });
});

// ✅ Rota para buscar uma reclamação por ID
app.get("/api/opinioes/:id", async (req, res) => {
    try {
        const reclamacao = await Opiniao.findById(req.params.id);
        if (!reclamacao) return res.status(404).json({ message: "❌ Reclamação não encontrada!" });
        res.json(reclamacao);
    } catch (error) {
        res.status(500).json({ message: "❌ Erro interno ao buscar reclamação." });
    }
});

app.listen(process.env.PORT || 3000, () => console.log("🚀 Servidor rodando!"));
