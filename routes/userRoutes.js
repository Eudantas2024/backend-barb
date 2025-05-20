const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();
const jwtSecret = process.env.JWT_SECRET;

// ✅ Registro de Usuário
router.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        const trimmedUsername = username.trim(); // ✅ Remove espaços extras

        // ✅ Verifica se o usuário já existe
        const existingUser = await User.findOne({ username: trimmedUsername });
        if (existingUser) {
            return res.status(400).json({ message: "❌ Usuário já cadastrado." });
        }

        // ✅ Criação do novo usuário com senha criptografada
        const hashedPassword = await bcrypt.hash(password.trim(), 10);
        const newUser = new User({ username: trimmedUsername, password: hashedPassword });
        await newUser.save();

        res.json({ message: "✅ Usuário registrado com sucesso!" });
    } catch (error) {
        console.error("❌ Erro ao registrar usuário:", error);
        res.status(500).json({ message: "❌ Erro interno no servidor." });
    }
});

// ✅ Login de Usuário
router.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const trimmedUsername = username.trim();
        const user = await User.findOne({ username: trimmedUsername });

        console.log(`🔍 Buscando usuário: ${trimmedUsername}`);
        console.log("✅ Usuário encontrado:", user);


        if (!user) {
            console.log("❌ Usuário não encontrado!");
            return res.status(401).json({ message: "❌ Usuário não encontrado." });

        }
        console.log(`✅ Usuário encontrado: ${user.username}`);

        const validPassword = await bcrypt.compare(password.trim(), user.password);
        console.log(`🛠 Comparação de senha: ${validPassword}`);

        if (!validPassword) {
            return res.status(401).json({ message: "❌ Senha incorreta." });
        }

        // ✅ Gera o token corretamente
        const token = jwt.sign({ username: user.username, id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ message: "✅ Login bem-sucedido!", token });
    } catch (error) {
        console.error("❌ Erro ao realizar login:", error);
        res.status(500).json({ message: "❌ Erro interno no login." });
    }
});

// ✅ Middleware de autenticação JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "❌ Token inválido!" });
        }
        req.user = decoded;
        next();
    });
}

// ✅ Perfil do Usuário (Rota Protegida)
router.get("/profile", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");

        if (!user) {
            return res.status(404).json({ message: "❌ Usuário não encontrado." });
        }

        res.json(user);
    } catch (error) {
        console.error("❌ Erro ao buscar perfil do usuário:", error);
        res.status(500).json({ message: "❌ Erro interno ao buscar perfil." });
    }
});

module.exports = router;
