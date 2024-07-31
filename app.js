require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Configurar JSON Response
app.use(express.json());

// Models
const User = require("./models/User");

// Rota aberta - Rota pública
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API!" });
});

//Rota Privada
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // Checar se o usuário existe
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ msg: "Token inválido!" });
  }
}

// Registrar Usuário
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  // Validações
  if (!name) {
    return res.status(422).json({ msg: "o nome é obrigatório!" });
  }

  if (!email) {
    return res.status(422).json({ msg: "o email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "a senha é obrigatório!" });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "as senhas não conferem" });
  }

  // Chegar se o usuário existe
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "o email informado já está em uso!" });
  }

  // Criar senha
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Criar usuário
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    console.log(error);

    res.status(500).json({ msg: "Ocorreu um erro no servidor" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validação
  if (!email) {
    return res.status(422).json({ msg: "o email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "a senha é obrigatório!" });
  }

  // Checar se o usuário existe
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(422).json({ msg: "Usuário não encontrado" });
  }

  // Checando senhas
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
  } catch (err) {
    console.log(err);

    res.status(500).json({
      msg: "Ocorreu um erro no servidor!",
    });
  }
});

// Conexão com Banco de Dados
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    app.listen(3000);
    console.log("Conexão bem sucessida!");
  })
  .catch((err) => console.log(err));
