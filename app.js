require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');

const app = express();

// Configuração Json
app.use(express.json());

// Modelos
const User = require('./models/User')

// Principal Rota - Home
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo a nossa API!"})
})

// Rota privada
app.get("/user/:id", checkToken, async (req, res)=> {

    const id = req.params.id

    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(440).json({msg: 'Usuario não encontrado'})
    }

    res.status(200).json({user})
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'Acesso negado!'})
    }
    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error){
        res.status(400).json({msg: "Token inválido!"})
    }
}

// Registrar Usuario
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    // Validações
    if(!name) {
        return res.status(422).json({msg: "o nome é obrigatorio"})
    }
    if(!email) {
        return res.status(422).json({msg: "o email é obrigatorio"})
    }
    if(!password) {
        return res.status(422).json({msg: "a senha é obrigatoria"})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({msg: "as senhas não conferem"})
    }

    // Checando se o usuario existe
    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({msg: "Por favor, utilize outro e-mail"})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create usuario
    const user = new User ({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()
        res.status(201).json({msg: 'Usuario criado com sucesso!'})

    } catch(error) {
        console.log(error);

        res.status(500).json({msg: 'Aconteceu um erro no server.'})
    }
})

// Login usuario
app.post("/auth/login", async (req, res) => {

    const {email, password} = req.body
    
    // validações
    if(!email) {
        return res.status(422).json({msg: "o email é obrigatorio"})
    }
    if(!password) {
        return res.status(422).json({msg: "a senha é obrigatoria"})
    }

    // Checando se o usuario existe
    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(404).json({msg: 'Usuario não encontrado'})
    }

    // Checando as senhas
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha inválida'})
    }

    try {

        const secret = process.env.SECRET 

        const token = jwt.sign({
            id: user._id,
        }, secret)

        res.status(200).json({msg: "Autenticação realizada com sucesso", token})
    } catch(err) {
        console.log(error);

        res.status(500).json({msg: 'Aconteceu um erro no server.'})
    }

})

// Credencial
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@projectitalents.ajaepjc.mongodb.net/novoDB?retryWrites=true&w=majority`).then(() => {
    app.listen(3000)
    console.log('Conectou ao banco')
}).catch((err) => console.log(err));

