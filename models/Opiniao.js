// Aqui consta o modelo da tabela que vai ser usada no banco de dados MongoDB Atlas


const mongoose = require('mongoose');  // <----  esse comando faz a conexão com o Banco de Dados na Nuvem.

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

module.exports = mongoose.model('Barb', OpiniaoSchema);  // <----- onde w está escrito 'Barb' é nome da colection que vai ser criada no mongodb

