// Aqui é a estação central do projeto, onde conectar todas as rotas CRUD:  GET, POST, PUT e DELETE.


const express = require('express');
const router = express.Router();
const Opiniao = require('../models/Opiniao');

// POST - registrar nova opinião
router.post('/', async (req, res) => {
  try {
    const novaOpiniao = new Opiniao(req.body);
    await novaOpiniao.save();
    res.status(201).json({ mensagem: 'Reclamação registrada com sucesso!' });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao registrar reclamação.' });
  }
});

// GET - listar todas as opiniões
router.get('/', async (req, res) => {
  try {
    const opinioes = await Opiniao.find().sort({ data: -1 });
    res.json(opinioes);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar opiniões.' });
  }
});

// DELETE - excluir uma opinião por ID
router.delete('/:id', async (req, res) => {
  try {
    const resultado = await Opiniao.findByIdAndDelete(req.params.id);
    if (resultado) {
      res.status(200).json({ mensagem: 'Reclamação excluída com sucesso!' });
    } else {
      res.status(404).json({ erro: 'Reclamação não encontrada.' });
    }
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao excluir reclamação.' });
  }
});

// PUT

// PUT - atualizar uma opinião por ID
router.put('/:id', async (req, res) => {
  try {
    const opiniaoAtualizada = await Opiniao.findByIdAndUpdate(req.params.id, req.body, { new: true });
    
    if (opiniaoAtualizada) {
      res.status(200).json({ mensagem: 'Reclamação atualizada com sucesso!', opiniao: opiniaoAtualizada });
    } else {
      res.status(404).json({ erro: 'Reclamação não encontrada.' });
    }
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao atualizar reclamação.' });
  }
});


module.exports = router;
