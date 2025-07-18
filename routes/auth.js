const express = require('express');
const router = express.Router();
const Usuario = require('../models/Usuario');

// Ruta de login
router.post('/login', async (req, res) => {
  const { Nombre, Contraseña } = req.body;

  try {
    const usuario = await Usuario.findOne({ Nombre, Contraseña });

    if (!usuario) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    res.status(200).json({
      message: 'Login exitoso',
      usuario: {
        id: usuario._id,
        nombre: usuario.Nombre
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

//  Obtener pregunta de recuperación por nombre
router.post('/recuperar-pregunta', async (req, res) => {
  const { Nombre } = req.body;

  try {
    const usuario = await Usuario.findOne({ Nombre });

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.status(200).json({ pregunta: usuario['Pregunta de Recuperacion'] });
  } catch (error) {
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Validar respuesta para acceso y devolver contraseña
router.post('/recuperar-respuesta', async (req, res) => {
  const { Nombre, respuesta } = req.body;

  try {
    const usuario = await Usuario.findOne({ Nombre });

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    if (usuario['Respuesta de Recuperacion'] !== respuesta) {
      return res.status(401).json({ message: 'Respuesta incorrecta' });
    }

    // Acceso concedido y se devuelve la contraseña
    res.status(200).json({
      message: 'Respuesta correcta. Acceso concedido.',
      usuario: {
        id: usuario._id,
        nombre: usuario.Nombre,
        contraseña: usuario.Contraseña
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error del servidor' });
  }
});

//  Registrar nuevo usuario
router.post('/registrar', async (req, res) => {
  const { Nombre, Contraseña, Pregunta, Respuesta } = req.body;

  try {
    // Verificar si ya existe
    const usuarioExistente = await Usuario.findOne({ Nombre });
    if (usuarioExistente) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    // Crear nuevo usuario
    const nuevoUsuario = new Usuario({
      Nombre,
      Contraseña,
      "Pregunta de Recuperacion": Pregunta,
      "Respuesta de Recuperacion": Respuesta
    });

    await nuevoUsuario.save();

    // Asegúrate que aquí sólo envías la respuesta UNA vez y no hay ningún middleware que la modifique después

    return res.status(201).json({
      message: 'Usuario registrado exitosamente',
      usuario: {
        id: nuevoUsuario._id,
        nombre: nuevoUsuario.Nombre
      }
    });
  } catch (error) {
    console.error('Error en /registrar:', error);
    return res.status(500).json({ message: 'Error del servidor al registrar' });
  }
});


module.exports = router;
