const mongoose = require('mongoose');

const UsuarioSchema = new mongoose.Schema({
  Nombre: String,
  Contraseña: String,
  "Pregunta de Recuperacion": String,
  "Respuesta de Recuperacion": String,
  refreshToken: String 
}, { collection: 'Usuarios' });

module.exports = mongoose.model('Usuario', UsuarioSchema);