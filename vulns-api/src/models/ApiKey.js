const mongoose = require('mongoose');

/**
 * Colección: apikeys
 * Tercera colección del proyecto. Almacena las claves API para autenticar
 * las operaciones de escritura (POST, PUT, DELETE) sobre vulnerabilidades.
 */
const apiKeySchema = new mongoose.Schema({
  key:    { type: String, required: true, unique: true },
  name:   { type: String, required: true },
  active: { type: Boolean, default: true },
  usages: { type: Number, default: 0 },
  lastUsed: { type: Date },
}, {
  timestamps: true,
  toJSON: {
    transform(_doc, ret) {
      delete ret._id;
      delete ret.__v;
      // Nunca exponer la clave completa en respuestas
      ret.key = ret.key.slice(0, 8) + '****';
      return ret;
    },
  },
});

module.exports = mongoose.model('ApiKey', apiKeySchema);
