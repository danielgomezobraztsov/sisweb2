const ApiKey = require('../models/ApiKey');

/**
 * Middleware de autenticación.
 * Lee el header X-API-Key y valida contra la colección apikeys.
 * Como fallback también acepta la variable de entorno API_KEY (útil en desarrollo).
 */
async function requireAuth(req, res, next) {
  const key = req.headers['x-api-key'];

  if (!key) {
    return res.status(401).json({ codigo: 401, texto: 'No autenticado', descripcion: 'Se requiere el header X-API-Key' });
  }

  // Fallback: clave definida en .env (para desarrollo/tests)
  if (process.env.API_KEY && key === process.env.API_KEY) {
    return next();
  }

  try {
    const apiKey = await ApiKey.findOne({ key, active: true });
    if (!apiKey) {
      return res.status(401).json({ codigo: 401, texto: 'No autenticado', descripcion: 'API Key inválida o inactiva' });
    }
    // Actualizar estadísticas de uso
    apiKey.usages += 1;
    apiKey.lastUsed = new Date();
    await apiKey.save();
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = requireAuth;
