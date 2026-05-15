const express = require('express');
const app = express();

// ── Middlewares globales ──────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Parser de cuerpos XML  (Content-Type: application/xml)
const { parseXmlBody } = require('./middleware/parseXml');
app.use(parseXmlBody);

// Cabeceras CORS básicas
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-API-Key');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Rutas ─────────────────────────────────────────────────────────────────────
app.use('/vulns', require('./routes/vulns'));

// Ruta de salud
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// 404 genérico
app.use((_req, res) => {
  res.status(404).json({ codigo: 404, texto: 'Ruta no encontrada' });
});

// Manejador de errores global
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ codigo: 500, texto: 'Error interno del servidor', descripcion: err.message });
});

module.exports = app;
