require('dotenv').config();
const app            = require('./app');
const connectDB      = require('./config/db');
const { startPeriodicSync } = require('./services/externalApi');

const PORT     = process.env.PORT || 3000;
const INTERVAL = parseInt(process.env.SYNC_INTERVAL) || 3_600_000; // 1h

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor arriba en http://localhost:${PORT}`);
    console.log(`Entorno: ${process.env.NODE_ENV || 'development'}`);
  });
  // Sincronización en segundo plano con NVD y CISA (no bloquea si fallan)
  startPeriodicSync(INTERVAL);
}).catch(err => {
  console.error('Error al conectar con MongoDB:', err.message);
  process.exit(1);
});
