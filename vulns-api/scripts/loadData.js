#!/usr/bin/env node
/**
 * loadData.js
 * Carga el dataset en MongoDB. Uso: npm run load-data
 * Limpia las colecciones primero para evitar duplicados.
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const mongoose    = require('mongoose');
const fs          = require('fs');
const path        = require('path');

// Importar modelos
const Vuln        = require('../src/models/Vuln');
const Application = require('../src/models/Application');
const ApiKey      = require('../src/models/ApiKey');

const DATA_DIR = path.join(__dirname, '..', 'data');

async function main() {
  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/vulnsdb';
  console.log(`Conectando a MongoDB: ${uri}`);
  await mongoose.connect(uri);
  console.log('✅ Conectado\n');

  // ── 1. Cargar Aplicaciones ────────────────────────────────────────────────
  const appsFile = path.join(DATA_DIR, 'applications.json');
  if (fs.existsSync(appsFile)) {
    await Application.deleteMany({});
    const apps = JSON.parse(fs.readFileSync(appsFile, 'utf8'));
    await Application.insertMany(apps);
    console.log(`📦 Applications: ${apps.length} documentos cargados`);
  } else {
    console.warn('⚠️  data/applications.json no encontrado, saltando...');
  }

  // ── 2. Cargar Vulnerabilidades ────────────────────────────────────────────
  const vulnsFile = path.join(DATA_DIR, 'vulns.json');
  if (!fs.existsSync(vulnsFile)) {
    console.error('❌ data/vulns.json no encontrado. Ejecuta primero: npm run generate-dataset');
    process.exit(1);
  }

  await Vuln.deleteMany({});
  const rawVulns = JSON.parse(fs.readFileSync(vulnsFile, 'utf8'));

  // Cargar en lotes de 200 para no saturar la conexión
  const BATCH = 200;
  let loaded = 0;
  for (let i = 0; i < rawVulns.length; i += BATCH) {
    const batch = rawVulns.slice(i, i + BATCH);
    await Vuln.insertMany(batch, { ordered: false });
    loaded += batch.length;
    process.stdout.write(`\r📦 Vulnerabilidades: ${loaded}/${rawVulns.length}`);
  }
  console.log(`\n✅ Vulnerabilidades: ${loaded} documentos cargados`);

  // ── 3. Crear API Key por defecto ──────────────────────────────────────────
  const defaultKey = process.env.API_KEY || 'dev-api-key-12345';
  await ApiKey.deleteMany({ name: 'default' });
  await ApiKey.create({ key: defaultKey, name: 'default', active: true });
  console.log(`🔑 API Key por defecto creada: ${defaultKey.slice(0, 8)}****`);

  // ── Resumen ───────────────────────────────────────────────────────────────
  const totalVulns = await Vuln.countDocuments();
  const totalApps  = await Application.countDocuments();
  const totalKeys  = await ApiKey.countDocuments();

  console.log('\n── Resumen final ──────────────────────────────────────────');
  console.log(`   vulns:        ${totalVulns} documentos`);
  console.log(`   applications: ${totalApps} documentos`);
  console.log(`   apikeys:      ${totalKeys} documentos`);
  console.log('──────────────────────────────────────────────────────────\n');

  await mongoose.disconnect();
  console.log('✅ Datos cargados correctamente. ¡Listo para arrancar el servidor!');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
