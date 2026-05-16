#!/usr/bin/env node
require('dotenv').config();
const mongoose = require('mongoose');
const {
  axios,
  createRun,
  finishRun,
  saveRaw,
  upsertVuln,
  inferOs,
  inferVersion,
  inferTipo
} = require('./syncCommon');

const SOURCE = 'CISA-KEV';
const ENDPOINT = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function mapCisaItem(item) {
  const cveId = item.cveID || item.cveId || item.cve;
  const vendor = item.vendorProject || item.vendor || '';
  const product = item.product || '';
  const name = item.vulnerabilityName || `${cveId} Known Exploited Vulnerability`;
  const desc = item.shortDescription || item.notes || name;
  const text = `${vendor} ${product} ${name} ${desc}`;
  const os = inferOs(text);

  return {
    id: cveId,
    titulo: name,
    descripcion: desc,
    os,
    version: inferVersion(os, text),
    tipoVuln: inferTipo(text),
    severity: 'HIGH',
    cvss: { version: '3.1', score: 8.0, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    fechaPublicacion: item.dateAdded || new Date(),
    fechaActualizacion: item.dueDate || item.dateAdded || new Date(),
    explotadaActivamente: true,
    fuente: SOURCE,
    urlParche: item.requiredAction || `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    referencias: [`https://nvd.nist.gov/vuln/detail/${cveId}`, 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    isAppVuln: os !== 'windows' && os !== 'linux'
  };
}

async function main() {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
  if (!uri) throw new Error('Falta MONGODB_URI o MONGO_URI en .env');
  await mongoose.connect(uri);

  const limit = Number(process.env.SYNC_CISA_LIMIT || process.env.SYNC_LIMIT || 1000);
  const run = await createRun(SOURCE, ENDPOINT, { limit });
  const stats = { received: 0, rawSaved: 0, inserted: 0, updated: 0, skipped: 0, errors: 0 };
  const errors = [];

  try {
    const response = await axios.get(ENDPOINT, { timeout: 30000 });
    const list = (response.data.vulnerabilities || []).slice(0, limit);
    stats.received = list.length;

    for (const item of list) {
      const cveId = item.cveID || item.cveId || item.cve;
      if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) { stats.skipped++; continue; }
      try {
        const raw = await saveRaw(SOURCE, run, cveId, cveId, ENDPOINT, {}, item);
        if (raw) stats.rawSaved++;
        const result = await upsertVuln(mapCisaItem(item));
        if (result.inserted) stats.inserted++; else stats.updated++;
        if (raw) await raw.updateOne({ $set: { normalized: true } });
      } catch (err) {
        stats.errors++;
        errors.push({ message: err.message, cveId });
      }
    }

    await finishRun(run, stats.errors ? 'partial' : 'success', stats, errors);
    console.log(`CISA sync OK. Recibidas: ${stats.received}. Insertadas: ${stats.inserted}. Actualizadas: ${stats.updated}. Errores: ${stats.errors}.`);
  } catch (err) {
    stats.errors++;
    errors.push({ message: err.message });
    await finishRun(run, 'failed', stats, errors);
    throw err;
  } finally {
    await mongoose.disconnect();
  }
}

main().catch(err => { console.error('syncCisa error:', err.message); process.exit(1); });
