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
  inferTipo,
  normalizeSeverity
} = require('./syncCommon');

const SOURCE = 'OSV';
const QUERY_ENDPOINT = 'https://api.osv.dev/v1/query';
const VULN_ENDPOINT = 'https://api.osv.dev/v1/vulns';

const DEFAULT_QUERIES = [
  { package: { ecosystem: 'npm', name: 'express' } },
  { package: { ecosystem: 'npm', name: 'lodash' } },
  { package: { ecosystem: 'npm', name: 'axios' } },
  { package: { ecosystem: 'PyPI', name: 'django' } },
  { package: { ecosystem: 'PyPI', name: 'requests' } },
  { package: { ecosystem: 'PyPI', name: 'flask' } },
  { package: { ecosystem: 'Debian', name: 'openssl' } },
  { package: { ecosystem: 'Debian', name: 'openssh' } },
  { package: { ecosystem: 'Debian', name: 'linux' } }
];

function getCveId(osv) {
  const ids = [osv.id, ...(osv.aliases || [])];
  return ids.find(id => /^CVE-\d{4}-\d{4,}$/.test(id));
}

function mapOsv(osv) {
  const cveId = getCveId(osv);
  const text = `${osv.summary || ''} ${osv.details || ''}`;
  const os = inferOs(text);
  const severityItem = (osv.severity || []).find(s => String(s.type || '').includes('CVSS'));
  const scoreMatch = severityItem?.score?.match(/CVSS:[^\s]+/);
  const severity = normalizeSeverity(null, 7.0);

  return {
    id: cveId,
    titulo: osv.summary || cveId,
    descripcion: osv.details || osv.summary || cveId,
    os,
    version: inferVersion(os, text),
    tipoVuln: inferTipo(text),
    severity,
    cvss: {
      version: '3.1',
      score: 7.0,
      severity,
      vector: scoreMatch?.[0] || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    },
    fechaPublicacion: osv.published || new Date(),
    fechaActualizacion: osv.modified || new Date(),
    explotadaActivamente: false,
    fuente: SOURCE,
    urlParche: osv.references?.[0]?.url || `https://osv.dev/vulnerability/${osv.id}`,
    referencias: [...new Set([`https://osv.dev/vulnerability/${osv.id}`, ...(osv.references || []).map(r => r.url)].filter(Boolean))],
    isAppVuln: true
  };
}

async function main() {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
  if (!uri) throw new Error('Falta MONGODB_URI o MONGO_URI en .env');
  await mongoose.connect(uri);

  const limit = Number(process.env.SYNC_OSV_LIMIT || process.env.SYNC_LIMIT || 300);
  const run = await createRun(SOURCE, QUERY_ENDPOINT, { limit });
  const stats = { received: 0, rawSaved: 0, inserted: 0, updated: 0, skipped: 0, errors: 0 };
  const errors = [];

  try {
    const ids = new Set();
    for (const query of DEFAULT_QUERIES) {
      const response = await axios.post(QUERY_ENDPOINT, query, { timeout: 30000 });
      for (const v of response.data.vulns || []) ids.add(v.id);
    }

    for (const id of [...ids].slice(0, limit)) {
      try {
        const url = `${VULN_ENDPOINT}/${id}`;
        const response = await axios.get(url, { timeout: 30000 });
        const osv = response.data;
        stats.received++;
        const cveId = getCveId(osv);
        if (!cveId) { stats.skipped++; continue; }
        const raw = await saveRaw(SOURCE, run, id, cveId, url, {}, osv);
        if (raw) stats.rawSaved++;
        const result = await upsertVuln(mapOsv(osv));
        if (result.inserted) stats.inserted++; else stats.updated++;
        if (raw) await raw.updateOne({ $set: { normalized: true } });
      } catch (err) {
        stats.errors++;
        errors.push({ message: err.message, rawId: id });
      }
    }

    await finishRun(run, stats.errors ? 'partial' : 'success', stats, errors);
    console.log(`OSV sync OK. Recibidas: ${stats.received}. Insertadas: ${stats.inserted}. Actualizadas: ${stats.updated}. Errores: ${stats.errors}.`);
  } catch (err) {
    stats.errors++;
    errors.push({ message: err.message });
    await finishRun(run, 'failed', stats, errors);
    throw err;
  } finally {
    await mongoose.disconnect();
  }
}

main().catch(err => { console.error('syncOsv error:', err.message); process.exit(1); });
