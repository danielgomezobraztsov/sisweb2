#!/usr/bin/env node
require('dotenv').config();
const mongoose = require('mongoose');
const {
  axios,
  createRun,
  finishRun,
  saveRaw,
  upsertVuln,
  pickNvdCvss,
  inferOs,
  inferVersion,
  inferTipo,
  normalizeSeverity
} = require('./syncCommon');

const SOURCE = 'NVD';
const ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function mapNvdItem(item) {
  const cve = item.cve;
  const descripcion = cve.descriptions?.find(d => d.lang === 'en')?.value || cve.id;
  const cvssData = pickNvdCvss(cve.metrics || {});
  const severity = normalizeSeverity(cvssData?.baseSeverity, cvssData?.baseScore);
  const os = inferOs(descripcion);
  return {
    id: cve.id,
    titulo: cve.id,
    descripcion,
    os,
    version: inferVersion(os, descripcion),
    tipoVuln: inferTipo(descripcion),
    severity,
    cvss: cvssData,
    fechaPublicacion: cve.published,
    fechaActualizacion: cve.lastModified,
    explotadaActivamente: false,
    fuente: SOURCE,
    urlParche: cve.references?.referenceData?.[0]?.url || cve.references?.[0]?.url || `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    referencias: (cve.references?.referenceData || cve.references || []).map(r => r.url).filter(Boolean),
    isAppVuln: !['windows', 'linux'].some(x => descripcion.toLowerCase().includes(x))
  };
}

async function main() {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
  if (!uri) throw new Error('Falta MONGODB_URI o MONGO_URI en .env');
  await mongoose.connect(uri);

  const limit = Number(process.env.SYNC_NVD_LIMIT || process.env.SYNC_LIMIT || 1200);
  const pageSize = Math.min(Number(process.env.SYNC_NVD_PAGE_SIZE || 2000), 2000);
  const keywordSearch = process.env.SYNC_NVD_KEYWORD || 'windows linux';
  const requestParams = { resultsPerPage: pageSize, startIndex: 0, keywordSearch };
  const run = await createRun(SOURCE, ENDPOINT, { limit, pageSize, keywordSearch });

  const stats = { received: 0, rawSaved: 0, inserted: 0, updated: 0, skipped: 0, errors: 0 };
  const errors = [];

  try {
    let startIndex = 0;
    while (stats.received < limit) {
      const params = { ...requestParams, startIndex, resultsPerPage: Math.min(pageSize, limit - stats.received) };
      const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
      const response = await axios.get(ENDPOINT, { params, headers, timeout: 30000 });
      const items = response.data.vulnerabilities || [];
      if (!items.length) break;

      for (const item of items) {
        const cveId = item.cve?.id;
        if (!cveId) { stats.skipped++; continue; }
        try {
          const raw = await saveRaw(SOURCE, run, cveId, cveId, ENDPOINT, params, item);
          if (raw) stats.rawSaved++;
          const mapped = mapNvdItem(item);
          const result = await upsertVuln(mapped);
          if (result.inserted) stats.inserted++; else stats.updated++;
          if (raw) await raw.updateOne({ $set: { normalized: true } });
        } catch (err) {
          stats.errors++;
          errors.push({ message: err.message, cveId });
        }
      }

      stats.received += items.length;
      startIndex += items.length;
      if (startIndex >= Number(response.data.totalResults || 0)) break;
      if (!process.env.NVD_API_KEY) await new Promise(resolve => setTimeout(resolve, 6500));
    }

    await finishRun(run, stats.errors ? 'partial' : 'success', stats, errors);
    console.log(`NVD sync OK. Recibidas: ${stats.received}. Insertadas: ${stats.inserted}. Actualizadas: ${stats.updated}. Errores: ${stats.errors}.`);
  } catch (err) {
    stats.errors++;
    errors.push({ message: err.message });
    await finishRun(run, 'failed', stats, errors);
    throw err;
  } finally {
    await mongoose.disconnect();
  }
}

main().catch(err => { console.error('syncNvd error:', err.message); process.exit(1); });
