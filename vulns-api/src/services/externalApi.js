const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const Vuln = require('../models/Vuln');

const xmlParser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '' });

// ── NVD API v2 (JSON) ─────────────────────────────────────────────────────────
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/**
 * Obtiene CVEs recientes de la NVD API y los sincroniza en la BD.
 * Formato: JSON
 */
async function syncFromNVD() {
  const headers = {};
  if (process.env.NVD_API_KEY) headers['apiKey'] = process.env.NVD_API_KEY;

  // Últimas 24 h (o últimos 100 CVEs si no hay API key)
  const pubEndDate   = new Date().toISOString();
  const pubStartDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const params = {
    pubStartDate,
    pubEndDate,
    resultsPerPage: 100,
    startIndex: 0,
  };

  const { data } = await axios.get(NVD_BASE, { headers, params, timeout: 15000 });
  const vulnerabilities = data?.vulnerabilities ?? [];

  let imported = 0;
  for (const item of vulnerabilities) {
    const cve = item.cve;
    if (!cve) continue;

    const cveId = cve.id;
    // Solo procesamos CVEs de Windows o Linux
    const descEn = (cve.descriptions ?? []).find(d => d.lang === 'en')?.value ?? '';
    const isLinux   = /linux/i.test(descEn);
    const isWindows = /windows/i.test(descEn);
    if (!isLinux && !isWindows) continue;

    // CVSS v3.x (preferimos 3.1 sobre 3.0)
    const metrics = cve.metrics ?? {};
    const cvssData = (metrics.cvssMetricV31 ?? metrics.cvssMetricV30 ?? [])[0]?.cvssData;
    if (!cvssData) continue;

    const severityMap = { NONE: 'LOW', LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' };
    const severity = severityMap[cvssData.baseSeverity] ?? 'MEDIUM';

    const doc = {
      id:          cveId,
      titulo:      cve.vulnStatus ?? cveId,
      descripcion: descEn,
      os:          isWindows ? 'windows' : 'linux',
      severity,
      cvss: {
        version:  cvssData.version,
        score:    cvssData.baseScore,
        severity,
        vector:   cvssData.vectorString,
      },
      fechaPublicacion:   new Date(cve.published),
      fechaActualizacion: new Date(cve.lastModified),
      fuente: 'NVD',
      explotadaActivamente: false,
    };

    await Vuln.updateOne({ id: cveId }, { $set: doc }, { upsert: true });
    imported++;
  }

  console.log(`[NVD] Sincronizados ${imported} CVEs`);
  return imported;
}

// ── CISA KEV RSS / XML Feed ───────────────────────────────────────────────────
// El feed XML de CISA Known Exploited Vulnerabilities
const CISA_RSS = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';

/**
 * Descarga el feed RSS XML de CISA y marca como explotadaActivamente
 * las vulnerabilidades que ya tengamos en BD.
 * Formato: XML (RSS 2.0)
 */
async function syncFromCISA() {
  const { data: xmlRaw } = await axios.get(CISA_RSS, {
    timeout: 15000,
    headers: { Accept: 'application/xml, text/xml, */*' },
    responseType: 'text',
  });

  const parsed = xmlParser.parse(xmlRaw);
  const items  = parsed?.rss?.channel?.item ?? [];
  const arr    = Array.isArray(items) ? items : [items];

  let marked = 0;
  for (const item of arr) {
    // Extraemos CVE-IDs del título o descripción
    const text = `${item.title ?? ''} ${item.description ?? ''}`;
    const cveIds = [...text.matchAll(/CVE-\d{4}-\d{4,}/g)].map(m => m[0]);
    for (const cveId of cveIds) {
      const result = await Vuln.updateOne({ id: cveId }, { $set: { explotadaActivamente: true, fuente: 'CISA-KEV' } });
      if (result.modifiedCount > 0) marked++;
    }
  }

  console.log(`[CISA] ${marked} vulnerabilidades marcadas como explotadas activamente`);
  return marked;
}

/**
 * Ejecuta la sincronización completa.
 * Si alguna API falla, registra el error pero NO lanza excepción
 * para que la API siga funcionando aunque las externas estén caídas.
 */
async function syncAll() {
  await Promise.allSettled([
    syncFromNVD().catch(err => console.error('[NVD] Error:', err.message)),
    syncFromCISA().catch(err => console.error('[CISA] Error:', err.message)),
  ]);
}

/**
 * Lanza la sincronización periódica en segundo plano.
 */
function startPeriodicSync(intervalMs = 3_600_000) {
  // Primera ejecución al arrancar (sin bloquear el servidor)
  setTimeout(() => syncAll(), 5000);
  setInterval(() => syncAll(), intervalMs);
  console.log(`🔄 Sync con APIs externas cada ${intervalMs / 60000} min`);
}

module.exports = { syncAll, syncFromNVD, syncFromCISA, startPeriodicSync };
