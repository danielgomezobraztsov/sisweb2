const crypto = require('crypto');
const axios = require('axios');

const Vuln = require('../src/models/Vulnerability');
let RawApiPayload;
let ApiSyncRun;
try { RawApiPayload = require('../src/models/RawApiPayload'); } catch (_) { RawApiPayload = null; }
try { ApiSyncRun = require('../src/models/ApiSyncRun'); } catch (_) { ApiSyncRun = null; }

function sha256(obj) {
  return crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex');
}

function inferOs(text = '') {
  const t = String(text).toLowerCase();
  if (/(windows|microsoft|win32|active directory|powershell|exchange server|sharepoint)/i.test(t)) return 'windows';
  if (/(linux|ubuntu|debian|rhel|red hat|centos|fedora|alpine|opensuse|kernel|glibc|openssl|openssh|sudo|systemd)/i.test(t)) return 'linux';
  return 'linux';
}

function inferVersion(os, text = '') {
  const t = String(text).toLowerCase();
  if (os === 'windows') {
    if (t.includes('windows 11')) return 'windows-11';
    if (t.includes('windows 10')) return 'windows-10';
    if (t.includes('server 2025')) return 'windows-server-2025';
    if (t.includes('server 2022')) return 'windows-server-2022';
    if (t.includes('server 2019')) return 'windows-server-2019';
    return 'windows-11';
  }
  if (t.includes('ubuntu')) return 'ubuntu';
  if (t.includes('debian')) return 'debian';
  if (t.includes('alpine')) return 'alpine';
  if (t.includes('arch')) return 'arch';
  if (t.includes('fedora')) return 'fedora';
  if (t.includes('centos')) return 'centos';
  if (t.includes('rhel') || t.includes('red hat')) return 'rhel';
  if (t.includes('opensuse')) return 'opensuse';
  return 'ubuntu';
}

function inferTipo(text = '') {
  const t = String(text).toLowerCase();
  if (t.includes('remote code execution') || /\brce\b/.test(t)) return 'RCE';
  if (t.includes('elevation of privilege') || t.includes('privilege escalation')) return 'EoP';
  if (t.includes('denial of service') || /\bdos\b/.test(t)) return 'DoS';
  if (t.includes('information disclosure') || t.includes('memory disclosure')) return 'InfoDisclosure';
  if (t.includes('authentication bypass') || t.includes('security feature bypass') || t.includes('bypass')) return 'AuthBypass';
  if (t.includes('sql injection')) return 'SQLi';
  if (t.includes('cross-site scripting') || /\bxss\b/.test(t)) return 'XSS';
  return 'Other';
}

function normalizeSeverity(sev, score) {
  const s = String(sev || '').toUpperCase();
  if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(s)) return s;
  const n = Number(score || 0);
  if (n >= 9) return 'CRITICAL';
  if (n >= 7) return 'HIGH';
  if (n >= 4) return 'MEDIUM';
  return 'LOW';
}

function normalizeCvss(cvssData, fallbackSeverity = 'MEDIUM') {
  const score = Number(cvssData?.baseScore || cvssData?.score || 5.0);
  const severity = normalizeSeverity(cvssData?.baseSeverity || cvssData?.severity || fallbackSeverity, score);
  return {
    version: ['3.0', '3.1'].includes(String(cvssData?.version)) ? String(cvssData.version) : '3.1',
    score,
    severity,
    vector: cvssData?.vectorString || cvssData?.vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
  };
}

function cleanVuln(v) {
  const text = `${v.titulo || ''} ${v.descripcion || ''}`;
  const os = v.os && ['windows', 'linux'].includes(v.os) ? v.os : inferOs(text);
  const cvss = normalizeCvss(v.cvss, v.severity);
  const severity = normalizeSeverity(v.severity || cvss.severity, cvss.score);
  return {
    id: v.id,
    titulo: v.titulo || v.id,
    descripcion: v.descripcion || v.titulo || v.id,
    os,
    version: v.version || inferVersion(os, text),
    tipoVuln: v.tipoVuln || inferTipo(text),
    severity,
    cvss: { ...cvss, severity },
    fechaPublicacion: v.fechaPublicacion ? new Date(v.fechaPublicacion) : new Date(),
    fechaActualizacion: v.fechaActualizacion ? new Date(v.fechaActualizacion) : new Date(),
    explotadaActivamente: Boolean(v.explotadaActivamente),
    fuente: v.fuente,
    urlParche: v.urlParche || '',
    referencias: Array.isArray(v.referencias) ? [...new Set(v.referencias.filter(Boolean))] : [],
    isAppVuln: Boolean(v.isAppVuln)
  };
}

async function createRun(sourceCode, endpoint, requestParams = {}) {
  if (!ApiSyncRun) return null;
  return ApiSyncRun.create({ sourceCode, endpoint, requestParams });
}

async function finishRun(run, status, stats, errors = []) {
  if (!run || !ApiSyncRun) return;
  await ApiSyncRun.updateOne({ _id: run._id }, {
    $set: { status, finishedAt: new Date(), stats },
    $push: errors.length ? { errors: { $each: errors } } : {}
  });
}

async function saveRaw(sourceCode, run, externalId, cveId, url, params, payload, contentType = 'application/json') {
  if (!RawApiPayload) return null;
  return RawApiPayload.findOneAndUpdate(
    { sourceCode, externalId: String(externalId) },
    {
      $set: {
        sourceCode,
        syncRunId: run?._id,
        externalId: String(externalId),
        cveId,
        contentType,
        request: { url, params },
        checksum: sha256(payload),
        payload,
        normalized: false,
        fetchedAt: new Date()
      }
    },
    { upsert: true, new: true }
  );
}

async function upsertVuln(vuln) {
  const normalized = cleanVuln(vuln);
  const exists = await Vuln.exists({ id: normalized.id });
  const doc = await Vuln.findOneAndUpdate(
    { id: normalized.id },
    { $set: normalized },
    { upsert: true, new: true, runValidators: true }
  );
  return { doc, inserted: !exists };
}

function pickNvdCvss(metrics = {}) {
  return metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || metrics.cvssMetricV2?.[0]?.cvssData || null;
}

module.exports = {
  axios,
  sha256,
  inferOs,
  inferVersion,
  inferTipo,
  normalizeSeverity,
  normalizeCvss,
  cleanVuln,
  createRun,
  finishRun,
  saveRaw,
  upsertVuln,
  pickNvdCvss
};
