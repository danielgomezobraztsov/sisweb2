require('dotenv').config();
const crypto = require('crypto');
const mongoose = require('mongoose');

const ApiSyncRun = require('../src/models/ApiSyncRun');
const RawApiPayload = require('../src/models/RawApiPayload');
const Vulnerability = require('../src/models/Vulnerability');
const AffectedProduct = require('../src/models/AffectedProduct');

function sha256(obj) {
  return crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex');
}

function inferOs(text = '') {
  if (/windows|microsoft/i.test(text)) return 'windows';
  if (/linux|ubuntu|debian|rhel|centos|fedora|alpine/i.test(text)) return 'linux';
  return 'unknown';
}

function inferTipo(text = '') {
  if (/remote code execution|rce/i.test(text)) return 'RCE';
  if (/privilege|elevation/i.test(text)) return 'EoP';
  if (/denial of service|dos/i.test(text)) return 'DoS';
  if (/information disclosure/i.test(text)) return 'InfoDisclosure';
  if (/bypass/i.test(text)) return 'AuthBypass';
  if (/sql injection/i.test(text)) return 'SQLi';
  if (/cross-site scripting|xss/i.test(text)) return 'XSS';
  if (/path traversal/i.test(text)) return 'PathTraversal';
  return 'Other';
}

function normalizeNvdItem(item, rawId, syncRunId) {
  const cve = item.cve;
  const description = cve.descriptions?.find(d => d.lang === 'en')?.value || cve.id;
  const cvssData = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const severity = cvssData?.baseSeverity || cve.metrics?.cvssMetricV31?.[0]?.baseSeverity || 'UNKNOWN';

  return {
    id: cve.id,
    titulo: cve.vulnStatus ? `${cve.id} - ${cve.vulnStatus}` : cve.id,
    descripcion: description,
    os: inferOs(description),
    tipoVuln: inferTipo(description),
    severity,
    cvss: cvssData ? {
      version: cvssData.version,
      score: cvssData.baseScore,
      severity,
      vector: cvssData.vectorString,
    } : undefined,
    cwes: (cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(Boolean),
    fechaPublicacion: cve.published ? new Date(cve.published) : undefined,
    fechaActualizacion: cve.lastModified ? new Date(cve.lastModified) : undefined,
    explotadaActivamente: false,
    fuente: 'NVD',
    fuentes: [{ sourceCode: 'NVD', externalId: cve.id, url: `https://nvd.nist.gov/vuln/detail/${cve.id}`, firstSeenAt: new Date(), lastSeenAt: new Date() }],
    referencias: (cve.references?.referenceData || cve.references || []).map(r => r.url).filter(Boolean),
    rawPayloadIds: [rawId],
    lastSyncRunId: syncRunId,
  };
}

async function main() {
  await mongoose.connect(process.env.MONGODB_URI);

  const run = await ApiSyncRun.create({
    sourceCode: 'NVD',
    endpoint: 'example/local-object',
    requestParams: { example: true },
  });

  const example = {
    cve: {
      id: 'CVE-2025-99999',
      vulnStatus: 'Analyzed',
      published: '2025-03-01T10:00:00.000',
      lastModified: '2025-03-05T10:00:00.000',
      descriptions: [{ lang: 'en', value: 'Windows Kernel elevation of privilege vulnerability.' }],
      metrics: { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: 7.8, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' } }] },
      references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-99999' }],
      weaknesses: [{ description: [{ value: 'CWE-269' }] }],
    },
  };

  const raw = await RawApiPayload.findOneAndUpdate(
    { sourceCode: 'NVD', externalId: example.cve.id },
    {
      $set: {
        sourceCode: 'NVD', syncRunId: run._id, externalId: example.cve.id, cveId: example.cve.id,
        contentType: 'application/json', payload: example, checksum: sha256(example), normalized: false,
      }
    },
    { upsert: true, new: true }
  );

  const normalized = normalizeNvdItem(example, raw._id, run._id);
  const before = await Vulnerability.exists({ id: normalized.id });
  const vuln = await Vulnerability.findOneAndUpdate({ id: normalized.id }, { $set: normalized }, { upsert: true, new: true });

  await RawApiPayload.updateOne({ _id: raw._id }, { $set: { normalized: true } });

  await AffectedProduct.updateOne(
    { vulnerabilityId: vuln.id, productName: 'Windows Kernel', affectedVersionRange: 'unknown' },
    { $set: { vulnerabilityId: vuln.id, cveObjectId: vuln._id, productName: 'Windows Kernel', vendor: 'Microsoft', productType: 'os', os: 'windows', sourceCode: 'NVD' } },
    { upsert: true }
  );

  await ApiSyncRun.updateOne({ _id: run._id }, {
    $set: { status: 'success', finishedAt: new Date(), stats: { received: 1, rawSaved: 1, inserted: before ? 0 : 1, updated: before ? 1 : 0, skipped: 0, errors: 0 } }
  });

  console.log('✅ Ejemplo importado:', vuln.id);
  await mongoose.disconnect();
}

main().catch(async err => {
  console.error(err);
  try { await mongoose.disconnect(); } catch (_) {}
  process.exit(1);
});
