require('dotenv').config();
const mongoose = require('mongoose');

const ApiSource = require('../src/models/ApiSource');
const ApiKey = require('../src/models/ApiKey');
const Application = require('../src/models/Application');
const Vulnerability = require('../src/models/Vulnerability');
const AffectedProduct = require('../src/models/AffectedProduct');
const ApiSyncRun = require('../src/models/ApiSyncRun');
const RawApiPayload = require('../src/models/RawApiPayload');

const sources = [
  { code: 'NVD', name: 'National Vulnerability Database', baseUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0', format: 'json', authType: 'apiKeyHeader', rateLimit: { requests: 50, perSeconds: 30 } },
  { code: 'CISA-KEV', name: 'CISA Known Exploited Vulnerabilities', baseUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', format: 'json', authType: 'none' },
  { code: 'MSRC', name: 'Microsoft Security Response Center', baseUrl: 'https://api.msrc.microsoft.com', format: 'json', authType: 'none' },
  { code: 'OSV', name: 'Open Source Vulnerabilities', baseUrl: 'https://api.osv.dev/v1', format: 'json', authType: 'none' },
  { code: 'EXPLOIT-DB', name: 'Exploit Database', baseUrl: 'https://www.exploit-db.com', format: 'other', authType: 'none' },
];

const applications = [
  { name: 'Google Chrome', vendor: 'Google', version: '124.x', category: 'browser', os: 'cross-platform', description: 'Web browser based on Chromium' },
  { name: 'Mozilla Firefox', vendor: 'Mozilla', version: '126.x', category: 'browser', os: 'cross-platform', description: 'Open-source web browser' },
  { name: 'Microsoft Office', vendor: 'Microsoft', version: '365', category: 'office', os: 'windows', description: 'Office productivity suite' },
  { name: 'Apache HTTP Server', vendor: 'Apache', version: '2.4.x', category: 'webserver', os: 'linux', description: 'HTTP web server' },
  { name: 'Nginx', vendor: 'F5', version: '1.24.x', category: 'webserver', os: 'linux', description: 'Web server and reverse proxy' },
  { name: 'Node.js', vendor: 'OpenJS Foundation', version: '20.x', category: 'runtime', os: 'cross-platform', description: 'JavaScript runtime' },
  { name: 'OpenSSL', vendor: 'OpenSSL Project', version: '3.x', category: 'security', os: 'cross-platform', description: 'Cryptography and TLS toolkit' },
  { name: 'Redis', vendor: 'Redis', version: '7.x', category: 'database', os: 'linux', description: 'In-memory data store' },
];

async function main() {
  if (!process.env.MONGODB_URI) throw new Error('Falta MONGODB_URI en .env');
  await mongoose.connect(process.env.MONGODB_URI);

  await Promise.all([
    ApiSource.syncIndexes(), ApiKey.syncIndexes(), Application.syncIndexes(), Vulnerability.syncIndexes(),
    AffectedProduct.syncIndexes(), ApiSyncRun.syncIndexes(), RawApiPayload.syncIndexes(),
  ]);

  for (const source of sources) {
    await ApiSource.updateOne({ code: source.code }, { $set: source }, { upsert: true });
  }

  for (const app of applications) {
    await Application.updateOne({ name: app.name, vendor: app.vendor }, { $set: app }, { upsert: true });
  }

  const key = process.env.API_KEY || 'dev-api-key-12345';
  await ApiKey.updateOne(
    { name: 'default' },
    { $set: { key, active: true, scopes: ['read', 'write', 'sync', 'admin'] } },
    { upsert: true }
  );

  console.log('Base de datos inicializada en MongoDB Atlas');
  console.log('Colecciones: api_sources, api_sync_runs, raw_api_payloads, vulnerabilities, applications, affected_products, api_keys');
  await mongoose.disconnect();
}

main().catch(async err => {
  console.error('Error inicializando Atlas:', err.message);
  try { await mongoose.disconnect(); } catch (_) {}
  process.exit(1);
});
