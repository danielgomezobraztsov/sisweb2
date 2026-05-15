const Vuln = require('../models/Vuln');
const { formatResponse } = require('../utils/xmlUtils');

// ── helpers ───────────────────────────────────────────────────────────────────

function parsePagination(query) {
  const page        = Math.max(1, parseInt(query.page) || 1);
  const numElements = Math.min(50, Math.max(1, parseInt(query.numElements) || 10));
  return { page, numElements, skip: (page - 1) * numElements };
}

function buildFilter(query) {
  const filter = {};
  if (query.os)       filter.os       = query.os;
  if (query.severity) filter.severity = query.severity;
  if (query.version)  filter.version  = query.version;
  if (query.cveId)    filter.id       = query.cveId;
  return filter;
}

/** Proyección mínima para listados */
const MIN_PROJECTION = 'id titulo os version severity fechaPublicacion explotadaActivamente -_id';

function validateEnum(value, allowed, fieldName) {
  if (value !== undefined && !allowed.includes(value)) {
    return `Valor inválido para ${fieldName}: ${value}. Permitidos: ${allowed.join(', ')}`;
  }
  return null;
}

function validateQueryParams(query) {
  const errors = [];
  const e1 = validateEnum(query.os,       Vuln.OS_VALUES,       'os');
  const e2 = validateEnum(query.severity, Vuln.SEVERITY_VALUES, 'severity');
  const e3 = validateEnum(query.version,  Vuln.VERSION_VALUES,  'version');
  if (e1) errors.push(e1);
  if (e2) errors.push(e2);
  if (e3) errors.push(e3);
  if (query.page && (isNaN(query.page) || query.page < 1)) errors.push('page debe ser entero >= 1');
  if (query.numElements && (isNaN(query.numElements) || query.numElements < 1 || query.numElements > 50))
    errors.push('numElements debe ser entero entre 1 y 50');
  if (query.cveId && !/^CVE-\d{4}-\d{4,}$/.test(query.cveId)) errors.push('cveId con formato inválido');
  return errors;
}

function validateVulnBody(body) {
  const errors = [];
  const required = ['id', 'titulo', 'descripcion', 'os', 'severity', 'cvss', 'fechaPublicacion', 'fuente'];
  for (const f of required) {
    if (body[f] === undefined || body[f] === null || body[f] === '') errors.push(`Campo requerido: ${f}`);
  }
  if (body.id && !/^CVE-\d{4}-\d{4,}$/.test(body.id))     errors.push('id con formato inválido (CVE-YYYY-XXXXX)');
  if (body.os)       { const e = validateEnum(body.os, Vuln.OS_VALUES, 'os'); if (e) errors.push(e); }
  if (body.severity) { const e = validateEnum(body.severity, Vuln.SEVERITY_VALUES, 'severity'); if (e) errors.push(e); }
  if (body.version)  { const e = validateEnum(body.version, Vuln.VERSION_VALUES, 'version'); if (e) errors.push(e); }
  if (body.fuente)   { const e = validateEnum(body.fuente, Vuln.FUENTE_VALUES, 'fuente'); if (e) errors.push(e); }
  if (body.tipoVuln) { const e = validateEnum(body.tipoVuln, Vuln.TIPO_VULN_VALUES, 'tipoVuln'); if (e) errors.push(e); }
  if (body.cvss) {
    if (body.cvss.score !== undefined && (body.cvss.score < 0 || body.cvss.score > 10))
      errors.push('cvss.score debe estar entre 0.0 y 10.0');
  }
  return errors;
}

// ── Controladores ─────────────────────────────────────────────────────────────

/**
 * GET /vulns
 * Lista paginada con filtros opcionales (os, severity, version, cveId).
 */
async function getAll(req, res, next) {
  try {
    const paramErrors = validateQueryParams(req.query);
    if (paramErrors.length) {
      return res.status(422).json({ codigo: 422, texto: 'Parámetros incorrectos', descripcion: paramErrors.join('; ') });
    }

    const { page, numElements, skip } = parsePagination(req.query);
    const filter = buildFilter(req.query);

    const [vulns, total] = await Promise.all([
      Vuln.find(filter, MIN_PROJECTION).sort({ fechaPublicacion: -1 }).skip(skip).limit(numElements).lean(),
      Vuln.countDocuments(filter),
    ]);

    const result = vulns.map(v => ({
      id: v.id, titulo: v.titulo, os: v.os, version: v.version,
      severity: v.severity, fechaPublicacion: v.fechaPublicacion?.toISOString().split('T')[0],
      explotadaActivamente: v.explotadaActivamente,
    }));

    formatResponse(req, res, 200, result, 'vulnerabilidades', 'vuln');
  } catch (err) { next(err); }
}

/**
 * GET /vulns/:id
 * Detalle completo de una vulnerabilidad por CVE-ID.
 */
async function getById(req, res, next) {
  try {
    const vuln = await Vuln.findOne({ id: req.params.id }, '-_id -__v -isAppVuln -appId').lean();
    if (!vuln) return res.status(404).json({ codigo: 404, texto: 'No existe una vulnerabilidad con ese ID' });
    formatResponse(req, res, 200, vuln, 'vuln', 'vuln');
  } catch (err) { next(err); }
}

/**
 * POST /vulns
 * Crea nueva vulnerabilidad. Requiere autenticación.
 */
async function create(req, res, next) {
  try {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ codigo: 400, texto: 'Formato incorrecto', descripcion: 'Body vacío o no es JSON/XML válido' });
    }

    const errors = validateVulnBody(body);
    if (errors.length) {
      return res.status(422).json({ codigo: 422, texto: 'Error en JSON', descripcion: errors.join('; ') });
    }

    const exists = await Vuln.findOne({ id: body.id });
    if (exists) return res.status(409).json({ codigo: 409, texto: 'Ya existe una vulnerabilidad con ese CVE-ID' });

    await Vuln.create(body);
    formatResponse(req, res, 201, { codigo: 201, texto: `Vulnerabilidad ${body.id} creada correctamente` }, 'mensaje');
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(422).json({ codigo: 422, texto: 'Error en JSON', descripcion: err.message });
    }
    next(err);
  }
}

/**
 * PUT /vulns/:id
 * Actualización completa. Operación idempotente.
 */
async function update(req, res, next) {
  try {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ codigo: 400, texto: 'Formato incorrecto' });
    }

    const errors = validateVulnBody(body);
    if (errors.length) {
      return res.status(422).json({ codigo: 422, texto: 'JSON incorrecto', descripcion: errors.join('; ') });
    }

    // El id del path manda
    body.id = req.params.id;

    const result = await Vuln.findOneAndReplace({ id: req.params.id }, body, { new: false });
    if (!result) return res.status(404).json({ codigo: 404, texto: 'No existe una vulnerabilidad con ese ID' });

    formatResponse(req, res, 200, { codigo: 200, texto: `Vulnerabilidad ${req.params.id} actualizada` }, 'mensaje');
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(422).json({ codigo: 422, texto: 'JSON incorrecto', descripcion: err.message });
    }
    next(err);
  }
}

/**
 * DELETE /vulns/:id
 * Elimina una vulnerabilidad. Nunca masivo.
 */
async function remove(req, res, next) {
  try {
    const result = await Vuln.findOneAndDelete({ id: req.params.id });
    if (!result) return res.status(404).json({ codigo: 404, texto: 'No existe una vulnerabilidad con ese ID' });
    res.status(204).send();
  } catch (err) { next(err); }
}

/**
 * GET /vulns/os/:os
 * Filtra por sistema operativo.
 */
async function getByOs(req, res, next) {
  try {
    const { os } = req.params;
    if (!Vuln.OS_VALUES.includes(os)) {
      return res.status(404).json({ codigo: 404, texto: 'OS no reconocido', descripcion: `OS válidos: ${Vuln.OS_VALUES.join(', ')}` });
    }

    const paramErrors = validateQueryParams(req.query);
    if (paramErrors.length) return res.status(422).json({ codigo: 422, texto: 'Parámetros incorrectos', descripcion: paramErrors.join('; ') });

    const { page, numElements, skip } = parsePagination(req.query);
    const filter = { os };
    if (req.query.severity) filter.severity = req.query.severity;

    const vulns = await Vuln.find(filter, MIN_PROJECTION).sort({ fechaPublicacion: -1 }).skip(skip).limit(numElements).lean();

    const result = vulns.map(v => ({
      id: v.id, titulo: v.titulo, os: v.os, version: v.version,
      severity: v.severity, fechaPublicacion: v.fechaPublicacion?.toISOString().split('T')[0],
      explotadaActivamente: v.explotadaActivamente,
    }));

    formatResponse(req, res, 200, result, 'vulnerabilidades', 'vuln');
  } catch (err) { next(err); }
}

/**
 * GET /vulns/os/:os/version/:version
 * Filtra por OS y versión concreta.
 */
async function getByOsVersion(req, res, next) {
  try {
    const { os, version } = req.params;

    if (!Vuln.OS_VALUES.includes(os)) {
      return res.status(404).json({ codigo: 404, texto: 'OS no reconocido' });
    }
    if (!Vuln.VERSION_VALUES.includes(version)) {
      return res.status(404).json({ codigo: 404, texto: 'Versión no reconocida', descripcion: `Versiones válidas: ${Vuln.VERSION_VALUES.join(', ')}` });
    }

    const paramErrors = validateQueryParams(req.query);
    if (paramErrors.length) return res.status(422).json({ codigo: 422, texto: 'Parámetros incorrectos', descripcion: paramErrors.join('; ') });

    const { page, numElements, skip } = parsePagination(req.query);
    const filter = { os, version };
    if (req.query.severity) filter.severity = req.query.severity;

    const vulns = await Vuln.find(filter, MIN_PROJECTION).sort({ fechaPublicacion: -1 }).skip(skip).limit(numElements).lean();

    const result = vulns.map(v => ({
      id: v.id, titulo: v.titulo, os: v.os, version: v.version,
      severity: v.severity, fechaPublicacion: v.fechaPublicacion?.toISOString().split('T')[0],
      explotadaActivamente: v.explotadaActivamente,
    }));

    formatResponse(req, res, 200, result, 'vulnerabilidades', 'vuln');
  } catch (err) { next(err); }
}

/**
 * GET /vulns/apps
 * Vulnerabilidades de aplicaciones de usuario.
 */
async function getApps(req, res, next) {
  try {
    const paramErrors = validateQueryParams(req.query);
    if (paramErrors.length) return res.status(422).json({ codigo: 422, texto: 'Parámetros incorrectos', descripcion: paramErrors.join('; ') });

    const { page, numElements, skip } = parsePagination(req.query);
    const filter = { isAppVuln: true };
    if (req.query.os)       filter.os       = req.query.os;
    if (req.query.severity) filter.severity = req.query.severity;

    const vulns = await Vuln.find(filter, MIN_PROJECTION).sort({ fechaPublicacion: -1 }).skip(skip).limit(numElements).lean();

    const result = vulns.map(v => ({
      id: v.id, titulo: v.titulo, os: v.os, version: v.version,
      severity: v.severity, fechaPublicacion: v.fechaPublicacion?.toISOString().split('T')[0],
      explotadaActivamente: v.explotadaActivamente,
    }));

    formatResponse(req, res, 200, result, 'vulnerabilidades', 'vuln');
  } catch (err) { next(err); }
}

/**
 * GET /vulns/apps/:id
 * Detalle de una vulnerabilidad de aplicación.
 */
async function getAppById(req, res, next) {
  try {
    const vuln = await Vuln.findOne({ id: req.params.id, isAppVuln: true }, '-_id -__v -isAppVuln -appId').lean();
    if (!vuln) return res.status(404).json({ codigo: 404, texto: 'No existe una vulnerabilidad de aplicación con ese ID' });
    formatResponse(req, res, 200, vuln, 'vuln', 'vuln');
  } catch (err) { next(err); }
}

module.exports = { getAll, getById, create, update, remove, getByOs, getByOsVersion, getApps, getAppById };
