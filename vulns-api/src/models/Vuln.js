const mongoose = require('mongoose');

// ── Enumerados compartidos ────────────────────────────────────────────────────
const OS_VALUES        = ['windows', 'linux'];
const SEVERITY_VALUES  = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const TIPO_VULN_VALUES = ['RCE', 'EoP', 'DoS', 'InfoDisclosure', 'AuthBypass', 'SQLi', 'XSS', 'Other'];
const FUENTE_VALUES    = ['NVD', 'MSRC', 'CVE.org', 'CISA-KEV', 'OSV', 'Exploit-DB'];
const CVSS_VERSION     = ['3.0', '3.1'];
const VERSION_VALUES   = [
  // Linux
  'ubuntu', 'debian', 'alpine', 'arch', 'fedora', 'centos', 'rhel', 'opensuse',
  // Windows
  'windows-10', 'windows-11',
  'windows-server-2019', 'windows-server-2022', 'windows-server-2025',
];

const cvssSchema = new mongoose.Schema({
  version:  { type: String, enum: CVSS_VERSION },
  score:    { type: Number, min: 0, max: 10 },
  severity: { type: String, enum: SEVERITY_VALUES },
  vector:   { type: String },
}, { _id: false });

const vulnSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    unique: true,
    match: [/^CVE-\d{4}-\d{4,}$/, 'Formato CVE-ID incorrecto (CVE-YYYY-XXXXX)'],
  },
  titulo:       { type: String, required: true, trim: true },
  descripcion:  { type: String, required: true },
  os:           { type: String, enum: OS_VALUES, required: true },
  version:      { type: String, enum: VERSION_VALUES },
  tipoVuln:     { type: String, enum: TIPO_VULN_VALUES },
  severity:     { type: String, enum: SEVERITY_VALUES, required: true },
  cvss:         { type: cvssSchema, required: true },
  fechaPublicacion: { type: Date, required: true },
  fechaActualizacion: { type: Date },
  explotadaActivamente: { type: Boolean, default: false },
  fuente:       { type: String, enum: FUENTE_VALUES, required: true },
  urlParche:    { type: String },
  referencias:  [{ type: String }],

  // Campo interno para distinguir vulnerabilidades de aplicaciones
  isAppVuln:    { type: Boolean, default: false },
  // Referencia a la aplicación afectada (si isAppVuln = true)
  appId:        { type: mongoose.Schema.Types.ObjectId, ref: 'Application' },
}, {
  timestamps: false,
  toJSON: {
    transform(_doc, ret) {
      delete ret._id;
      delete ret.__v;
      delete ret.isAppVuln;
      delete ret.appId;
      return ret;
    },
  },
});

// Índices para las búsquedas más frecuentes
vulnSchema.index({ os: 1, severity: 1 });
vulnSchema.index({ os: 1, version: 1 });
vulnSchema.index({ severity: 1 });
vulnSchema.index({ explotadaActivamente: 1 });
vulnSchema.index({ isAppVuln: 1 });

module.exports = mongoose.model('Vuln', vulnSchema);
module.exports.VERSION_VALUES = VERSION_VALUES;
module.exports.OS_VALUES       = OS_VALUES;
module.exports.SEVERITY_VALUES = SEVERITY_VALUES;
module.exports.FUENTE_VALUES   = FUENTE_VALUES;
module.exports.TIPO_VULN_VALUES = TIPO_VULN_VALUES;
