const mongoose = require('mongoose');

const affectedProductSchema = new mongoose.Schema({
  vulnerabilityId: { type: String, required: true, index: true },
  cveObjectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vulnerability', index: true },
  applicationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Application', index: true },
  productName: { type: String, required: true, trim: true, index: true },
  vendor: { type: String, trim: true, index: true },
  productType: { type: String, enum: ['os', 'application', 'library', 'service', 'hardware', 'other'], default: 'application' },
  os: { type: String, enum: ['windows', 'linux', 'cross-platform', 'unknown'], default: 'unknown' },
  affectedVersionRange: String,
  affectedVersions: [{ type: String }],
  fixedVersions: [{ type: String }],
  cpe: String,
  purl: String,
  sourceCode: { type: String, uppercase: true },
}, { timestamps: true });

affectedProductSchema.index({ vulnerabilityId: 1, productName: 1, affectedVersionRange: 1 }, { unique: true });
affectedProductSchema.index({ vendor: 1, productName: 1 });

module.exports = mongoose.model('AffectedProduct', affectedProductSchema, 'affected_products');
