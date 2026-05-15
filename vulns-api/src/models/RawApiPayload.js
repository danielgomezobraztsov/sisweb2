const mongoose = require('mongoose');

const rawApiPayloadSchema = new mongoose.Schema({
  sourceCode: { type: String, required: true, uppercase: true, trim: true, index: true },
  syncRunId: { type: mongoose.Schema.Types.ObjectId, ref: 'ApiSyncRun', index: true },
  externalId: { type: String, index: true },
  cveId: { type: String, index: true },
  contentType: { type: String, enum: ['application/json', 'application/xml', 'text/xml', 'text/plain', 'other'], default: 'application/json' },
  fetchedAt: { type: Date, default: Date.now, index: true },
  request: {
    url: String,
    params: mongoose.Schema.Types.Mixed,
  },
  checksum: { type: String, index: true },
  payload: { type: mongoose.Schema.Types.Mixed, required: true },
  normalized: { type: Boolean, default: false, index: true },
  normalizationError: String,
}, { timestamps: true, minimize: false });

rawApiPayloadSchema.index({ sourceCode: 1, externalId: 1 }, { unique: true, sparse: true });
rawApiPayloadSchema.index({ sourceCode: 1, cveId: 1, fetchedAt: -1 });

module.exports = mongoose.model('RawApiPayload', rawApiPayloadSchema, 'raw_api_payloads');
