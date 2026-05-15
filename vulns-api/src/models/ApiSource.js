const mongoose = require('mongoose');

const apiSourceSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true, trim: true },
  name: { type: String, required: true, trim: true },
  baseUrl: { type: String, required: true },
  format: { type: String, enum: ['json', 'xml', 'rss', 'csv', 'other'], default: 'json' },
  enabled: { type: Boolean, default: true },
  authType: { type: String, enum: ['none', 'apiKeyHeader', 'apiKeyQuery', 'bearer'], default: 'none' },
  rateLimit: {
    requests: Number,
    perSeconds: Number,
  },
  notes: String,
}, { timestamps: true });

apiSourceSchema.index({ enabled: 1, code: 1 });

module.exports = mongoose.model('ApiSource', apiSourceSchema, 'api_sources');
