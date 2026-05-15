const mongoose = require('mongoose');

const apiSyncRunSchema = new mongoose.Schema({
  sourceCode: { type: String, required: true, uppercase: true, trim: true },
  status: { type: String, enum: ['running', 'success', 'partial', 'failed'], default: 'running', index: true },
  startedAt: { type: Date, default: Date.now, index: true },
  finishedAt: Date,
  endpoint: String,
  requestParams: mongoose.Schema.Types.Mixed,
  stats: {
    received: { type: Number, default: 0 },
    rawSaved: { type: Number, default: 0 },
    inserted: { type: Number, default: 0 },
    updated: { type: Number, default: 0 },
    skipped: { type: Number, default: 0 },
    errors: { type: Number, default: 0 },
  },
  errors: [{
    message: String,
    cveId: String,
    rawId: String,
    at: { type: Date, default: Date.now },
  }],
}, { timestamps: true });

apiSyncRunSchema.index({ sourceCode: 1, startedAt: -1 });

module.exports = mongoose.model('ApiSyncRun', apiSyncRunSchema, 'api_sync_runs');
