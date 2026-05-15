const mongoose = require('mongoose');

const applicationSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  vendor: { type: String, trim: true },
  version: String,
  category: {
    type: String,
    enum: ['browser', 'office', 'database', 'webserver', 'runtime', 'multimedia', 'security', 'other'],
    default: 'other',
  },
  os: {
    type: String,
    enum: ['windows', 'linux', 'cross-platform'],
    default: 'cross-platform',
  },
  description: String,
  externalRefs: [{
    sourceCode: String,
    externalId: String,
    url: String,
  }],
}, { timestamps: true });

applicationSchema.index({ name: 1, vendor: 1 }, { unique: true });
applicationSchema.index({ category: 1, os: 1 });

module.exports = mongoose.model('Application', applicationSchema, 'applications');
