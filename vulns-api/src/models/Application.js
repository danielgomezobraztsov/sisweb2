const mongoose = require('mongoose');

/**
 * Colección: applications
 * Representa aplicaciones de usuario que pueden tener vulnerabilidades (isAppVuln=true en Vuln).
 * Es la segunda colección del proyecto.
 */
const applicationSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true },
  vendor:   { type: String, trim: true },
  version:  { type: String },
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
  description: { type: String },
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform(_doc, ret) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  },
});

module.exports = mongoose.model('Application', applicationSchema);
