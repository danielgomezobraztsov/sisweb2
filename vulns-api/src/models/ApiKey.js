const mongoose = require('mongoose');

const apiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  active: { type: Boolean, default: true },
  scopes: [{ type: String, enum: ['read', 'write', 'sync', 'admin'] }],
  usages: { type: Number, default: 0 },
  lastUsed: Date,
}, { timestamps: true });

apiKeySchema.index({ active: 1, name: 1 });

module.exports = mongoose.model('ApiKey', apiKeySchema, 'api_keys');
