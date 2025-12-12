const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  failedAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null }
});

module.exports = mongoose.model('Admin', AdminSchema);
 