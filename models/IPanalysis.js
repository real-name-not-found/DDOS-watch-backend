const mongoose = require('mongoose');

const ipAnalysisSchema = new mongoose.Schema({
  ipAddress: { type: String, required: true },
  abuseScore: { type: Number, required: true },
  totalReports: { type: Number },
  isp: { type: String },
  country: { type: String },
  countryCode: { type: String },
  region: { type: String },
  regionName: { type: String },
  city: { type: String },
  district: { type: String },
  zip: { type: String },
  lat: { type: Number },
  lon: { type: Number },
  timezone: { type: String },
  org: { type: String },
  as: { type: String },
  isProxy: { type: Boolean },
  analyzedAt: { type: Date, default: Date.now }
});

const IPAnalysis = mongoose.model('IPAnalysis', ipAnalysisSchema);
module.exports = IPAnalysis;