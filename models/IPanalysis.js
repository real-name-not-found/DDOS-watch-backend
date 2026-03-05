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
  analyzedAt: { type: Date, default: Date.now },
  usageType: { type: String, default: '' },
  lastReportedAt: { type: String, default: null },
  isTor: { type: Boolean, default: false },
  domain: { type: String, default: '' },
  hostnames: { type: [String], default: [] },
  numDistinctUsers: { type: Number, default: 0 },
  ipVersion: { type: Number, default: 4 },
  isWhitelisted: { type: Boolean, default: false },
});

const IPAnalysis = mongoose.model('IPAnalysis', ipAnalysisSchema);
module.exports = IPAnalysis;