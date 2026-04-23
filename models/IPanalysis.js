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
  mlMaliciousProbability: { type: Number, default: null },
  mlRiskBand: { type: String, default: '' },
  mlLowRiskThreshold: { type: Number, default: null },
  mlHighRiskThreshold: { type: Number, default: null },
  mlMiddleBandLabel: { type: String, default: '' },
  mlProviderStatus: { type: mongoose.Schema.Types.Mixed, default: {} },
  mlDisplayContext: { type: mongoose.Schema.Types.Mixed, default: {} },
  finalRiskScore: { type: Number, default: 0 },
  finalRiskLabel: { type: String, default: '' },
  finalRecommendation: { type: String, default: '' },
});

//Mongodb compound index — must be defined BEFORE mongoose.model()
ipAnalysisSchema.index({ ipAddress: 1, analyzedAt: -1 });

const IPAnalysis = mongoose.model('IPAnalysis', ipAnalysisSchema);

module.exports = IPAnalysis;
