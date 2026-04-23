const axios = require('axios');
const { isIP } = require('node:net');
const IPAnalysis = require('../models/IPanalysis');
const { predictIpWithMl } = require('../services/mlService');
const { buildFinalRisk } = require('../utils/finalRisk');

// Small retry wrapper for flaky third-party APIs so one temporary timeout does
// not immediately fail the whole analysis request.
const retryRequest = async (fn, retries = 1, delayMs = 2000) => {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === retries) {
        throw err;
      }

      console.log(`[retry] Attempt ${attempt + 1}/${retries + 1} failed: ${err.message}`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return null;
};

const ipVersion = (ip) => isIP(ip);
const isValidIPv4 = (ip) => ipVersion(ip) === 4;
const isValidIPv6 = (ip) => ipVersion(ip) === 6;

// Private/reserved IPv4 addresses are blocked because the model and live data
// providers are designed for public internet IPs.
const isPrivateIPv4 = (ip) => {
  const parts = ip.split('.').map(Number);

  if (parts.length !== 4) {
    return false;
  }

  if (parts[0] === 10) {
    return true;
  }

  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }

  if (parts[0] === 192 && parts[1] === 168) {
    return true;
  }

  return parts[0] === 127 || parts[0] === 0;
};

// These provider helpers keep request details out of the main controller body.
const fetchAbuseIpdb = (ip) => retryRequest(() => axios.get('https://api.abuseipdb.com/api/v2/check', {
  headers: {
    Key: process.env.ABUSEIPDB_API_KEY,
    Accept: 'application/json'
  },
  params: {
    ipAddress: ip,
    maxAgeInDays: 90
  },
  timeout: 10000
}));

const fetchIpwho = (ip) => retryRequest(() => axios.get(`https://ipwho.is/${ip}`, {
  timeout: 10000
}));

const analyzeIP = async (req, res) => {
  try {
    const ip = req.params.ip.trim();

    // Validate early so we fail fast before calling AbuseIPDB, ipwho, or the ML API.
    if (ipVersion(ip) === 0) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }

    if (isValidIPv4(ip) && isPrivateIPv4(ip)) {
      return res.status(400).json({ error: 'Private/reserved IP addresses cannot be analyzed' });
    }

    console.log(`[analyzeIP] Checking cache for ${ip}`);

    const existing = await IPAnalysis.findOne({
      ipAddress: ip,
      analyzedAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    });

    // If we already have a fresh row with ML fields, we can return it directly.
    if (existing && typeof existing.mlMaliciousProbability === 'number') {
      console.log(`[analyzeIP] Cache hit for ${ip}`);
      return res.status(200).json(existing);
    }

    if (existing) {
      console.log(`[analyzeIP] Cache row exists for ${ip} but is missing ML fields. Refreshing.`);
    } else {
      console.log(`[analyzeIP] Cache miss for ${ip}. Fetching provider data and ML prediction.`);
    }

    const mlPromise = predictIpWithMl(ip).catch((err) => {
      console.warn(`[analyzeIP] ML API failed for ${ip}: ${err.message}`);
      return null;
    });

    // AbuseIPDB, ipwho, and the ML API are fetched in parallel to keep latency down.
    const [abuseResponse, geoResponse, mlResponse] = await Promise.all([
      fetchAbuseIpdb(ip),
      fetchIpwho(ip),
      mlPromise
    ]);

    console.log(`[analyzeIP] AbuseIPDB responded for ${ip}`);
    console.log(`[analyzeIP] ipwho.is responded for ${ip}`);
    console.log(`[analyzeIP] ML service ${mlResponse ? 'responded' : 'did not respond'} for ${ip}`);

    const abuseData = abuseResponse.data.data;
    const geo = geoResponse.data;

    if (geo.success === false) {
      console.log(`[analyzeIP] ipwho.is failed for ${ip}: ${geo.message}`);
    }

    const mlProbability = typeof mlResponse?.ml_malicious_probability === 'number'
      ? mlResponse.ml_malicious_probability
      : null;
    const mlRiskBand = mlResponse?.risk_band || '';
    const finalRisk = buildFinalRisk({
      abuseScore: abuseData.abuseConfidenceScore,
      isWhitelisted: abuseData.isWhitelisted
    });

    // This is the single merged payload that gets saved and sent back to the frontend.
    // It combines AbuseIPDB data, ipwho display data, ML output, and final UI-ready risk fields.
    const result = {
      ipAddress: abuseData.ipAddress || ip,
      abuseScore: abuseData.abuseConfidenceScore,
      totalReports: abuseData.totalReports,
      isp: abuseData.isp,
      numDistinctUsers: abuseData.numDistinctUsers,
      ipVersion: abuseData.ipVersion,
      isWhitelisted: abuseData.isWhitelisted,
      country: geo.country || '',
      countryCode: geo.country_code || '',
      region: geo.region_code || '',
      regionName: geo.region || '',
      city: geo.city || '',
      district: '',
      zip: geo.postal || '',
      lat: geo.latitude,
      lon: geo.longitude,
      timezone: geo.timezone?.id || '',
      org: geo.connection?.org || '',
      as: geo.connection?.asn ? `AS${geo.connection.asn} ${geo.connection.org || ''}` : '',
      isProxy: geo.security?.proxy || false,
      usageType: abuseData.usageType,
      lastReportedAt: abuseData.lastReportedAt,
      isTor: abuseData.isTor,
      domain: abuseData.domain,
      hostnames: abuseData.hostnames,
      mlMaliciousProbability: mlProbability,
      mlRiskBand: mlRiskBand,
      mlLowRiskThreshold: mlResponse?.thresholds?.low_risk_below_or_equal ?? 0.6,
      mlHighRiskThreshold: mlResponse?.thresholds?.high_risk_from_or_equal ?? 0.7,
      mlMiddleBandLabel: mlResponse?.thresholds?.middle_label || 'monitor',
      mlProviderStatus: mlResponse?.provider_status || {},
      mlDisplayContext: mlResponse?.display_context || {},
      finalRiskScore: finalRisk.finalRiskScore,
      finalRiskLabel: finalRisk.finalRiskLabel,
      finalRecommendation: finalRisk.finalRecommendation,
      analyzedAt: new Date(),
    };

    console.log(`[analyzeIP] Saving analysis for ${ip}`);

    let saved;
    // Old cached rows from before ML integration are upgraded in place instead of duplicated.
    if (existing) {
      Object.assign(existing, result);
      saved = await existing.save();
    } else {
      saved = await IPAnalysis.create(result);
    }

    console.log(`[analyzeIP] Done for ${ip}`);
    return res.status(200).json(saved);
  } catch (err) {
    console.error(`[analyzeIP] ERROR for ${req.params.ip}: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
};

const getHistory = async (req, res) => {
  try {
    // History still works the same way; it now simply returns rows that include ML fields too.
    const history = await IPAnalysis.find().sort({ analyzedAt: -1 });
    return res.status(200).json(history);
  } catch (err) {
    console.error(`getHistory error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
};

module.exports = { analyzeIP, getHistory };
