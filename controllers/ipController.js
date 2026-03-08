const axios = require('axios');
const IPAnalysis = require('../models/IPanalysis');

// --- IP Validation Helpers ---
const isValidIPv4 = (ip) => {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    const num = Number(part);
    return /^\d{1,3}$/.test(part) && num >= 0 && num <= 255;
  });
};

const isValidIPv6 = (ip) => {
  // Supports full and compressed forms (::1, 2001:db8::1, etc.)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  // also match full 8-group form
  const ipv6Full = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip) || ipv6Full.test(ip);
};

const isPrivateIP = (ip) => {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false; // only check IPv4 private ranges
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 0) return true;
  return false;
};

const analyzeIP = async (req, res) => {
  try {
    const ip = req.params.ip.trim();

    // S1 FIX: Validate IP before sending to ANY external API
    if (!isValidIPv4(ip) && !isValidIPv6(ip)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }

    if (isValidIPv4(ip) && isPrivateIP(ip)) {
      return res.status(400).json({ error: 'Private/reserved IP addresses cannot be analyzed' });
    }

    // Check MongoDB cache for recent analysis
    const existing = await IPAnalysis.findOne({
      ipAddress: ip,
      analyzedAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // within last 1 hour
    });

    if (existing) {
      return res.status(200).json(existing); // return cached data, no API call needed
    }

    const [abuseResponse, geoResponse] = await Promise.all([
      axios.get('https://api.abuseipdb.com/api/v2/check', {
        headers: {
          'Key': process.env.ABUSEIPDB_API_KEY,
          'Accept': 'application/json'
        },
        params: {
          ipAddress: ip,
          maxAgeInDays: 90
        }
      }),
      axios.get(`http://ip-api.com/json/${ip}`, {
        params: {
          fields: 'status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,proxy,query'
        }
      })

    ]);


    // extract data from both responses
    const abuseData = abuseResponse.data.data;
    const geoData = geoResponse.data;





    //save to mongoDB
    const result = {
      // from AbuseIPDB
      ipAddress: abuseData.ipAddress,
      abuseScore: abuseData.abuseConfidenceScore,
      totalReports: abuseData.totalReports,
      isp: abuseData.isp,
      numDistinctUsers: abuseData.numDistinctUsers,
      ipVersion: abuseData.ipVersion,
      isWhitelisted: abuseData.isWhitelisted,
      // from ip-api
      country: geoData.country,
      countryCode: geoData.countryCode,
      region: geoData.region,
      regionName: geoData.regionName,
      city: geoData.city,
      district: geoData.district,
      zip: geoData.zip,
      lat: geoData.lat,
      lon: geoData.lon,
      timezone: geoData.timezone,
      org: geoData.org,
      as: geoData.as,
      isProxy: geoData.proxy,
      usageType: abuseData.usageType,
      lastReportedAt: abuseData.lastReportedAt,
      isTor: abuseData.isTor,
      domain: abuseData.domain,
      hostnames: abuseData.hostnames
    };

    const saved = await IPAnalysis.create(result);

    // send back to frontend
    res.status(200).json(saved);

  } catch (err) {
    console.error('analyzeIP error:', err.message);
    res.status(500).json({ error: err.message });
  }
};

// get all previously analyzed IPs from database
const getHistory = async (req, res) => {
  try {
    const history = await IPAnalysis.find().sort({ analyzedAt: -1 });
    res.status(200).json(history);
  } catch (err) {
    console.error('getHistory error:', err.message);
    res.status(500).json({ error: err.message });
  }
};

module.exports = { analyzeIP, getHistory };