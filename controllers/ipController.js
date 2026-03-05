const axios = require('axios');
const IPAnalysis = require('../models/IPanalysis');

//promis.all now calls both ip-api and abuseipdb
const analyzeIP = async (req, res) => {
  try {
    const ip = req.params.ip;

    // call AbuseIPDB
    // const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
    //   headers: {
    //     'Key': process.env.ABUSEIPDB_API_KEY,
    //     'Accept': 'application/json'
    //   },
    //   params: {
    //     ipAddress: ip,
    //     maxAgeInDays: 90
    //   }
    // });

    //call Abuseipdb and ip-api fr geolocation

    //caching from mongoDB
    // check if we already have recent data for this IP
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