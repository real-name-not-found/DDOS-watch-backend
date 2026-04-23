const axios = require('axios');
const { isIP } = require('node:net');
const IPAnalysis = require('../models/IPanalysis');

// retry logics crazyy - retry 1 time with 10 sec timeout 
const retryRequest = async (fn, retries = 1, delayMs = 2000) => {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === retries) throw err;
      console.log(`[retry] Attempt ${attempt + 1}/${retries} failed: ${err.message}`);
      await new Promise(res => setTimeout(res, delayMs));
    }
  }
};
const ipVersion = (ip) => isIP(ip);
const isValidIPv4 = (ip) => ipVersion(ip) === 4;
const isValidIPv6 = (ip) => ipVersion(ip) === 6;

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
    if (ipVersion(ip) === 0) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }

    if (isValidIPv4(ip) && isPrivateIP(ip)) {
      return res.status(400).json({ error: 'Private/reserved IP addresses cannot be analyzed' });
    }
    //addedd log so that to catch the error in render log becoz i am not understanfing why the fuck is it not workign :( 
    console.log(`[analyzeIP] Checking cache for ${ip}`);

    // Check MongoDB cache for recent analysis
    const existing = await IPAnalysis.findOne({
      ipAddress: ip,
      analyzedAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // within last 1 hour
    });

    if (existing) {
      //again to see the data which is shwoed is it because ofmongdodb cache ? 
      console.log(`[analyzeIP] Cache hit for ${ip}`);
      return res.status(200).json(existing); // return cached data, no API call needed
    }

    // ADDED: log cache miss + which APIs we're calling
    // WHY: If Render logs stop here, you know the API calls below are hanging
    console.log(`[analyzeIP] Cache miss — fetching from AbuseIPDB + ipwho.is for ${ip}`);

    const [abuseResponse, geoResponse] = await Promise.all([
      retryRequest(() => axios.get('https://api.abuseipdb.com/api/v2/check', {
        headers: {
          'Key': process.env.ABUSEIPDB_API_KEY,
          'Accept': 'application/json'
        },
        params: {
          ipAddress: ip,
          maxAgeInDays: 90
        },
        timeout: 10000
      })),

      //changing from ip-api to ipwho
      retryRequest(() => axios.get(`https://ipwho.is/${ip}`, {
        // params: {
        //   fields: 'status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,proxy,query'
        // }
        timeout: 10000
      }))
    ]);
    // ADDED: log after both APIs respond
    // WHY: If you see these in Render logs, you know the APIs worked and the problem is elsewhere
    console.log(`[analyzeIP] AbuseIPDB responded for ${ip}`);
    console.log(`[analyzeIP] ipwho.is responded for ${ip}`);

    // extract data from both responses
    const abuseData = abuseResponse.data.data;
    const geo = geoResponse.data;
    //ipwho error check
    if (geo.success === false) {
      console.log(`[analyzeIP] ipwho.is failed for ${ip}: ${geo.message}`);
    }



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
      // country: geoData.country,
      // countryCode: geoData.countryCode,
      // region: geoData.region,
      // regionName: geoData.regionName,
      // city: geoData.city,
      // district: geoData.district,
      // zip: geoData.zip,
      // lat: geoData.lat,
      // lon: geoData.lon,
      // timezone: geoData.timezone,
      // org: geoData.org,
      // as: geoData.as,
      // isProxy: geoData.proxy,

      //from ipwho
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

      //abuseipdb
      usageType: abuseData.usageType,
      lastReportedAt: abuseData.lastReportedAt,
      isTor: abuseData.isTor,
      domain: abuseData.domain,
      hostnames: abuseData.hostnames
    };

    // ADDED: log before/after MongoDB save
    // WHY: If Render logs show "Saving" but not "Done", MongoDB write is hanging
    console.log(`[analyzeIP] Saving to MongoDB for ${ip}`);


    const saved = await IPAnalysis.create(result);
    console.log(`[analyzeIP] Done for ${ip}`);

    // send back to frontend
    res.status(200).json(saved);

  } catch (err) {
    // CHANGED: more descriptive error log with IP included
    // WHY: Old log just said "analyzeIP error" — now shows which IP failed
    console.error(`[analyzeIP] ERROR for ${req.params.ip}: ${err.message}`);
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
