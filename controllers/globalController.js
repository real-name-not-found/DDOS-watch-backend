const axios = require('axios');

//this was for 7d only 
// let cachedData = null;
// let lastFetched = null;

//this is for 7d , 28d ,12w
const cache = {};

const ONE_HOUR = 60 * 60 * 1000;

const cfHeaders = {
  'Authorization': `Bearer ${process.env.CLOUDFLARE_RADAR_TOKEN}`,
  'Content-Type': 'application/json'
};

const getGlobalDDoS = async (req, res) => {

  const period = req.query.period || '7d';

  //check for invalid period
  if (!['7d', '28d', '12w'].includes(period)) {
    return res.status(400).json({ error: 'Invalid period. Use 7d, 28d, or 12w' });
  }

  //check for cache
  if (cache[period] && Date.now() - cache[period].lastFetched < ONE_HOUR) {
    console.log(`Returning cached Cloudflare data for ${period}`);
    return res.status(200).json(cache[period].data);
  }

  try {
    const [timeseriesRes, originsRes, targetsRes, protocolRes, vectorRes, bitrateRes, durationRes] = await Promise.all([
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/timeseries', {
        headers: cfHeaders,
        params: {
          aggInterval: period === '12w' ? '1d' : '1h',  // daily for 12w, hourly for 7d/28d
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      }),

      // top countries being attacked
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/summary/protocol', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/summary/vector', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/summary/bitrate', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/summary/duration', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          format: 'json'
        }
      })
    ]);
    // console.log('Cloudflare timeseries:', JSON.stringify(timeseriesRes.data.result, null, 2));
    // console.log('Cloudflare origins:', JSON.stringify(originsRes.data.result.top_0, null, 2));
    // console.log('Cloudflare targets:', JSON.stringify(targetsRes.data.result.top_0, null, 2));

    const result = {
      timeseries: timeseriesRes.data.result,
      topOrigins: originsRes.data.result.top_0,
      topTargets: targetsRes.data.result.top_0,
      bitrate: bitrateRes.data.result.summary_0,
      duration: durationRes.data.result.summary_0,
      period: period,
      protocol: protocolRes.data.result.summary_0,
      vector: vectorRes.data.result.summary_0,
      fetchedAt: new Date().toISOString()
    };
    // cachedData = result;
    // lastFetched = Date.now();

    cache[period] = { data: result, lastFetched: Date.now() };
    res.status(200).json(result);


  } catch (err) {
    console.error('Cloudflare Radar error:', err.message);
    res.status(500).json({ error: err.message });
  }



};

module.exports = { getGlobalDDoS };