const axios = require('axios');

//this was for 7d only 
// let cachedData = null;
// let lastFetched = null;

//this is for 7d , 28d ,12w
const cache = {};

const ONE_HOUR = 60 * 60 * 1000;

const fallbackTimeseries = () => ({
  serie_0: {
    timestamps: [],
    values: []
  },
  meta: {
    dateRange: []
  }
});

const settledData = (result, mapper, fallbackValue) => (
  result.status === 'fulfilled' ? mapper(result.value) : fallbackValue
);

const getGlobalDDoS = async (req, res) => {
  const cfHeaders = {
    'Authorization': `Bearer ${process.env.CLOUDFLARE_RADAR_TOKEN}`,
    'Content-Type': 'application/json'
  };

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
    const settledResponses = await Promise.allSettled([
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/timeseries', {
        headers: cfHeaders,
        params: {
          aggInterval: period === '12w' ? '1d' : '1h',
          dateRange: period,
          format: 'json'
        }
      }),
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          limit: 100,
          format: 'json'
        }
      }),

      // top countries being attacked
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          limit: 100,
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
      }),
      // Real origin→target attack pairs
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/attacks', {
        headers: cfHeaders,
        params: {
          dateRange: period,
          limit: 100,
          format: 'json'
        }
      })
    ]);

    const failedCount = settledResponses.filter((result) => result.status === 'rejected').length;

    if (failedCount === settledResponses.length) {
      throw new Error('Cloudflare Radar is temporarily unavailable');
    }

    const [
      timeseriesRes,
      originsRes,
      targetsRes,
      protocolRes,
      vectorRes,
      bitrateRes,
      durationRes,
      attackPairsRes
    ] = settledResponses;

    const result = {
      timeseries: settledData(timeseriesRes, (response) => response.data.result, fallbackTimeseries()),
      topOrigins: settledData(originsRes, (response) => response.data.result?.top_0 || [], []),
      topTargets: settledData(targetsRes, (response) => response.data.result?.top_0 || [], []),
      attackPairs: settledData(attackPairsRes, (response) => response.data.result?.top_0 || [], []),
      bitrate: settledData(bitrateRes, (response) => response.data.result?.summary_0 || {}, {}),
      duration: settledData(durationRes, (response) => response.data.result?.summary_0 || {}, {}),
      period: period,
      protocol: settledData(protocolRes, (response) => response.data.result?.summary_0 || {}, {}),
      vector: settledData(vectorRes, (response) => response.data.result?.summary_0 || {}, {}),
      partialFailures: failedCount,
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
