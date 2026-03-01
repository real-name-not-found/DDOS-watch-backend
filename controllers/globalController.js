const axios = require('axios');


let cachedData = null;
let lastFetched = null;
const ONE_HOUR = 60 * 60 * 1000;



const getGlobalDDoS = async (req,res) => {
    if (cachedData && Date.now() - lastFetched < ONE_HOUR) {
  console.log('Returning cached Cloudflare data');
  return res.status(200).json(cachedData);
    }

    try {
        const [timeseriesRes, originsRes, targetsRes] = await Promise.all([
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/timeseries', { 
                headers:{'Authorization': `Bearer ${process.env.CLOUDFLARE_RADAR_TOKEN}`,
                'Content-Type': 'application/json'
            }, 
                params: {
                    aggInterval: '1h',  // group data into 1 hour buckets
                    dateRange: '7d',    // last 7 days of data
                    format: 'json'      // return as JSON not CSV
                }
            }),
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin', {
        headers: {
          'Authorization': `Bearer ${process.env.CLOUDFLARE_RADAR_TOKEN}`,
          'Content-Type': 'application/json'
        },
        params: {
          dateRange: '7d',
          format: 'json'
        }
      }),

      // top countries being attacked
      axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target', {
        headers: {
          'Authorization': `Bearer ${process.env.CLOUDFLARE_RADAR_TOKEN}`,
          'Content-Type': 'application/json'
        },
        params: {
          dateRange: '7d',
          format: 'json'
        }
      })
        ]);

        const result = {
      timeseries: timeseriesRes.data.result,
      topOrigins: originsRes.data.result.top_0,
      topTargets: targetsRes.data.result.top_0,
      fetchedAt: new Date().toISOString()
    };
    cachedData = result;
    lastFetched = Date.now();
    res.status(200).json(result);

        
    } catch (err) {
    console.error('Cloudflare Radar error:', err.message);
    res.status(500).json({ error: err.message });
    }



};

module.exports = { getGlobalDDoS };