const axios = require('axios');

// This helper keeps all Python-ML API calling logic in one place so the controller
// only has to ask for a prediction instead of building HTTP requests itself.
const predictIpWithMl = async (ip) => {
  const baseUrl = process.env.ML_API_URL;

  if (!baseUrl) {
    throw new Error('ML_API_URL is not configured');
  }

  // The Node backend sends the raw IP to the Flask service; the Flask service
  // handles feature building, preprocessing, model inference, and thresholds.
  const response = await axios.post(
    `${baseUrl.replace(/\/+$/, '')}/predict`,
    { ip },
    {
      // The ML service performs live feature collection before inference, so
      // give it a little more room than the individual provider timeouts.
      timeout: 35000,
      headers: {
        'Content-Type': 'application/json'
      }
    }
  );

  return response.data;
};

module.exports = { predictIpWithMl };
