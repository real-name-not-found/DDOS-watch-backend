const express = require('express');

const router = express.Router();
const { getGlobalDDoS } = require ('../controllers/globalController');

router.get('/ddos',getGlobalDDoS);

module.exports = router;

