const express = require('express');
const router = express.Router();
const { analyzeIP, getHistory } = require('../controllers/ipControllerIntegrated');

router.get('/history', getHistory);
router.get('/:ip', analyzeIP);

module.exports = router;
