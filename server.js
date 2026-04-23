require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const app = express();

// Base middleware for security headers, request logging, CORS, and JSON parsing.
app.use(helmet());
app.use(morgan('dev'));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173'
}));
app.use(express.json());

// Rate limiting is applied only to API routes so the app is less vulnerable to spam traffic.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again after 15 minutes' }
});
app.use('/api/', limiter);

// Main API route groups.
app.use('/api/analyze-ip', require('./routes/ipRoutes'));
app.use('/api/global', require('./routes/globalRoutes'));

// Simple root route for quick smoke checks.
app.get('/', (req, res) => {
  res.json({ message: 'Server is running' });
});

// Dedicated backend health route for local checks and later Render monitoring.
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ddos-watch-backend' });
});

// Connect once on startup so the analyzer can cache and read IP history from MongoDB.
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection failed:', err.message));

// Final catch-all error handler for any uncaught Express errors.
app.use((err, req, res, next) => {
  console.error('Unahndeled error: ', err.stack);
  res.status(err.status || 500).json({
    error: err.message || "Something went crazy"
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
