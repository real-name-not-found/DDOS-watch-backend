require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/analyze-ip', require('./routes/ipRoutes'));
app.use('/api/global', require('./routes/globalRoutes'));

app.get('/' , (req,res) => {
    // console.log("server is running ");
    res.json({message : 'Server is running' });
})


mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection failed:', err.message));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});