const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect('mongodb+srv://wmaseko1_db_user:7nXXIzmiqxWv0nLc@tasselgroupwebapp.akjl1sr.mongodb.net/', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Define Models (e.g., Booking, User)
const BookingSchema = new mongoose.Schema({
  name: String,
  email: String,
  service: String,
  date: Date,
  time: String,
  notes: String
});
const Booking = mongoose.model('Booking', BookingSchema);

// API Endpoints
app.post('/api/bookings', async (req, res) => {
  const { name, email, service, date, time, notes } = req.body;
  const booking = new Booking({ name, email, service, date, time, notes });
  await booking.save();
  res.status(201).send('Booking saved');
});

app.get('/api/services', (req, res) => {
  res.send(['Hair Salon', 'Beauty Spa', 'Gift Packages']);
});

// Start Server
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
