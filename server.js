// back/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// --- Models ---
const BookingSchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  service: String,
  date: Date,
  time: String,
  status: { type: String, default: 'pending' },
  paymentStatus: { type: String, default: 'unpaid' }
});
const Booking = mongoose.model('Booking', BookingSchema);

// --- Routes ---

// 1. Create Booking (Initial Request)
app.post('/api/bookings', async (req, res) => {
  try {
    const booking = new Booking(req.body);
    await booking.save();
    res.status(201).json({ message: 'Booking saved', booking });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Initiate Payment (Returns PayFast Form Data)
app.post('/api/payfast/initiate', async (req, res) => {
  const { bookingId, amount } = req.body;

  // Payfast expects a signature for security
  // Construct the data string
  const data = {
    merchant_id: process.env.PAYFAST_MERCHANT_ID,
    merchant_key: process.env.PAYFAST_MERCHANT_KEY,
    return_url: 'https://your-github-username.github.io/tassel-front/payment-success.html',
    cancel_url: 'https://your-github-username.github.io/tassel-front/payment-cancel.html',
    notify_url: `https://your-backend-url.onrender.com/api/payfast/notify`,
    m_payment_id: bookingId,
    amount: amount.toFixed(2),
    item_name: 'Tassel Salon Booking',
  };

  // Note: In production, you must generate an MD5 signature of these fields.
  // For simplicity in this snippet, we are returning the data object.
  // Always generate signatures server-side to keep your passphrase secret.

  res.json(data);
});

// 3. Payfast ITN (Instant Transaction Notification)
// This is where Payfast tells your server payment is complete
app.post('/api/payfast/notify', async (req, res) => {
  // Validate the request comes from Payfast
  // Update booking status in MongoDB
  console.log('Payment Notification Received:', req.body);
  
  const paymentId = req.body.m_payment_id;
  
  try {
    await Booking.findByIdAndUpdate(paymentId, { 
      paymentStatus: 'paid', 
      status: 'confirmed' 
    });
    res.status(200).send('OK');
  } catch (err) {
    res.status(500).send('Error');
  }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
