// back/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For creating tokens

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key'; // Store this in .env

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- Models ---

// User Model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['customer', 'staff', 'admin'],
        default: 'customer'
    },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Booking Model
const BookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Link booking to user
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

const ProductSchema = new mongoose.Schema({
    name: String, price: Number, category: String, image: String, stock: { type: Number, default: 0 }
});
const Product = mongoose.model('Product', ProductSchema);

const VoucherSchema = new mongoose.Schema({
    code: String, discount: Number, expiry: Date, isActive: { type: Boolean, default: true }
});
const Voucher = mongoose.model('Voucher', VoucherSchema);

const LeaveSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    startDate: Date, endDate: Date, reason: String, status: { type: String, default: 'pending' } // pending, approved, rejected
});
const Leave = mongoose.model('Leave', LeaveSchema);

// --- Middleware ---

// Auth Middleware (Protects Routes)
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id: '...', role: '...' }
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token is not valid' });
    }
};

// Role Middleware
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
        }
        next();
    };
};

// --- Routes ---

// 1. AUTH ROUTES ---

// Register (ONLY for Customers)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if user exists
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ error: 'User already exists' });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user (Role is automatically 'customer' by default in Schema)
        user = new User({ name, email, password: hashedPassword });
        await user.save();

        // Create token
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.status(201).json({
            token,
            user: { id: user._id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login (For all roles)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid Credentials' });

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid Credentials' });

        // Create token
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.json({
            token,
            user: { id: user._id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Current User (Profile)
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. USER MANAGEMENT (Admin Enrollments) ---

// Admin/Staff Creation (Protected by a Setup Secret Key)
// This allows you to create Admins/Staff using Postman or a script without building a UI
app.post('/api/users/create-internal', async (req, res) => {
    const { setup_key, name, email, password, role } = req.body;

    // Verify the request comes from an authorized source (like a setup script)
    // Ideally, use a specific key stored in your .env file
    if (setup_key !== process.env.SETUP_SECRET_KEY) {
        return res.status(403).json({ error: 'Invalid Setup Key' });
    }

    if (!['admin', 'staff'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role for internal creation' });
    }

    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ error: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ name, email, password: hashedPassword, role });
        await user.save();

        res.status(201).json({ message: `${role} user created successfully`, user: { id: user._id, name, email, role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 3. BOOKING ROUTES ---

// Create Booking (Any logged-in user, usually Customer)
app.post('/api/bookings', auth, async (req, res) => {
    try {
        const booking = new Booking({
            ...req.body,
            userId: req.user.id // Attach logged-in user ID
        });
        await booking.save();
        res.status(201).json({ message: 'Booking saved', booking });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Bookings
// Admin gets all, Staff gets all, Customer gets only their own
app.get('/api/bookings', auth, async (req, res) => {
    try {
        let bookings;
        if (req.user.role === 'admin' || req.user.role === 'staff') {
            bookings = await Booking.find().sort({ date: -1 });
        } else {
            bookings = await Booking.find({ userId: req.user.id }).sort({ date: -1 });
        }
        res.json(bookings);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Booking Status (Admin/Staff Only)
app.put('/api/bookings/:id', auth, authorize('admin', 'staff'), async (req, res) => {
    try {
        const booking = await Booking.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(booking);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 4. PAYMENT ROUTES ---

app.post('/api/payfast/initiate', auth, async (req, res) => {
    // In a real app, you might verify the booking belongs to the user
    const { bookingId, amount } = req.body;

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

    res.json(data);
});

app.post('/api/payfast/notify', async (req, res) => {
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

// == PRODUCTS (Admin Only) ==
app.get('/api/products', auth, authorize('admin'), async (req, res) => {
    const products = await Product.find();
    res.json(products);
});

app.post('/api/products', auth, authorize('admin'), async (req, res) => {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
});

// == VOUCHERS (Admin Only) ==
app.get('/api/vouchers', auth, authorize('admin'), async (req, res) => {
    const vouchers = await Voucher.find();
    res.json(vouchers);
});

app.post('/api/vouchers', auth, authorize('admin'), async (req, res) => {
    const voucher = new Voucher(req.body);
    await voucher.save();
    res.status(201).json(voucher);
});

// == USERS (Admin & Staff) ==
app.get('/api/users', auth, authorize('admin', 'staff'), async (req, res) => {
    const users = await User.find().select('-password');
    res.json(users);
});

// == LEAVE MANAGEMENT ==
// Staff Request Leave
app.post('/api/leave', auth, authorize('staff'), async (req, res) => {
    const leave = new Leave({ ...req.body, userId: req.user.id });
    await leave.save();
    res.status(201).json(leave);
});

// Admin Get All Leaves
app.get('/api/leave', auth, authorize('admin'), async (req, res) => {
    const leaves = await Leave.find().populate('userId', 'name email');
    res.json(leaves);
});

// Admin Approve/Reject Leave
app.put('/api/leave/:id', auth, authorize('admin'), async (req, res) => {
    const { status } = req.body;
    const leave = await Leave.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json(leave);
});

// == STATS (Admin Dashboard) ==
app.get('/api/stats', auth, authorize('admin'), async (req, res) => {
    const totalBookings = await Booking.countDocuments();
    const totalUsers = await User.countDocuments();
    const revenueResult = await Booking.aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }]);

    res.json({
        bookings: totalBookings,
        users: totalUsers,
        revenue: revenueResult[0]?.total || 0
    });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
