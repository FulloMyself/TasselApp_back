// back/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- Models ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['customer', 'staff', 'admin'], default: 'customer' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const BookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, email: String, phone: String, service: String,
    date: Date, time: String,
    status: { type: String, default: 'pending' },
    paymentStatus: { type: String, default: 'unpaid' }
});
const Booking = mongoose.model('Booking', BookingSchema);

const ProductSchema = new mongoose.Schema({
    name: String, price: Number, category: String, image: String, stock: { type: Number, default: 0 }
});
const Product = mongoose.model('Product', ProductSchema);

const VoucherSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    discount: { type: Number, required: true },
    discountType: { type: String, enum: ['fixed', 'percentage'], default: 'fixed' },
    expiry: { type: Date, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Voucher = mongoose.model('Voucher', VoucherSchema);

const LeaveSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    startDate: Date, endDate: Date, reason: String, status: { type: String, default: 'pending' }
});
const Leave = mongoose.model('Leave', LeaveSchema);

// --- Utilities & Middleware ---

// 1. Async Wrapper (Eliminates repetitive try/catch)
const catchAsync = fn => (req, res, next) => fn(req, res, next).catch(next);

// 2. Auth Middleware
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token is not valid' });
    }
};

// 3. Role Middleware
const authorize = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
};

// --- Routes ---

// == AUTH ==
app.post('/api/auth/register', catchAsync(async (req, res) => {
    const { name, email, password } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await new User({ name, email, password: hashedPassword }).save();

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.status(201).json({ token, user: { id: user._id, name, email, role: user.role } });
}));

app.post('/api/auth/login', catchAsync(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: 'Invalid Credentials' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
}));

// == USER PROFILE & MANAGEMENT ==
app.get('/api/auth/me', auth, catchAsync(async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
}));

// Update Profile (Name, Email, Password) - USED BY ALL USERS
app.put('/api/users/me', auth, catchAsync(async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { name, email, password } = req.body;
    user.name = name || user.name;
    user.email = email || user.email;
    if (password) user.password = await bcrypt.hash(password, 10);

    await user.save();
    res.json({ message: 'Profile updated', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
}));

// Internal Create Admin/Staff
app.post('/api/users/create-internal', catchAsync(async (req, res) => {
    const { setup_key, name, email, password, role } = req.body;
    if (setup_key !== process.env.SETUP_SECRET_KEY) return res.status(403).json({ error: 'Invalid Key' });
    if (!['admin', 'staff'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await new User({ name, email, password: hashedPassword, role }).save();
    res.status(201).json({ message: 'User created', user: { id: user._id, name, email, role } });
}));

// Get Users (Admin/Staff)
app.get('/api/users', auth, authorize('admin', 'staff'), catchAsync(async (req, res) => {
    const users = await User.find().select('-password');
    res.json(users);
}));

// == BOOKINGS ==
app.post('/api/bookings', auth, catchAsync(async (req, res) => {
    const booking = await new Booking({ ...req.body, userId: req.user.id }).save();
    res.status(201).json(booking);
}));

app.get('/api/bookings', auth, catchAsync(async (req, res) => {
    const filter = (req.user.role === 'admin' || req.user.role === 'staff') ? {} : { userId: req.user.id };
    const bookings = await Booking.find(filter).sort({ date: -1 });
    res.json(bookings);
}));

app.put('/api/bookings/:id', auth, authorize('admin', 'staff'), catchAsync(async (req, res) => {
    const booking = await Booking.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(booking);
}));

// == PRODUCTS (Admin Only) ==
app.get('/api/products', auth, authorize('admin'), catchAsync(async (req, res) => {
    res.json(await Product.find());
}));

app.post('/api/products', auth, authorize('admin'), catchAsync(async (req, res) => {
    const product = await new Product(req.body).save();
    res.status(201).json(product);
}));

app.put('/api/products/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    res.json(await Product.findByIdAndUpdate(req.params.id, req.body, { new: true }));
}));

app.delete('/api/products/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Deleted' });
}));

// == VOUCHERS (Admin Only) ==
// Get all vouchers
app.get('/api/vouchers', auth, authorize('admin'), catchAsync(async (req, res) => {
    const vouchers = await Voucher.find().sort({ createdAt: -1 });
    res.json(vouchers);
}));

// Create new voucher
app.post('/api/vouchers', auth, authorize('admin'), catchAsync(async (req, res) => {
    const { code, discount, discountType, expiry, isActive } = req.body;

    // Check if voucher code already exists
    const existingVoucher = await Voucher.findOne({ code: code.toUpperCase() });
    if (existingVoucher) {
        return res.status(400).json({ error: 'Voucher code already exists' });
    }

    // Validate discount based on type
    if (discountType === 'percentage' && (discount < 0 || discount > 100)) {
        return res.status(400).json({ error: 'Percentage discount must be between 0 and 100' });
    }

    const voucher = new Voucher({
        code: code.toUpperCase(),
        discount,
        discountType: discountType || 'fixed',
        expiry,
        isActive: isActive !== undefined ? isActive : true
    });

    await voucher.save();
    res.status(201).json(voucher);
}));

// Update voucher - PUT endpoint (THIS IS THE MISSING ONE)
app.put('/api/vouchers/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    console.log('PUT /api/vouchers/:id called with ID:', req.params.id); // Debug log
    console.log('Request body:', req.body); // Debug log

    const { code, discount, discountType, expiry, isActive } = req.body;

    // Validate discount based on type
    if (discountType === 'percentage' && (discount < 0 || discount > 100)) {
        return res.status(400).json({ error: 'Percentage discount must be between 0 and 100' });
    }

    // Check if code exists for another voucher (excluding this one)
    if (code) {
        const existingVoucher = await Voucher.findOne({
            code: code.toUpperCase(),
            _id: { $ne: req.params.id }
        });
        if (existingVoucher) {
            return res.status(400).json({ error: 'Voucher code already exists' });
        }
    }

    const voucher = await Voucher.findByIdAndUpdate(
        req.params.id,
        {
            code: code ? code.toUpperCase() : undefined,
            discount,
            discountType,
            expiry,
            isActive
        },
        { new: true, runValidators: true }
    );

    if (!voucher) {
        return res.status(404).json({ error: 'Voucher not found' });
    }

    console.log('Voucher updated successfully:', voucher); // Debug log
    res.json(voucher);
}));

// Delete voucher
app.delete('/api/vouchers/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    const voucher = await Voucher.findByIdAndDelete(req.params.id);
    if (!voucher) {
        return res.status(404).json({ error: 'Voucher not found' });
    }
    res.json({ message: 'Voucher deleted successfully' });
}));

// Add this TEMPORARY debug route - put it near your other routes
app.get('/api/debug/routes', (req, res) => {
    const routes = [];
    app._router.stack.forEach(middleware => {
        if (middleware.route) {
            // Routes registered directly
            const methods = Object.keys(middleware.route.methods).join(', ').toUpperCase();
            routes.push({
                path: middleware.route.path,
                methods: methods
            });
        } else if (middleware.name === 'router') {
            // Router middleware
            middleware.handle.stack.forEach(handler => {
                if (handler.route) {
                    const methods = Object.keys(handler.route.methods).join(', ').toUpperCase();
                    routes.push({
                        path: handler.route.path,
                        methods: methods
                    });
                }
            });
        }
    });
    res.json(routes);
});

// == LEAVE ==
app.post('/api/leave', auth, authorize('staff'), catchAsync(async (req, res) => {
    const leave = await new Leave({ ...req.body, userId: req.user.id }).save();
    res.status(201).json(leave);
}));

app.get('/api/leave', auth, authorize('admin'), catchAsync(async (req, res) => {
    res.json(await Leave.find().populate('userId', 'name email'));
}));

app.put('/api/leave/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    res.json(await Leave.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }));
}));

// == STATS ==
app.get('/api/stats', auth, authorize('admin'), catchAsync(async (req, res) => {
    const bookings = await Booking.countDocuments();
    const users = await User.countDocuments();
    const revenue = await Booking.aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }]);
    res.json({ bookings, users, revenue: revenue[0]?.total || 0 });
}));

// == PAYMENTS ==
app.post('/api/payfast/initiate', auth, (req, res) => {
    const { bookingId, amount } = req.body;
    res.json({
        merchant_id: process.env.PAYFAST_MERCHANT_ID,
        merchant_key: process.env.PAYFAST_MERCHANT_KEY,
        return_url: 'https://your-github-username.github.io/tassel-front/payment-success.html',
        cancel_url: 'https://your-github-username.github.io/tassel-front/payment-cancel.html',
        notify_url: `https://your-backend-url.onrender.com/api/payfast/notify`,
        m_payment_id: bookingId,
        amount: amount.toFixed(2),
        item_name: 'Tassel Salon Booking',
    });
});

app.post('/api/payfast/notify', catchAsync(async (req, res) => {
    await Booking.findByIdAndUpdate(req.body.m_payment_id, { paymentStatus: 'paid', status: 'confirmed' });
    res.status(200).send('OK');
}));

// == GLOBAL ERROR HANDLER ==
// This catches any errors passed by next(error) or caught by catchAsync
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
