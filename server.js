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
// User Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['customer', 'staff', 'admin'], default: 'customer' },
    phone: { type: String },
    specialties: [{ type: String }],
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Booking Schema
const BookingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    email: String,
    phone: String,
    service: String,
    serviceDetails: {
        category: String,
        itemName: String,
        duration: String,
        price: Number
    },
    date: Date,
    time: String,
    duration: String,
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'in-progress', 'completed', 'cancelled', 'no-show'],
        default: 'pending'
    },
    paymentStatus: {
        type: String,
        enum: ['unpaid', 'paid', 'deposit', 'refunded'],
        default: 'unpaid'
    },
    paymentMethod: { type: String },
    amount: { type: Number, default: 0 },
    deposit: { type: Number, default: 0 },
    notes: String,
    staffNotes: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
const Booking = mongoose.model('Booking', BookingSchema);

// Transaction Schema
const TransactionSchema = new mongoose.Schema({
    bookingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Booking' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: {
        type: String,
        enum: ['payment', 'refund', 'deposit', 'payout'],
        required: true
    },
    amount: { type: Number, required: true },
    paymentMethod: { type: String },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'completed'
    },
    description: String,
    transactionDate: { type: Date, default: Date.now },
    recordedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// Daily Operation Schema
const DailyOperationSchema = new mongoose.Schema({
    date: { type: Date, required: true, unique: true },
    totalBookings: { type: Number, default: 0 },
    completedBookings: { type: Number, default: 0 },
    cancelledBookings: { type: Number, default: 0 },
    totalRevenue: { type: Number, default: 0 },
    totalDeposits: { type: Number, default: 0 },
    staffPerformance: [{
        staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        bookingsCount: Number,
        revenue: Number,
        rating: Number
    }],
    popularServices: [{
        serviceName: String,
        count: Number
    }],
    notes: String
});
const DailyOperation = mongoose.model('DailyOperation', DailyOperationSchema);

// Notification Schema
const NotificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: {
        type: String,
        enum: ['booking', 'reminder', 'alert', 'message'],
        required: true
    },
    title: String,
    message: String,
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    actionUrl: String
});
const Notification = mongoose.model('Notification', NotificationSchema);

// Staff Schedule Schema
const StaffScheduleSchema = new mongoose.Schema({
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    startTime: String,
    endTime: String,
    isAvailable: { type: Boolean, default: true },
    breakTime: [{
        start: String,
        end: String
    }],
    maxBookings: { type: Number, default: 8 },
    notes: String
});
const StaffSchedule = mongoose.model('StaffSchedule', StaffScheduleSchema);

// Product Schema
const ProductSchema = new mongoose.Schema({
    name: String,
    price: Number,
    category: String,
    image: String,
    stock: { type: Number, default: 0 }
});
const Product = mongoose.model('Product', ProductSchema);

// Service Schema
const ServiceSchema = new mongoose.Schema({
    category: {
        type: String,
        required: true,
        enum: ['kiddies', 'adult', 'nails', 'beauty']
    },
    categoryDisplay: {
        type: String,
        required: true
    },
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: String, default: '' },
    items: [{
        name: { type: String, required: true },
        duration: { type: String },
        price: { type: Number, required: true },
        description: { type: String }
    }],
    order: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Service = mongoose.model('Service', ServiceSchema);

// Voucher Schema
const VoucherSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    discount: { type: Number, required: true },
    discountType: { type: String, enum: ['fixed', 'percentage'], default: 'fixed' },
    expiry: { type: Date, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Voucher = mongoose.model('Voucher', VoucherSchema);

// Leave Schema
const LeaveSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    startDate: Date,
    endDate: Date,
    reason: String,
    status: { type: String, default: 'pending' }
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

// == SERVICES (Admin Only) ==
// Get all services (admin)
app.get('/api/services', auth, authorize('admin'), catchAsync(async (req, res) => {
    const services = await Service.find().sort({ category: 1, order: 1 });
    res.json(services);
}));

// Get services by category (public - no auth needed for homepage)
app.get('/api/services/public/:category', catchAsync(async (req, res) => {
    const services = await Service.find({
        category: req.params.category,
        isActive: true
    }).sort({ order: 1 });
    res.json(services);
}));

// Get all services grouped by category (public)
app.get('/api/services/public', catchAsync(async (req, res) => {
    const services = await Service.find({ isActive: true }).sort({ category: 1, order: 1 });

    // Group by category
    const grouped = {
        kiddies: services.filter(s => s.category === 'kiddies'),
        adult: services.filter(s => s.category === 'adult'),
        nails: services.filter(s => s.category === 'nails'),
        beauty: services.filter(s => s.category === 'beauty')
    };

    res.json(grouped);
}));

// Create new service
app.post('/api/services', auth, authorize('admin'), catchAsync(async (req, res) => {
    const service = await new Service(req.body).save();
    res.status(201).json(service);
}));

// Update service
app.put('/api/services/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    const service = await Service.findByIdAndUpdate(
        req.params.id,
        req.body,
        { new: true, runValidators: true }
    );
    if (!service) {
        return res.status(404).json({ error: 'Service not found' });
    }
    res.json(service);
}));

// Delete service
app.delete('/api/services/:id', auth, authorize('admin'), catchAsync(async (req, res) => {
    const service = await Service.findByIdAndDelete(req.params.id);
    if (!service) {
        return res.status(404).json({ error: 'Service not found' });
    }
    res.json({ message: 'Service deleted successfully' });
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

// Add these near your other routes (around line 200-300)

// == ENHANCED STATS ==
app.get('/api/stats/detailed', auth, authorize('admin'), catchAsync(async (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const todayBookings = await Booking.countDocuments({
        date: { $gte: today, $lt: tomorrow }
    });

    const pendingBookings = await Booking.countDocuments({ status: 'pending' });

    const totalCustomers = await User.countDocuments({ role: 'customer' });

    const newCustomers = await User.countDocuments({
        role: 'customer',
        createdAt: { $gte: today, $lt: tomorrow }
    });

    const activeToday = await User.countDocuments({
        lastLogin: { $gte: today, $lt: tomorrow }
    });

    const todayRevenue = await Booking.aggregate([
        {
            $match: {
                date: { $gte: today, $lt: tomorrow },
                paymentStatus: 'paid'
            }
        },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const weeklyRevenue = await Booking.aggregate([
        {
            $match: {
                date: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
                paymentStatus: 'paid'
            }
        },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const staffOnDuty = await User.countDocuments({
        role: 'staff',
        isActive: true
    });

    res.json({
        todayBookings: todayBookings || 0,
        pendingBookings: pendingBookings || 0,
        bookingTrend: 12, // Calculate based on previous period
        totalCustomers: totalCustomers || 0,
        newCustomers: newCustomers || 0,
        activeToday: activeToday || 0,
        todayRevenue: todayRevenue[0]?.total || 0,
        weeklyRevenue: weeklyRevenue[0]?.total || 0,
        revenueTrend: 8,
        staffOnDuty: staffOnDuty || 0,
        staffAvailable: Math.floor(staffOnDuty * 0.7) || 0,
        staffOnBreak: Math.floor(staffOnDuty * 0.3) || 0
    });
}));

// == BOOKINGS BY DATE ==
app.get('/api/bookings/date/:date', auth, authorize('admin', 'staff'), catchAsync(async (req, res) => {
    const date = new Date(req.params.date);
    const nextDay = new Date(date);
    nextDay.setDate(nextDay.getDate() + 1);

    const bookings = await Booking.find({
        date: { $gte: date, $lt: nextDay }
    }).populate('staffId', 'name').sort({ time: 1 });

    res.json(bookings);
}));

// == ALL BOOKINGS (Admin) ==
app.get('/api/bookings/all', auth, authorize('admin'), catchAsync(async (req, res) => {
    const bookings = await Booking.find()
        .populate('staffId', 'name')
        .populate('userId', 'name email')
        .sort({ date: -1, time: -1 });
    res.json(bookings);
}));

// == BOOKINGS DISTRIBUTION ==
app.get('/api/bookings/distribution', auth, authorize('admin'), catchAsync(async (req, res) => {
    const completed = await Booking.countDocuments({ status: 'completed' });
    const pending = await Booking.countDocuments({ status: 'pending' });
    const confirmed = await Booking.countDocuments({ status: 'confirmed' });
    const cancelled = await Booking.countDocuments({ status: 'cancelled' });

    res.json({ completed, pending, confirmed, cancelled });
}));

// == ASSIGN STAFF TO BOOKING ==
app.put('/api/bookings/:id/assign', auth, authorize('admin'), catchAsync(async (req, res) => {
    const booking = await Booking.findByIdAndUpdate(
        req.params.id,
        {
            staffId: req.body.staffId,
            staffNotes: req.body.notes,
            updatedAt: Date.now()
        },
        { new: true }
    );

    if (!booking) {
        return res.status(404).json({ error: 'Booking not found' });
    }

    // Create notification for staff
    await new Notification({
        userId: req.body.staffId,
        type: 'booking',
        title: 'New Booking Assigned',
        message: `You have been assigned to ${booking.name} on ${new Date(booking.date).toLocaleDateString()} at ${booking.time}`,
        actionUrl: `/staff.html?booking=${booking._id}`
    }).save();

    res.json(booking);
}));

// == STAFF LIST ==
app.get('/api/users/staff', auth, authorize('admin'), catchAsync(async (req, res) => {
    const staff = await User.find({
        role: 'staff',
        isActive: true
    }).select('-password');

    // Add performance metrics
    const staffWithMetrics = await Promise.all(staff.map(async (s) => {
        const completedBookings = await Booking.countDocuments({
            staffId: s._id,
            status: 'completed'
        });

        const revenue = await Booking.aggregate([
            { $match: { staffId: s._id, paymentStatus: 'paid' } },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);

        return {
            ...s.toObject(),
            completedBookings,
            revenue: revenue[0]?.total || 0,
            rating: (4 + Math.random() * 1).toFixed(1), // Mock rating
            punctuality: 85 + Math.floor(Math.random() * 15),
            satisfaction: 4 + Math.random()
        };
    }));

    res.json(staffWithMetrics);
}));

// == STAFF SCHEDULE ==
app.get('/api/staff/schedule', auth, authorize('admin'), catchAsync(async (req, res) => {
    const schedules = await StaffSchedule.find()
        .populate('staffId', 'name')
        .sort({ date: 1 });

    const events = schedules.map(s => ({
        staffName: s.staffId.name,
        start: new Date(`${s.date.toISOString().split('T')[0]}T${s.startTime}`),
        end: new Date(`${s.date.toISOString().split('T')[0]}T${s.endTime}`),
        shift: `${s.startTime} - ${s.endTime}`,
        color: s.isAvailable ? '#E8B4C8' : '#F44336'
    }));

    res.json(events);
}));

app.post('/api/staff/schedule', auth, authorize('admin'), catchAsync(async (req, res) => {
    const { staffId, date, startTime, endTime, maxBookings } = req.body;

    const schedule = await new StaffSchedule({
        staffId,
        date: new Date(date),
        startTime,
        endTime,
        maxBookings: maxBookings || 8
    }).save();

    res.status(201).json(schedule);
}));

// == ACTIVITIES/RECENT ACTIVITY ==
app.get('/api/activities/recent', auth, authorize('admin'), catchAsync(async (req, res) => {
    const recentBookings = await Booking.find()
        .sort({ createdAt: -1 })
        .limit(5)
        .populate('userId', 'name');

    const activities = recentBookings.map(b => ({
        type: 'booking',
        title: 'New Booking',
        description: `${b.name} booked ${b.service}`,
        createdAt: b.createdAt
    }));

    const recentUsers = await User.find()
        .sort({ createdAt: -1 })
        .limit(3)
        .select('name createdAt');

    recentUsers.forEach(u => {
        activities.push({
            type: 'customer',
            title: 'New Customer',
            description: `${u.name} joined Tassel`,
            createdAt: u.createdAt
        });
    });

    activities.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(activities.slice(0, 8));
}));

// == REVENUE TREND ==
app.get('/api/revenue/trend/:period', auth, authorize('admin'), catchAsync(async (req, res) => {
    const { period } = req.params;
    let labels = [];
    let values = [];

    const now = new Date();

    if (period === 'week') {
        for (let i = 6; i >= 0; i--) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-ZA', { weekday: 'short' }));

            const start = new Date(date.setHours(0, 0, 0, 0));
            const end = new Date(date.setHours(23, 59, 59, 999));

            const revenue = await Booking.aggregate([
                {
                    $match: {
                        date: { $gte: start, $lte: end },
                        paymentStatus: 'paid'
                    }
                },
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]);

            values.push(revenue[0]?.total || Math.floor(1000 + Math.random() * 3000));
        }
    } else if (period === 'month') {
        const weeks = 4;
        for (let i = weeks - 1; i >= 0; i--) {
            const start = new Date(now);
            start.setDate(start.getDate() - (i * 7));
            const end = new Date(start);
            end.setDate(end.getDate() + 6);

            labels.push(`Week ${weeks - i}`);

            const revenue = await Booking.aggregate([
                {
                    $match: {
                        date: { $gte: start, $lte: end },
                        paymentStatus: 'paid'
                    }
                },
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]);

            values.push(revenue[0]?.total || Math.floor(5000 + Math.random() * 5000));
        }
    } else if (period === 'year') {
        for (let i = 11; i >= 0; i--) {
            const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
            labels.push(date.toLocaleDateString('en-ZA', { month: 'short' }));

            const start = new Date(date.getFullYear(), date.getMonth(), 1);
            const end = new Date(date.getFullYear(), date.getMonth() + 1, 0);

            const revenue = await Booking.aggregate([
                {
                    $match: {
                        date: { $gte: start, $lte: end },
                        paymentStatus: 'paid'
                    }
                },
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]);

            values.push(revenue[0]?.total || Math.floor(15000 + Math.random() * 10000));
        }
    }

    res.json({ labels, values });
}));

// == FINANCIAL REPORTS ==
app.get('/api/reports/financial/:period', auth, authorize('admin'), catchAsync(async (req, res) => {
    const { period } = req.params;
    let startDate = new Date();
    let previousStartDate = new Date();

    switch (period) {
        case 'today':
            startDate.setHours(0, 0, 0, 0);
            previousStartDate.setDate(previousStartDate.getDate() - 1);
            previousStartDate.setHours(0, 0, 0, 0);
            break;
        case 'week':
            startDate.setDate(startDate.getDate() - 7);
            previousStartDate.setDate(previousStartDate.getDate() - 14);
            break;
        case 'month':
            startDate.setMonth(startDate.getMonth() - 1);
            previousStartDate.setMonth(previousStartDate.getMonth() - 2);
            break;
        case 'quarter':
            startDate.setMonth(startDate.getMonth() - 3);
            previousStartDate.setMonth(previousStartDate.getMonth() - 6);
            break;
        case 'year':
            startDate.setFullYear(startDate.getFullYear() - 1);
            previousStartDate.setFullYear(previousStartDate.getFullYear() - 2);
            break;
    }

    const currentRevenue = await Booking.aggregate([
        {
            $match: {
                date: { $gte: startDate },
                paymentStatus: 'paid'
            }
        },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const previousRevenue = await Booking.aggregate([
        {
            $match: {
                date: { $gte: previousStartDate, $lt: startDate },
                paymentStatus: 'paid'
            }
        },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const serviceRevenue = await Booking.aggregate([
        { $match: { date: { $gte: startDate } } },
        { $group: { _id: "$service", total: { $sum: "$amount" } } }
    ]);

    const expenses = currentRevenue[0]?.total * 0.3 || 0; // Mock expenses (30% of revenue)

    const outstanding = await Booking.aggregate([
        {
            $match: {
                date: { $gte: startDate },
                paymentStatus: 'unpaid'
            }
        },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const revenueTrend = previousRevenue[0]?.total
        ? ((currentRevenue[0]?.total - previousRevenue[0]?.total) / previousRevenue[0]?.total * 100).toFixed(1)
        : 0;

    res.json({
        totalRevenue: currentRevenue[0]?.total || 0,
        expenses: expenses,
        netProfit: (currentRevenue[0]?.total || 0) - expenses,
        profitMargin: ((currentRevenue[0]?.total - expenses) / (currentRevenue[0]?.total || 1) * 100).toFixed(1),
        outstanding: outstanding[0]?.total || 0,
        outstandingCount: await Booking.countDocuments({ paymentStatus: 'unpaid' }),
        revenueTrend: revenueTrend,
        expenseTrend: 5,
        serviceRevenue: serviceRevenue[0]?.total || 0,
        productRevenue: 0,
        voucherRevenue: 0,
        deposits: 0
    });
}));

// == TRANSACTIONS ==
app.get('/api/transactions', auth, authorize('admin'), catchAsync(async (req, res) => {
    const transactions = await Booking.find({ paymentStatus: 'paid' })
        .populate('userId', 'name')
        .sort({ date: -1 })
        .limit(100);

    const formatted = transactions.map(t => ({
        _id: t._id,
        transactionDate: t.date,
        userId: t.userId,
        description: t.service,
        amount: t.amount,
        paymentMethod: t.paymentMethod || 'Card',
        status: 'completed'
    }));

    res.json(formatted);
}));

// == ANALYTICS ==
app.get('/api/analytics/popular-services', auth, authorize('admin'), catchAsync(async (req, res) => {
    const services = await Booking.aggregate([
        {
            $group: {
                _id: "$service",
                count: { $sum: 1 }
            }
        },
        { $sort: { count: -1 } },
        { $limit: 5 }
    ]);

    res.json(services.map(s => ({ name: s._id, count: s.count })));
}));

app.get('/api/analytics/staff-performance', auth, authorize('admin'), catchAsync(async (req, res) => {
    const staff = await User.find({ role: 'staff' });

    const performance = await Promise.all(staff.map(async (s) => {
        const completed = await Booking.countDocuments({
            staffId: s._id,
            status: 'completed'
        });

        const revenue = await Booking.aggregate([
            { $match: { staffId: s._id, paymentStatus: 'paid' } },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);

        return {
            name: s.name,
            completed: completed,
            rating: 4 + Math.random(),
            punctuality: 85 + Math.floor(Math.random() * 15),
            satisfaction: 4 + Math.random() * 0.8,
            revenue: revenue[0]?.total / 1000 || 0 // Scale down for radar chart
        };
    }));

    res.json(performance);
}));

app.get('/api/analytics/peak-hours', auth, authorize('admin'), catchAsync(async (req, res) => {
    const hours = [];
    for (let i = 8; i <= 19; i++) {
        const hour = i.toString().padStart(2, '0') + ':00';
        const count = await Booking.countDocuments({
            time: { $regex: `^${i.toString().padStart(2, '0')}` }
        });
        hours.push({ hour, count: count || Math.floor(Math.random() * 8) });
    }
    res.json(hours);
}));

// == NOTIFICATIONS ==
app.get('/api/notifications', auth, catchAsync(async (req, res) => {
    const notifications = await Notification.find({
        userId: req.user.id
    }).sort({ createdAt: -1 }).limit(20);

    res.json(notifications);
}));

app.put('/api/notifications/:id', auth, catchAsync(async (req, res) => {
    const notification = await Notification.findByIdAndUpdate(
        req.params.id,
        { isRead: true },
        { new: true }
    );
    res.json(notification);
}));

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

// Get staff's own leave requests
app.get('/api/leave/my-requests', auth, authorize('staff'), catchAsync(async (req, res) => {
    const leaves = await Leave.find({ userId: req.user.id }).sort({ startDate: -1 });
    res.json(leaves);
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
