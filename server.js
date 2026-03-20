const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();
const db = new sqlite3.Database('./database.db');

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!file.mimetype.match(/^image\/(jpeg|jpg|png|gif|webp)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'), false);
        }
    }
});

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'"],
            mediaSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(cookieParser());

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false
});

const uploadLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: { error: 'Too many uploads. Please slow down.' }
});

app.use('/api/', apiLimiter);
app.use('/api/admin/', apiLimiter);

// Database initialization
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        balance REAL DEFAULT 0,
        referrals INTEGER DEFAULT 0,
        xp INTEGER DEFAULT 0,
        level INTEGER DEFAULT 1,
        avatar_icon TEXT DEFAULT 'fa-rocket',
        avatar_color TEXT DEFAULT '#f97316',
        is_admin INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        login_attempts INTEGER DEFAULT 0,
        lock_until INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        icon TEXT,
        color TEXT,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS brands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        logo TEXT,
        description TEXT,
        website TEXT,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price REAL,
        old_price REAL,
        category_id INTEGER,
        brand_id INTEGER,
        image TEXT,
        images TEXT,
        stock INTEGER DEFAULT 100,
        rating REAL DEFAULT 0,
        reviews INTEGER DEFAULT 0,
        featured INTEGER DEFAULT 0,
        on_sale INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(category_id) REFERENCES categories(id),
        FOREIGN KEY(brand_id) REFERENCES brands(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        total REAL,
        status TEXT DEFAULT 'pending',
        shipping_address TEXT,
        phone TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        price REAL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS offers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        payout REAL,
        category TEXT,
        image TEXT,
        link TEXT,
        clicks INTEGER DEFAULT 0,
        conversions INTEGER DEFAULT 0,
        featured INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS clicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        offer_id INTEGER,
        ip_address TEXT,
        clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(offer_id) REFERENCES offers(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        rating INTEGER,
        comment TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        success INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.get("SELECT id FROM users WHERE email = ?", ['admin@profithub.com'], (err, row) => {
        if (!row) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            db.run(`INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)`,
                ['Admin', 'admin@profithub.com', hashedPassword, 1]);
            console.log('Default admin created: admin@profithub.com / admin123');
        }
    });

    db.get("SELECT COUNT(*) as count FROM categories", (err, row) => {
        if (row.count === 0) {
            const categories = [
                ['Electronics', 'fa-laptop', '#3b82f6'],
                ['Fashion', 'fa-shirt', '#ec4899'],
                ['Home & Garden', 'fa-home', '#22c55e'],
                ['Sports', 'fa-futbol', '#f59e0b'],
                ['Beauty', 'fa-spa', '#8b5cf6'],
                ['Toys', 'fa-gamepad', '#ef4444'],
                ['Books', 'fa-book', '#06b6d4'],
                ['Automotive', 'fa-car', '#64748b']
            ];
            const stmt = db.prepare("INSERT INTO categories (name, icon, color) VALUES (?, ?, ?)");
            categories.forEach(cat => stmt.run(cat));
            stmt.finalize();
        }
    });

    db.get("SELECT COUNT(*) as count FROM brands", (err, row) => {
        if (row.count === 0) {
            const brands = [
                ['Apple', 'Apple - Premium electronics and technology'],
                ['Samsung', 'Samsung - Innovation for everyone'],
                ['Nike', 'Nike - Just Do It'],
                ['Adidas', 'Adidas - Impossible is Nothing'],
                ['Sony', 'Sony - Be Moved'],
                ['LG', 'LG - Life is Good'],
                ['Dell', 'Dell - Power to Do More'],
                ['HP', 'HP - Keep Reinventing']
            ];
            const stmt = db.prepare("INSERT INTO brands (name, description) VALUES (?, ?)");
            brands.forEach(brand => stmt.run(brand));
            stmt.finalize();
        }
    });

    db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
        if (row.count === 0) {
            const products = [
                ['iPhone 15 Pro Max', 'Latest Apple smartphone with A17 Pro chip', 1199.99, 1299.99, 1, 1, 1],
                ['Samsung Galaxy S24 Ultra', 'AI-powered smartphone experience', 1099.99, 1199.99, 1, 2, 1],
                ['MacBook Pro 16"', 'M3 Max chip for extreme performance', 2499.99, 2799.99, 1, 1, 1],
                ['AirPods Pro 2nd Gen', 'Active noise cancellation', 249.99, 299.99, 1, 1, 0],
                ['Nike Air Max 90', 'Iconic running shoes', 149.99, 179.99, 2, 3, 1],
                ['Samsung 65" QLED TV', '8K Quantum Matrix Technology', 1799.99, 2199.99, 3, 2, 1],
                ['PS5 Console', 'Next-gen gaming experience', 499.99, 549.99, 4, null, 1],
                ['Dyson V15 Vacuum', 'Most powerful cordless vacuum', 749.99, 899.99, 3, null, 0],
                ['Sony WH-1000XM5', 'Industry-leading noise cancellation', 349.99, 399.99, 1, 5, 1],
                ['Adidas Ultraboost', 'Premium running footwear', 189.99, 219.99, 2, 4, 0]
            ];
            const stmt = db.prepare("INSERT INTO products (name, description, price, old_price, category_id, brand_id, featured) VALUES (?, ?, ?, ?, ?, ?, ?)");
            products.forEach(p => stmt.run(p));
            stmt.finalize();
        }
    });
});

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: false
}));
app.use('/uploads', express.static(uploadsDir, {
    maxAge: '1d',
    etag: false
}));
app.use(session({
    secret: process.env.SESSION_SECRET || 'shop-hub-secret-2026-very-secure',
    name: 'shophub_sid',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

// Input sanitization helper
function sanitizeInput(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim();
}

// Auth Middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Login required' });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Login required' });
    }
    db.get("SELECT is_admin FROM users WHERE id = ?", [req.session.userId], (err, user) => {
        if (!user || !user.is_admin) return res.status(403).json({ error: 'Admin access required' });
        next();
    });
};

// ==================== SHOP ROUTES ====================

app.get('/shop', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'shop.html'));
});

app.get('/api/products', (req, res) => {
    const { category, brand, search, sort, minPrice, maxPrice, featured, onSale } = req.query;
    let query = `SELECT p.*, c.name as category_name, b.name as brand_name
                 FROM products p
                 LEFT JOIN categories c ON p.category_id = c.id
                 LEFT JOIN brands b ON p.brand_id = b.id
                 WHERE p.status = 'active'`;
    const params = [];

    if (category) { 
        const catId = parseInt(category);
        if (!isNaN(catId)) { query += " AND p.category_id = ?"; params.push(catId); }
    }
    if (brand) {
        const brId = parseInt(brand);
        if (!isNaN(brId)) { query += " AND p.brand_id = ?"; params.push(brId); }
    }
    if (search) { 
        const safeSearch = sanitizeInput(search).substring(0, 100);
        query += " AND (p.name LIKE ? OR p.description LIKE ?)";
        params.push(`%${safeSearch}%`, `%${safeSearch}%`);
    }
    if (minPrice) {
        const min = parseFloat(minPrice);
        if (!isNaN(min) && min >= 0) { query += " AND p.price >= ?"; params.push(min); }
    }
    if (maxPrice) {
        const max = parseFloat(maxPrice);
        if (!isNaN(max) && max >= 0) { query += " AND p.price <= ?"; params.push(max); }
    }
    if (featured === 'true') { query += " AND p.featured = 1"; }
    if (onSale === 'true') { query += " AND p.on_sale = 1"; }

    if (sort === 'price_asc') query += " ORDER BY p.price ASC";
    else if (sort === 'price_desc') query += " ORDER BY p.price DESC";
    else if (sort === 'name') query += " ORDER BY p.name ASC";
    else if (sort === 'rating') query += " ORDER BY p.rating DESC";
    else query += " ORDER BY p.featured DESC, p.created_at DESC";

    query += " LIMIT 100";
    db.all(query, params, (err, products) => res.json(products));
});

app.get('/api/products/featured', (req, res) => {
    db.all("SELECT p.*, c.name as category_name, b.name as brand_name FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN brands b ON p.brand_id = b.id WHERE p.featured = 1 AND p.status = 'active' LIMIT 8", [], (err, products) => res.json(products));
});

app.get('/api/products/on-sale', (req, res) => {
    db.all("SELECT p.*, c.name as category_name, b.name as brand_name FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN brands b ON p.brand_id = b.id WHERE p.on_sale = 1 AND p.status = 'active' LIMIT 8", [], (err, products) => res.json(products));
});

app.get('/api/products/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid product ID' });
    
    db.get("SELECT p.*, c.name as category_name, c.icon as category_icon, b.name as brand_name, b.logo as brand_logo FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN brands b ON p.brand_id = b.id WHERE p.id = ?", [id], (err, product) => {
        if (!product) return res.status(404).json({ error: 'Product not found' });
        db.all("SELECT r.*, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = ? AND r.status = 'approved' ORDER BY r.created_at DESC LIMIT 20", [id], (err, reviews) => {
            res.json({ ...product, reviews: reviews || [] });
        });
    });
});

app.get('/api/categories', (req, res) => {
    db.all("SELECT c.*, COUNT(p.id) as product_count FROM categories c LEFT JOIN products p ON c.id = p.category_id AND p.status = 'active' GROUP BY c.id ORDER BY c.name", [], (err, categories) => res.json(categories));
});

app.get('/api/brands', (req, res) => {
    db.all("SELECT b.*, COUNT(p.id) as product_count FROM brands b LEFT JOIN products p ON b.id = p.brand_id AND p.status = 'active' GROUP BY b.id ORDER BY b.name", [], (err, brands) => res.json(brands));
});

// ==================== CART ROUTES ====================

app.get('/api/cart', requireAuth, (req, res) => {
    db.all("SELECT cart.*, products.name, products.price, products.old_price, products.image, products.stock FROM cart JOIN products ON cart.product_id = products.id WHERE cart.user_id = ?", [req.session.userId], (err, items) => {
        const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        res.json({ items, total, count: items.reduce((sum, item) => sum + item.quantity, 0) });
    });
});

app.post('/api/cart', requireAuth, (req, res) => {
    const product_id = parseInt(req.body.product_id);
    const quantity = Math.max(1, Math.min(100, parseInt(req.body.quantity) || 1));
    
    if (isNaN(product_id)) return res.status(400).json({ error: 'Invalid product ID' });
    
    db.get("SELECT * FROM products WHERE id = ? AND status = 'active'", [product_id], (err, product) => {
        if (!product) return res.status(404).json({ error: 'Product not found' });
        db.get("SELECT * FROM cart WHERE user_id = ? AND product_id = ?", [req.session.userId, product_id], (err, existing) => {
            if (existing) {
                const newQty = Math.min(existing.quantity + quantity, product.stock, 100);
                db.run("UPDATE cart SET quantity = ? WHERE id = ?", [newQty, existing.id]);
            } else {
                const qty = Math.min(quantity, product.stock, 100);
                db.run("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)", [req.session.userId, product_id, qty]);
            }
            res.json({ success: true });
        });
    });
});

app.put('/api/cart/:productId', requireAuth, (req, res) => {
    const productId = parseInt(req.params.productId);
    const quantity = Math.max(1, Math.min(100, parseInt(req.body.quantity)));
    
    if (isNaN(productId) || isNaN(quantity)) return res.status(400).json({ error: 'Invalid request' });
    
    db.get("SELECT stock FROM products WHERE id = ?", [productId], (err, product) => {
        if (!product) return res.status(404).json({ error: 'Product not found' });
        const qty = Math.min(quantity, product.stock, 100);
        db.run("UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?", [qty, req.session.userId, productId]);
        res.json({ success: true });
    });
});

app.delete('/api/cart/:productId', requireAuth, (req, res) => {
    const productId = parseInt(req.params.productId);
    if (isNaN(productId)) return res.status(400).json({ error: 'Invalid product ID' });
    db.run("DELETE FROM cart WHERE user_id = ? AND product_id = ?", [req.session.userId, productId]);
    res.json({ success: true });
});

app.delete('/api/cart', requireAuth, (req, res) => {
    db.run("DELETE FROM cart WHERE user_id = ?", [req.session.userId]);
    res.json({ success: true });
});

// ==================== ORDER ROUTES ====================

app.post('/api/orders', requireAuth, (req, res) => {
    const shipping_address = sanitizeInput(req.body.shipping_address || '').substring(0, 500);
    const phone = sanitizeInput(req.body.phone || '').substring(0, 20);
    const notes = sanitizeInput(req.body.notes || '').substring(0, 1000);
    
    if (!shipping_address || !phone) {
        return res.status(400).json({ error: 'Shipping address and phone are required' });
    }
    
    db.all("SELECT cart.*, products.price, products.stock, products.name FROM cart JOIN products ON cart.product_id = products.id WHERE cart.user_id = ?", [req.session.userId], (err, items) => {
        if (!items.length) return res.status(400).json({ error: 'Cart is empty' });
        const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        db.run("INSERT INTO orders (user_id, total, shipping_address, phone, notes) VALUES (?, ?, ?, ?, ?)",
            [req.session.userId, total, shipping_address, phone, notes], function(err) {
                if (err) return res.status(500).json({ error: 'Failed to create order' });
                const orderId = this.lastID;
                items.forEach(item => {
                    db.run("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                        [orderId, item.product_id, item.quantity, item.price]);
                    db.run("UPDATE products SET stock = stock - ? WHERE id = ?", [item.quantity, item.product_id]);
                });
                db.run("DELETE FROM cart WHERE user_id = ?", [req.session.userId]);
                res.json({ success: true, orderId });
            });
    });
});

app.get('/api/orders', requireAuth, (req, res) => {
    db.all("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", [req.session.userId], (err, orders) => {
        const promises = orders.map(order => new Promise((resolve) => {
            db.all("SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?", [order.id], (err, items) => {
                resolve({ ...order, items });
            });
        }));
        Promise.all(promises).then(ordersWithItems => res.json(ordersWithItems));
    });
});

app.post('/api/reviews', requireAuth, (req, res) => {
    const product_id = parseInt(req.body.product_id);
    const rating = Math.max(1, Math.min(5, parseInt(req.body.rating)));
    const comment = sanitizeInput(req.body.comment || '').substring(0, 1000);
    
    if (isNaN(product_id) || !rating) {
        return res.status(400).json({ error: 'Invalid review data' });
    }
    
    db.run("INSERT INTO reviews (user_id, product_id, rating, comment) VALUES (?, ?, ?, ?)",
        [req.session.userId, product_id, rating, comment], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to add review' });
            db.get("SELECT AVG(rating) as avg, COUNT(*) as count FROM reviews WHERE product_id = ? AND status = 'approved'", [product_id], (err, stats) => {
                db.run("UPDATE products SET rating = ?, reviews = ? WHERE id = ?", [stats.avg || 0, stats.count, product_id]);
                res.json({ success: true });
            });
        });
});

// ==================== USER ROUTES ====================

app.get('/api/user', requireAuth, (req, res) => {
    db.get("SELECT id, username, email, balance, avatar_icon, avatar_color, level, xp, created_at FROM users WHERE id = ?", [req.session.userId], (err, user) => {
        if (!user) return res.status(404).json({ error: 'User not found' });
        db.get("SELECT COUNT(*) as orders FROM orders WHERE user_id = ?", [req.session.userId], (err, orders) => {
            res.json({ ...user, totalOrders: orders?.orders || 0 });
        });
    });
});

app.get('/api/stats', requireAuth, (req, res) => {
    const userId = req.session.userId;
    db.get("SELECT balance, referrals FROM users WHERE id = ?", [userId], (err, user) => {
        db.get("SELECT COUNT(*) as total_clicks FROM clicks WHERE user_id = ?", [userId], (err, clicks) => {
            db.get("SELECT SUM(o.payout) as earnings FROM clicks c JOIN offers o ON c.offer_id = o.id WHERE c.user_id = ?", [userId], (err, earnings) => {
                res.json({
                    balance: user?.balance || 0,
                    referrals: user?.referrals || 0,
                    clicks: clicks?.total_clicks || 0,
                    earnings: earnings?.earnings || 0
                });
            });
        });
    });
});

// ==================== ADMIN ROUTES ====================

app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/login', (req, res) => {
    if (req.session.userId) {
        db.get("SELECT is_admin FROM users WHERE id = ?", [req.session.userId], (err, user) => {
            if (user && user.is_admin) return res.redirect('/admin');
            res.redirect('/dashboard');
        });
    } else {
        res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
    }
});

app.post('/api/admin/login', authLimiter, (req, res) => {
    const email = sanitizeInput(req.body.email || '').toLowerCase().substring(0, 100);
    const password = req.body.password || '';
    const clientIp = req.ip || req.connection.remoteAddress;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user) {
            logLoginAttempt(null, clientIp, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const now = Date.now();
        if (user.lock_until && user.lock_until > now) {
            const remaining = Math.ceil((user.lock_until - now) / 60000);
            return res.status(423).json({ error: `Account locked. Try again in ${remaining} minutes.` });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            const attempts = (user.login_attempts || 0) + 1;
            const lockUntil = attempts >= 5 ? now + 15 * 60 * 1000 : 0;
            db.run("UPDATE users SET login_attempts = ?, lock_until = ? WHERE id = ?", [attempts, lockUntil, user.id]);
            logLoginAttempt(user.id, clientIp, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (!user.is_admin) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        db.run("UPDATE users SET login_attempts = 0, lock_until = 0 WHERE id = ?", [user.id]);
        logLoginAttempt(user.id, clientIp, true);
        req.session.userId = user.id;
        res.json({ success: true });
    });
});

function logLoginAttempt(userId, ip, success) {
    db.run("INSERT INTO login_logs (user_id, ip_address, success) VALUES (?, ?, ?)", [userId, ip, success ? 1 : 0]);
}

app.get('/api/admin/stats', requireAdmin, (req, res) => {
    db.get("SELECT COUNT(*) as total_users FROM users WHERE is_admin = 0", [], (err, users) => {
        db.get("SELECT COUNT(*) as total_products FROM products", [], (err, products) => {
            db.get("SELECT COUNT(*) as total_orders FROM orders", [], (err, orders) => {
                db.get("SELECT COUNT(*) as total_brands FROM brands", [], (err, brands) => {
                    db.get("SELECT COUNT(*) as total_categories FROM categories", [], (err, categories) => {
                        db.get("SELECT SUM(total) as revenue FROM orders WHERE status = 'completed'", [], (err, revenue) => {
                            db.get("SELECT SUM(total) as total_revenue FROM orders", [], (err, totalRevenue) => {
                                db.get("SELECT COUNT(*) as pending_orders FROM orders WHERE status = 'pending'", [], (err, pending) => {
                                    res.json({
                                        totalUsers: users?.total_users || 0,
                                        totalProducts: products?.total_products || 0,
                                        totalOrders: orders?.total_orders || 0,
                                        totalBrands: brands?.total_brands || 0,
                                        totalCategories: categories?.total_categories || 0,
                                        revenue: revenue?.revenue || 0,
                                        totalRevenue: totalRevenue?.total_revenue || 0,
                                        pendingOrders: pending?.pending_orders || 0
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// Categories CRUD
app.get('/api/admin/categories', requireAdmin, (req, res) => {
    db.all("SELECT c.*, COUNT(p.id) as product_count FROM categories c LEFT JOIN products p ON c.id = p.category_id GROUP BY c.id", [], (err, categories) => res.json(categories));
});

app.post('/api/admin/categories', requireAdmin, (req, res) => {
    const name = sanitizeInput(req.body.name || '').substring(0, 50);
    const icon = sanitizeInput(req.body.icon || 'fa-folder').substring(0, 50);
    const color = sanitizeInput(req.body.color || '#666').substring(0, 10);
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    
    if (!name) return res.status(400).json({ error: 'Name required' });
    
    db.run("INSERT INTO categories (name, icon, color, status) VALUES (?, ?, ?, ?)",
        [name, icon, color, status], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to create category' });
            res.json({ success: true, id: this.lastID });
        });
});

app.put('/api/admin/categories/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    const name = sanitizeInput(req.body.name || '');
    const icon = sanitizeInput(req.body.icon || '');
    const color = sanitizeInput(req.body.color || '');
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    
    db.run("UPDATE categories SET name = COALESCE(?, name), icon = COALESCE(?, icon), color = COALESCE(?, color), status = ? WHERE id = ?",
        [name || null, icon || null, color || null, status, id], function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ success: true });
        });
});

app.delete('/api/admin/categories/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    db.run("DELETE FROM categories WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: 'Cannot delete category with products' });
        res.json({ success: true });
    });
});

// Brands CRUD
app.get('/api/admin/brands', requireAdmin, (req, res) => {
    db.all("SELECT b.*, COUNT(p.id) as product_count FROM brands b LEFT JOIN products p ON b.id = p.brand_id GROUP BY b.id", [], (err, brands) => res.json(brands));
});

app.post('/api/admin/brands', [requireAdmin, uploadLimiter], (req, res) => {
    const name = sanitizeInput(req.body.name || '').substring(0, 100);
    const description = sanitizeInput(req.body.description || '').substring(0, 500);
    const website = sanitizeInput(req.body.website || '').substring(0, 200);
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    const logo = req.file ? '/uploads/' + req.file.filename : null;
    
    if (!name) return res.status(400).json({ error: 'Name required' });
    
    db.run("INSERT INTO brands (name, description, website, logo, status) VALUES (?, ?, ?, ?, ?)",
        [name, description, website, logo, status], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to create brand' });
            res.json({ success: true, id: this.lastID });
        });
});

app.put('/api/admin/brands/:id', [requireAdmin, uploadLimiter], (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    const name = sanitizeInput(req.body.name || '');
    const description = sanitizeInput(req.body.description || '');
    const website = sanitizeInput(req.body.website || '');
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    const logo = req.file ? '/uploads/' + req.file.filename : req.body.existing_logo;
    
    db.run("UPDATE brands SET name = COALESCE(?, name), description = COALESCE(?, description), website = COALESCE(?, website), logo = COALESCE(?, logo), status = ? WHERE id = ?",
        [name || null, description || null, website || null, logo, status, id], function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ success: true });
        });
});

app.delete('/api/admin/brands/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    db.run("DELETE FROM brands WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: 'Cannot delete brand with products' });
        res.json({ success: true });
    });
});

// Products CRUD
app.get('/api/admin/products', requireAdmin, (req, res) => {
    db.all("SELECT p.*, c.name as category_name, b.name as brand_name FROM products p LEFT JOIN categories c ON p.category_id = c.id LEFT JOIN brands b ON p.brand_id = b.id ORDER BY p.created_at DESC", [], (err, products) => res.json(products));
});

app.post('/api/admin/products', [requireAdmin, uploadLimiter], (req, res) => {
    const name = sanitizeInput(req.body.name || '').substring(0, 200);
    const description = sanitizeInput(req.body.description || '').substring(0, 2000);
    const price = Math.max(0, parseFloat(req.body.price) || 0);
    const old_price = req.body.old_price ? Math.max(0, parseFloat(req.body.old_price)) : null;
    const category_id = parseInt(req.body.category_id) || null;
    const brand_id = parseInt(req.body.brand_id) || null;
    const stock = Math.max(0, Math.min(100000, parseInt(req.body.stock) || 100));
    const image = req.files && req.files[0] ? '/uploads/' + req.files[0].filename : null;
    const featured = req.body.featured ? 1 : 0;
    const on_sale = req.body.on_sale ? 1 : 0;
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    
    if (!name || price <= 0) {
        return res.status(400).json({ error: 'Name and valid price required' });
    }
    
    db.run(`INSERT INTO products (name, description, price, old_price, category_id, brand_id, stock, image, featured, on_sale, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, description, price, old_price, category_id, brand_id, stock, image, featured, on_sale, status],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        });
});

app.put('/api/admin/products/:id', [requireAdmin, uploadLimiter], (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    const name = sanitizeInput(req.body.name || '');
    const description = sanitizeInput(req.body.description || '');
    const price = req.body.price ? Math.max(0, parseFloat(req.body.price)) : null;
    const old_price = req.body.old_price ? Math.max(0, parseFloat(req.body.old_price)) : null;
    const category_id = req.body.category_id ? parseInt(req.body.category_id) : null;
    const brand_id = req.body.brand_id ? parseInt(req.body.brand_id) : null;
    const stock = req.body.stock ? Math.max(0, Math.min(100000, parseInt(req.body.stock))) : null;
    const image = req.files && req.files[0] ? '/uploads/' + req.files[0].filename : req.body.existing_image;
    const featured = req.body.featured !== undefined ? (req.body.featured ? 1 : 0) : null;
    const on_sale = req.body.on_sale !== undefined ? (req.body.on_sale ? 1 : 0) : null;
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    
    db.run(`UPDATE products SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        price = COALESCE(?, price),
        old_price = COALESCE(?, old_price),
        category_id = COALESCE(?, category_id),
        brand_id = COALESCE(?, brand_id),
        stock = COALESCE(?, stock),
        image = COALESCE(?, image),
        featured = COALESCE(?, featured),
        on_sale = COALESCE(?, on_sale),
        status = ?
        WHERE id = ?`,
        [name || null, description || null, price, old_price, category_id, brand_id, stock, image, featured, on_sale, status, id],
        function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ success: true });
        });
});

app.delete('/api/admin/products/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    db.run("DELETE FROM products WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: 'Delete failed' });
        res.json({ success: true });
    });
});

// Orders CRUD
app.get('/api/admin/orders', requireAdmin, (req, res) => {
    const { status } = req.query;
    let query = "SELECT o.*, u.username, u.email FROM orders o JOIN users u ON o.user_id = u.id";
    const params = [];
    if (status) { query += " WHERE o.status = ?"; params.push(status); }
    query += " ORDER BY o.created_at DESC LIMIT 200";
    
    db.all(query, params, (err, orders) => {
        const promises = orders.map(order => new Promise((resolve) => {
            db.all("SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?", [order.id], (err, items) => {
                resolve({ ...order, items });
            });
        }));
        Promise.all(promises).then(ordersWithItems => res.json(ordersWithItems));
    });
});

app.put('/api/admin/orders/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    const status = ['pending', 'processing', 'shipped', 'completed', 'cancelled'].includes(req.body.status)
        ? req.body.status : 'pending';
    
    db.run("UPDATE orders SET status = ? WHERE id = ?", [status, id], function(err) {
        if (err) return res.status(500).json({ error: 'Update failed' });
        res.json({ success: true });
    });
});

// Users CRUD
app.get('/api/admin/users', requireAdmin, (req, res) => {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;
    
    let query = "SELECT id, username, email, balance, referrals, xp, level, status, created_at FROM users WHERE is_admin = 0";
    const params = [];
    
    if (search) {
        const safeSearch = sanitizeInput(search).substring(0, 50);
        query += " AND (username LIKE ? OR email LIKE ?)";
        params.push(`%${safeSearch}%`, `%${safeSearch}%`);
    }
    if (status) {
        query += " AND status = ?";
        params.push(status);
    }
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limitNum, offset);
    
    db.get("SELECT COUNT(*) as count FROM users WHERE is_admin = 0", [], (err, count) => {
        db.all(query, params, (err, users) => res.json({ users: users || [], total: count?.count || 0, page: pageNum }));
    });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    const balance = req.body.balance !== undefined ? Math.max(0, parseFloat(req.body.balance)) : null;
    const status = ['active', 'banned', 'pending'].includes(req.body.status) ? req.body.status : null;
    
    db.run("UPDATE users SET balance = COALESCE(?, balance), status = COALESCE(?, status) WHERE id = ?",
        [balance, status, id], function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ success: true });
        });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    
    db.run("DELETE FROM users WHERE id = ? AND is_admin = 0", [id], function(err) {
        if (err) return res.status(500).json({ error: 'Delete failed' });
        res.json({ success: true });
    });
});

// ==================== PUBLIC ROUTES ====================

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.post('/api/register', (req, res) => {
    const username = sanitizeInput(req.body.username || '').substring(0, 50);
    const email = sanitizeInput(req.body.email || '').toLowerCase().substring(0, 100);
    const password = req.body.password || '';
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 12);
    
    db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already exists' });
                return res.status(500).json({ error: 'Registration failed' });
            }
            res.json({ success: true });
        });
});

app.post('/api/login', authLimiter, (req, res) => {
    const email = sanitizeInput(req.body.email || '').toLowerCase().substring(0, 100);
    const password = req.body.password || '';
    const clientIp = req.ip || req.connection.remoteAddress;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user) {
            logLoginAttempt(null, clientIp, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const now = Date.now();
        if (user.lock_until && user.lock_until > now) {
            const remaining = Math.ceil((user.lock_until - now) / 60000);
            return res.status(423).json({ error: `Account locked. Try again in ${remaining} minutes.` });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            const attempts = (user.login_attempts || 0) + 1;
            const lockUntil = attempts >= 5 ? now + 15 * 60 * 1000 : 0;
            db.run("UPDATE users SET login_attempts = ?, lock_until = ? WHERE id = ?", [attempts, lockUntil, user.id]);
            logLoginAttempt(user.id, clientIp, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (user.status === 'banned') {
            return res.status(403).json({ error: 'Account suspended' });
        }
        
        db.run("UPDATE users SET login_attempts = 0, lock_until = 0 WHERE id = ?", [user.id]);
        logLoginAttempt(user.id, clientIp, true);
        req.session.userId = user.id;
        res.json({ success: true });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/cpa', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    if (err.message.includes('Invalid file type')) {
        return res.status(400).json({ error: 'Only image files are allowed' });
    }
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🔒 ShopHub E-commerce running on http://localhost:${PORT}`);
    console.log(`🛒 Shop: http://localhost:${PORT}/shop`);
    console.log(`⚙️  Admin: http://localhost:${PORT}/admin`);
    console.log(`🔑 Admin Login: admin@profithub.com / admin123`);
    console.log('\n✅ Security Features Enabled:');
    console.log('   - Helmet.js security headers');
    console.log('   - Rate limiting (auth: 5/15min, API: 100/min, uploads: 10/min)');
    console.log('   - Input sanitization');
    console.log('   - Account lockout after 5 failed attempts');
    console.log('   - Password hashing with bcrypt (cost factor 12)');
    console.log('   - Secure session cookies');
    console.log('   - File type validation for uploads');
    console.log('   - Request body size limits\n');
});
