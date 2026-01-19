require('dotenv').config();
const express = require('express');
const session = require('express-session');
// const FileStore = require('session-file-store')(session); // Moved to lazy load
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs-extra');
const path = require('path');
const { authenticator } = require('otplib');
const protobuf = require('protobufjs');
const base32Encode = require('base32-encode').default;
const { v4: uuidv4 } = require('uuid');
const https = require('https');

const app = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'accounts.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const PROTO_FILE = path.join(__dirname, 'google_auth.proto');
const { User, Account, connectDB } = require('./db');

// Determine mode immediately to avoid race conditions
// If MONGO_URI is set, we INTEND to use Mongo. Mongoose buffers commands.
let useMongo = !!process.env.MONGO_URI;

// Trigger connection immediately
connectDB().then(res => {
    console.log(`DB Connection status: ${res}`);
    // If connection failed but we expected it to work, we might want to fallback or log error
    if (!res && useMongo) {
        console.error("Critical: MONGO_URI present but connection failed.");
    }
});

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Vercel handles static files differently, but for standard Express this is fine
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Session Config (MemoryStore for Vercel / FileStore for Local)
// Session Config (MemoryStore for Vercel / FileStore for Local)
const isVercel = !!process.env.VERCEL;
let sessionStore;

if (!isVercel) {
    const FileStore = require('session-file-store')(session);
    sessionStore = new FileStore({ path: './.sessions', ttl: 86400 });
} else {
    console.log("Running on Vercel - Using MemoryStore");
    // MemoryStore is the default if store is not provided
}

app.use(session({
    store: sessionStore,
    secret: 'antigravity-secret-key-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Ensure files exist (Only locally or specific dirs)
if (!isVercel) {
    if (!fs.existsSync(DATA_FILE)) fs.writeJsonSync(DATA_FILE, []);
    if (!fs.existsSync(USERS_FILE)) fs.writeJsonSync(USERS_FILE, []);
} else {
    // On Vercel, we can't write to root. Use /tmp if really needed, but data will be lost.
    // For this demo, we'll try to use /tmp for pseudo-persistence within same lambda instance (rarely works long term)
    // Actually, Vercel is Read-Only mostly. We will catch write errors.
}

// --- Helpers ---

// --- Helpers ---

const getUsers = async () => {
    if (useMongo) {
        return await User.find({}).lean(); // lean() for plain objects
    }
    // Fallback if file doesn't exist or is empty/corrupt
    try {
        const data = await fs.readJson(USERS_FILE);
        return Array.isArray(data) ? data : [];
    } catch (e) {
        return [];
    }
};

const saveUsers = async (users) => {
    if (useMongo) {
        for (const u of users) {
            await User.findOneAndUpdate({ id: u.id }, u, { upsert: true, new: true });
        }
        return;
    }
    await fs.writeJson(USERS_FILE, users, { spaces: 2 });
};

const getAccounts = async () => {
    if (useMongo) {
        return await Account.find({}).lean();
    }
    try {
        const data = await fs.readJson(DATA_FILE);
        return Array.isArray(data) ? data : [];
    } catch (e) {
        return [];
    }
};

const saveAccounts = async (accounts) => {
    if (useMongo) {
        // Same naive sync strategy
        for (const a of accounts) {
            await Account.findOneAndUpdate({ id: a.id }, a, { upsert: true, new: true });
        }
        // Handle deletions? This naive approach doesn't handle deletions if we just loop updates.
        // We need to delete what's NOT in the array.
        const ids = accounts.map(a => a.id);
        await Account.deleteMany({ id: { $nin: ids } });
        return;
    }
    await fs.writeJson(DATA_FILE, accounts, { spaces: 2 });
};

const getUserAccounts = async (userId) => {
    if (useMongo) return await Account.find({ userId }).lean();

    const all = await getAccounts();
    return all.filter(a => a.userId === userId);
};

// --- Auth Middleware ---

const checkAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

const apiCheckAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// --- Auth Routes ---

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await getUsers();
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.passwordHash)) {
        // Check if OTP is enabled and user has phone
        if (user.otpEnabled === false || !user.phone) {
            req.session.userId = user.id;
            req.session.username = user.username;
            return res.redirect('/');
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save to session (temp)
        req.session.tempUserId = user.id;
        req.session.tempUsername = user.username;
        req.session.otp = otp;
        req.session.otpExpires = Date.now() + 5 * 60 * 1000; // 5 mins
        req.session.phone = user.phone;

        // Send WhatsApp
        const apiUrl = `https://wa-api.pnblk.my.id/send-text?userId=patrolwaa1&to=${user.phone}@s.whatsapp.net&message=Your+2FA+Login+OTP+is:+${otp}`;

        https.get(apiUrl, (resp) => {
            // We just fire and forget or log
            console.log('WhatsApp OTP sent to ' + user.phone);
        }).on("error", (err) => {
            console.log("Error sending WhatsApp: " + err.message);
        });

        return res.redirect('/verify-otp');
    }

    res.render('login', { error: 'Invalid username or password' });
});

// Verify OTP Page
app.get('/verify-otp', (req, res) => {
    if (!req.session.tempUserId) return res.redirect('/login');
    res.render('verify-otp', { error: null, phone: req.session.phone });
});

// Verify OTP Action
app.post('/verify-otp', (req, res) => {
    if (!req.session.tempUserId) return res.redirect('/login');

    const { otp } = req.body;

    if (Date.now() > req.session.otpExpires) {
        return res.render('verify-otp', { error: 'OTP Expired', phone: req.session.phone });
    }

    if (otp === req.session.otp) {
        // Success
        req.session.userId = req.session.tempUserId;
        req.session.username = req.session.tempUsername;

        // Clear temps
        delete req.session.tempUserId;
        delete req.session.tempUsername;
        delete req.session.otp;
        delete req.session.otpExpires;
        delete req.session.phone;

        return res.redirect('/');
    } else {
        return res.render('verify-otp', { error: 'Invalid OTP', phone: req.session.phone });
    }
});

// Resend OTP
app.post('/resend-otp', (req, res) => {
    if (!req.session.tempUserId || !req.session.phone) {
        return res.status(400).json({ error: 'Session expired' });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.otp = otp;
    req.session.otpExpires = Date.now() + 5 * 60 * 1000;

    const apiUrl = `https://wa-api.pnblk.my.id/send-text?userId=patrolwaa1&to=${req.session.phone}@s.whatsapp.net&message=Resent+OTP+is:+${otp}`;

    https.get(apiUrl, (resp) => {
        console.log('WhatsApp OTP Resent to ' + req.session.phone);
        res.json({ success: true });
    }).on("error", (err) => {
        console.error("Error sending WhatsApp: " + err.message);
        res.json({ success: false, error: 'Failed to send OTP' });
    });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    const { username, password, phone } = req.body;
    if (!username || !password || !phone) return res.render('register', { error: 'All fields required' });

    const users = await getUsers();
    if (users.find(u => u.username === username)) {
        return res.render('register', { error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
        id: uuidv4(),
        username,
        passwordHash: hashedPassword,
        phone: phone.replace(/[^0-9]/g, ''), // clean phone
        otpEnabled: true, // Default on
        created: new Date()
    });

    await saveUsers(users);
    res.redirect('/login');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// --- App Routes ---

// Dashboard
app.get('/', checkAuth, async (req, res) => {
    const users = await getUsers();
    const currentUser = users.find(u => u.id === req.session.userId);
    const otpEnabled = currentUser ? (currentUser.otpEnabled !== false) : false; // Default true if undefined

    const accounts = await getUserAccounts(req.session.userId);
    res.render('index', { accounts, user: req.session.username, otpEnabled });
});

// Add Account Page
app.get('/add', checkAuth, (req, res) => {
    res.render('add', { user: req.session.username });
});

// API: Get Codes
app.get('/api/codes', apiCheckAuth, async (req, res) => {
    const accounts = await getUserAccounts(req.session.userId);
    const data = accounts.map(acc => {
        try {
            authenticator.options = {
                digits: acc.digits || 6,
                step: 30,
                window: 1
            };
            const token = authenticator.generate(acc.secret);
            const timeRemaining = authenticator.timeRemaining();
            return { id: acc.id, token, timeRemaining };
        } catch (e) {
            return { id: acc.id, token: 'ERROR', timeRemaining: 0 };
        }
    });
    res.json(data);
});

// API: Add Manual
app.post('/api/add-manual', apiCheckAuth, async (req, res) => {
    const { name, secret, issuer } = req.body;
    if (!name || !secret) return res.status(400).json({ error: 'Name and Secret required' });

    const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
    try { authenticator.generate(cleanSecret); } catch (err) {
        return res.status(400).json({ error: 'Invalid Base32 Secret' });
    }

    const accounts = await getAccounts();
    accounts.push({
        id: uuidv4(),
        userId: req.session.userId, // Link to user
        name,
        issuer: issuer || 'Manual',
        secret: cleanSecret,
        type: 'TOTP',
        digits: 6
    });
    await saveAccounts(accounts);
    res.json({ success: true });
});

// API: Import Migration
app.post('/api/import-migration', apiCheckAuth, async (req, res) => {
    const { migrationUri } = req.body;
    if (!migrationUri || !migrationUri.startsWith('otpauth-migration://')) {
        return res.status(400).json({ error: 'Invalid migration URI' });
    }

    try {
        const url = new URL(migrationUri);
        const data = url.searchParams.get('data');
        if (!data) return res.status(400).json({ error: 'No data parameter found' });

        const buffer = Buffer.from(data, 'base64');
        const root = await protobuf.load(PROTO_FILE);
        const MigrationPayload = root.lookupType("googleauth.MigrationPayload");
        const message = MigrationPayload.decode(buffer);

        const accounts = await getAccounts();
        let addedCount = 0;

        for (let i = 0; i < message.otpParameters.length; i++) {
            const param = message.otpParameters[i];
            const secretBuffer = param.secret;
            const secretBase32 = base32Encode(secretBuffer, 'RFC4648', { padding: false });

            const name = param.name || 'Unknown';
            const issuer = param.issuer || 'Google Authenticator';

            // Check dupes for this user
            const exists = accounts.find(a => a.userId === req.session.userId && a.secret === secretBase32);
            if (!exists) {
                accounts.push({
                    id: uuidv4(),
                    userId: req.session.userId,
                    name,
                    issuer,
                    secret: secretBase32,
                    type: 'TOTP', // Generalizing
                    digits: 6
                });
                addedCount++;
            }
        }

        await saveAccounts(accounts);
        res.json({ success: true, count: addedCount });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    }
});

// API: Delete Account
app.delete('/api/delete/:id', apiCheckAuth, async (req, res) => {
    const { id } = req.params;
    let accounts = await getAccounts();
    const initialLength = accounts.length;

    // Filter out the account if it belongs to the user
    accounts = accounts.filter(acc => !(acc.id === id && acc.userId === req.session.userId));

    if (accounts.length === initialLength) {
        return res.status(404).json({ error: 'Account not found or unauthorized' });
    }

    await saveAccounts(accounts);
    res.json({ success: true });
});

// API: Update Account
app.put('/api/update/:id', apiCheckAuth, async (req, res) => {
    const { id } = req.params;
    const { name, issuer } = req.body;

    let accounts = await getAccounts();
    const index = accounts.findIndex(acc => acc.id === id && acc.userId === req.session.userId);

    if (index === -1) {
        return res.status(404).json({ error: 'Account not found' });
    }

    accounts[index].name = name;
    accounts[index].issuer = issuer;

    await saveAccounts(accounts);
    res.json({ success: true });
});

// API: Export Accounts
app.get('/api/export', apiCheckAuth, async (req, res) => {
    const accounts = await getUserAccounts(req.session.userId);
    // Export standard fields only (exclude internal IDs if preferred, but keeping them is fine for restore)
    const exportData = accounts.map(a => ({
        secret: a.secret,
        name: a.name,
        issuer: a.issuer,
        type: a.type,
        algorithm: a.algorithm,
        digits: a.digits,
        period: 30
    }));

    res.setHeader('Content-Disposition', `attachment; filename="2fa-backup-${Date.now()}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(exportData, null, 2));
});

// API: Toggle OTP
app.post('/api/settings/toggle-otp', apiCheckAuth, async (req, res) => {
    const { enabled } = req.body;
    const users = await getUsers();
    const userIndex = users.findIndex(u => u.id === req.session.userId);

    if (userIndex === -1) return res.status(404).json({ error: 'User not found' });

    // Only allow enabling if phone exists
    if (enabled && !users[userIndex].phone) {
        return res.status(400).json({ error: 'Phone number required to enable OTP' });
    }

    users[userIndex].otpEnabled = enabled;
    await saveUsers(users);
    res.json({ success: true, enabled: users[userIndex].otpEnabled });
});

// Export for Vercel
module.exports = app;

// Start (Only listen if running directly)
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}
