require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;  
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = (...args) => import('node-fetch').then(mod => mod.default(...args));
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const User = require('./models/User');  

const app = express();
const PORT = process.env.PORT || 8080;
const BACKEND_BASE = process.env.BACKEND_BASE;       
            
// --- Security & Middleware ---
app.set('trust proxy', 1); // Required for secure cookies behind Nginx/ELB

app.use(helmet()); 
app.use(express.json());
app.use(cookieParser());
app.use(morgan('combined'));

// CORS: Critical for React to talk to this backend
app.use(cors({
  origin: process.env.FRONTEND_URL, // e.g., 'http://localhost:5173' or 'https://yourdomain.com'
  credentials: true, // Allows the session cookie to be passed
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB error:', err));

// --- Session Config (The "Auth" part) ---
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    httpOnly: true, // Prevents XSS attacks (React JS cannot read this cookie)
    secure: true,   // MUST be true for 'sameSite: none' or production HTTPS
    sameSite: 'none', // Allows cookie cross-origin (e.g. localhost -> api.domain.com)
    maxAge: 1000 * 60 * 60 * 24 // 1 Day
  }
}));

// --- Middleware: Check Auth ---
function requireAuth(req, res, next) {   
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'unauthenticated' });
}

// --- Routes ---

// 1. Check Session (React calls this on page load)
app.get('/api/me', (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ user: null });
  }
});

// 2. Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // Check Lockout logic here if needed...

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Save User to Session
    req.session.user = { id: user._id, username: user.username };
    res.json({ ok: true, user: req.session.user });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// 3. Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('connect.sid');
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ ok: true });
  });
});

// 4. Proxy (React calls /api/proxy/users -> Backend fetches BACKEND_BASE/users)
app.use('/api/proxy', requireAuth, async (req, res) => {
  try {
    const targetUrl = `${BACKEND_BASE}${req.originalUrl.replace(/^\/api\/proxy/, '')}`;
    
    const backendRes = await fetch(targetUrl, {
      method: req.method,
      headers: { 
        ...req.headers, 
        host: new URL(BACKEND_BASE).host 
      }, 
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body)
    });

    res.status(backendRes.status);
    // Forward response body
    const body = await backendRes.buffer();
    res.send(body);

  } catch (err) {
    console.error('Proxy Error:', err);
    res.status(502).json({ error: 'Bad Gateway' });
  }
});

app.listen(PORT, () => {
  console.log(`Backend listening on ${PORT}`);
});