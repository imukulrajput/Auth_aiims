require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const cors = require('cors');

const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = (...args) => import('node-fetch').then(mod => mod.default(...args));
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const corsOptions = {
  origin: process.env.FRONTEND_URL,   
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Requested-With'],
};

const User = require('./models/User');

const app = express(); 
const PORT = process.env.PORT || 8080;
const BACKEND_BASE = process.env.BACKEND_BASE 

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}
  
// --- security middlewares ---           
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('combined'));
app.use(cors(corsOptions));

// --- connect mongodb ---
mongoose.connect(process.env.MONGO_URI, {});

// --- session config (Mongo-backed) ---
app.use(session({      
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'lax',
    maxAge: 1000 * 60 * 30 
  }
}));


const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 12,
  handler: (req, res) => res.status(429).json({ error: 'Too many attempts, try later' })
});
 

function requireAuth(req, res, next){
  if(req.session && req.session.user){ return next(); }
 
  if(req.xhr || req.headers.accept?.includes('application/json')) return res.status(401).json({ error: 'unauthenticated' });
  res.redirect('/login');
}


app.post('/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error: 'missing' });

  const user = await User.findOne({ username });
  if(!user) return res.status(401).json({ error: 'invalid' });

  // check lockout
  if(user.lockedUntil && user.lockedUntil > new Date()){
    return res.status(403).json({ error: 'account_locked' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if(!ok){
    user.failedAttempts = (user.failedAttempts || 0) + 1;
    if(user.failedAttempts >= 6){
      user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // lock 15m
      user.failedAttempts = 0;
    }
    await user.save();
    return res.status(401).json({ error: 'invalid' });
  }

  // success
  user.failedAttempts = 0;
  user.lockedUntil = null;
  await user.save();

  req.session.user = { id: user._id, username: user.username };
  // optionally regenerate session id
  req.session.regenerate(err => {
    if(err) console.error(err);
    req.session.user = { id: user._id, username: user.username };
    res.json({ ok: true });
  });
});

// --- logout ---
app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('connect.sid');
    if(err) return res.status(500).json({ error: 'logout_failed' });
    res.json({ ok: true });
  });
});

// --- serve login page (simple) ---
app.get('/login', (req, res) => {
  // serve a login page or a simple HTML form (example below)
  res.sendFile(require('path').join(__dirname, 'public', 'login.html'));
});        

// --- protect all dashboard static files (if serving) ---
app.use('/dashboard', requireAuth, express.static('dashboard_build_folder')); // your built frontend

// --- proxy endpoint: frontend calls /api/proxy/* and we fetch from BACKEND_BASE ---
app.use('/api/proxy', requireAuth, async (req, res) => {
  try{
    const targetUrl = `${BACKEND_BASE}${req.originalUrl.replace(/^\/api\/proxy/, '')}`;
    // forward method, headers (but strip cookies/authorization from client)
    const headers = { 'accept': req.headers['accept'] || 'application/json' };
    // If backend needs some headers, add them here (e.g., API-Key) BUT you said no change on backend.
    const fetchOptions = {
      method: req.method,
      headers,
      body: ['GET','HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body)
    };
    const backendRes = await fetch(targetUrl, fetchOptions);
    // copy status + headers (careful with set-cookie)
    res.status(backendRes.status);
    backendRes.headers.forEach((v, k) => {
      if(k.toLowerCase() === 'set-cookie') return; // don't forward backend cookies to client
      res.setHeader(k, v);
    });
    const body = await backendRes.buffer();
    res.send(body);
  }catch(err){
    console.error(err);
    res.status(502).json({ error: 'bad_gateway' });
  }
});

// --- Example protected API route hosted locally ---
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// --- start ---
app.listen(PORT, () => {
  console.log('Auth proxy listening on', PORT);
});
    