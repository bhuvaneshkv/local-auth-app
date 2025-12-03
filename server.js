const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
require('dotenv').config();
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
// const nodemailer = require('nodemailer'); // Uncomment when implementing forgot password

// Ensure data folder exists
if (!fs.existsSync('./data')) fs.mkdirSync('./data');

// SQLite DB file on disk
const DB_PATH = path.join(__dirname, 'data', 'trading.db');
const db = new sqlite3.Database(DB_PATH);

// Create users table if not exists
db.serialize(() => {
  // Wait up to 4 seconds for locks to clear to reduce SQLITE_BUSY errors
  db.run(`PRAGMA busy_timeout = 4000;`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);
  
  // Create password reset tokens table
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );`);

  // Ensure 'role' column exists on users table (default 'user')
  db.all(`PRAGMA table_info(users);`, (err, rows) => {
    if (!err && Array.isArray(rows)) {
      const hasRole = rows.some(r => r.name === 'role');
      if (!hasRole) {
        db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';`);
      }
    }
  });

  // Seed or promote an admin account (for development convenience)
  (async () => {
    try {
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@gmail.com';
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin';

      // If a user with adminEmail exists, promote to admin and reset password; else create new admin
      db.get(`SELECT id, role FROM users WHERE email=? LIMIT 1;`, [adminEmail], async (findErr, userRow) => {
        if (findErr) return; // ignore on error
        if (userRow) {
          const newHash = await bcrypt.hash(adminPassword, 10);
          db.run(`UPDATE users SET role='admin', password_hash=? WHERE id=?;`, [newHash, userRow.id]);
          console.log(`Promoted existing user to admin and reset password -> ${adminEmail}`);
        } else {
          const hash = await bcrypt.hash(adminPassword, 10);
          const stmt = db.prepare(`INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin');`);
          stmt.run(['Admin', adminEmail, hash], function(){ stmt.finalize(); });
          console.log(`Seeded admin user -> email: ${adminEmail}`);
        }
      });
    } catch (e) {
      // ignore
    }
  })();
});

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'change-this-secret-please',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 3600 * 1000 }
}));

// Serve static frontend
app.use('/', express.static(path.join(__dirname, 'public')));

// Require login helper
function requireLogin(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

function requireAdmin(req, res, next) {
  if (!(req.session && req.session.userId)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (req.session.role === 'admin') return next();
  return res.status(403).json({ error: 'forbidden' });
}

// ---------- Habits downstream integration (user sync) ----------
// Configuration via environment variables
// Load Habits configuration - force values from .env
const config = require('dotenv').config({ path: __dirname + '/.env' }).parsed || {};
const HABITS_ENABLED = (config.HABITS_ENABLED || '').toLowerCase() === 'true' || (config.HABITS_ENABLED === '1');
const HABITS_BASE_URL = config.HABITS_BASE_URL || '';
const HABITS_API_KEY = config.HABITS_API_KEY || '';

// Debug log to verify Habits config at startup
console.log('Habits config -> enabled:', HABITS_ENABLED, 'baseUrl:', HABITS_BASE_URL || '(empty)');

// Simple resilient POST with retries and idempotency
async function postToHabitsUsers(payload, idempotencyKey) {
  if (!HABITS_ENABLED || !HABITS_BASE_URL) return;
  const url = HABITS_BASE_URL.replace(/\/$/, '') + '/api/users';
  const headers = {
    'Content-Type': 'application/json',
    'Idempotency-Key': idempotencyKey
  };
  if (HABITS_API_KEY) headers['Authorization'] = `Bearer ${HABITS_API_KEY}`;

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        // keepalive helps when response is ending; supported in modern Node/browsers
        keepalive: true,
      });
      if (res.ok || res.status === 409) {
        // 2xx success or 409 conflict treated as success due to idempotency
        return;
      }
      const text = await res.text().catch(() => '');
      console.warn(`Habits sync attempt ${attempt} failed with status ${res.status}: ${text}`);
    } catch (e) {
      console.warn(`Habits sync attempt ${attempt} error:`, e?.message || String(e));
    }
    // Exponential backoff: 300ms, 700ms
    const delay = attempt === 1 ? 300 : 700;
    await new Promise(r => setTimeout(r, delay));
  }
}

function buildHabitsIdempotencyKey(localId, email) {
  try {
    const base = `${localId}:${email || ''}`;
    return crypto.createHash('sha256').update(base).digest('hex');
  } catch (_) {
    return String(localId) + ':' + (email || '');
  }
}
// ---------- end Habits integration ----------

// ---------- NIFTY50 price endpoint (drop-in replacement) ----------
const YahooFinance = require('yahoo-finance2').default;
const yf = new YahooFinance();
// robust lru-cache import that works across versions
const _LRU = require('lru-cache');
const LRUClass = (_LRU && (_LRU.default || _LRU.LRUCache)) ? (_LRU.default || _LRU.LRUCache) : _LRU;
// create cache (TTL in ms)
const cache = new LRUClass({ max: 100, ttl: 1000 * 120 }); // cache 120s

const _pLimit = require('p-limit');
const pLimit = _pLimit?.default || _pLimit;

// Current NIFTY 50 tickers (Yahoo uses .NS suffix)
// Updated: Sep 2025 - TATAMOTORS.NS removed (demerged), replaced by MAXHEALTH.NS
// Note: HDFC.NS removed (merged with HDFC Bank, now HDFCBANK.NS)
const NIFTY_TICKERS = [
  "RELIANCE.NS","TCS.NS","HDFCBANK.NS","ICICIBANK.NS","HINDUNILVR.NS",
  "INFY.NS","KOTAKBANK.NS","SBIN.NS","ITC.NS",
  "LT.NS","AXISBANK.NS","BHARTIARTL.NS","BAJFINANCE.NS","ASIANPAINT.NS",
  "HCLTECH.NS","WIPRO.NS","POWERGRID.NS","ONGC.NS","NTPC.NS",
  "BAJAJ-AUTO.NS","MARUTI.NS","TITAN.NS","INDUSINDBK.NS","ULTRACEMCO.NS",
  "TATASTEEL.NS","SUNPHARMA.NS","BRITANNIA.NS","DIVISLAB.NS","ADANIENT.NS",
  "COALINDIA.NS","GRASIM.NS","JSWSTEEL.NS","SBILIFE.NS","HINDALCO.NS",
  "NESTLEIND.NS","M&M.NS","EICHERMOT.NS","HDFCLIFE.NS",
  "TECHM.NS","BPCL.NS","GAIL.NS",
  "CIPLA.NS","DRREDDY.NS","INDIGO.NS","HEROMOTOCO.NS","SHREECEM.NS",
  "APOLLOHOSP.NS","ADANIPORTS.NS","TATACONSUM.NS","BAJAJFINSV.NS",
  "MAXHEALTH.NS"
];

const limit = pLimit(6); // at most 6 concurrent requests to remote API

// helper to pick the oldest (closest to 1 month ago) historical row
function pickOldest(histArray) {
  if (!Array.isArray(histArray) || histArray.length === 0) return null;
  return histArray.reduce((oldest, item) => {
    if (!oldest) return item;
    return (new Date(item.date) < new Date(oldest.date)) ? item : oldest;
  }, null);
}

async function getSymbolPrices(sym) {
  try {
    // Try quote method first (simpler, more direct)
    const quote = await yf.quote(sym);
    
    // Debug: log first symbol structure
    if (sym === NIFTY_TICKERS[0]) {
      console.log('Sample quote for', sym, ':', JSON.stringify(quote, null, 2).substring(0, 500));
    }
    
    const now = new Date();
    const past = new Date(now);
    past.setMonth(past.getMonth() - 1);
    const hist = await yf.historical(sym, { period1: past, period2: now, interval: '1d' });

    const oldest = pickOldest(hist);
    
    // Try multiple field paths for LTP
    const ltp = quote?.regularMarketPrice ?? 
                quote?.price ?? 
                (quote?.regularMarket && quote.regularMarket.regularMarketPrice) ??
                quote?.regularMarketPreviousClose ?? 
                quote?.ask ?? 
                quote?.bid ?? 
                quote?.currentPrice ??
                (quote?.price?.regularMarketPrice) ??
                null;
    const ltp_1m = oldest ? (oldest.close ?? null) : null;
    
    // Get dates
    // LTP date - use regularMarketTime if available, otherwise use current date
    let ltpDate = now;
    if (quote?.regularMarketTime) {
      try {
        // regularMarketTime is typically an ISO string like "2025-11-25T10:00:00.000Z"
        if (typeof quote.regularMarketTime === 'string') {
          ltpDate = new Date(quote.regularMarketTime);
        } else if (typeof quote.regularMarketTime === 'number') {
          // If it's a number, it might be milliseconds (not seconds)
          // Check if it's reasonable (after year 2000)
          const testDate = new Date(quote.regularMarketTime);
          if (testDate.getFullYear() > 2000) {
            ltpDate = testDate;
          } else {
            // Try as seconds
            ltpDate = new Date(quote.regularMarketTime * 1000);
          }
        }
        // Validate the date
        if (isNaN(ltpDate.getTime()) || ltpDate.getFullYear() < 2000 || ltpDate.getFullYear() > 2100) {
          ltpDate = now;
        }
      } catch (e) {
        ltpDate = now;
      }
    }
    // 1M LTP date - use the date from historical data
    const ltp_1m_date = oldest && oldest.date ? new Date(oldest.date) : null;

    return {
      symbol: sym,
      name: quote?.shortName || quote?.longName || quote?.displayName || null,
      ltp,
      ltp_date: ltpDate ? ltpDate.toISOString() : null,
      ltp_1m,
      ltp_1m_date: ltp_1m_date ? ltp_1m_date.toISOString() : null,
      pct_change_1m: (ltp != null && ltp_1m != null) ? ((ltp - ltp_1m) / ltp_1m * 100) : null
    };
  } catch (err) {
    const errorMsg = err?.message || String(err);
    // Check if it's a delisted/invalid symbol error
    const isDelisted = errorMsg.toLowerCase().includes('delisted') || 
                       errorMsg.toLowerCase().includes('no data found') ||
                       errorMsg.toLowerCase().includes('invalid symbol');
    
    if (isDelisted) {
      console.warn(`Symbol ${sym} appears to be delisted or invalid: ${errorMsg}`);
    } else {
      console.error(`Error fetching ${sym}:`, errorMsg);
    }
    
    // Return error info
    return { 
      symbol: sym, 
      error: isDelisted ? 'delisted' : 'fetch_failed',
      errorMsg: isDelisted ? 'Symbol may be delisted' : errorMsg
    };
  }
}

app.get('/api/nifty50', async (req, res) => {
  try {
    // Allow cache bypass with ?nocache=1
    const useCache = !req.query.nocache;
    if (useCache) {
      const cached = cache.get('nifty50');
      if (cached) return res.json({ fromCache: true, data: cached });
    }

    console.log('Fetching NIFTY50 data...');
    // queue tasks with limited concurrency
    const tasks = NIFTY_TICKERS.map(sym => limit(() => getSymbolPrices(sym)));
    const results = await Promise.all(tasks);

    // Log first result for debugging
    if (results.length > 0) {
      console.log('First result sample:', JSON.stringify(results[0], null, 2));
    }

    cache.set('nifty50', results);
    return res.json({ fromCache: false, data: results });
  } catch (err) {
    console.error('nifty50 error', err);
    res.status(500).json({ error: 'failed to fetch prices', details: err?.message });
  }
});
// ---------- end NIFTY50 block ----------

// ---------- F&O (Futures & Options) endpoint ----------
async function getFuturesData(sym) {
  try {
    const quote = await yf.quote(sym);
    const ltp = quote?.regularMarketPrice ?? 
                quote?.regularMarketPreviousClose ?? 
                null;
    
    // For futures, we'll use the spot price and calculate theoretical futures
    // In real scenario, you'd fetch actual futures contracts
    const spotPrice = ltp;
    
    return {
      symbol: sym,
      name: quote?.shortName || quote?.longName || null,
      spot_price: spotPrice,
      // Note: Actual futures prices would come from a dedicated futures API
      // This is a placeholder structure
      futures: {
        current_month: spotPrice ? (spotPrice * 1.001).toFixed(2) : null, // Theoretical
        next_month: spotPrice ? (spotPrice * 1.002).toFixed(2) : null
      }
    };
  } catch (err) {
    return { 
      symbol: sym, 
      error: 'fetch_failed',
      errorMsg: err?.message || String(err)
    };
  }
}

// Helper function to get last Thursday of a month (NSE options expiry)
function getLastThursday(year, month) {
  const lastDay = new Date(year, month + 1, 0); // Last day of month
  let thursday = lastDay;
  thursday.setDate(lastDay.getDate() - ((lastDay.getDay() + 3) % 7));
  return thursday;
}

// Generate expiry dates (current month, next month, and month after)
function generateExpiryDates() {
  const now = new Date();
  const expiries = [];
  
  for (let i = 0; i < 3; i++) {
    const date = new Date(now.getFullYear(), now.getMonth() + i, 1);
    const expiry = getLastThursday(date.getFullYear(), date.getMonth());
    // If expiry has passed this month, use next month
    if (i === 0 && expiry < now) {
      const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
      expiries.push(getLastThursday(nextMonth.getFullYear(), nextMonth.getMonth()));
    } else {
      expiries.push(expiry);
    }
  }
  
  return expiries.map(d => d.toISOString().split('T')[0]); // Return as YYYY-MM-DD
}

async function getOptionsData(sym) {
  try {
    const quote = await yf.quote(sym);
    const spotPrice = quote?.regularMarketPrice ?? 
                     quote?.regularMarketPreviousClose ?? 
                     null;
    
    if (!spotPrice) {
      return { symbol: sym, error: 'no_spot_price' };
    }
    
    // Generate expiry dates
    const expiryDates = generateExpiryDates();
    
    // Generate theoretical options chain around current price
    // In production, you'd fetch actual options data from a dedicated API
    const allStrikes = [];
    const step = Math.max(10, Math.round(spotPrice * 0.02)); // 2% steps, min 10
    
    // Generate strikes from -20% to +20% of spot
    for (let i = -10; i <= 10; i++) {
      const strike = Math.round((spotPrice + (i * step)) / 10) * 10; // Round to nearest 10
      if (strike > 0) {
        // Generate data for each expiry
        expiryDates.forEach((expiry, expIdx) => {
          // Premiums increase with time to expiry
          const timeMultiplier = 1 + (expIdx * 0.1);
          const callPremium = Math.max(0.1, ((spotPrice - strike) * 0.1 + Math.random() * 5) * timeMultiplier);
          const putPremium = Math.max(0.1, ((strike - spotPrice) * 0.1 + Math.random() * 5) * timeMultiplier);
          
          allStrikes.push({
            strike: strike,
            expiry: expiry,
            call: {
              premium: callPremium.toFixed(2),
              oi: 0,
              volume: 0
            },
            put: {
              premium: putPremium.toFixed(2),
              oi: 0,
              volume: 0
            }
          });
        });
      }
    }
    
    // Calculate total OI across all contracts (calls + puts)
    let totalCallOI = 0;
    let totalPutOI = 0;
    allStrikes.forEach(strike => {
      totalCallOI += parseInt(strike.call.oi) || 0;
      totalPutOI += parseInt(strike.put.oi) || 0;
    });
    const totalOI = totalCallOI + totalPutOI;
    
    return {
      symbol: sym,
      spot_price: spotPrice,
      expiry_dates: expiryDates,
      strikes: allStrikes,
      total_oi: totalOI,
      total_call_oi: totalCallOI,
      total_put_oi: totalPutOI
    };
  } catch (err) {
    return { 
      symbol: sym, 
      error: 'fetch_failed',
      errorMsg: err?.message || String(err)
    };
  }
}

// F&O endpoint - using query parameter to handle symbols with dots
app.get('/api/fno', async (req, res) => {
  try {
    const symbol = req.query.symbol; // Use query parameter instead of route parameter
    const useCache = !req.query.nocache;
    const cacheKey = symbol ? `fno_${symbol}` : 'fno_all';
    
    if (useCache) {
      const cached = cache.get(cacheKey);
      if (cached) return res.json({ fromCache: true, data: cached });
    }
    
    if (symbol) {
      // Get F&O for specific symbol
      const futuresData = await getFuturesData(symbol);
      const optionsData = await getOptionsData(symbol);
      
      const result = {
        symbol: symbol,
        futures: futuresData,
        options: optionsData
      };
      
      cache.set(cacheKey, result);
      return res.json({ fromCache: false, data: result });
    } else {
      // Get F&O for all NIFTY 50 stocks
      const tasks = NIFTY_TICKERS.map(sym => limit(async () => {
        const futures = await getFuturesData(sym);
        const options = await getOptionsData(sym);
        return { symbol: sym, futures, options };
      }));
      
      const results = await Promise.all(tasks);
      cache.set(cacheKey, results);
      return res.json({ fromCache: false, data: results });
    }
  } catch (err) {
    console.error('F&O error', err);
    res.status(500).json({ error: 'failed to fetch F&O data', details: err?.message });
  }
});
// ---------- end F&O block ----------

// ---------- INDICATOR (200-day MA) endpoint ----------
app.get('/api/indicators', async (req, res) => {
  try {
    // Allow cache bypass with ?nocache=1
    const useCache = !req.query.nocache;
    if (useCache) {
      const cached = cache.get('indicators');
      if (cached) return res.json({ fromCache: true, data: cached });
    }

    // Limit to Nifty 50 stocks unless overridden
    const symbols = req.query.nifty50 === '1' ? NIFTY_TICKERS : (req.query.symbols ? req.query.symbols.split(',') : NIFTY_TICKERS);
    const tasks = symbols.map(sym => limit(async () => {
      try {
        const quote = await yf.quote(sym);
        const now = new Date();
        const historicFrom = new Date(now);
        historicFrom.setDate(historicFrom.getDate() - 260); // ~20 trading days/month x 10m = 200 days
        const hist = await yf.historical(sym, { period1: historicFrom, period2: now, interval: '1d' });
        let closes = (Array.isArray(hist) ? hist.filter(h=>h.close!=null).map(h=>h.close) : []);
        closes = closes.length > 200 ? closes.slice(closes.length-200) : closes; // Only last 200 closes
        const ma200 = closes.length === 200 ? closes.reduce((a,b)=>a+b,0)/200 : (closes.length ? closes.reduce((a,b)=>a+b,0)/closes.length : null);
        // LTP logic as in getSymbolPrices
        const ltp = quote?.regularMarketPrice ?? quote?.price ?? (quote?.regularMarket && quote.regularMarket.regularMarketPrice) ?? quote?.regularMarketPreviousClose ?? quote?.ask ?? quote?.bid ?? quote?.currentPrice ?? (quote?.price?.regularMarketPrice) ?? null;
        return {
          symbol: sym,
          name: quote?.shortName || quote?.longName || quote?.displayName || null,
          ltp,
          ma200
        };
      } catch (err) {
        return { symbol: sym, error: 'fetch_failed', errorMsg: err?.message || String(err) };
      }
    }));
    const results = await Promise.all(tasks);
    cache.set('indicators', results);
    return res.json({ fromCache: false, data: results });
  } catch (err) {
    res.status(500).json({ error: 'failed to fetch indicators', details: err?.message });
  }
});
// ---------- end INDICATOR block ----------


// Signup
app.post('/api/signup', async (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    // Only an authenticated admin can assign 'admin' role at signup; otherwise force 'user'
    const isAdminSession = req.session && req.session.role === 'admin';
    const newRole = (isAdminSession && role === 'admin') ? 'admin' : 'user';
    const stmt = db.prepare(`INSERT INTO users (name, email, password_hash, role)
                             VALUES (?, ?, ?, ?);`);
    stmt.run([name || null, email, hash, newRole], function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT')
          return res.status(400).json({ error: 'email already used' });
        return res.status(500).json({ error: 'db error' });
      }

      req.session.userId = this.lastID;
      req.session.email = email;

      // Fire-and-forget sync to Habits (does not block response)
      try {
        const payload = { name: name || null, email, role: newRole };
        const idemKey = buildHabitsIdempotencyKey(this.lastID, email);
        // Avoid blocking – schedule after response cycle
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore */ }

      return res.json({ success: true });
    });
    stmt.finalize();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT id, password_hash, role FROM users WHERE email=?`, [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(400).json({ error: 'invalid email or password' });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(400).json({ error: 'invalid email or password' });

    req.session.userId = row.id;
    req.session.email = email;
    req.session.role = row.role || 'user';

    res.json({ success: true });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Protected profile
app.get('/api/me', requireLogin, (req, res) => {
  db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ user: row });
  });
});

// Public roles endpoint
app.get('/api/roles', (req, res) => {
  res.json({ roles: ['user', 'admin'] });
});

// ---------------- Admin: User Management APIs ----------------
// List all users (basic fields)
app.get('/api/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, name, email, role FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ data: rows });
  });
});

// Admin-only: inspect current Habits integration config
app.get('/api/habits-config', requireAdmin, (req, res) => {
  res.json({
    enabled: HABITS_ENABLED,
    baseUrl: HABITS_BASE_URL || null,
    hasApiKey: !!HABITS_API_KEY
  });
});

// Sync existing users to Habits (define BEFORE :id route so it matches correctly)
app.get('/api/users/sync-habits', requireAdmin, (req, res) => {
  if (!HABITS_ENABLED || !HABITS_BASE_URL) {
    return res.status(400).json({ error: 'habits_not_configured' });
  }
  db.all(`SELECT id, name, email, role FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    const users = Array.isArray(rows) ? rows : [];
    users.forEach(u => {
      try {
        const payload = { name: u.name || null, email: u.email, role: u.role || 'user' };
        const idemKey = buildHabitsIdempotencyKey(u.id, u.email);
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore */ }
    });
    res.json({ queued: users.length });
  });
});
app.post('/api/users/sync-habits', requireAdmin, (req, res) => {
  if (!HABITS_ENABLED || !HABITS_BASE_URL) {
    return res.status(400).json({ error: 'habits_not_configured' });
  }
  db.all(`SELECT id, name, email, role FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    const users = Array.isArray(rows) ? rows : [];
    users.forEach(u => {
      try {
        const payload = { name: u.name || null, email: u.email, role: u.role || 'user' };
        const idemKey = buildHabitsIdempotencyKey(u.id, u.email);
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore */ }
    });
    res.json({ queued: users.length });
  });
});

// Get single user by ID
app.get('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(404).json({ error: 'not_found' });
    res.json({ user: row });
  });
});

// Create a user (admin)
app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const userRole = role === 'admin' ? 'admin' : 'user';
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare(`INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?);`);
    stmt.run([name || null, email, hash, userRole], function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') return res.status(400).json({ error: 'email already used' });
        return res.status(500).json({ error: 'db error' });
      }
      // Fire-and-forget sync to Habits (does not block response)
      try {
        const payload = { name: name || null, email, role: userRole };
        const idemKey = buildHabitsIdempotencyKey(this.lastID, email);
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore */ }

      res.status(201).json({ id: this.lastID, name: name || null, email, role: userRole });
    });
    stmt.finalize();
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// Update a user (admin)
app.patch('/api/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  const { name, email, password, role } = req.body || {};

  // Build dynamic update
  const fields = [];
  const params = [];
  if (typeof name !== 'undefined') { fields.push('name=?'); params.push(name || null); }
  if (typeof email !== 'undefined') { fields.push('email=?'); params.push(email); }
  if (typeof role !== 'undefined') { fields.push('role=?'); params.push(role === 'admin' ? 'admin' : 'user'); }
  if (typeof password !== 'undefined') {
    try {
      const hash = await bcrypt.hash(password, 10);
      fields.push('password_hash=?'); params.push(hash);
    } catch (e) { return res.status(500).json({ error: 'hash_failed' }); }
  }
  if (fields.length === 0) return res.status(400).json({ error: 'no_fields' });
  params.push(id);

  db.run(`UPDATE users SET ${fields.join(', ')} WHERE id=?;`, params, function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') return res.status(400).json({ error: 'email already used' });
      return res.status(500).json({ error: 'db error' });
    }
    if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
    db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [id], (gerr, row) => {
      if (gerr) return res.status(500).json({ error: 'db error' });
      res.json(row);
    });
  });
});

// Delete a user (admin)
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
  db.run(`DELETE FROM users WHERE id=?;`, [id], function (err) {
    if (err) return res.status(500).json({ error: 'db error' });
    if (this.changes === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ success: true });
  });
});
// ---------------- end Admin block ----------------

// ---------------- Admin: Sync existing users to Habits ----------------
// Queues a downstream sync for all existing users. Fire-and-forget; does not wait for remote.
app.post('/api/users/sync-habits', requireAdmin, (req, res) => {
  if (!HABITS_ENABLED || !HABITS_BASE_URL) {
    return res.status(400).json({ error: 'habits_not_configured' });
  }
  db.all(`SELECT id, name, email, role FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    const users = Array.isArray(rows) ? rows : [];
    users.forEach(u => {
      try {
        const payload = { name: u.name || null, email: u.email, role: u.role || 'user' };
        const idemKey = buildHabitsIdempotencyKey(u.id, u.email);
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore individual errors */ }
    });
    res.json({ queued: users.length });
  });
});

// GET alias for convenience (same behavior as POST)
app.get('/api/users/sync-habits', requireAdmin, (req, res) => {
  if (!HABITS_ENABLED || !HABITS_BASE_URL) {
    return res.status(400).json({ error: 'habits_not_configured' });
  }
  db.all(`SELECT id, name, email, role FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    const users = Array.isArray(rows) ? rows : [];
    users.forEach(u => {
      try {
        const payload = { name: u.name || null, email: u.email, role: u.role || 'user' };
        const idemKey = buildHabitsIdempotencyKey(u.id, u.email);
        setImmediate(() => postToHabitsUsers(payload, idemKey));
      } catch (_) { /* ignore individual errors */ }
    });
    res.json({ queued: users.length });
  });
});
// ---------------- end Sync block ----------------

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`SQLite DB stored at: ${DB_PATH}`);
});
