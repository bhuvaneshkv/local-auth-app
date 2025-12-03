const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');

// Ensure data dir
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'habits.db');
const db = new sqlite3.Database(DB_PATH);

// Create tables
// users: mirror of upstream minimal fields
// idempotency_keys: store request key -> created user to make create-user idempotent

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS idempotency_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    user_id INTEGER,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);
});

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.json());
app.use(session({
  secret: 'habits-session-secret-change',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 3600 * 1000 }
}));

// serve static UI for quick manual tests
app.use('/', express.static(path.join(__dirname, 'public')));

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Optional: list users (for quick local verification)
app.get('/api/users', (req, res) => {
  db.all(`SELECT id, name, email, role, created_at FROM users ORDER BY id ASC;`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ data: rows });
  });
});

// Simple session auth: email-only login for mirror system
app.post('/api/login', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });
  db.get(`SELECT id, name, email, role FROM users WHERE email=?`, [email], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!row) return res.status(400).json({ error: 'not_found' });
    req.session.userId = row.id;
    req.session.email = row.email;
    req.session.role = row.role || 'user';
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!(req.session && req.session.userId)) return res.status(401).json({ error: 'unauthorized' });
  db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ user: row });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Create user with idempotency support
app.post('/api/users', (req, res) => {
  const idemKey = req.header('Idempotency-Key');
  const { name, email, role } = req.body || {};

  if (!email) return res.status(400).json({ error: 'email_required' });
  const safeRole = role === 'admin' ? 'admin' : 'user';

  const respondWithUser = (userRow, status = 201) => {
    const payload = { id: userRow.id, name: userRow.name || null, email: userRow.email, role: userRow.role };
    res.status(status).json(payload);
  };

  // If idempotency key exists and was used before, return same result
  if (idemKey) {
    db.get(`SELECT user_id FROM idempotency_keys WHERE key=? LIMIT 1;`, [idemKey], (e1, keyRow) => {
      if (e1) return res.status(500).json({ error: 'db_error' });
      if (keyRow && keyRow.user_id) {
        db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [keyRow.user_id], (e2, userRow) => {
          if (e2) return res.status(500).json({ error: 'db_error' });
          if (!userRow) return res.status(404).json({ error: 'not_found' });
          return respondWithUser(userRow, 200);
        });
        return;
      }

      // Proceed to create and then store idempotency mapping
      createUserAndMaybeStoreKey();
    });
  } else {
    // No idempotency key: just create
    createUserAndMaybeStoreKey();
  }

  function createUserAndMaybeStoreKey() {
    const stmt = db.prepare(`INSERT INTO users (name, email, role) VALUES (?, ?, ?);`);
    stmt.run([name || null, email, safeRole], function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          // Email already used — if idempotency key is present but first time, treat as conflict
          return res.status(409).json({ error: 'email_exists' });
        }
        return res.status(500).json({ error: 'db_error' });
      }

      const newId = this.lastID;
      if (idemKey) {
        const kstmt = db.prepare(`INSERT OR IGNORE INTO idempotency_keys (key, user_id, email) VALUES (?, ?, ?);`);
        kstmt.run([idemKey, newId, email], function (_e3) {
          // Even if this fails, user was created; continue
          db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [newId], (e4, row) => {
            if (e4) return res.status(500).json({ error: 'db_error' });
            return respondWithUser(row, 201);
          });
        });
      } else {
        db.get(`SELECT id, name, email, role FROM users WHERE id=?`, [newId], (e5, row) => {
          if (e5) return res.status(500).json({ error: 'db_error' });
          return respondWithUser(row, 201);
        });
      }
    });
    stmt.finalize();
  }
});

app.listen(PORT, () => {
  console.log(`Habits service running at http://localhost:${PORT}`);
  console.log(`SQLite DB stored at: ${DB_PATH}`);
});
