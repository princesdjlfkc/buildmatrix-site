'use strict';
require('dotenv').config();

const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const bcrypt     = require('bcryptjs');
const cors       = require('cors');
const session    = require('express-session');
const Database   = require('better-sqlite3');
const { exec }   = require('child_process');

let priceSources = null;
try {
  priceSources = require('./price-sources.js');
} catch (_) {
  priceSources = { STORES: {}, getPricesForProduct: async () => ({ prices: [], bestPrice: null }) };
}

const PORT         = Number(process.env.PORT || 5000);
const DB_FILE      = process.env.DB_FILE || (fs.existsSync('/data') ? '/data/buildmatrix.sqlite' : path.join(__dirname, 'buildmatrix.sqlite'));
const isProduction = process.env.NODE_ENV === 'production';

const sqliteDb = new Database(DB_FILE);
sqliteDb.pragma('journal_mode = WAL');
sqliteDb.pragma('foreign_keys = ON');

sqliteDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    email       TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,
    bio         TEXT    DEFAULT '',
    theme       TEXT    DEFAULT 'dark',
    avatar_url  TEXT    DEFAULT NULL,
    is_admin    INTEGER DEFAULT 0,
    banned      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS password_resets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token       TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS builds (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    items_json  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS shared_builds (
    id          TEXT PRIMARY KEY,
    items_json  TEXT NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    name        TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    price       INTEGER NOT NULL,
    tier        TEXT,
    specs       TEXT,
    img         TEXT,
    rating      REAL,
    ratingCount INTEGER,
    meta        TEXT
  );
  CREATE TABLE IF NOT EXISTS newsletter (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

for (const m of [
  "ALTER TABLE users ADD COLUMN is_admin   INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN banned     INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN bio        TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN theme      TEXT DEFAULT 'dark'",
]) { try { sqliteDb.exec(m); } catch (_) {} }

// Auto-create owner
try {
  const ownerEmail = 'princeramos231@gmail.com';
  const existing = sqliteDb.prepare('SELECT id FROM users WHERE email = ?').get(ownerEmail);
  if (!existing) {
    const bcrypt = require('bcryptjs');
    const hash = bcrypt.hashSync('BuildMatrix2026!', 10);
    sqliteDb.prepare('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, 1)').run('prinzz', ownerEmail, hash);
  } else {
    sqliteDb.prepare('UPDATE users SET is_admin = 1 WHERE email = ?').run(ownerEmail);
  }
} catch(e) {}

const db = {
  query(sql, params = []) {
    const isSelect = /^\s*select/i.test(sql.trim());
    if (isSelect) {
      const rows = sqliteDb.prepare(sql).all(...params);
      return Promise.resolve([rows]);
    }
    const info = sqliteDb.prepare(sql).run(...params);
    return Promise.resolve([{ affectedRows: info.changes, insertId: info.lastInsertRowid }]);
  }
};

const app = express();
app.set('trust proxy', 1);

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) return cb(null, true);
    if (origin.includes('.onrender.com') || origin.includes('.netlify.app')) return cb(null, true);
    if (origin.includes('.railway.app') || origin.includes('ngrok')) return cb(null, true);
    cb(null, true);
  },
  credentials: true,
  optionsSuccessStatus: 200,
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: 'buildmatrix.sid',
  secret: (() => {
    const s = process.env.SESSION_SECRET;
    if (!s || s === 'dev-secret-change-me') return crypto.randomBytes(32).toString('hex');
    return s;
  })(),
  resave: true,
  saveUninitialized: true,
  rolling: true,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure:   isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge:   7 * 24 * 60 * 60 * 1000,
    path: '/',
  },
}));

async function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ success: false, error: 'Unauthorized' });
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    const user = rows[0];
    if (!user) { req.session.destroy(() => {}); return res.status(401).json({ success: false, error: 'User not found' }); }
    if (user.banned) return res.status(403).json({ success: false, error: 'Your account has been banned.' });
    req.user = user;
    next();
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
}

async function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ success: false, error: 'Unauthorized' });
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    if (!rows[0]?.is_admin) return res.status(403).json({ success: false, error: 'Admin access required' });
    req.user = rows[0];
    next();
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
}

function sanitizeUser(row) {
  if (!row) return null;
  return {
    id:        row.id,
    name:      row.name,
    email:     row.email,
    bio:       row.bio   || '',
    theme:     row.theme || 'dark',
    avatarUrl: row.avatar_url || null,
    is_admin:  !!row.is_admin,
    createdAt: row.created_at,
  };
}

app.get('/api/auth/test', (req, res) => res.json({ success: true, message: 'Backend is running!', time: new Date().toISOString() }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const name     = String(req.body.name     || '').trim();
    const email    = String(req.body.email    || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!name || !email || !password) return res.status(400).json({ success: false, error: 'All fields are required' });
    if (password.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    const [exists] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(400).json({ success: false, error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const isAdmin = email === 'princeramos231@gmail.com' ? 1 : 0;
    await db.query('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)', [name, email, hashed, isAdmin]);
    const [newRows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
    req.session.userId = newRows[0].id;
    req.session.save(() => res.json({ success: true, message: 'Account created successfully!', user: sanitizeUser(newRows[0]) }));
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email    = String(req.body.email    || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const [rows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];
    if (!user)       return res.status(401).json({ success: false, error: 'Invalid credentials' });
    if (user.banned) return res.status(403).json({ success: false, error: 'Your account has been banned.' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    if (email === 'princeramos231@gmail.com' && !user.is_admin) {
      await db.query('UPDATE users SET is_admin = 1 WHERE email = ?', [email]);
      user.is_admin = 1;
    }
    req.session.userId = user.id;
    req.session.save(() => res.json({ success: true, user: sanitizeUser(user) }));
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(() => { res.clearCookie('buildmatrix.sid'); res.json({ success: true, message: 'Logged out' }); });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try { res.json(sanitizeUser(req.user)); }
  catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/auth/theme', requireAuth, async (req, res) => {
  try {
    const theme = req.body.theme === 'light' ? 'light' : 'dark';
    await db.query('UPDATE users SET theme=? WHERE id=?', [theme, req.user.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/auth/reset-password-captcha', async (req, res) => {
  try {
    const email       = String(req.body.email       || '').trim().toLowerCase();
    const newPassword = String(req.body.newPassword || '');
    if (!email) return res.status(400).json({ success: false, error: 'Email is required' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    const [rows] = await db.query('SELECT id FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(404).json({ success: false, error: 'No account found with that email' });
    await db.query('UPDATE users SET password=? WHERE email=?', [await bcrypt.hash(newPassword, 10), email]);
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword     = String(req.body.newPassword     || '');
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, error: 'All fields are required' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
    const ok = await bcrypt.compare(currentPassword, req.user.password);
    if (!ok) return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    await db.query('UPDATE users SET password=? WHERE id=?', [await bcrypt.hash(newPassword, 10), req.user.id]);
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/auth/avatar', requireAuth, async (req, res) => {
  try {
    const avatarUrl = req.body.avatarUrl || null;
    if (avatarUrl && avatarUrl.length > 250000) return res.status(400).json({ success: false, error: 'Image too large. Max 200KB.' });
    await db.query('UPDATE users SET avatar_url=? WHERE id=?', [avatarUrl, req.user.id]);
    res.json({ success: true, avatarUrl });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/auth/profile', requireAuth, async (req, res) => {
  try {
    const name  = String(req.body.name  || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!name) return res.status(400).json({ success: false, error: 'Name is required' });
    const fields = ['name=?']; const values = [name];
    if (email && email !== req.user.email) {
      const [existing] = await db.query('SELECT id FROM users WHERE email=? AND id!=?', [email, req.user.id]);
      if (existing.length) return res.status(409).json({ success: false, error: 'Email already in use' });
      fields.push('email=?'); values.push(email);
    }
    values.push(req.user.id);
    await db.query(`UPDATE users SET ${fields.join(',')} WHERE id=?`, values);
    const [rows] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
    res.json({ success: true, user: sanitizeUser(rows[0]) });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/profile/:userId', requireAuth, async (req, res) => {
  try {
    const [userRows] = await db.query('SELECT * FROM users WHERE id=?', [req.params.userId]);
    const user = userRows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const [builds] = await db.query('SELECT * FROM builds WHERE user_id=? ORDER BY created_at DESC', [user.id]);
    const totalSpent = builds.reduce((s, b) => s + (b.total || 0), 0);
    res.json({ user: sanitizeUser(user), stats: { totalBuilds: builds.length, totalSpent: Math.round(totalSpent), avgBuild: builds.length ? Math.round(totalSpent / builds.length) : 0 }, recentBuilds: builds.slice(0, 5).map(b => ({ id: b.id, name: b.name, total: b.total, created_at: b.created_at })) });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/profile/update', requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 80);
    const bio  = String(req.body.bio  || '').trim().slice(0, 300);
    if (!name) return res.status(400).json({ error: 'Name cannot be empty' });
    await db.query('UPDATE users SET name=?, bio=? WHERE id=?', [name, bio, req.user.id]);
    const [rows] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
    res.json({ success: true, user: sanitizeUser(rows[0]) });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/builds', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id,name,total,items_json,created_at FROM builds WHERE user_id=? ORDER BY created_at DESC', [req.user.id]);
    res.json({ success: true, builds: rows.map(r => ({ id: r.id, name: r.name, total: r.total, createdAt: r.created_at, items: (() => { try { return JSON.parse(r.items_json || '[]'); } catch { return []; } })() })) });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/builds/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM builds WHERE id=? AND user_id=? LIMIT 1', [req.params.id, req.user.id]);
    const r = rows[0];
    if (!r) return res.status(404).json({ success: false, error: 'Build not found' });
    res.json({ success: true, build: { id: r.id, name: r.name, total: r.total, createdAt: r.created_at, items: (() => { try { return JSON.parse(r.items_json || '[]'); } catch { return []; } })() } });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/builds', requireAuth, async (req, res) => {
  try {
    const name  = String(req.body.name  || '').trim();
    const total = Number(req.body.total || 0);
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!name)         return res.status(400).json({ success: false, error: 'Build name is required' });
    if (!items.length) return res.status(400).json({ success: false, error: 'Build must contain at least 1 item' });
    const id = crypto.randomUUID();
    await db.query('INSERT INTO builds (id,user_id,name,total,items_json) VALUES (?,?,?,?,?)', [id, req.user.id, name, Math.round(total), JSON.stringify(items)]);
    res.json({ success: true, message: 'Build saved', id });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/builds/:id', requireAuth, async (req, res) => {
  try {
    const [exists] = await db.query('SELECT id FROM builds WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    if (!exists.length) return res.status(404).json({ success: false, error: 'Build not found' });
    const fields = []; const values = [];
    const name  = String(req.body.name  || '').trim();
    const total = req.body.total != null ? Number(req.body.total) : null;
    const items = req.body.items != null ? (Array.isArray(req.body.items) ? req.body.items : null) : null;
    if (name)  { fields.push('name=?');       values.push(name); }
    if (total != null && !Number.isNaN(total)) { fields.push('total=?'); values.push(Math.round(total)); }
    if (items) { fields.push('items_json=?'); values.push(JSON.stringify(items)); }
    if (!fields.length) return res.json({ success: true, message: 'Nothing to update' });
    fields.push('updated_at=?'); values.push(new Date().toISOString(), req.params.id, req.user.id);
    await db.query(`UPDATE builds SET ${fields.join(',')} WHERE id=? AND user_id=?`, values);
    res.json({ success: true, message: 'Build updated' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.delete('/api/builds/:id', requireAuth, async (req, res) => {
  try {
    await db.query('DELETE FROM builds WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Build deleted' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/builds/:id/notes', requireAuth, async (req, res) => {
  try {
    const [exists] = await db.query('SELECT id FROM builds WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    if (!exists.length) return res.status(404).json({ success: false, error: 'Build not found' });
    await db.query('UPDATE builds SET updated_at=? WHERE id=?', [new Date().toISOString(), req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/share', async (req, res) => {
  try {
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!items.length) return res.status(400).json({ success: false, error: 'No items in build' });
    const id = crypto.randomBytes(4).toString('hex');
    await db.query('INSERT INTO shared_builds (id,items_json,total,name) VALUES (?,?,?,?)', [id, JSON.stringify(items), Math.round(Number(req.body.total) || 0), String(req.body.name || 'Shared Build').trim()]);
    res.json({ success: true, id, url: `${req.protocol}://${req.get('host')}/index.html?buildShare=${id}` });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/share/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM shared_builds WHERE id=?', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ success: false, error: 'Shared build not found' });
    const r = rows[0];
    res.json({ success: true, build: { id: r.id, name: r.name, total: r.total, createdAt: r.created_at, items: (() => { try { return JSON.parse(r.items_json); } catch { return []; } })() } });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [[{ count: tu }]] = await db.query('SELECT COUNT(*) as count FROM users');
    const [[{ count: tb }]] = await db.query('SELECT COUNT(*) as count FROM builds');
    const [[{ count: tp }]] = await db.query('SELECT COUNT(*) as count FROM products');
    const [[{ count: nw }]] = await db.query("SELECT COUNT(*) as count FROM users WHERE created_at > datetime('now','-7 days')");
    res.json({ success: true, stats: { totalUsers: tu, totalBuilds: tb, totalProducts: tp, newUsersThisWeek: nw } });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.query(`SELECT u.id,u.name,u.email,u.is_admin,u.banned,u.created_at,COUNT(b.id) AS build_count FROM users u LEFT JOIN builds b ON b.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC`);
    res.json({ success: true, users: rows.map(r => ({ _id: String(r.id), id: String(r.id), name: r.name, email: r.email, is_admin: !!r.is_admin, banned: !!r.banned, buildCount: r.build_count || 0, createdAt: r.created_at })) });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { name, email, password, is_admin } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, error: 'name, email, password required' });
    const [exists] = await db.query('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) return res.status(409).json({ success: false, error: 'Email already in use' });
    await db.query('INSERT INTO users (name,email,password,is_admin) VALUES (?,?,?,?)', [name, email, await bcrypt.hash(password, 10), is_admin ? 1 : 0]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { name, email, is_admin } = req.body;
    const fields = []; const values = [];
    if (name     !== undefined) { fields.push('name=?');     values.push(name); }
    if (email    !== undefined) { fields.push('email=?');    values.push(email); }
    if (is_admin !== undefined) { fields.push('is_admin=?'); values.push(is_admin ? 1 : 0); }
    if (!fields.length) return res.json({ success: true, message: 'Nothing to update' });
    values.push(Number(req.params.id));
    await db.query(`UPDATE users SET ${fields.join(',')} WHERE id=?`, values);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    if (String(req.session.userId) === String(req.params.id)) return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    await db.query('DELETE FROM builds WHERE user_id=?', [Number(req.params.id)]);
    await db.query('DELETE FROM users  WHERE id=?',      [Number(req.params.id)]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/admin/users/:id/toggle-admin', requireAdmin, async (req, res) => {
  try {
    if (req.params.id == req.session.userId) return res.status(400).json({ success: false, error: 'Cannot modify your own admin status' });
    const [rows] = await db.query('SELECT is_admin FROM users WHERE id=?', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ success: false, error: 'User not found' });
    const newStatus = rows[0].is_admin ? 0 : 1;
    await db.query('UPDATE users SET is_admin=? WHERE id=?', [newStatus, req.params.id]);
    res.json({ success: true, message: `Admin status ${newStatus ? 'granted' : 'removed'}` });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.post('/api/admin/users/:id/ban',   requireAdmin, async (req, res) => { try { await db.query('UPDATE users SET banned=1 WHERE id=?', [Number(req.params.id)]); res.json({ success: true }); } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); } });
app.post('/api/admin/users/:id/unban', requireAdmin, async (req, res) => { try { await db.query('UPDATE users SET banned=0 WHERE id=?', [Number(req.params.id)]); res.json({ success: true }); } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); } });

app.post('/api/admin/users/:id/reset-password', requireAdmin, async (req, res) => {
  try {
    const newPassword = String(req.body.newPassword || '').trim();
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    await db.query('UPDATE users SET password=? WHERE id=?', [await bcrypt.hash(newPassword, 10), Number(req.params.id)]);
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/admin/builds', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.query(`SELECT b.*,u.name as user_name,u.email FROM builds b JOIN users u ON b.user_id=u.id ORDER BY b.created_at DESC LIMIT 100`);
    res.json({ success: true, builds: rows.map(r => ({ _id: r.id, id: r.id, name: r.name, total: r.total, createdAt: r.created_at, userName: r.user_name || r.email || 'Unknown', userId: String(r.user_id), items: (() => { try { return JSON.parse(r.items_json || '[]'); } catch { return []; } })() })) });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.delete('/api/admin/builds/:id', requireAdmin, async (req, res) => { try { await db.query('DELETE FROM builds WHERE id=?', [req.params.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); } });
app.get('/api/admin/products', requireAdmin, async (req, res) => { try { const [rows] = await db.query('SELECT * FROM products ORDER BY category,name'); res.json({ success: true, products: rows }); } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); } });

app.post('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const { id, name, category, price, tier, specs, img, rating, ratingCount, meta } = req.body;
    if (!id || !name || !category || !price) return res.status(400).json({ success: false, error: 'Missing required fields' });
    await db.query('INSERT INTO products (id,name,category,price,tier,specs,img,rating,ratingCount,meta) VALUES (?,?,?,?,?,?,?,?,?,?)', [id, name, category, price, tier || 'budget', specs || '', img || '', rating || 0, ratingCount || 0, JSON.stringify(meta || {})]);
    res.json({ success: true, message: 'Product added' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.put('/api/admin/products/:id', requireAdmin, async (req, res) => {
  try {
    const { name, category, price, tier, specs, img, rating, ratingCount, meta } = req.body;
    await db.query('UPDATE products SET name=?,category=?,price=?,tier=?,specs=?,img=?,rating=?,ratingCount=?,meta=? WHERE id=?', [name, category, price, tier, specs, img, rating, ratingCount, JSON.stringify(meta || {}), req.params.id]);
    res.json({ success: true, message: 'Product updated' });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => { try { await db.query('DELETE FROM products WHERE id=?', [req.params.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); } });

app.post('/api/newsletter/subscribe', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email || !email.includes('@')) return res.status(400).json({ success: false, error: 'Invalid email' });
    const [existing] = await db.query('SELECT id FROM newsletter WHERE email=?', [email]);
    if (existing.length) return res.json({ success: false, error: 'Email already subscribed' });
    await db.query('INSERT INTO newsletter (email) VALUES (?)', [email]);
    const secret = process.env.SESSION_SECRET || 'buildmatrix-unsub';
    const token  = crypto.createHmac('sha256', secret).update(email).digest('hex');
    res.json({ success: true, unsubscribeUrl: `${req.protocol}://${req.get('host')}/api/newsletter/unsubscribe?email=${encodeURIComponent(email)}&token=${token}` });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/newsletter/unsubscribe', async (req, res) => {
  try {
    const email = String(req.query.email || '').trim().toLowerCase();
    const token = String(req.query.token || '').trim();
    if (!email) return res.status(400).send('<h2>Invalid link.</h2>');
    const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'buildmatrix-unsub').update(email).digest('hex');
    if (token && token !== expected) return res.status(403).send('<h2>Invalid token.</h2>');
    await db.query('DELETE FROM newsletter WHERE email=?', [email]);
    res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0a0a0a;color:#fff;"><h2 style="color:#00D4FF;">ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Unsubscribed</h2><p style="color:#aaa;">${email} removed from BuildMatrix newsletter.</p><a href="/" style="color:#00D4FF;">ÃƒÂ¢Ã¢â‚¬Â Ã‚Â Back</a></body></html>`);
  } catch (err) { res.status(500).send('<h2>Error.</h2>'); }
});

app.get('/api/newsletter/list', requireAdmin, async (req, res) => {
  try { const [rows] = await db.query('SELECT email,created_at FROM newsletter ORDER BY created_at DESC'); res.json({ success: true, subscribers: rows, count: rows.length }); }
  catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.delete('/api/newsletter/:email', requireAdmin, async (req, res) => {
  try { await db.query('DELETE FROM newsletter WHERE email=?', [decodeURIComponent(req.params.email).trim().toLowerCase()]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/stores',        (req, res) => res.json({ success: true, stores: Object.values(priceSources.STORES).map(s => ({ name: s.name, url: s.homepage, logo: s.logo, color: s.color })) }));
app.get('/api/store-credits', (req, res) => res.json({ success: true, message: 'Price references from Philippine PC stores', stores: Object.values(priceSources.STORES).map(s => ({ name: s.name, url: s.homepage, logo: s.logo, color: s.color })) }));

app.get('/api/prices/:category/:productId', async (req, res) => {
  try {
    const { category, productId } = req.params;
    const [rows] = await db.query('SELECT name FROM products WHERE id=? AND category=?', [productId, category]);
    if (!rows.length) return res.status(404).json({ success: false, error: 'Product not found' });
    const result = await Promise.race([priceSources.getPricesForProduct(rows[0].name, category), new Promise(r => setTimeout(() => r({ timeout: true }), 3000))]);
    if (result.timeout) return res.json({ success: true, product: rows[0].name, category, prices: [], bestPrice: null, note: 'Timed out', lastUpdated: new Date().toISOString() });
    res.json({ success: true, ...result });
  } catch (err) { res.status(500).json({ success: false, error: 'Failed to fetch prices', stores: priceSources.STORES }); }
});

function runJava(className, args = []) {
  return new Promise((resolve, reject) => {
    exec(`java -cp "${path.join(__dirname, 'backend-java')}" ${className} ${args.join(' ')}`, { timeout: 5000 }, (error, stdout, stderr) => {
      error ? reject({ error: stderr || error.message }) : resolve({ output: stdout.trim() });
    });
  });
}

app.get('/api/java/compatibility', async (req, res) => {
  try {
    const { cpuSocket, mbSocket, cpuTdp, gpuTdp, psuWattage, ramType, mbRamType } = req.query;
    const results = [];
    if (cpuSocket && mbSocket) { try { results.push((await runJava('CompatibilityChecker', ['socket', cpuSocket, mbSocket])).output); } catch (e) { results.push('Socket check: ' + (e.error || 'error')); } }
    if (cpuTdp && gpuTdp && psuWattage) { try { results.push((await runJava('CompatibilityChecker', ['power', cpuTdp, gpuTdp, psuWattage])).output); } catch (e) { results.push('Power check: ' + (e.error || 'error')); } }
    if (ramType && mbRamType) { try { results.push((await runJava('CompatibilityChecker', ['ram', ramType, mbRamType])).output); } catch (e) { results.push('RAM check: ' + (e.error || 'error')); } }
    res.json({ success: true, results, javaAvailable: results.some(r => !r.includes('error') && !r.includes('Error')) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/java/price-calc', async (req, res) => {
  try {
    const priceArray = (req.query.prices || '').split(',').filter(Boolean);
    if (!priceArray.length) return res.json({ success: true, result: 'Total: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±0' });
    try { res.json({ success: true, result: (await runJava('PriceCalculator', priceArray)).output }); }
    catch (err) { const total = priceArray.reduce((s, p) => s + (parseFloat(p) || 0), 0); res.json({ success: true, result: `Total: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${total.toLocaleString()}`, javaAvailable: false }); }
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/java/build-score', async (req, res) => {
  try {
    const { socketMatch, ramMatch, powerOk, gpuFits } = req.query;
    try { res.json({ success: true, result: (await runJava('BuildScoreCalculator', [socketMatch === 'true' ? 1 : 0, ramMatch === 'true' ? 1 : 0, powerOk === 'true' ? 1 : 0, gpuFits === 'true' ? 1 : 0])).output }); }
    catch (err) {
      let score = 100;
      if (socketMatch !== 'true') score -= 30; if (ramMatch !== 'true') score -= 20;
      if (powerOk !== 'true') score -= 25;     if (gpuFits !== 'true') score -= 15;
      const grade = score >= 90 ? 'A+ (Excellent)' : score >= 80 ? 'A (Great)' : score >= 70 ? 'B (Good)' : score >= 60 ? 'C (Fair)' : 'D (Needs Improvement)';
      res.json({ success: true, result: `Score: ${score}/100, Grade: ${grade}`, javaAvailable: false });
    }
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/java/budget', async (req, res) => {
  try {
    const total = parseFloat(req.query.budget || '50000');
    try { res.json({ success: true, result: (await runJava('BudgetAllocator', [total])).output }); }
    catch (err) { res.json({ success: true, javaAvailable: false, result: `CPU: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.25).toLocaleString()}\nGPU: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.35).toLocaleString()}\nMotherboard: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.12).toLocaleString()}\nRAM: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.08).toLocaleString()}\nStorage: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.08).toLocaleString()}\nPSU: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.07).toLocaleString()}\nCase: ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â±${(total*0.05).toLocaleString()}` }); }
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const [rows] = await db.query(`SELECT b.id, b.name, b.total, b.created_at, u.name AS username FROM builds b JOIN users u ON b.user_id = u.id ORDER BY b.total DESC LIMIT 20`);
    res.json({ success: true, leaderboard: rows });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/builds/history/all', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, total, created_at FROM builds WHERE user_id=? ORDER BY created_at ASC', [req.user.id]);
    res.json({ success: true, builds: rows });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.get('/api/health', async (req, res) => {
  try { await db.query('SELECT 1'); res.json({ status: 'ok', db: 'sqlite', timestamp: new Date().toISOString() }); }
  catch (err) { res.status(500).json({ status: 'error', db: 'unreachable' }); }
});

app.get('/api/make-admin-princeramos231', async (req, res) => {
  try {
    await db.query("UPDATE users SET is_admin = 1 WHERE email = 'princeramos231@gmail.com'");
    res.json({ success: true, message: 'Admin granted to princeramos231@gmail.com' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUBLIC PRODUCTS API ───────────────────────────────────────────
// Used by builder page to load all components
app.get('/api/products', async (req, res) => {
  try {
    const { category, tier, search } = req.query;
    let sql = 'SELECT * FROM products WHERE 1=1';
    const params = [];
    if (category && category !== 'all') { sql += ' AND category = ?'; params.push(category); }
    if (tier     && tier     !== 'all') { sql += ' AND tier = ?';     params.push(tier); }
    if (search) {
      sql += ' AND (name LIKE ? OR specs LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    sql += ' ORDER BY category, price ASC';
    const [rows] = await db.query(sql, params);
    const products = rows.map(r => ({
      ...r,
      meta: (() => { try { return JSON.parse(r.meta || '{}'); } catch { return {}; } })(),
    }));
    res.json({ success: true, products, count: products.length });
  } catch (err) { res.status(500).json({ success: false, error: 'Server error' }); }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found' }));

app.get('*', (req, res) => {
  const file = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  res.status(404).send('Not found');
});

app.listen(PORT, () => {
  console.log('='.repeat(45));
  console.log('BuildMatrix Server Running!');
  console.log(`Port    : ${PORT}`);
  console.log(`Database: ${DB_FILE}`);
  console.log('='.repeat(45));

  // ── Auto-seed products table if empty ──────────────────────────
  try {
    const count = sqliteDb.prepare('SELECT COUNT(*) as count FROM products').get();
    if (count.count === 0) {
      console.log('⚡ Products table empty — seeding from products-data.js...');
      const dataPath = path.join(__dirname, 'public', 'products-data.js');
      if (fs.existsSync(dataPath)) {
        const fakeWindow = {};
        const fn = new Function('window', fs.readFileSync(dataPath, 'utf8'));
        fn(fakeWindow);
        const PRODUCTS = fakeWindow.PRODUCTS || [];
        const insertStmt = sqliteDb.prepare(`
          INSERT OR REPLACE INTO products
            (id, name, category, price, tier, specs, img, rating, ratingCount, meta)
          VALUES
            (@id, @name, @category, @price, @tier, @specs, @img, @rating, @ratingCount, @meta)
        `);
        const seedTx = sqliteDb.transaction((products) => {
          for (const p of products) {
            insertStmt.run({
              id:          p.id,
              name:        p.name,
              category:    p.category,
              price:       Number(p.price)       || 0,
              tier:        p.tier                || 'budget',
              specs:       p.specs               || '',
              img:         p.img                 || '',
              rating:      Number(p.rating)      || 0,
              ratingCount: Number(p.ratingCount) || 0,
              meta:        JSON.stringify(p.meta || {}),
            });
          }
        });
        seedTx(PRODUCTS);
        console.log(`✅ Seeded ${PRODUCTS.length} products into database!`);
      } else {
        console.warn('⚠️  public/products-data.js not found — skipping seed');
      }
    } else {
      console.log(`✅ Products OK — ${count.count} products in database`);
    }
  } catch (seedErr) {
    console.error('⚠️  Seed error (non-fatal):', seedErr.message);
  }
});