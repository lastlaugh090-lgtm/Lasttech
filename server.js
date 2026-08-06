require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lasttech-secret-change-me-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Database
const dbPath = path.join(__dirname, 'data', 'lasttech.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    balance REAL DEFAULT 0,
    ref_balance REAL DEFAULT 0,
    bank TEXT,
    account_number TEXT,
    account_name TEXT,
    referral_code TEXT UNIQUE,
    referred_by TEXT,
    has_deposited INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS deposits (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    plan TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    bank TEXT,
    account_number TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS tasks_completed (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    task_id INTEGER NOT NULL,
    reward REAL NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, task_id)
  );

  CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT,
    amount REAL,
    status TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    user_name TEXT,
    email TEXT,
    subject TEXT,
    message TEXT,
    status TEXT DEFAULT 'unread',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    const token = header.split(' ')[1];
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = data;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== AUTH ==========
app.post('/api/register', (req, res) => {
  try {
    const { name, email, phone, password, bank, account_number, account_name, referral_code } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const id = uuidv4();
    const hash = bcrypt.hashSync(password, 10);
    const myCode = name.replace(/\s+/g, '').substring(0, 6).toUpperCase() + Math.floor(Math.random() * 90 + 10);

    let referredBy = null;
    if (referral_code) {
      const ref = db.prepare('SELECT id FROM users WHERE referral_code = ?').get(referral_code);
      if (ref) referredBy = ref.id;
    }

    db.prepare(`
      INSERT INTO users (id, name, email, phone, password, bank, account_number, account_name, referral_code, referred_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, name, email, phone || '', hash, bank || '', account_number || '', account_name || '', myCode, referredBy);

    const token = jwt.sign({ id, email, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: { id, name, email, plan: 'free', balance: 0, ref_balance: 0, referral_code: myCode }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan,
        balance: user.balance,
        ref_balance: user.ref_balance,
        referral_code: user.referral_code,
        bank: user.bank,
        account_number: user.account_number,
        account_name: user.account_name
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// ========== USER ==========
app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, phone, plan, balance, ref_balance, bank, account_number, account_name, referral_code, has_deposited FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ========== DEPOSITS ==========
app.post('/api/deposits', auth, (req, res) => {
  const { plan, amount } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO deposits (id, user_id, plan, amount) VALUES (?, ?, ?, ?)').run(id, req.user.id, plan, amount);
  db.prepare('INSERT INTO history (id, user_id, type, title, amount, status) VALUES (?, ?, ?, ?, ?, ?)').run(
    uuidv4(), req.user.id, 'deposit', plan + ' Plan payment', amount, 'pending'
  );
  res.json({ id, status: 'pending' });
});

// ========== WITHDRAWALS ==========
app.post('/api/withdrawals', auth, (req, res) => {
  const { type, amount } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  if (type === 'main') {
    if (amount < 500) return res.status(400).json({ error: 'Minimum ₦500' });
    if (amount > user.balance) return res.status(400).json({ error: 'Insufficient balance' });
    // Check date window (30th-6th)
    const day = new Date().getDate();
    if (!(day >= 30 || day <= 6)) return res.status(400).json({ error: 'Main withdraw only open 30th–6th' });
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, req.user.id);
  } else {
    if (amount < 200) return res.status(400).json({ error: 'Minimum ₦200' });
    if (amount > user.ref_balance) return res.status(400).json({ error: 'Insufficient referral balance' });
    const hour = new Date().getHours();
    if (hour !== 9) return res.status(400).json({ error: 'Referral withdraw only 9AM–10AM' });
    db.prepare('UPDATE users SET ref_balance = ref_balance - ? WHERE id = ?').run(amount, req.user.id);
  }

  const id = uuidv4();
  db.prepare('INSERT INTO withdrawals (id, user_id, type, amount, bank, account_number) VALUES (?, ?, ?, ?, ?, ?)').run(
    id, req.user.id, type, amount, user.bank, user.account_number
  );
  db.prepare('INSERT INTO history (id, user_id, type, title, amount, status) VALUES (?, ?, ?, ?, ?, ?)').run(
    uuidv4(), req.user.id, 'withdrawal', type + ' withdrawal', amount, 'pending'
  );
  res.json({ id, status: 'pending' });
});

// ========== TASKS ==========
app.post('/api/tasks/complete', auth, (req, res) => {
  const { task_id, reward } = req.body;
  const existing = db.prepare('SELECT id FROM tasks_completed WHERE user_id = ? AND task_id = ?').get(req.user.id, task_id);
  if (existing) return res.status(400).json({ error: 'Task already completed' });

  db.prepare('INSERT INTO tasks_completed (id, user_id, task_id, reward) VALUES (?, ?, ?, ?)').run(uuidv4(), req.user.id, task_id, reward);
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(reward, req.user.id);
  db.prepare('INSERT INTO history (id, user_id, type, title, amount) VALUES (?, ?, ?, ?, ?)').run(
    uuidv4(), req.user.id, 'earning', 'Task #' + task_id, reward
  );

  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  res.json({ reward, balance: user.balance });
});

app.get('/api/tasks/completed', auth, (req, res) => {
  const rows = db.prepare('SELECT task_id FROM tasks_completed WHERE user_id = ?').all(req.user.id);
  res.json(rows.map(r => r.task_id));
});

// ========== HISTORY ==========
app.get('/api/history', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
  res.json(rows);
});

// ========== MESSAGES ==========
app.post('/api/messages', auth, (req, res) => {
  const { subject, message } = req.body;
  const user = db.prepare('SELECT name, email FROM users WHERE id = ?').get(req.user.id);
  db.prepare('INSERT INTO messages (id, user_id, user_name, email, subject, message) VALUES (?, ?, ?, ?, ?, ?)').run(
    uuidv4(), req.user.id, user.name, user.email, subject, message
  );
  res.json({ ok: true });
});

// ========== ADMIN ==========
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const pendingDeps = db.prepare("SELECT COUNT(*) as c FROM deposits WHERE status = 'pending'").get().c;
  const pendingWds = db.prepare("SELECT COUNT(*) as c FROM withdrawals WHERE status = 'pending'").get().c;
  const unread = db.prepare("SELECT COUNT(*) as c FROM messages WHERE status = 'unread'").get().c;
  res.json({ users, pendingDeps, pendingWds, unread });
});

app.get('/api/admin/deposits', adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT d.*, u.name as user_name, u.email 
    FROM deposits d JOIN users u ON d.user_id = u.id 
    WHERE d.status = 'pending' ORDER BY d.created_at DESC
  `).all();
  res.json(rows);
});

app.post('/api/admin/deposits/:id/approve', adminAuth, (req, res) => {
  const dep = db.prepare('SELECT * FROM deposits WHERE id = ?').get(req.params.id);
  if (!dep || dep.status !== 'pending') return res.status(400).json({ error: 'Invalid deposit' });

  db.prepare("UPDATE deposits SET status = 'approved' WHERE id = ?").run(dep.id);
  db.prepare("UPDATE users SET plan = ?, has_deposited = 1 WHERE id = ?").run(dep.plan, dep.user_id);
  db.prepare("UPDATE history SET status = 'approved' WHERE user_id = ? AND type = 'deposit' AND status = 'pending' AND amount = ?").run(dep.user_id, dep.amount);

  // Referral reward
  const user = db.prepare('SELECT referred_by FROM users WHERE id = ?').get(dep.user_id);
  if (user && user.referred_by) {
    db.prepare('UPDATE users SET ref_balance = ref_balance + 200 WHERE id = ?').run(user.referred_by);
    db.prepare('INSERT INTO history (id, user_id, type, title, amount) VALUES (?, ?, ?, ?, ?)').run(
      uuidv4(), user.referred_by, 'earning', 'Referral bonus', 200
    );
  }

  res.json({ ok: true });
});

app.post('/api/admin/deposits/:id/reject', adminAuth, (req, res) => {
  db.prepare("UPDATE deposits SET status = 'rejected' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT w.*, u.name as user_name, u.email 
    FROM withdrawals w JOIN users u ON w.user_id = u.id 
    WHERE w.status = 'pending' ORDER BY w.created_at DESC
  `).all();
  res.json(rows);
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, (req, res) => {
  db.prepare("UPDATE withdrawals SET status = 'approved' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, (req, res) => {
  // Refund could be added here
  db.prepare("UPDATE withdrawals SET status = 'rejected' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT id, name, email, plan, balance, ref_balance, has_deposited, created_at FROM users ORDER BY created_at DESC').all();
  res.json(rows);
});

app.get('/api/admin/messages', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM messages ORDER BY created_at DESC LIMIT 50').all();
  res.json(rows);
});

// Health
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Serve frontend
app.get('*', (req, res) => {
  const index = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(index)) res.sendFile(index);
  else res.json({ message: 'Last Tech API is running. Put frontend in /public folder.' });
});

app.listen(PORT, () => {
  console.log(`Last Tech API running on http://localhost:${PORT}`);
});
