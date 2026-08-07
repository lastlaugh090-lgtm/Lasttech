const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lasttech-secret-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Simple JSON file database
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

function loadDB() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
      const empty = { users: [], deposits: [], withdrawals: [], tasks: [], history: [], messages: [] };
      fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
      return empty;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return { users: [], deposits: [], withdrawals: [], tasks: [], history: [], messages: [] };
  }
}

function saveDB(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Auth helpers
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    const data = jwt.verify(header.split(' ')[1], JWT_SECRET);
    if (data.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
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

    const db = loadDB();
    if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already registered' });

    const id = uuidv4();
    const hash = bcrypt.hashSync(password, 10);
    const myCode = (name.replace(/\s+/g, '').substring(0, 6) + Math.floor(Math.random() * 90 + 10)).toUpperCase();

    let referredBy = null;
    if (referral_code) {
      const ref = db.users.find(u => u.referral_code === referral_code);
      if (ref) referredBy = ref.id;
    }

    const user = {
      id, name, email, phone: phone || '', password: hash,
      plan: 'free', balance: 0, ref_balance: 0,
      bank: bank || '', account_number: account_number || '', account_name: account_name || '',
      referral_code: myCode, referred_by: referredBy, has_deposited: false,
      created_at: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);

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
    const db = loadDB();
    const user = db.users.find(u => u.email === email);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: {
        id: user.id, name: user.name, email: user.email, plan: user.plan,
        balance: user.balance, ref_balance: user.ref_balance, referral_code: user.referral_code,
        bank: user.bank, account_number: user.account_number, account_name: user.account_name
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// ========== USER ==========
app.get('/api/me', auth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id, name: user.name, email: user.email, phone: user.phone,
    plan: user.plan, balance: user.balance, ref_balance: user.ref_balance,
    bank: user.bank, account_number: user.account_number, account_name: user.account_name,
    referral_code: user.referral_code, has_deposited: user.has_deposited
  });
});

// ========== DEPOSITS ==========
app.post('/api/deposits', auth, (req, res) => {
  const { plan, amount } = req.body;
  const db = loadDB();
  const id = uuidv4();
  db.deposits.push({
    id, user_id: req.user.id, plan, amount,
    status: 'pending', created_at: new Date().toISOString()
  });
  db.history.push({
    id: uuidv4(), user_id: req.user.id, type: 'deposit',
    title: plan + ' Plan payment', amount, status: 'pending',
    created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ id, status: 'pending' });
});

// ========== WITHDRAWALS ==========
app.post('/api/withdrawals', auth, (req, res) => {
  const { type, amount } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (type === 'main') {
    if (amount < 500) return res.status(400).json({ error: 'Minimum ₦500' });
    if (amount > user.balance) return res.status(400).json({ error: 'Insufficient balance' });
    const day = new Date().getDate();
    if (!(day >= 30 || day <= 6)) return res.status(400).json({ error: 'Main withdraw only open 30th–6th' });
    user.balance -= amount;
  } else {
    if (amount < 200) return res.status(400).json({ error: 'Minimum ₦200' });
    if (amount > user.ref_balance) return res.status(400).json({ error: 'Insufficient referral balance' });
    if (new Date().getHours() !== 9) return res.status(400).json({ error: 'Referral withdraw only 9AM–10AM' });
    user.ref_balance -= amount;
  }

  const id = uuidv4();
  db.withdrawals.push({
    id, user_id: req.user.id, type, amount,
    bank: user.bank, account_number: user.account_number,
    status: 'pending', created_at: new Date().toISOString()
  });
  db.history.push({
    id: uuidv4(), user_id: req.user.id, type: 'withdrawal',
    title: type + ' withdrawal', amount, status: 'pending',
    created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ id, status: 'pending' });
});

// ========== TASKS ==========
app.post('/api/tasks/complete', auth, (req, res) => {
  const { task_id, reward } = req.body;
  const db = loadDB();
  if (db.tasks.find(t => t.user_id === req.user.id && t.task_id === task_id)) {
    return res.status(400).json({ error: 'Task already completed' });
  }
  db.tasks.push({ id: uuidv4(), user_id: req.user.id, task_id, reward, created_at: new Date().toISOString() });
  const user = db.users.find(u => u.id === req.user.id);
  user.balance += reward;
  db.history.push({
    id: uuidv4(), user_id: req.user.id, type: 'earning',
    title: 'Task #' + task_id, amount: reward, created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ reward, balance: user.balance });
});

app.get('/api/tasks/completed', auth, (req, res) => {
  const db = loadDB();
  res.json(db.tasks.filter(t => t.user_id === req.user.id).map(t => t.task_id));
});

// ========== HISTORY ==========
app.get('/api/history', auth, (req, res) => {
  const db = loadDB();
  res.json(db.history.filter(h => h.user_id === req.user.id).reverse().slice(0, 100));
});

// ========== MESSAGES ==========
app.post('/api/messages', auth, (req, res) => {
  const { subject, message } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  db.messages.push({
    id: uuidv4(), user_id: req.user.id, user_name: user?.name, email: user?.email,
    subject, message, status: 'unread', created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ ok: true });
});

// ========== ADMIN ==========
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const db = loadDB();
  res.json({
    users: db.users.length,
    pendingDeps: db.deposits.filter(d => d.status === 'pending').length,
    pendingWds: db.withdrawals.filter(w => w.status === 'pending').length,
    unread: db.messages.filter(m => m.status === 'unread').length
  });
});

app.get('/api/admin/deposits', adminAuth, (req, res) => {
  const db = loadDB();
  const list = db.deposits.filter(d => d.status === 'pending').map(d => {
    const u = db.users.find(x => x.id === d.user_id);
    return { ...d, user_name: u?.name, email: u?.email };
  });
  res.json(list.reverse());
});

app.post('/api/admin/deposits/:id/approve', adminAuth, (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find(d => d.id === req.params.id);
  if (!dep || dep.status !== 'pending') return res.status(400).json({ error: 'Invalid' });
  dep.status = 'approved';
  const user = db.users.find(u => u.id === dep.user_id);
  if (user) {
    user.plan = dep.plan;
    user.has_deposited = true;
    // Referral bonus
    if (user.referred_by) {
      const ref = db.users.find(u => u.id === user.referred_by);
      if (ref) {
        ref.ref_balance = (ref.ref_balance || 0) + 200;
        db.history.push({
          id: uuidv4(), user_id: ref.id, type: 'earning',
          title: 'Referral bonus', amount: 200, created_at: new Date().toISOString()
        });
      }
    }
  }
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/deposits/:id/reject', adminAuth, (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find(d => d.id === req.params.id);
  if (dep) dep.status = 'rejected';
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', adminAuth, (req, res) => {
  const db = loadDB();
  const list = db.withdrawals.filter(w => w.status === 'pending').map(w => {
    const u = db.users.find(x => x.id === w.user_id);
    return { ...w, user_name: u?.name, email: u?.email };
  });
  res.json(list.reverse());
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, (req, res) => {
  const db = loadDB();
  const w = db.withdrawals.find(x => x.id === req.params.id);
  if (w) w.status = 'approved';
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, (req, res) => {
  const db = loadDB();
  const w = db.withdrawals.find(x => x.id === req.params.id);
  if (w) w.status = 'rejected';
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({
    id: u.id, name: u.name, email: u.email, plan: u.plan,
    balance: u.balance, ref_balance: u.ref_balance,
    has_deposited: u.has_deposited, created_at: u.created_at
  })).reverse());
});

app.get('/api/admin/messages', adminAuth, (req, res) => {
  const db = loadDB();
  res.json(db.messages.slice().reverse().slice(0, 50));
});


// ========== BANK RESOLVE (Paystack) ==========
const BANK_CODES = {
  opay: '999992', kuda: '50211', gtb: '058', access: '044', zenith: '057',
  uba: '033', firstbank: '011', palmpay: '999991', fidelity: '070',
  stanbic: '221', union: '032', wema: '035', eco: '050', polaris: '076', sterling: '232'
};

app.get('/api/resolve-account', async (req, res) => {
  try {
    const { account_number, bank } = req.query;
    if (!account_number || account_number.length !== 10) {
      return res.status(400).json({ error: 'Invalid account number' });
    }
    const bankCode = BANK_CODES[bank] || bank;
    const secret = process.env.PAYSTACK_SECRET_KEY;

    if (secret) {
      // Real Paystack resolution
      const url = `https://api.paystack.co/bank/resolve?account_number=${account_number}&bank_code=${bankCode}`;
      const r = await fetch(url, {
        headers: { Authorization: 'Bearer ' + secret }
      });
      const data = await r.json();
      if (data.status && data.data && data.data.account_name) {
        return res.json({ account_name: data.data.account_name, real: true });
      }
      return res.status(400).json({ error: data.message || 'Could not resolve account' });
    }

    // Demo fallback (no Paystack key) - consistent fake name from account number
    const names = ['CHINEDU OKORO','ADEOLA BALOGUN','FATIMA ABDULLAHI','EMMANUEL NWANKWO','BLESSING ADEYEMI','IBRAHIM MUSA','CHIOMA EZE','OLUWASEUN ADEKUNLE','AMINA BELLO','TUNDE OKAFOR'];
    let h = 0;
    for (let i = 0; i < account_number.length; i++) h = (h + account_number.charCodeAt(i) * (i + 1)) % names.length;
    res.json({ account_name: names[h], real: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Resolve failed' });
  }
});


app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('*', (req, res) => {
  const index = path.join(__dirname, 'index.html');
  if (require('fs').existsSync(index)) {
    res.sendFile(index);
  } else {
    res.json({ message: 'Last Tech API is running', health: '/api/health' });
  }
});

app.listen(PORT, () => {
  console.log('Last Tech API running on port ' + PORT);
});
