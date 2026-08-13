const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lasttech-secret-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const MONGODB_URI = process.env.MONGODB_URI || '';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ========== SCHEMAS ==========
const userSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4(), unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, default: '' },
  password: { type: String, required: true },
  plan: { type: String, default: 'free' },
  balance: { type: Number, default: 0 },
  ref_balance: { type: Number, default: 0 },
  bank: { type: String, default: '' },
  account_number: { type: String, default: '' },
  account_name: { type: String, default: '' },
  referral_code: { type: String, unique: true, sparse: true },
  referred_by: { type: String, default: null },
  has_deposited: { type: Boolean, default: false },
  reset_code: { type: String, default: null },
  reset_expires: { type: Number, default: null },
  created_at: { type: Date, default: Date.now }
});

const depositSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4(), unique: true },
  user_id: { type: String, required: true, index: true },
  plan: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { type: String, default: 'pending' },
  created_at: { type: Date, default: Date.now }
});

const withdrawalSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4(), unique: true },
  user_id: { type: String, required: true, index: true },
  type: { type: String, required: true },
  amount: { type: Number, required: true },
  bank: { type: String, default: '' },
  account_number: { type: String, default: '' },
  status: { type: String, default: 'pending' },
  created_at: { type: Date, default: Date.now }
});

const taskSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  user_id: { type: String, required: true, index: true },
  task_id: { type: Number, required: true },
  reward: { type: Number, required: true },
  created_at: { type: Date, default: Date.now }
});
taskSchema.index({ user_id: 1, task_id: 1 }, { unique: true });

const historySchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  user_id: { type: String, required: true, index: true },
  type: { type: String, required: true },
  title: { type: String, default: '' },
  amount: { type: Number, default: 0 },
  status: { type: String, default: null },
  created_at: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  user_id: { type: String },
  user_name: { type: String },
  email: { type: String },
  subject: { type: String },
  message: { type: String },
  status: { type: String, default: 'unread' },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const TaskDone = mongoose.model('TaskDone', taskSchema);
const History = mongoose.model('History', historySchema);
const Message = mongoose.model('Message', messageSchema);

// ========== AUTH HELPERS ==========
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
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password, bank, account_number, account_name, referral_code } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    if (await User.findOne({ email: email.toLowerCase() })) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    if (account_number && await User.findOne({ account_number })) {
      return res.status(400).json({ error: 'This bank account is already linked to another Last Tech account' });
    }

    const myCode = (name.replace(/\s+/g, '').substring(0, 6) + Math.floor(Math.random() * 90 + 10)).toUpperCase();
    let referredBy = null;
    if (referral_code) {
      const ref = await User.findOne({ referral_code });
      if (ref) referredBy = ref.id;
    }

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      phone: phone || '',
      password: bcrypt.hashSync(password, 10),
      bank: bank || '',
      account_number: account_number || '',
      account_name: account_name || '',
      referral_code: myCode,
      referred_by: referredBy
    });

    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '90d' });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, plan: 'free', balance: 0, ref_balance: 0, referral_code: myCode }
    });
  } catch (e) {
    console.error(e);
    if (e.code === 11000) return res.status(400).json({ error: 'Email or bank account already registered' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: (email || '').toLowerCase() });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '90d' });
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
app.get('/api/me', auth, async (req, res) => {
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id, name: user.name, email: user.email, phone: user.phone,
    plan: user.plan, balance: user.balance, ref_balance: user.ref_balance,
    bank: user.bank, account_number: user.account_number, account_name: user.account_name,
    referral_code: user.referral_code, has_deposited: user.has_deposited
  });
});

// ========== DEPOSITS ==========
app.post('/api/deposits', auth, async (req, res) => {
  const { plan, amount } = req.body;
  const id = uuidv4();
  await Deposit.create({ id, user_id: req.user.id, plan, amount, status: 'pending' });
  await History.create({ id: uuidv4(), user_id: req.user.id, type: 'deposit', title: plan + ' Plan payment', amount, status: 'pending' });
  res.json({ id, status: 'pending' });
});

// ========== WITHDRAWALS ==========
app.post('/api/withdrawals', auth, async (req, res) => {
  const { type, amount } = req.body;
  const user = await User.findOne({ id: req.user.id });
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
  await user.save();

  const id = uuidv4();
  await Withdrawal.create({
    id, user_id: req.user.id, type, amount,
    bank: user.bank, account_number: user.account_number, status: 'pending'
  });
  await History.create({
    id: uuidv4(), user_id: req.user.id, type: 'withdrawal',
    title: type + ' withdrawal', amount, status: 'pending'
  });
  res.json({ id, status: 'pending' });
});

// ========== TASKS ==========
app.post('/api/tasks/complete', auth, async (req, res) => {
  const { task_id, reward } = req.body;
  const exists = await TaskDone.findOne({ user_id: req.user.id, task_id });
  if (exists) return res.status(400).json({ error: 'Task already completed' });

  await TaskDone.create({ id: uuidv4(), user_id: req.user.id, task_id, reward });
  const user = await User.findOne({ id: req.user.id });
  user.balance += reward;
  await user.save();
  await History.create({ id: uuidv4(), user_id: req.user.id, type: 'earning', title: 'Task #' + task_id, amount: reward });
  res.json({ reward, balance: user.balance });
});

app.get('/api/tasks/completed', auth, async (req, res) => {
  const rows = await TaskDone.find({ user_id: req.user.id });
  res.json(rows.map(r => r.task_id));
});

// ========== HISTORY ==========
app.get('/api/history', auth, async (req, res) => {
  const rows = await History.find({ user_id: req.user.id }).sort({ created_at: -1 }).limit(100);
  res.json(rows);
});

// ========== MESSAGES ==========
app.post('/api/messages', auth, async (req, res) => {
  const { subject, message } = req.body;
  const user = await User.findOne({ id: req.user.id });
  await Message.create({
    id: uuidv4(), user_id: req.user.id, user_name: user?.name, email: user?.email,
    subject, message, status: 'unread'
  });
  res.json({ ok: true });
});

// ========== PASSWORD RECOVERY ==========
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({ ok: true, message: 'If that email is registered, a recovery code was sent.' });
    }
    const code = String(Math.floor(100000 + Math.random() * 900000));
    user.reset_code = code;
    user.reset_expires = Date.now() + 30 * 60 * 1000;
    await user.save();

    const resendKey = process.env.RESEND_API_KEY;
    const fromEmail = process.env.FROM_EMAIL || 'onboarding@resend.dev';
    if (resendKey) {
      fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + resendKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: fromEmail,
          to: [email],
          subject: 'Last Tech – Password Recovery Code',
          html: `<p>Hi ${user.name || 'there'},</p><p>Your recovery code is:</p><h2 style="letter-spacing:4px">${code}</h2><p>Expires in 30 minutes.</p><p>— Team LastTech</p>`
        })
      }).catch(err => console.log('Email failed:', err.message));
    } else {
      console.log('[PASSWORD RESET]', email, 'code:', code);
    }

    res.json({
      ok: true,
      message: 'If that email is registered, a recovery code was sent.',
      ...(resendKey ? {} : { dev_hint: 'Email not configured. Check server logs for the code.' })
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, password } = req.body;
    if (!email || !code || !password) return res.status(400).json({ error: 'Email, code and new password required' });
    if (password.length < 4) return res.status(400).json({ error: 'Password too short' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.reset_code || user.reset_code !== String(code).trim()) {
      return res.status(400).json({ error: 'Invalid or expired recovery code' });
    }
    if (!user.reset_expires || Date.now() > user.reset_expires) {
      return res.status(400).json({ error: 'Recovery code has expired. Request a new one.' });
    }
    user.password = bcrypt.hashSync(password, 10);
    user.reset_code = null;
    user.reset_expires = null;
    await user.save();
    res.json({ ok: true, message: 'Password updated. You can sign in now.' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ========== ADMIN ==========
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const users = await User.countDocuments();
  const pendingDeps = await Deposit.countDocuments({ status: 'pending' });
  const pendingWds = await Withdrawal.countDocuments({ status: 'pending' });
  const unread = await Message.countDocuments({ status: 'unread' });
  res.json({ users, pendingDeps, pendingWds, unread });
});

app.get('/api/admin/deposits', adminAuth, async (req, res) => {
  const list = await Deposit.find({ status: 'pending' }).sort({ created_at: -1 });
  const out = [];
  for (const d of list) {
    const u = await User.findOne({ id: d.user_id });
    out.push({ ...d.toObject(), user_name: u?.name, email: u?.email });
  }
  res.json(out);
});

app.post('/api/admin/deposits/:id/approve', adminAuth, async (req, res) => {
  const dep = await Deposit.findOne({ id: req.params.id });
  if (!dep || dep.status !== 'pending') return res.status(400).json({ error: 'Invalid' });
  dep.status = 'approved';
  await dep.save();
  const user = await User.findOne({ id: dep.user_id });
  if (user) {
    user.plan = dep.plan;
    user.has_deposited = true;
    await user.save();
    if (user.referred_by) {
      const ref = await User.findOne({ id: user.referred_by });
      if (ref) {
        ref.ref_balance = (ref.ref_balance || 0) + 200;
        await ref.save();
        await History.create({ id: uuidv4(), user_id: ref.id, type: 'earning', title: 'Referral bonus', amount: 200 });
      }
    }
  }
  res.json({ ok: true });
});

app.post('/api/admin/deposits/:id/reject', adminAuth, async (req, res) => {
  await Deposit.updateOne({ id: req.params.id }, { status: 'rejected' });
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  const list = await Withdrawal.find({ status: 'pending' }).sort({ created_at: -1 });
  const out = [];
  for (const w of list) {
    const u = await User.findOne({ id: w.user_id });
    out.push({ ...w.toObject(), user_name: u?.name, email: u?.email });
  }
  res.json(out);
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  await Withdrawal.updateOne({ id: req.params.id }, { status: 'approved' });
  res.json({ ok: true });
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, async (req, res) => {
  await Withdrawal.updateOne({ id: req.params.id }, { status: 'rejected' });
  res.json({ ok: true });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await User.find().sort({ created_at: -1 }).select('-password -reset_code');
  res.json(users.map(u => ({
    id: u.id, name: u.name, email: u.email, plan: u.plan,
    balance: u.balance, ref_balance: u.ref_balance,
    has_deposited: u.has_deposited, created_at: u.created_at
  })));
});

app.get('/api/admin/messages', adminAuth, async (req, res) => {
  const rows = await Message.find().sort({ created_at: -1 }).limit(50);
  res.json(rows);
});

// ========== BANK RESOLVE ==========
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

    function demoName(acc) {
      const names = ['CHINEDU OKORO','ADEOLA BALOGUN','FATIMA ABDULLAHI','EMMANUEL NWANKWO','BLESSING ADEYEMI','IBRAHIM MUSA','CHIOMA EZE','OLUWASEUN ADEKUNLE','AMINA BELLO','TUNDE OKAFOR'];
      let h = 0;
      for (let i = 0; i < acc.length; i++) h = (h + acc.charCodeAt(i) * (i + 1)) % names.length;
      return names[h];
    }

    if (secret && secret.startsWith('sk_')) {
      try {
        const url = `https://api.paystack.co/bank/resolve?account_number=${account_number}&bank_code=${bankCode}`;
        const r = await fetch(url, { headers: { Authorization: 'Bearer ' + secret } });
        const data = await r.json();
        if (data.status && data.data && data.data.account_name) {
          return res.json({ account_name: data.data.account_name, real: true });
        }
      } catch (err) {
        console.log('Paystack error:', err.message);
      }
    }
    res.json({ account_name: demoName(account_number), real: false });
  } catch (e) {
    res.status(500).json({ error: 'Resolve failed' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    time: new Date().toISOString()
  });
});

app.get('*', (req, res) => {
  const index = path.join(__dirname, 'index.html');
  if (fs.existsSync(index)) res.sendFile(index);
  else res.json({ message: 'Last Tech API is running', health: '/api/health' });
});

// ========== START ==========
async function start() {
  if (!MONGODB_URI) {
    console.error('ERROR: MONGODB_URI environment variable is not set.');
    console.error('Create a free cluster at https://cloud.mongodb.com and set MONGODB_URI on Render.');
    process.exit(1);
  }
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('MongoDB connected');
    app.listen(PORT, () => console.log('Last Tech API on port ' + PORT));
  } catch (e) {
    console.error('MongoDB connection failed:', e.message);
    process.exit(1);
  }
}

start();
