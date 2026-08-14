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
  date: { type: String, required: true }, // YYYY-MM-DD for daily reset at midnight
  created_at: { type: Date, default: Date.now }
});
taskSchema.index({ user_id: 1, task_id: 1, date: 1 }, { unique: true });

function todayDateStr() {
  // Africa/Lagos (WAT, UTC+1) — tasks refresh at 12:00 AM local
  try {
    return new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Lagos' }); // YYYY-MM-DD
  } catch {
    const d = new Date(Date.now() + 60 * 60 * 1000);
    return d.toISOString().slice(0, 10);
  }
}

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
const PLAN_RANK = { free: 0, beginner: 1, pro: 2, master: 3 };

app.post('/api/deposits', auth, async (req, res) => {
  const { plan, amount } = req.body;
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const curRank = PLAN_RANK[user.plan] ?? 0;
  const newRank = PLAN_RANK[plan] ?? -1;
  if (newRank <= curRank) {
    return res.status(400).json({ error: 'You can only upgrade to a higher plan than your current one' });
  }
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

// ========== TASKS (daily reset at 12:00 AM WAT) ==========
app.post('/api/tasks/complete', auth, async (req, res) => {
  try {
    const { task_id, reward } = req.body;
    if (task_id == null || reward == null) {
      return res.status(400).json({ error: 'Missing task or reward' });
    }

    const date = todayDateStr();
    const exists = await TaskDone.findOne({ user_id: req.user.id, task_id: Number(task_id), date });
    if (exists) {
      return res.status(400).json({ error: 'Task already completed today' });
    }

    try {
      await TaskDone.create({
        id: uuidv4(),
        user_id: req.user.id,
        task_id: Number(task_id),
        reward: Number(reward),
        date
      });
    } catch (createErr) {
      // Handle old unique index or duplicate key
      if (createErr.code === 11000) {
        return res.status(400).json({ error: 'Task already completed today' });
      }
      throw createErr;
    }

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.balance = (user.balance || 0) + Number(reward);
    await user.save();

    await History.create({
      id: uuidv4(),
      user_id: req.user.id,
      type: 'earning',
      title: 'Task #' + task_id,
      amount: Number(reward)
    });

    res.json({ reward: Number(reward), balance: user.balance });
  } catch (e) {
    console.error('Task complete error:', e.message);
    res.status(500).json({ error: 'Could not complete task. Please try again.' });
  }
});

app.get('/api/tasks/completed', auth, async (req, res) => {
  const date = todayDateStr();
  const rows = await TaskDone.find({ user_id: req.user.id, date });
  res.json(rows.map(r => r.task_id));
});

// ========== REFERRALS ==========
app.get('/api/referrals', auth, async (req, res) => {
  const refs = await User.find({ referred_by: req.user.id })
    .select('name email plan has_deposited created_at')
    .sort({ created_at: -1 });
  res.json(refs.map(u => ({
    name: u.name,
    email: u.email,
    plan: u.plan || 'free',
    has_deposited: !!u.has_deposited,
    created_at: u.created_at
  })));
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

app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>LastTech – Privacy Policy</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:720px;margin:0 auto;padding:24px 16px;line-height:1.6;color:#1a1a2e;background:#f5f6fa}
    h1{font-size:24px;margin-bottom:8px}
    h2{font-size:17px;margin-top:28px;margin-bottom:8px;color:#e11d48}
    p,li{font-size:15px;color:#374151}
    ul{padding-left:20px}
    a{color:#e11d48}
    .back{display:inline-block;margin-bottom:20px;color:#e11d48;font-weight:600;text-decoration:none}
  </style>
</head>
<body>
  <a class="back" href="/">← Back to LastTech</a>
  <h1>LastTech Privacy Policy</h1>
  <p><strong>Last updated:</strong> August 14, 2026</p>

  <h2>1. Information We Collect</h2>
  <p>When you use LastTech, we may collect:</p>
  <ul>
    <li>Name, email address, and phone number</li>
    <li>Bank account details (for withdrawals)</li>
    <li>Referral information</li>
    <li>Task completion and transaction history</li>
    <li>Device and usage information</li>
  </ul>

  <h2>2. How We Use Your Information</h2>
  <p>We use your information to:</p>
  <ul>
    <li>Create and manage your account</li>
    <li>Process deposits and withdrawals</li>
    <li>Track tasks and earnings</li>
    <li>Manage the referral system</li>
    <li>Provide customer support</li>
    <li>Improve our services</li>
  </ul>

  <h2>3. Sharing of Information</h2>
  <p>We do <strong>not</strong> sell your personal information. We only share data when necessary with payment providers, administrators, or if required by law.</p>

  <h2>4. Data Security</h2>
  <p>We take reasonable steps to protect your information. However, no method of transmission over the internet is 100% secure.</p>

  <h2>5. Bank Details</h2>
  <p>Your bank account information is used only for processing withdrawals. We do not store full sensitive banking credentials beyond what is needed for payouts.</p>

  <h2>6. Your Rights</h2>
  <p>You may request to view, correct, or delete your information (subject to pending transactions).</p>

  <h2>7. Contact Us</h2>
  <p>
    Email: <a href="mailto:support@lasttech.com.ng">support@lasttech.com.ng</a><br/>
    Support Bot: <a href="https://t.me/LastTechNigeriaBot">@LastTechNigeriaBot</a><br/>
    Channel: <a href="https://t.me/LASTTECHNIGERIA">@LASTTECHNIGERIA</a>
  </p>
</body>
</html>`);
});

app.get('*', (req, res) => {
  const index = path.join(__dirname, 'index.html');
  if (fs.existsSync(index)) res.sendFile(index);
  else res.json({ message: 'Last Tech API is running', health: '/api/health' });
});

// ========== TELEGRAM BOT ==========
function startTelegramBot() {
  const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  if (!TELEGRAM_BOT_TOKEN) {
    console.log('TELEGRAM_BOT_TOKEN not set – Telegram bot disabled');
    return;
  }

  let TelegramBot;
  try {
    TelegramBot = require('node-telegram-bot-api');
  } catch (e) {
    console.error('node-telegram-bot-api not installed');
    return;
  }

  const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

  bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const name = msg.from.first_name || 'there';

    bot.sendMessage(chatId,
`👋 Hello ${name}!

Welcome to *LastTech Support Bot*.

I can help you with:
• How to deposit
• How to withdraw
• Tasks & daily reset
• Referral system
• Contact support

Choose an option below:`, {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: '💰 How to Deposit', callback_data: 'deposit' }],
          [{ text: '💸 How to Withdraw', callback_data: 'withdraw' }],
          [{ text: '✅ Tasks Info', callback_data: 'tasks' }],
          [{ text: '👥 Referrals', callback_data: 'referral' }],
          [{ text: '📞 Contact Support', callback_data: 'support' }],
          [{ text: '🌐 Open LastTech Website', url: 'https://lasttech.onrender.com' }]
        ]
      }
    }).catch(err => console.log('TG send error:', err.message));
  });

  bot.on('callback_query', (query) => {
    const chatId = query.message.chat.id;
    const data = query.data;
    let text = '';

    if (data === 'deposit') {
      text = `💰 *How to Deposit / Upgrade Plan*\n\n1. Open the LastTech app\n2. Go to *Plans*\n3. Choose a higher plan than your current one\n4. Transfer the exact amount to the account shown\n5. Tap *I have paid*\n6. Wait for admin approval\n\nYou can only upgrade to a *higher* plan.`;
    } else if (data === 'withdraw') {
      text = `💸 *Withdrawal Rules*\n\n*Main Balance:*\n• Minimum ₦500\n• Only open from 30th – 6th of every month\n\n*Referral Balance:*\n• Minimum ₦200\n• Only open 9AM – 10AM daily\n\nMake sure your bank details are correct in the app.`;
    } else if (data === 'tasks') {
      text = `✅ *Tasks Info*\n\n• Tasks refresh every day at *12:00 AM*\n• You can complete the same tasks again every day\n• Higher plans earn more per task\n• Always leave genuine reviews`;
    } else if (data === 'referral') {
      text = `👥 *Referral System*\n\n• Share your invite link\n• When your friend signs up *and deposits*, you earn ₦200\n• You can see your referrals and their progress inside the app (Invite page)`;
    } else if (data === 'support') {
      text = `📞 *Contact Support*\n\n• Support Bot: https://t.me/LastTechNigeriaBot\n• Channel: https://t.me/LASTTECHNIGERIA\n• Email: support@lasttech.com.ng\n\nOr just type your question here and an admin will reply as soon as possible.`;
    }

    bot.answerCallbackQuery(query.id).catch(() => {});
    if (text) {
      bot.sendMessage(chatId, text, { parse_mode: 'Markdown' }).catch(err => console.log('TG send error:', err.message));
    }
  });

  bot.on('message', (msg) => {
    if (msg.text && !msg.text.startsWith('/')) {
      bot.sendMessage(msg.chat.id,
`Thanks for your message. An admin will reply soon.

Meanwhile you can use the menu:
/start`).catch(() => {});
    }
  });

  bot.on('polling_error', (err) => {
    console.log('Telegram polling error:', err.message);
  });

  console.log('LastTech Telegram Support Bot started');
}

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
    app.listen(PORT, () => {
      console.log('Last Tech API on port ' + PORT);
      startTelegramBot();
    });
  } catch (e) {
    console.error('MongoDB connection failed:', e.message);
    process.exit(1);
  }
}

start();
