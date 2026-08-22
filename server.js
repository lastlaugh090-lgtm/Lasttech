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
  day_key: { type: String, required: true, index: true },
  completion_key: { type: String, required: true, unique: true },
  reward: { type: Number, required: true },
  created_at: { type: Date, default: Date.now }
}, { collection: 'task_completions' });

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
const TaskDone = mongoose.model('TaskCompletion', taskSchema);
const History = mongoose.model('History', historySchema);
const Message = mongoose.model('Message', messageSchema);

const sponsoredSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4(), unique: true },
  owner_id: { type: String, required: true, index: true },
  owner_name: { type: String, default: '' },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  link: { type: String, default: '' },
  icon: { type: String, default: '📋' },
  completions_wanted: { type: Number, required: true },
  completions_done: { type: Number, default: 0 },
  views_wanted: { type: Number, default: 0 },
  price_per: { type: Number, default: 300 },
  total_paid: { type: Number, default: 0 },
  pay_method: { type: String, default: 'transfer' }, // balance | transfer
  status: { type: String, default: 'pending' }, // pending | active | paused | done | rejected
  created_at: { type: Date, default: Date.now }
});
const SponsoredTask = mongoose.model('SponsoredTask', sponsoredSchema);

const submissionSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4(), unique: true },
  sponsored_id: { type: String, required: true, index: true },
  worker_id: { type: String, required: true, index: true },
  worker_name: { type: String, default: '' },
  screenshot: { type: String, required: true }, // data URL or https image
  note: { type: String, default: '' },
  reward: { type: Number, default: 0 },
  status: { type: String, default: 'pending' }, // pending | approved | rejected
  created_at: { type: Date, default: Date.now },
  reviewed_at: { type: Date, default: null }
});
submissionSchema.index({ sponsored_id: 1, worker_id: 1 }, { unique: true });
const TaskSubmission = mongoose.model('TaskSubmission', submissionSchema);

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

    const myCode = (String(name).replace(/\s+/g, '').substring(0, 6) + Math.floor(Math.random() * 90 + 10)).toUpperCase();
    let referredBy = null;
    if (referral_code) {
      const code = String(referral_code).trim().toUpperCase();
      const ref = await User.findOne({
        $expr: { $eq: [{ $toUpper: '$referral_code' }, code] }
      });
      // fallback exact
      const ref2 = ref || await User.findOne({ referral_code: code }) || await User.findOne({ referral_code: String(referral_code).trim() });
      if (ref2) referredBy = ref2.id;
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
  try {
    const { plan, amount } = req.body;
    if (!plan || !amount) return res.status(400).json({ error: 'Plan and amount required' });
    const id = uuidv4();
    await Deposit.create({ id, user_id: req.user.id, plan, amount, status: 'pending' });
    await History.create({
      id: uuidv4(), user_id: req.user.id, type: 'deposit',
      title: plan + ' Plan payment', amount, status: 'pending'
    });
    res.json({ id, status: 'pending' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not create deposit' });
  }
});

// ========== WITHDRAWALS ==========
app.post('/api/withdrawals', auth, async (req, res) => {
  const { type, amount } = req.body;
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (type === 'main') {
    const mainMins = { free: 10000, beginner: 10000, pro: 50000, master: 150000 };
    const mainMaxs = { free: 20000, beginner: 20000, pro: 100000, master: 300000 };
    const minMain = mainMins[user.plan] || 10000;
    const maxMain = mainMaxs[user.plan] || 20000;
    if (amount < minMain) {
      return res.status(400).json({
        error: 'Minimum main withdraw for ' + (user.plan || 'your') + ' plan is ₦' + minMain.toLocaleString()
      });
    }
    if (amount > maxMain) {
      return res.status(400).json({
        error: 'Maximum main withdraw for ' + (user.plan || 'your') + ' plan is ₦' + maxMain.toLocaleString()
      });
    }
    if (amount > user.balance) return res.status(400).json({ error: 'Insufficient balance' });
    const day = new Date().getDate();
    if (!(day >= 30 || day <= 6)) return res.status(400).json({ error: 'Main withdraw only open 30th–6th' });
    user.balance -= amount;
  } else {
    if (type === 'referral' && amount < 500) return res.status(400).json({ error: 'Minimum referral withdraw is ₦500' });
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
function todayKey() {
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Africa/Lagos',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).format(new Date());
  } catch (e) {
    return new Date(Date.now() + 3600000).toISOString().slice(0, 10);
  }
}

app.post('/api/tasks/complete', auth, async (req, res) => {
  try {
    const task_id = Number(req.body.task_id);
    let reward = Number(req.body.reward);
    if (!task_id || Number.isNaN(task_id)) {
      return res.status(400).json({ error: 'Invalid task' });
    }
    if (Number.isNaN(reward) || reward < 0) reward = 0;

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Cap by plan
    const planCaps = { free: 30, beginner: 100, pro: 500, master: 1500 };
    const planMins = { free: 10, beginner: 80, pro: 400, master: 1200 };
    const cap = planCaps[user.plan] || 50;
    const floor = planMins[user.plan] || 0;
    if (reward > cap) reward = cap;
    if (reward < floor) reward = floor;

    const day = todayKey();
    const completion_key = String(req.user.id) + '_' + String(task_id) + '_' + day;

    // Atomic: only insert if not done today
    let created = null;
    try {
      created = await TaskDone.create({
        id: uuidv4(),
        user_id: String(req.user.id),
        task_id: task_id,
        day_key: day,
        completion_key: completion_key,
        reward: reward
      });
    } catch (ce) {
      // Already completed today — return current balance (no double pay)
      if (ce && ce.code === 11000) {
        return res.json({
          ok: true,
          already: true,
          reward: 0,
          balance: Number(user.balance || 0),
          day: day,
          message: 'Already completed today'
        });
      }
      throw ce;
    }

    // Credit balance
    user.balance = Number(user.balance || 0) + reward;
    await user.save();

    try {
      await History.create({
        id: uuidv4(),
        user_id: String(req.user.id),
        type: 'earning',
        title: 'Task reward',
        amount: reward
      });
    } catch (he) {
      console.log('history write failed', he.message);
    }

    return res.json({
      ok: true,
      already: false,
      reward: reward,
      balance: Number(user.balance),
      day: day,
      message: '₦' + reward + ' added to your balance'
    });
  } catch (e) {
    console.error('task complete error:', e);
    return res.status(500).json({ error: e.message || 'Server error' });
  }
});

app.get('/api/tasks/completed', auth, async (req, res) => {
  try {
    const day = todayKey();
    const rows = await TaskDone.find({
      user_id: String(req.user.id),
      day_key: day
    }).lean();
    return res.json(rows.map(r => Number(r.task_id)));
  } catch (e) {
    console.error(e);
    return res.json([]);
  }
});

// Referral list with deposit progress
app.get('/api/referrals', auth, async (req, res) => {
  try {
    const list = await User.find({ referred_by: String(req.user.id) })
      .select('id name email plan has_deposited created_at')
      .sort({ created_at: -1 })
      .lean();
    // Also match if referred_by stored differently
    if (!list.length) {
      const all = await User.find({ referred_by: { $ne: null } }).select('id name email plan has_deposited created_at referred_by').lean();
      const filtered = all.filter(u => String(u.referred_by) === String(req.user.id));
      const me = await User.findOne({ id: req.user.id });
      const hist = await History.find({ user_id: req.user.id, title: /Referral/i }).lean();
      return res.json(filtered.map(u => ({
        id: u.id,
        name: u.name,
        plan: u.plan || 'free',
        has_deposited: !!u.has_deposited,
        joined: u.created_at,
        your_bonus: 0
      })));
    }
    res.json(list.map(u => ({
      id: u.id,
      name: u.name,
      plan: u.plan || 'free',
      has_deposited: !!u.has_deposited,
      joined: u.created_at,
      your_bonus: 0
    })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load referrals' });
  }
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
        const bonus = Math.floor(Number(dep.amount || 0) * 0.30); // 30% of deposit
        if (bonus > 0) {
          ref.ref_balance = Number(ref.ref_balance || 0) + bonus;
          await ref.save();
          await History.create({
            id: uuidv4(),
            user_id: ref.id,
            type: 'earning',
            title: 'Referral 30% of deposit',
            amount: bonus
          });
        }
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


// ========== SPONSORED TASKS (post a task) ==========
const TASK_PRICE_PER = 300;

app.get('/api/tasks/feed', auth, async (req, res) => {
  try {
    const sponsored = await SponsoredTask.find({
      status: 'active',
      $expr: { $lt: ['$completions_done', '$completions_wanted'] }
    }).sort({ created_at: -1 }).limit(50).lean();
    res.json(sponsored.map(t => ({
      id: 's_' + t.id,
      sid: t.id,
      title: t.title,
      desc: t.description,
      link: t.link,
      icon: t.icon || '📋',
      type: 'sponsored',
      completions_left: Math.max(0, (t.completions_wanted || 0) - (t.completions_done || 0))
    })));
  } catch (e) {
    res.json([]);
  }
});

app.post('/api/tasks/sponsor', auth, async (req, res) => {
  try {
    const { title, description, link, icon, completions_wanted, views_wanted, pay_method } = req.body;
    const completions = Math.max(1, Math.min(5000, Number(completions_wanted) || 0));
    const views = Math.max(0, Number(views_wanted) || 0);
    if (!title || !title.trim()) return res.status(400).json({ error: 'Title required' });
    const total = completions * TASK_PRICE_PER;
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const method = pay_method === 'balance' ? 'balance' : 'transfer';
    let status = 'pending';

    if (method === 'balance') {
      if (Number(user.balance || 0) < total) {
        return res.status(400).json({ error: 'Insufficient balance. Need ₦' + total.toLocaleString() });
      }
      user.balance = Number(user.balance) - total;
      await user.save();
      status = 'active'; // paid from wallet — go live
      await History.create({
        id: uuidv4(), user_id: user.id, type: 'withdrawal',
        title: 'Posted task: ' + title.trim().slice(0, 40), amount: total, status: 'paid'
      });
    }

    const id = uuidv4();
    await SponsoredTask.create({
      id,
      owner_id: user.id,
      owner_name: user.name || '',
      title: title.trim().slice(0, 80),
      description: (description || '').trim().slice(0, 300),
      link: (link || '').trim().slice(0, 500),
      icon: (icon || '📋').slice(0, 8),
      completions_wanted: completions,
      views_wanted: views,
      price_per: TASK_PRICE_PER,
      total_paid: total,
      pay_method: method,
      status
    });

    if (method === 'transfer') {
      await Deposit.create({
        id: uuidv4(),
        user_id: user.id,
        plan: 'task_sponsor',
        amount: total,
        status: 'pending'
      });
      await History.create({
        id: uuidv4(), user_id: user.id, type: 'deposit',
        title: 'Task post payment', amount: total, status: 'pending'
      });
    }

    res.json({
      ok: true,
      id,
      total,
      status,
      message: status === 'active'
        ? 'Task is live. ₦' + total.toLocaleString() + ' deducted from balance.'
        : 'Transfer ₦' + total.toLocaleString() + ' then wait for admin approval.'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || 'Could not create task' });
  }
});

app.get('/api/tasks/my-sponsored', auth, async (req, res) => {
  const list = await SponsoredTask.find({ owner_id: req.user.id }).sort({ created_at: -1 }).lean();
  res.json(list);
});

app.get('/api/admin/sponsored', adminAuth, async (req, res) => {
  const list = await SponsoredTask.find({ status: 'pending' }).sort({ created_at: -1 }).lean();
  res.json(list);
});

app.post('/api/admin/sponsored/:id/approve', adminAuth, async (req, res) => {
  const t = await SponsoredTask.findOne({ id: req.params.id });
  if (!t || t.status !== 'pending') return res.status(400).json({ error: 'Invalid' });
  t.status = 'active';
  await t.save();
  res.json({ ok: true });
});

app.post('/api/admin/sponsored/:id/reject', adminAuth, async (req, res) => {
  await SponsoredTask.updateOne({ id: req.params.id }, { status: 'rejected' });
  res.json({ ok: true });
});



// ========== TASK PROOFS (sponsored) ==========
app.post('/api/tasks/submit-proof', auth, async (req, res) => {
  try {
    const { sponsored_id, screenshot, note, reward } = req.body;
    if (!sponsored_id) return res.status(400).json({ error: 'Task required' });
    if (!screenshot || String(screenshot).length < 20) {
      return res.status(400).json({ error: 'Screenshot required' });
    }
    // Limit ~700KB base64
    if (String(screenshot).length > 900000) {
      return res.status(400).json({ error: 'Screenshot too large. Use a smaller image.' });
    }
    const task = await SponsoredTask.findOne({ id: sponsored_id, status: 'active' });
    if (!task) return res.status(404).json({ error: 'Task not available' });
    if ((task.completions_done || 0) >= (task.completions_wanted || 0)) {
      return res.status(400).json({ error: 'This task is already full' });
    }
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const planCaps = { free: 30, beginner: 100, pro: 500, master: 1500 };
    const planMins = { free: 10, beginner: 80, pro: 400, master: 1200 };
    let pay = Number(reward) || 0;
    const cap = planCaps[user.plan] || 30;
    const floor = planMins[user.plan] || 10;
    if (pay > cap) pay = cap;
    if (pay < floor) pay = floor;

    try {
      await TaskSubmission.create({
        id: uuidv4(),
        sponsored_id,
        worker_id: user.id,
        worker_name: user.name || '',
        screenshot: String(screenshot),
        note: (note || '').slice(0, 200),
        reward: pay,
        status: 'pending'
      });
    } catch (ce) {
      if (ce.code === 11000) return res.status(400).json({ error: 'You already submitted proof for this task' });
      throw ce;
    }
    res.json({ ok: true, status: 'pending', message: 'Screenshot submitted. Waiting for poster to verify.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || 'Submit failed' });
  }
});

app.get('/api/sponsor/queue', auth, async (req, res) => {
  try {
    const myTasks = await SponsoredTask.find({ owner_id: req.user.id }).select('id title').lean();
    const ids = myTasks.map(t => t.id);
    const titleMap = {};
    myTasks.forEach(t => { titleMap[t.id] = t.title; });
    const rows = await TaskSubmission.find({ sponsored_id: { $in: ids }, status: 'pending' })
      .sort({ created_at: -1 }).lean();
    res.json(rows.map(r => ({
      id: r.id,
      sponsored_id: r.sponsored_id,
      task_title: titleMap[r.sponsored_id] || 'Task',
      worker_name: r.worker_name,
      note: r.note,
      reward: r.reward,
      screenshot: r.screenshot,
      created_at: r.created_at
    })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load queue' });
  }
});

app.post('/api/sponsor/review/:id', auth, async (req, res) => {
  try {
    const { action } = req.body; // approve | reject
    const sub = await TaskSubmission.findOne({ id: req.params.id });
    if (!sub || sub.status !== 'pending') return res.status(400).json({ error: 'Invalid submission' });
    const task = await SponsoredTask.findOne({ id: sub.sponsored_id });
    if (!task || task.owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Not your task' });
    }
    if (action === 'reject') {
      sub.status = 'rejected';
      sub.reviewed_at = new Date();
      await sub.save();
      return res.json({ ok: true, status: 'rejected' });
    }
    if (action !== 'approve') return res.status(400).json({ error: 'Invalid action' });

    // Approve: pay worker + count completion
    const worker = await User.findOne({ id: sub.worker_id });
    if (worker) {
      worker.balance = Number(worker.balance || 0) + Number(sub.reward || 0);
      await worker.save();
      await History.create({
        id: uuidv4(),
        user_id: worker.id,
        type: 'earning',
        title: 'Sponsored task approved',
        amount: sub.reward
      });
    }
    sub.status = 'approved';
    sub.reviewed_at = new Date();
    await sub.save();
    task.completions_done = Number(task.completions_done || 0) + 1;
    if (task.completions_done >= task.completions_wanted) task.status = 'done';
    await task.save();
    res.json({ ok: true, status: 'approved', paid: sub.reward });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || 'Review failed' });
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
