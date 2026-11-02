// Rewards app MVP backend. Node 18+, `npm i express better-sqlite3`
// Run: ADMIN_KEY=secret node server.js
const express = require('express');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const CFG = {
  AD_RATE_PAISE: 15,        // ESTIMATE of your revenue per ad (paise). Replace with measured value.
  SHARE_EARLY: 0.6,         // days 1-15
  SHARE_LATE: 0.5,
  DAILY_CAP: 25,
  COOLDOWN_SEC: 30,
  MIN_WITHDRAW_PAISE: 10000, // Rs 100
  REFERRAL_BONUS_PAISE: 1000, // Rs 10
  REF_QUALIFY_DAYS: 3,      // distinct active days
  REF_QUALIFY_ADS_PER_DAY: 5,
  EXPIRY_DAYS: 180,
};

const db = new Database(process.env.DB_PATH || 'rewards.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, phone TEXT UNIQUE, device_id TEXT, ref_code TEXT UNIQUE,
  referred_by INTEGER, ref_paid INTEGER DEFAULT 0, flagged INTEGER DEFAULT 0,
  created_at INTEGER, last_active INTEGER, deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY, code TEXT, expires INTEGER, tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
-- Ledger: balance = SUM(amount). Never edit rows; add compensating rows.
CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY, user_id INTEGER, amount INTEGER, kind TEXT, ref TEXT UNIQUE, created_at INTEGER);
CREATE TABLE IF NOT EXISTS ad_views(
  id INTEGER PRIMARY KEY, user_id INTEGER, tx_id TEXT UNIQUE, day TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS withdrawals(
  id INTEGER PRIMARY KEY, user_id INTEGER, amount INTEGER, upi TEXT, status TEXT, created_at INTEGER);
CREATE INDEX IF NOT EXISTS i_led ON ledger(user_id);
CREATE INDEX IF NOT EXISTS i_adv ON ad_views(user_id, day);
`);

const now = () => Date.now();
const today = () => new Date().toISOString().slice(0, 10);
const balance = (uid) => db.prepare('SELECT COALESCE(SUM(amount),0) b FROM ledger WHERE user_id=?').get(uid).b;
const credit = (uid, amount, kind, ref) =>
  db.prepare('INSERT OR IGNORE INTO ledger(user_id,amount,kind,ref,created_at) VALUES(?,?,?,?,?)').run(uid, amount, kind, ref, now());

const app = express();
app.use(express.json());

// ---------- Auth (phone OTP) ----------
app.post('/auth/request-otp', (req, res) => {
  const phone = String(req.body.phone || '');
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Invalid Indian mobile number' });
  const code = String(crypto.randomInt(100000, 999999));
  db.prepare('INSERT OR REPLACE INTO otps(phone,code,expires,tries) VALUES(?,?,?,0)').run(phone, code, now() + 5 * 60e3);
  if (process.env.MSG91_KEY && process.env.MSG91_TEMPLATE) {
    // MSG91 OTP API. Needs a DLT-registered template in India.
    const url = `https://control.msg91.com/api/v5/otp?template_id=${process.env.MSG91_TEMPLATE}` +
      `&mobile=91${phone}&authkey=${process.env.MSG91_KEY}&otp=${code}`;
    fetch(url, { method: 'POST' }).catch((e) => console.error('SMS failed', e));
  } else {
    console.log(`[DEV] OTP for ${phone}: ${code}`); // development only
  }
  res.json({ ok: true });
});

app.post('/auth/verify', (req, res) => {
  const { phone, code, device_id, ref_code } = req.body;
  const o = db.prepare('SELECT * FROM otps WHERE phone=?').get(phone);
  if (!o || o.expires < now() || o.tries >= 5) return res.status(400).json({ error: 'OTP expired' });
  if (o.code !== String(code)) {
    db.prepare('UPDATE otps SET tries=tries+1 WHERE phone=?').run(phone);
    return res.status(400).json({ error: 'Wrong OTP' });
  }
  db.prepare('DELETE FROM otps WHERE phone=?').run(phone);
  let u = db.prepare('SELECT * FROM users WHERE phone=? AND deleted=0').get(phone);
  if (!u) {
    let referrer = ref_code ? db.prepare('SELECT id FROM users WHERE ref_code=?').get(ref_code) : null;
    // Basic fraud check: block referral if another account already uses this device.
    const dup = device_id && db.prepare('SELECT 1 FROM users WHERE device_id=?').get(device_id);
    if (dup) { referrer = null; }
    const info = db.prepare(
      'INSERT INTO users(phone,device_id,ref_code,referred_by,created_at,last_active) VALUES(?,?,?,?,?,?)'
    ).run(phone, device_id || null, crypto.randomBytes(4).toString('hex'), referrer ? referrer.id : null, now(), now());
    u = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
    if (dup) db.prepare('UPDATE users SET flagged=1 WHERE id=?').run(u.id);
  }
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id) VALUES(?,?)').run(token, u.id);
  res.json({ token, ref_code: u.ref_code });
});

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(t);
  if (!s) return res.status(401).json({ error: 'Unauthorized' });
  req.uid = s.user_id;
  next();
}

// ---------- AdMob server-side verification ----------
// Configure the rewarded ad in your app with ServerSideVerificationOptions(userId = our user id).
let keyCache = { at: 0, keys: {} };
async function googleKey(keyId) {
  if (now() - keyCache.at > 24 * 3600e3 || !keyCache.keys[keyId]) {
    const r = await fetch('https://www.gstatic.com/admob/reward/verifier-keys.json');
    const j = await r.json();
    keyCache = { at: now(), keys: Object.fromEntries(j.keys.map((k) => [String(k.keyId), k.pem])) };
  }
  return keyCache.keys[keyId];
}

app.get('/ssv', async (req, res) => {
  try {
    const qs = req.originalUrl.split('?')[1] || '';
    const sigIdx = qs.indexOf('&signature=');
    const signed = qs.slice(0, sigIdx);
    const m = qs.slice(sigIdx).match(/&signature=([^&]+)&key_id=(\d+)/);
    if (sigIdx < 0 || !m) return res.sendStatus(400);
    const pem = await googleKey(m[2]);
    if (!pem) return res.sendStatus(400);
    const sig = Buffer.from(m[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const ok = crypto.createVerify('SHA256').update(signed).verify(pem, sig);
    if (!ok) return res.sendStatus(403);

    const uid = Number(req.query.user_id);
    const tx = String(req.query.transaction_id);
    const u = db.prepare('SELECT * FROM users WHERE id=? AND deleted=0').get(uid);
    if (!u || u.flagged) return res.sendStatus(200); // acknowledge, but no credit

    const day = today();
    const count = db.prepare('SELECT COUNT(*) c FROM ad_views WHERE user_id=? AND day=?').get(uid, day).c;
    const last = db.prepare('SELECT MAX(created_at) t FROM ad_views WHERE user_id=?').get(uid).t || 0;
    if (count >= CFG.DAILY_CAP || now() - last < CFG.COOLDOWN_SEC * 1000) return res.sendStatus(200);

    const ageDays = (now() - u.created_at) / 86400e3;
    const share = ageDays < 15 ? CFG.SHARE_EARLY : CFG.SHARE_LATE;
    const reward = Math.floor(CFG.AD_RATE_PAISE * share);

    db.transaction(() => {
      const ins = db.prepare('INSERT OR IGNORE INTO ad_views(user_id,tx_id,day,created_at) VALUES(?,?,?,?)').run(uid, tx, day, now());
      if (ins.changes === 0) return; // replayed callback
      credit(uid, reward, 'ad', 'ad:' + tx);
      db.prepare('UPDATE users SET last_active=? WHERE id=?').run(now(), uid);
      maybePayReferral(u);
    })();
    res.sendStatus(200);
  } catch (e) { console.error(e); res.sendStatus(500); }
});

function maybePayReferral(u) {
  if (!u.referred_by || u.ref_paid) return;
  const days = db.prepare(
    'SELECT COUNT(*) n FROM (SELECT day FROM ad_views WHERE user_id=? GROUP BY day HAVING COUNT(*)>=?)'
  ).get(u.id, CFG.REF_QUALIFY_ADS_PER_DAY).n;
  if (days >= CFG.REF_QUALIFY_DAYS) {
    const referrer = db.prepare('SELECT flagged FROM users WHERE id=?').get(u.referred_by);
    if (referrer && !referrer.flagged) credit(u.referred_by, CFG.REFERRAL_BONUS_PAISE, 'referral', 'ref:' + u.id);
    db.prepare('UPDATE users SET ref_paid=1 WHERE id=?').run(u.id);
  }
}

// ---------- User API ----------
app.get('/me', auth, (req, res) => {
  const u = db.prepare('SELECT ref_code,created_at FROM users WHERE id=?').get(req.uid);
  const used = db.prepare('SELECT COUNT(*) c FROM ad_views WHERE user_id=? AND day=?').get(req.uid, today()).c;
  res.json({
    user_id: String(req.uid), balance_paise: balance(req.uid), ads_today: used, ads_left: Math.max(0, CFG.DAILY_CAP - used),
    ref_code: u.ref_code, min_withdraw_paise: CFG.MIN_WITHDRAW_PAISE,
    history: db.prepare('SELECT amount,kind,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.uid),
  });
});

app.post('/withdraw', auth, (req, res) => {
  const upi = String(req.body.upi || '');
  if (!/^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(upi)) return res.status(400).json({ error: 'Invalid UPI ID' });
  const result = db.transaction(() => {
    const u = db.prepare('SELECT flagged FROM users WHERE id=?').get(req.uid);
    const bal = balance(req.uid);
    if (u.flagged) return { error: 'Account under review' };
    if (bal < CFG.MIN_WITHDRAW_PAISE) return { error: 'Minimum withdrawal is Rs 100' };
    const w = db.prepare('INSERT INTO withdrawals(user_id,amount,upi,status,created_at) VALUES(?,?,?,?,?)')
      .run(req.uid, bal, upi, 'pending', now());
    credit(req.uid, -bal, 'withdraw', 'wd:' + w.lastInsertRowid);
    return { ok: true, id: w.lastInsertRowid, amount_paise: bal };
  })();
  res.status(result.error ? 400 : 200).json(result);
});

// Required by Play Store: in-app account deletion.
app.delete('/me', auth, (req, res) => {
  db.prepare('UPDATE users SET deleted=1, phone=? WHERE id=?').run('deleted:' + req.uid, req.uid);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.uid);
  res.json({ ok: true });
});

// ---------- Admin ----------
const admin = (req, res, next) =>
  process.env.ADMIN_KEY && req.headers['x-admin-key'] === process.env.ADMIN_KEY ? next() : res.sendStatus(403);

app.get('/admin', (_, res) => res.sendFile(require('path').join(__dirname, 'admin.html')));

app.get('/admin/users', admin, (_, res) =>
  res.json(db.prepare(`SELECT u.id, u.phone, u.flagged, u.created_at, u.referred_by,
    COALESCE((SELECT SUM(amount) FROM ledger WHERE user_id=u.id),0) AS balance,
    (SELECT COUNT(*) FROM ad_views WHERE user_id=u.id) AS ads
    FROM users u WHERE u.deleted=0 ORDER BY u.id DESC LIMIT 200`).all()));

app.get('/admin/withdrawals', admin, (_, res) =>
  res.json(db.prepare(`SELECT w.*, u.flagged, u.device_id, u.created_at AS user_created
    FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending' ORDER BY w.id`).all()));

app.post('/admin/withdrawals/:id/:action', admin, (req, res) => {
  const w = db.prepare('SELECT * FROM withdrawals WHERE id=?').get(req.params.id);
  if (!w || w.status !== 'pending') return res.status(400).json({ error: 'Not pending' });
  if (req.params.action === 'approve') {
    // Pay manually via UPI, or call a payout API here, then mark paid.
    db.prepare("UPDATE withdrawals SET status='paid' WHERE id=?").run(w.id);
  } else if (req.params.action === 'reject') {
    db.transaction(() => {
      db.prepare("UPDATE withdrawals SET status='rejected' WHERE id=?").run(w.id);
      credit(w.user_id, w.amount, 'withdraw_refund', 'wdr:' + w.id);
    })();
  } else return res.sendStatus(400);
  res.json({ ok: true });
});

app.post('/admin/users/:id/flag', admin, (req, res) => {
  db.prepare('UPDATE users SET flagged=? WHERE id=?').run(req.body.flagged ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

// ---------- Balance expiry (run daily) ----------
setInterval(() => {
  const cutoff = now() - CFG.EXPIRY_DAYS * 86400e3;
  for (const u of db.prepare('SELECT id FROM users WHERE deleted=0 AND last_active<?').all(cutoff)) {
    const b = balance(u.id);
    if (b > 0) credit(u.id, -b, 'expiry', 'exp:' + u.id + ':' + today());
  }
}, 24 * 3600e3);

app.listen(process.env.PORT || 3000, () => console.log('Rewards backend running'));
