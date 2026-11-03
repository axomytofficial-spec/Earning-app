// Rewards app backend (Postgres / Supabase version). Node 18+.
// Env: DATABASE_URL (Supabase pooler string), ADMIN_KEY, optional MSG91_KEY + MSG91_TEMPLATE
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool, types } = require('pg');

// Return BIGINT (int8) and NUMERIC as JS numbers instead of strings.
types.setTypeParser(20, (v) => parseInt(v, 10));
types.setTypeParser(1700, (v) => parseInt(v, 10));

const CFG = {
  AD_RATE_PAISE: 15,        // ESTIMATE of your revenue per ad (paise). Replace with measured value.
  SHARE_EARLY: 0.6,         // days 1-15
  SHARE_LATE: 0.5,
  DAILY_CAP: 25,
  COOLDOWN_SEC: 30,
  MIN_WITHDRAW_PAISE: 10000, // Rs 100
  REFERRAL_BONUS_PAISE: 1000, // Rs 10
  REF_QUALIFY_DAYS: 3,
  REF_QUALIFY_ADS_PER_DAY: 5,
  EXPIRY_DAYS: 180,
};

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, phone TEXT UNIQUE, device_id TEXT, ref_code TEXT UNIQUE,
  referred_by INTEGER, ref_paid INTEGER DEFAULT 0, flagged INTEGER DEFAULT 0,
  created_at BIGINT, last_active BIGINT, deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY, code TEXT, expires BIGINT, tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS ledger(
  id SERIAL PRIMARY KEY, user_id INTEGER, amount BIGINT, kind TEXT, ref TEXT UNIQUE, created_at BIGINT);
CREATE TABLE IF NOT EXISTS ad_views(
  id SERIAL PRIMARY KEY, user_id INTEGER, tx_id TEXT UNIQUE, day TEXT, created_at BIGINT);
CREATE TABLE IF NOT EXISTS withdrawals(
  id SERIAL PRIMARY KEY, user_id INTEGER, amount BIGINT, upi TEXT, status TEXT, created_at BIGINT);
CREATE INDEX IF NOT EXISTS i_led ON ledger(user_id);
CREATE INDEX IF NOT EXISTS i_adv ON ad_views(user_id, day);
`;

const now = () => Date.now();
const today = () => new Date().toISOString().slice(0, 10);

// Helpers. `db` is either the pool or a transaction client.
const q = (db, text, params) => db.query(text, params);
const one = async (db, text, params) => (await db.query(text, params)).rows[0];
const all = async (db, text, params) => (await db.query(text, params)).rows;

const balance = async (db, uid) =>
  (await one(db, 'SELECT COALESCE(SUM(amount),0)::bigint AS b FROM ledger WHERE user_id=$1', [uid])).b;

const credit = (db, uid, amount, kind, ref) =>
  q(db, 'INSERT INTO ledger(user_id,amount,kind,ref,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT (ref) DO NOTHING',
    [uid, amount, kind, ref, now()]);

async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// Wrap async route handlers so errors return 500 instead of crashing.
const ah = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((e) => {
    console.error(e);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  });

const app = express();
app.use(express.json());

app.get('/health', (_, res) => res.send('ok'));

// ---------- Auth (phone OTP) ----------
app.post('/auth/request-otp', ah(async (req, res) => {
  const phone = String(req.body.phone || '');
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Invalid Indian mobile number' });
  const code = String(crypto.randomInt(100000, 999999));
  await q(pool,
    `INSERT INTO otps(phone,code,expires,tries) VALUES($1,$2,$3,0)
     ON CONFLICT (phone) DO UPDATE SET code=EXCLUDED.code, expires=EXCLUDED.expires, tries=0`,
    [phone, code, now() + 5 * 60e3]);
  if (process.env.MSG91_KEY && process.env.MSG91_TEMPLATE) {
    const url = `https://control.msg91.com/api/v5/otp?template_id=${process.env.MSG91_TEMPLATE}` +
      `&mobile=91${phone}&authkey=${process.env.MSG91_KEY}&otp=${code}`;
    fetch(url, { method: 'POST' }).catch((e) => console.error('SMS failed', e));
  } else {
    console.log(`[DEV] OTP for ${phone}: ${code}`); // development only
  }
  res.json({ ok: true });
}));

app.post('/auth/verify', ah(async (req, res) => {
  const { phone, code, device_id, ref_code } = req.body;
  const o = await one(pool, 'SELECT * FROM otps WHERE phone=$1', [phone]);
  if (!o || o.expires < now() || o.tries >= 5) return res.status(400).json({ error: 'OTP expired' });
  if (o.code !== String(code)) {
    await q(pool, 'UPDATE otps SET tries=tries+1 WHERE phone=$1', [phone]);
    return res.status(400).json({ error: 'Wrong OTP' });
  }
  await q(pool, 'DELETE FROM otps WHERE phone=$1', [phone]);

  let u = await one(pool, 'SELECT * FROM users WHERE phone=$1 AND deleted=0', [phone]);
  if (!u) {
    let referrer = ref_code ? await one(pool, 'SELECT id FROM users WHERE ref_code=$1', [ref_code]) : null;
    // Basic fraud check: block referral if another account already uses this device.
    const dup = device_id ? await one(pool, 'SELECT 1 AS x FROM users WHERE device_id=$1', [device_id]) : null;
    if (dup) referrer = null;
    u = await one(pool,
      `INSERT INTO users(phone,device_id,ref_code,referred_by,created_at,last_active)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [phone, device_id || null, crypto.randomBytes(4).toString('hex'), referrer ? referrer.id : null, now(), now()]);
    if (dup) await q(pool, 'UPDATE users SET flagged=1 WHERE id=$1', [u.id]);
  }
  const token = crypto.randomBytes(24).toString('hex');
  await q(pool, 'INSERT INTO sessions(token,user_id) VALUES($1,$2)', [token, u.id]);
  res.json({ token, ref_code: u.ref_code });
}));

const auth = ah(async (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const s = await one(pool, 'SELECT user_id FROM sessions WHERE token=$1', [t]);
  if (!s) return res.status(401).json({ error: 'Unauthorized' });
  req.uid = s.user_id;
  next();
});

// ---------- AdMob server-side verification ----------
let keyCache = { at: 0, keys: {} };
async function googleKey(keyId) {
  if (now() - keyCache.at > 24 * 3600e3 || !keyCache.keys[keyId]) {
    const r = await fetch('https://www.gstatic.com/admob/reward/verifier-keys.json');
    const j = await r.json();
    keyCache = { at: now(), keys: Object.fromEntries(j.keys.map((k) => [String(k.keyId), k.pem])) };
  }
  return keyCache.keys[keyId];
}

async function maybePayReferral(db, u) {
  if (!u.referred_by || u.ref_paid) return;
  const r = await one(db,
    'SELECT COUNT(*) AS n FROM (SELECT day FROM ad_views WHERE user_id=$1 GROUP BY day HAVING COUNT(*)>=$2) t',
    [u.id, CFG.REF_QUALIFY_ADS_PER_DAY]);
  if (r.n >= CFG.REF_QUALIFY_DAYS) {
    const referrer = await one(db, 'SELECT flagged FROM users WHERE id=$1', [u.referred_by]);
    if (referrer && !referrer.flagged) await credit(db, u.referred_by, CFG.REFERRAL_BONUS_PAISE, 'referral', 'ref:' + u.id);
    await q(db, 'UPDATE users SET ref_paid=1 WHERE id=$1', [u.id]);
  }
}

app.get('/ssv', ah(async (req, res) => {
  const qs = req.originalUrl.split('?')[1] || '';
  const sigIdx = qs.indexOf('&signature=');
  const m = qs.slice(sigIdx).match(/&signature=([^&]+)&key_id=(\d+)/);
  if (sigIdx < 0 || !m) return res.sendStatus(400);
  const signed = qs.slice(0, sigIdx);
  const pem = await googleKey(m[2]);
  if (!pem) return res.sendStatus(400);
  const sig = Buffer.from(m[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const ok = crypto.createVerify('SHA256').update(signed).verify(pem, sig);
  if (!ok) return res.sendStatus(403);

  const uid = Number(req.query.user_id);
  const txId = String(req.query.transaction_id);

  await tx(async (db) => {
    // Lock the user row so concurrent callbacks can't bypass the daily cap/cooldown.
    const u = await one(db, 'SELECT * FROM users WHERE id=$1 AND deleted=0 FOR UPDATE', [uid]);
    if (!u || u.flagged) return; // acknowledge, but no credit

    const day = today();
    const count = (await one(db, 'SELECT COUNT(*) AS c FROM ad_views WHERE user_id=$1 AND day=$2', [uid, day])).c;
    const last = (await one(db, 'SELECT COALESCE(MAX(created_at),0) AS t FROM ad_views WHERE user_id=$1', [uid])).t;
    if (count >= CFG.DAILY_CAP || now() - last < CFG.COOLDOWN_SEC * 1000) return;

    const ageDays = (now() - u.created_at) / 86400e3;
    const share = ageDays < 15 ? CFG.SHARE_EARLY : CFG.SHARE_LATE;
    const reward = Math.floor(CFG.AD_RATE_PAISE * share);

    const ins = await q(db,
      'INSERT INTO ad_views(user_id,tx_id,day,created_at) VALUES($1,$2,$3,$4) ON CONFLICT (tx_id) DO NOTHING',
      [uid, txId, day, now()]);
    if (ins.rowCount === 0) return; // replayed callback
    await credit(db, uid, reward, 'ad', 'ad:' + txId);
    await q(db, 'UPDATE users SET last_active=$1 WHERE id=$2', [now(), uid]);
    await maybePayReferral(db, u);
  });
  res.sendStatus(200);
}));

// ---------- User API ----------
app.get('/me', auth, ah(async (req, res) => {
  const u = await one(pool, 'SELECT ref_code,created_at FROM users WHERE id=$1', [req.uid]);
  const used = (await one(pool, 'SELECT COUNT(*) AS c FROM ad_views WHERE user_id=$1 AND day=$2', [req.uid, today()])).c;
  res.json({
    user_id: String(req.uid),
    balance_paise: await balance(pool, req.uid),
    ads_today: used,
    ads_left: Math.max(0, CFG.DAILY_CAP - used),
    ref_code: u.ref_code,
    min_withdraw_paise: CFG.MIN_WITHDRAW_PAISE,
    history: await all(pool, 'SELECT amount,kind,created_at FROM ledger WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [req.uid]),
    claimed: (await all(pool, "SELECT ref FROM ledger WHERE user_id=$1 AND ref LIKE $2", [req.uid, 'ch:' + req.uid + ':' + today() + ':%'])).map(r => r.ref.split(':')[3]),
    withdrawals: await all(pool, 'SELECT id,amount,status,created_at FROM withdrawals WHERE user_id=$1 ORDER BY id DESC LIMIT 10', [req.uid]),
  });
}));

// Daily challenges. Rewards in paise, claimable once per day (the unique ref makes a double claim impossible).
const CHALLENGES = { c3: { need: 0, paise: 5 }, c1: { need: 5, paise: 1 }, c10: { need: 10, paise: 2 }, c15: { need: 15, paise: 4 }, c20: { need: 20, paise: 6 }, c2: { need: 25, paise: 12 } };
app.post('/challenge/claim', auth, ah(async (req, res) => {
  const id = String((req.body || {}).id || '');
  const c = CHALLENGES[id];
  if (!c) return res.status(400).json({ error: 'Unknown challenge' });
  const row = await one(pool, 'SELECT COUNT(*) AS c FROM ad_views WHERE user_id=$1 AND day=$2', [req.uid, today()]);
  if (Number(row.c) < c.need) return res.status(400).json({ error: 'Challenge not completed yet' });
  await credit(pool, req.uid, c.paise, 'challenge', 'ch:' + req.uid + ':' + today() + ':' + id);
  res.json({ ok: true });
}));

app.post('/withdraw', auth, ah(async (req, res) => {
  const upi = String(req.body.upi || '');
  if (!/^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(upi)) return res.status(400).json({ error: 'Invalid UPI ID' });
  const result = await tx(async (db) => {
    // Lock the user row so two simultaneous withdrawals can't both succeed.
    const u = await one(db, 'SELECT flagged FROM users WHERE id=$1 FOR UPDATE', [req.uid]);
    const bal = await balance(db, req.uid);
    if (u.flagged) return { error: 'Account under review' };
    if (bal < CFG.MIN_WITHDRAW_PAISE) return { error: 'Minimum withdrawal is Rs 100' };
    const w = await one(db,
      'INSERT INTO withdrawals(user_id,amount,upi,status,created_at) VALUES($1,$2,$3,$4,$5) RETURNING id',
      [req.uid, bal, upi, 'pending', now()]);
    await credit(db, req.uid, -bal, 'withdraw', 'wd:' + w.id);
    return { ok: true, id: w.id, amount_paise: bal };
  });
  res.status(result.error ? 400 : 200).json(result);
}));

// Required by Play Store: in-app account deletion.
app.delete('/me', auth, ah(async (req, res) => {
  await q(pool, 'UPDATE users SET deleted=1, phone=$1 WHERE id=$2', ['deleted:' + req.uid, req.uid]);
  await q(pool, 'DELETE FROM sessions WHERE user_id=$1', [req.uid]);
  res.json({ ok: true });
}));

// ---------- Admin ----------
const admin = (req, res, next) =>
  process.env.ADMIN_KEY && req.headers['x-admin-key'] === process.env.ADMIN_KEY ? next() : res.sendStatus(403);

app.get('/admin', (_, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.get('/admin/users', admin, ah(async (_, res) =>
  res.json(await all(pool, `SELECT u.id, u.phone, u.flagged, u.created_at, u.referred_by,
    COALESCE((SELECT SUM(amount) FROM ledger WHERE user_id=u.id),0)::bigint AS balance,
    (SELECT COUNT(*) FROM ad_views WHERE user_id=u.id) AS ads
    FROM users u WHERE u.deleted=0 ORDER BY u.id DESC LIMIT 200`))));

app.get('/admin/withdrawals', admin, ah(async (_, res) =>
  res.json(await all(pool, `SELECT w.*, u.flagged, u.device_id, u.created_at AS user_created
    FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending' ORDER BY w.id`))));

app.post('/admin/withdrawals/:id/:action', admin, ah(async (req, res) => {
  const id = Number(req.params.id);
  const action = req.params.action;
  if (action !== 'approve' && action !== 'reject') return res.sendStatus(400);
  const out = await tx(async (db) => {
    const w = await one(db, 'SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE', [id]);
    if (!w || w.status !== 'pending') return { error: 'Not pending' };
    if (action === 'approve') {
      // Pay manually via UPI, or call a payout API here, then mark paid.
      await q(db, "UPDATE withdrawals SET status='paid' WHERE id=$1", [w.id]);
    } else {
      await q(db, "UPDATE withdrawals SET status='rejected' WHERE id=$1", [w.id]);
      await credit(db, w.user_id, w.amount, 'withdraw_refund', 'wdr:' + w.id);
    }
    return { ok: true };
  });
  res.status(out.error ? 400 : 200).json(out);
}));

app.post('/admin/users/:id/flag', admin, ah(async (req, res) => {
  await q(pool, 'UPDATE users SET flagged=$1 WHERE id=$2', [req.body.flagged ? 1 : 0, Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---------- Balance expiry (runs daily) ----------
setInterval(async () => {
  try {
    const cutoff = now() - CFG.EXPIRY_DAYS * 86400e3;
    for (const u of await all(pool, 'SELECT id FROM users WHERE deleted=0 AND last_active<$1', [cutoff])) {
      const b = await balance(pool, u.id);
      if (b > 0) await credit(pool, u.id, -b, 'expiry', 'exp:' + u.id + ':' + today());
    }
  } catch (e) { console.error('expiry job failed', e); }
}, 24 * 3600e3);

// ---------- Start ----------
pool.query(SCHEMA)
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Rewards backend running (Postgres)')))
  .catch((e) => { console.error('DB init failed:', e.message); process.exit(1); });
