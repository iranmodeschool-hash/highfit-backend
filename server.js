const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

process.on('unhandledRejection', (reason) => console.error('Unhandled:', reason));
process.on('uncaughtException', (err) => console.error('Uncaught:', err));

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'highfit-core-db',
  ssl: process.env.DB_HOST ? false : { rejectUnauthorized: false },
  max: 15, idleTimeoutMillis: 60000, connectionTimeoutMillis: 15000,
});

const createTables = async () => {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, email VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(30) DEFAULT 'workshop_manager', workshop_id VARCHAR(50), allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb;`);
    await pool.query(`CREATE TABLE IF NOT EXISTS app_rows (id VARCHAR(100) PRIMARY KEY, collection VARCHAR(50) NOT NULL, json JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    console.log("Tables ready");
  } catch (err) { console.error("Error:", err); }
};
createTables();

const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET || 'super-secret-key'); next(); }
  catch (err) { res.status(401).json({ error: 'Invalid token' }); }
};

// 🛡️ تابع کمکی: تضمین می‌کند خروجی همیشه آبجکت بوده و همیشه یک id داشته باشد
const safeParse = (data, dbId) => {
  let obj = data;
  if (typeof obj === 'string') {
    try { obj = JSON.parse(obj); } catch(e) { obj = {}; }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) obj = {};
  return { ...obj, id: obj.id || dbId || Math.random().toString(36).substring(7) };
};

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// ===== احراز هویت =====
app.get('/api/force-create-admin', async (req, res) => {
  const { email, password } = req.query;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const check = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (check.rows.length > 0) { await pool.query("UPDATE users SET role='admin', password_hash=$1 WHERE email=$2", [hashed, email]); return res.send('Admin reset.'); }
    await pool.query('INSERT INTO users (username, email, password_hash, role, allowed_apps) VALUES ($1,$2,$3,$4,$5)', ['HAMID', email, hashed, 'admin', '["doakhtyar","petty_cash"]']);
    res.send('New admin created.');
  } catch (err) { res.status(500).send(err.message); }
});

app.post('/api/login', async (req, res) => {
  const { email, password, app_name } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid' });
    const u = r.rows[0];
    if (!(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Invalid' });
    if (app_name && u.role !== 'admin' && !(u.allowed_apps || []).includes(app_name)) return res.status(403).json({ error: 'No access' });
    const token = jwt.sign({ id: u.id, role: u.role, workshop_id: u.workshop_id }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: u.id, username: u.username, email: u.email, role: u.role, workshop_id: u.workshop_id, allowed_apps: u.allowed_apps } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== مدیریت کاربران =====
app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const r = await pool.query('SELECT id, username, email, role, workshop_id, allowed_apps, created_at FROM users ORDER BY id DESC');
  res.json(r.rows);
});

app.post('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, email, role, workshop_id, allowed_apps', [username, email, hashed, role || 'workshop_manager', workshop_id || null, allowed_apps || '["doakhtyar"]']);
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, allowed_apps } = req.body;
  try {
    const r = await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, allowed_apps=$5 WHERE id=$6 RETURNING id, username, email, role, workshop_id, allowed_apps', [username, email, role, workshop_id || null, allowed_apps || '["doakhtyar"]', req.params.id]);
    res.json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/password', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const hashed = await bcrypt.hash(req.body.newPassword, 10);
  await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hashed, req.params.id]);
  res.json({ message: 'Updated' });
});

app.delete('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ===== Store عمومی (با تضمین id) =====
app.get('/api/store/:collection', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, json FROM app_rows WHERE collection=$1', [req.params.collection]);
    res.json(r.rows.map(x => safeParse(x.json, x.id)));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/store/:collection', auth, async (req, res) => {
  try {
    const collection = req.params.collection;
    const data = req.body;
    if (!data || Object.keys(data).length === 0) return res.status(400).json({ error: 'سند خالی قابل ثبت نیست.' });
    const id = data.id || Date.now().toString();
    await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json', [id, collection, data]);
    res.json({ message: 'Saved', id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/store/:collection/:id', auth, async (req, res) => {
  try { await pool.query('DELETE FROM app_rows WHERE id=$1', [req.params.id]); res.json({ message: 'Deleted' }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 🎯 لیست خرابی برش (کاملاً امن)
// ==========================================
app.get('/api/cut-defects', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT id, json FROM app_rows WHERE collection='cut_defects' ORDER BY (json->>'created_at') DESC`);
    res.json(r.rows.map(row => safeParse(row.json, row.id)));
  } catch (err) { 
    console.error("Cut Defects Error:", err);
    res.status(500).json({ error: 'خطا در خواندن لیست خرابی‌ها' }); 
  }
});

// ==========================================
// 🎯 تصمیم‌گیری مدیر روی خرابی برش
// ==========================================
app.put('/api/cut-defects/:id/decide', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params; 
  const { approved_qty, rejected_qty, corrected_qty, note } = req.body;
  
  try {
    const row = await pool.query(`SELECT json FROM app_rows WHERE id=$1 AND collection='cut_defects'`, [id]);
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });
    
    const data = safeParse(row.rows[0].json, id);
    const declared = parseInt(data.declared_qty || 0);
    const approved = parseInt(approved_qty || 0);
    const rejected = parseInt(rejected_qty || 0);
    const corrected = parseInt(corrected_qty || 0);
    
    // اعتبارسنجی: جمع سه تصمیم باید برابر تعداد اعلامی باشد
    if (approved + rejected + corrected !== declared) {
      return res.status(400).json({ error: `جمع تایید (${approved}) + رد (${rejected}) + اصلاح (${corrected}) باید برابر تعداد اعلامی (${declared}) باشد.` });
    }

    // آپدیت وضعیت رکورد خرابی
    const updated = { ...data, approved_qty: approved, rejected_qty: rejected, corrected_qty: corrected, status: 'reviewed', review_note: note || '', reviewed_at: new Date().toISOString() };
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(updated), id]);

    // اثر روی ردیف حواله (فقط ضایعات تایید شده کم می‌شوند)
    if (approved > 0 && data.dispatch_line_id) {
      const dl = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='dispatch_lines'`, [data.dispatch_line_id]);
      if (dl.rows.length) {
        const line = safeParse(dl.rows[0].json, dl.rows[0].id);
        line.qty_approved_defects = (parseInt(line.qty_approved_defects || 0) + approved);
        // اگر اصلاح شده بود، به عنوان یک فیلد گزارش ثبت می‌کنیم
        line.qty_corrected_total = (parseInt(line.qty_corrected_total || 0) + corrected);
        await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(line), data.dispatch_line_id]);
      }
    }
    
    res.json({ message: 'تصمیم با موفقیت ثبت شد' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 🎯 آمار داشبورد (پاسخ مسطح)
// ==========================================
app.get('/api/dashboard/stats', auth, async (req, res) => {
  let response = { users: 0, workshops: 0, products: 0, dispatches: 0, actual_dispatched: 0, deliveries: 0, actual_delivered: 0, pending_returns: 0, pending_defects: 0, total_wage: 0, total_scrap: 0, scrap_from_cut: 0, scrap_from_sewing: 0 };
  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const filter = !isAdmin && wid ? ` AND (json->>'workshop_id' = '${wid}' OR json->>'workshopId' = '${wid}')` : '';

    if (isAdmin) { const u = await pool.query('SELECT COUNT(*) FROM users'); response.users = parseInt(u.rows[0].count) || 0; }
    const w = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='workshops'${filter}`); response.workshops = parseInt(w.rows[0].count) || 0;
    const p = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='products'${filter}`); response.products = parseInt(p.rows[0].count) || 0;

    let totalDispatched = 0; const dq = await pool.query(`SELECT json FROM app_rows WHERE collection='dispatch_size_qty'`);
    for (const row of dq.rows) { const p = safeParse(row.json, row.id); totalDispatched += parseInt(p.qty) || 0; }
    response.dispatches = totalDispatched;

    let totalDefects = 0, pendingDefectsCount = 0, scrapFromCut = 0;
    const df = await pool.query(`SELECT json FROM app_rows WHERE collection='cut_defects' AND json->>'status' IN ('pending', 'reviewed') ${filter}`);
    for (const row of df.rows) {
      const p = safeParse(row.json, row.id);
      totalDefects += parseInt(p.declared_qty) || 0;
      if (p.status === 'pending' || !p.status) pendingDefectsCount++;
      if (p.status === 'reviewed') scrapFromCut += parseInt(p.approved_qty) || 0;
    }
    response.actual_dispatched = Math.max(0, response.dispatches - totalDefects);
    response.pending_defects = pendingDefectsCount;
    response.scrap_from_cut = scrapFromCut;

    let totalDelivered = 0; const dl = await pool.query(`SELECT json FROM app_rows WHERE collection='sewing_delivery_lines'`);
    for (const row of dl.rows) { const p = safeParse(row.json, row.id); totalDelivered += parseInt(p.qty_delivered) || 0; }
    response.deliveries = totalDelivered;
    response.actual_delivered = totalDelivered; // فعلا بدون کسر مرجوعی

    let totalWage = 0; const tw = await pool.query(`SELECT json FROM app_rows WHERE collection='wage_ledger'`);
    for (const row of tw.rows) { const p = safeParse(row.json, row.id); totalWage += parseFloat(p.net_amount) || 0; }
    response.total_wage = totalWage;
    response.total_scrap = scrapFromCut;
  } catch (err) { console.error("Dashboard Stats Error:", err); }
  res.json(response);
});

app.get('/api/dashboard/alerts', auth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const filter = !isAdmin && wid ? ` AND (json->>'workshop_id' = '${wid}' OR json->>'workshopId' = '${wid}')` : '';
    const alerts = [];
    if (isAdmin) {
      const pd = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='cut_defects' AND (json->>'status' IS NULL OR json->>'status'='pending')`);
      if (parseInt(pd.rows[0].count) > 0) alerts.push({ type: 'defect', title: 'خرابی برش در انتظار تایید', count: parseInt(pd.rows[0].count), link: '/cut-defects', color: 'orange' });
      const pdv = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='sewing_deliveries' AND json->>'status'='pending_approval'`);
      if (parseInt(pdv.rows[0].count) > 0) alerts.push({ type: 'delivery', title: 'تحویل دوخت در انتظار تایید', count: parseInt(pdv.rows[0].count), link: '/deliveries', color: 'green' });
    }
    res.json(alerts);
  } catch (err) { res.json([]); }
});

// ===== چت و ریست =====
app.post('/api/chat/send', auth, async (req, res) => {
  const { receiver_id, text } = req.body;
  if (!receiver_id || !text) return res.status(400).json({ error: 'Missing' });
  const id = 'msg_' + Date.now(); const data = { id, sender_id: req.user.id, receiver_id, text, status: 'sent', created_at: new Date().toISOString() };
  await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)', [id, 'messages', data]); res.status(201).json(data);
});
app.get('/api/chat/messages/:contactId', auth, async (req, res) => {
  const myId = req.user.id, cid = req.params.contactId;
  await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"delivered"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status'='sent'`, [cid, myId]);
  const r = await pool.query(`SELECT id, json FROM app_rows WHERE collection='messages' AND ((json->>'sender_id'=$1 AND json->>'receiver_id'=$2) OR (json->>'sender_id'=$2 AND json->>'receiver_id'=$1)) ORDER BY (json->>'created_at') ASC`, [myId, cid]);
  res.json(r.rows.map(x => safeParse(x.json, x.id)));
});
app.put('/api/chat/seen/:contactId', auth, async (req, res) => {
  await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"seen"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status' IN ('sent','delivered')`, [req.params.contactId, req.user.id]); res.json({ message: 'Seen' });
});
app.get('/api/chat/contacts', auth, async (req, res) => {
  let q = 'SELECT id, username, role, workshop_id FROM users', p = []; if (req.user.role !== 'admin') { q += ' WHERE role=$1'; p.push('admin'); } const r = await pool.query(q, p); res.json(r.rows);
});
app.delete('/api/admin/reset-workshop/:workshopId', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); const wid = req.params.workshopId; const cols = ['dispatches','sewing_deliveries','wage_ledger','payments'];
  try {
    const dR = await pool.query(`SELECT id FROM app_rows WHERE collection='dispatches' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const dIds = dR.rows.map(r => r.id);
    const sR = await pool.query(`SELECT id FROM app_rows WHERE collection='sewing_deliveries' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const sIds = sR.rows.map(r => r.id);
    if (dIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('dispatch_lines','workshop_receipts','cut_defects','dispatch_size_qty') AND (json->>'dispatch_id'=ANY($1) OR json->>'dispatchId'=ANY($1))`, [dIds]);
    if (sIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('sewing_delivery_lines') AND (json->>'delivery_id'=ANY($1) OR json->>'deliveryId'=ANY($1))`, [sIds]);
    await pool.query(`DELETE FROM app_rows WHERE collection=ANY($1) AND (json->>'workshop_id'=$2 OR json->>'workshopId'=$2)`, [cols, wid]); res.json({ message: 'Reset complete' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/admin/clear-all-transactions', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); const cols = ['dispatches','dispatch_lines','dispatch_size_qty','workshop_receipts','workshop_receipt_lines','sewing_deliveries','sewing_delivery_lines','cut_defects','wage_ledger','payments','payment_allocations','adjustments','sync_queue','audit_log']; const r = await pool.query('DELETE FROM app_rows WHERE collection=ANY($1)', [cols]); res.json({ message: `Cleared ${r.rowCount} records` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));
