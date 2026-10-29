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

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

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

// ===== Store عمومی =====
app.get('/api/store/:collection', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, json FROM app_rows WHERE collection=$1', [req.params.collection]);
    res.json(r.rows.map(x => x.json));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/store/:collection', auth, async (req, res) => {
  try {
    const collection = req.params.collection;
    const data = req.body;
    
    // 🛡️ ۴. اعتبارسنجی هوشمند سند خالی
    const validCollections = ['dispatches', 'workshop_receipts', 'sewing_deliveries', 'repair_returns', 'cut_defects'];
    if (validCollections.includes(collection)) {
      const jsonStr = JSON.stringify(data);
      // اگر کل دیتا خالی بود
      if (!data || jsonStr === '{}' || jsonStr === 'null') {
        return res.status(400).json({ error: 'سند خالی قابل ثبت نیست.' });
      }
      
      // بررسی اینکه آیا حداقل یک آرایه دارای داده وجود دارد یا فیلد معتبری مثل شماره سند پر شده است
      const hasArrayData = Object.values(data).some(val => Array.isArray(val) && val.length > 0);
      const hasQtyData = data.qty || data.total_qty || data.qty_original || data.declared_qty || data.qty_received;
      const hasHeaderData = data.serial || data.workshop_id || data.dispatch_date || data.date;
      
      if (!hasArrayData && !hasQtyData && !hasHeaderData) {
        return res.status(400).json({ error: 'سند خالی قابل ثبت نیست. اطلاعات وارد شده نامعتبر است.' });
      }
    }

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
// API اختصاصی برای Dropdown مرجوعی
// ==========================================
app.get('/api/delivery-lines-for-return', auth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const deliveries = await pool.query(`SELECT json FROM app_rows WHERE collection='sewing_deliveries'`);
    const deliveryLines = await pool.query(`SELECT json FROM app_rows WHERE collection='sewing_delivery_lines'`);
    const dispatchLines = await pool.query(`SELECT json FROM app_rows WHERE collection='dispatch_lines'`);
    const products = await pool.query(`SELECT json FROM app_rows WHERE collection='products'`);
    const sizes = await pool.query(`SELECT json FROM app_rows WHERE collection='sizes'`);

    const deliveriesMap = {}; deliveries.rows.forEach(r => deliveriesMap[r.json.id] = r.json);
    const dispatchLinesMap = {}; dispatchLines.rows.forEach(r => dispatchLinesMap[r.json.id] = r.json);
    const productsMap = {}; products.rows.forEach(r => productsMap[r.json.id] = r.json);
    const sizesMap = {}; sizes.rows.forEach(r => sizesMap[r.json.id] = r.json);

    const result = [];
    for (const row of deliveryLines.rows) {
      const line = row.json;
      const delivery = deliveriesMap[line.delivery_id || line.deliveryId];
      if (!delivery) continue;
      if (!isAdmin && wid && String(delivery.workshop_id || delivery.workshopId) !== String(wid)) continue;
      if (parseInt(line.qty_accepted || 0) <= 0) continue;

      const dLine = dispatchLinesMap[line.dispatch_line_id || line.dispatchLineId] || {};
      const product = productsMap[dLine.product_id || dLine.productId] || {};
      const size = sizesMap[line.size_id || line.sizeId] || { name: line.size_id || 'نامشخص' };
      
      const currentAccepted = parseInt(line.qty_accepted || 0);
      const alreadyReturned = parseInt(line.qty_returned_pending || 0);
      const maxReturnable = currentAccepted - alreadyReturned;
      if (maxReturnable <= 0) continue;

      result.push({
        line_id: line.id,
        delivery_id: delivery.id,
        serial: delivery.serial || delivery.id,
        product_name: product.name || 'نامشخص',
        product_code: product.code || '',
        size_name: size.name || 'نامشخص',
        max_returnable: maxReturnable,
        workshop_id: delivery.workshop_id || delivery.workshopId
      });
    }
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// آمار داشبورد و هشدارها
// ==========================================
app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const filter = !isAdmin && wid ? ` AND (json->>'workshop_id' = '${wid}' OR json->>'workshopId' = '${wid}')` : '';

    const dispatchQtyRes = await pool.query(`SELECT COALESCE(SUM((json->>'qty')::int), 0) as total FROM app_rows, jsonb_array_elements(json->'lines') l WHERE collection='dispatches' AND (json->>'status' != 'draft') ${filter}`);
    const cutDefectsRes = await pool.query(`SELECT COALESCE(SUM((json->>'declared_qty')::int), 0) as total FROM app_rows WHERE collection='cut_defects' AND json->>'status' IN ('pending', 'reviewed') ${filter}`);
    const deliveryRes = await pool.query(`SELECT COALESCE(SUM((json->>'qty_delivered')::int), 0) as total FROM app_rows, jsonb_array_elements(json->'lines') l WHERE collection='sewing_deliveries' AND (json->>'status' != 'draft') ${filter}`);
    const returnRes = await pool.query(`SELECT COALESCE(SUM((json->>'qty_original')::int), 0) as total FROM app_rows WHERE collection='repair_returns' AND json->>'status' IN ('pending_workshop_report', 'pending_admin_decision', 'completed') ${filter}`);

    const [users, workshops, products, pendingReturns, pendingDefects, totalWage, scrapTotal] = await Promise.all([
      isAdmin ? pool.query('SELECT COUNT(*) FROM users') : { rows: [{ count: 0 }] },
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='workshops'${filter}`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='products'${filter}`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='repair_returns' AND json->>'status' IN ('pending_workshop_report','pending_admin_decision')${filter}`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='cut_defects' AND (json->>'status' IS NULL OR json->>'status'='pending')${filter}`),
      pool.query(`SELECT COALESCE(SUM((json->>'net_amount')::numeric), 0) as total FROM app_rows WHERE collection='wage_ledger'${filter}`),
      pool.query(`SELECT (SELECT COALESCE(SUM((json->>'approved_qty')::int), 0) FROM app_rows WHERE collection='cut_defects' AND json->>'status'='reviewed') + (SELECT COALESCE(SUM((d->>'qty')::int), 0) FROM app_rows, jsonb_array_elements(COALESCE(json->'decisions', '[]'::jsonb)) d WHERE collection='repair_returns' AND json->>'status'='completed' AND ((d->>'group'='unrepairable' AND d->>'decision'='accept_as_scrap') OR (d->>'group'='needs_review' AND d->>'decision'='accept_scrap'))) as total`)
    ]);

    const rawDispatch = parseInt(dispatchQtyRes.rows[0].total) || 0;
    const liveDefects = parseInt(cutDefectsRes.rows[0].total) || 0;
    const rawDelivery = parseInt(deliveryRes.rows[0].total) || 0;
    const liveReturns = parseInt(returnRes.rows[0].total) || 0;

    res.json({
      users: parseInt(users.rows[0].count), workshops: parseInt(workshops.rows[0].count), products: parseInt(products.rows[0].count),
      dispatches: rawDispatch,
      actual_dispatched: Math.max(0, rawDispatch - liveDefects),
      deliveries: rawDelivery, 
      actual_delivered: Math.max(0, rawDelivery - liveReturns),
      pending_returns: parseInt(pendingReturns.rows[0].count), pending_defects: parseInt(pendingDefects.rows[0].count),
      total_wage: parseFloat(totalWage.rows[0].total), total_scrap: parseInt(scrapTotal.rows[0].total)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
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

      const pr = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='repair_returns' AND json->>'status'='pending_admin_decision'`);
      if (parseInt(pr.rows[0].count) > 0) alerts.push({ type: 'return', title: 'مرجوعی در انتظار تصمیم', count: parseInt(pr.rows[0].count), link: '/returns', color: 'red' });
      
      const pdv = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='sewing_deliveries' AND json->>'status'='pending_approval'`);
      if (parseInt(pdv.rows[0].count) > 0) alerts.push({ type: 'delivery', title: 'تحویل دوخت در انتظار تایید', count: parseInt(pdv.rows[0].count), link: '/deliveries', color: 'green' });
    } else {
      const pr = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='repair_returns' AND json->>'status'='pending_workshop_report' ${filter}`);
      if (parseInt(pr.rows[0].count) > 0) alerts.push({ type: 'return_report', title: 'نیاز به ثبت گزارش مرجوعی', count: parseInt(pr.rows[0].count), link: '/returns', color: 'orange' });
    }
    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// سایر APIها (خرابی، مرجوعی، ضایعات، چت)
// ==========================================
app.put('/api/cut-defects/:id/decide', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params; const { approved_qty, rejected_qty, corrected_qty, note } = req.body;
  try {
    const row = await pool.query(`SELECT json FROM app_rows WHERE id=$1 AND collection='cut_defects'`, [id]);
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });
    const data = row.rows[0].json;
    if (parseInt(approved_qty||0) + parseInt(rejected_qty||0) + parseInt(corrected_qty||0) !== parseInt(data.declared_qty||0)) return res.status(400).json({ error: 'جمع برابر تعداد اعلامی نیست.' });
    const updated = { ...data, approved_qty, rejected_qty, corrected_qty, status: 'reviewed', review_note: note || '', reviewed_at: new Date().toISOString() };
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(updated), id]);
    if (parseInt(approved_qty) > 0 && data.dispatch_line_id) {
      const dl = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='dispatch_lines'`, [data.dispatch_line_id]);
      if (dl.rows.length) {
        const line = dl.rows[0].json;
        line.qty_approved_defects = (parseInt(line.qty_approved_defects || 0) + parseInt(approved_qty));
        await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(line), data.dispatch_line_id]);
      }
    }
    res.json({ message: 'ثبت شد' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/repair-returns', auth, async (req, res) => {
  try { const r = await pool.query(`SELECT json FROM app_rows WHERE collection='repair_returns' ORDER BY (json->>'created_at') DESC`); res.json(r.rows.map(x => x.json)); } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/repair-returns', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { delivery_line_id, delivery_id, workshop_id, qty, reason } = req.body;
  if (!delivery_line_id || !qty || qty <= 0) return res.status(400).json({ error: 'ورودی نامعتبر' });
  try {
    const dlRow = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='sewing_delivery_lines'`, [delivery_line_id]);
    if (!dlRow.rows.length) return res.status(404).json({ error: 'یافت نشد' });
    const line = dlRow.rows[0].json;
    if (qty > parseInt(line.qty_accepted || 0)) return res.status(400).json({ error: 'بیشتر از تاییدشده است' });
    line.qty_accepted = parseInt(line.qty_accepted || 0) - qty;
    line.qty_returned_pending = parseInt(line.qty_returned_pending || 0) + qty;
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(line), delivery_line_id]);
    const returnId = 'rr_' + Date.now();
    const record = { id: returnId, delivery_line_id, delivery_id: delivery_id || '', workshop_id: workshop_id || '', qty_original: qty, qty_repaired: 0, qty_unrepairable: 0, qty_needs_review: 0, reason: reason || '', status: 'pending_workshop_report', created_by: req.user.id, created_at: new Date().toISOString(), workshop_report: null, decisions: [] };
    await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)', [returnId, 'repair_returns', record]);
    res.status(201).json({ message: 'ثبت شد', return_id: returnId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/repair-returns/:id/workshop-report', auth, async (req, res) => {
  const { qty_repaired, qty_unrepairable, qty_needs_review, note } = req.body;
  try {
    const row = await pool.query(`SELECT json FROM app_rows WHERE id=$1 AND collection='repair_returns'`, [req.params.id]);
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });
    const data = row.rows[0].json;
    if (parseInt(qty_repaired||0) + parseInt(qty_unrepairable||0) + parseInt(qty_needs_review||0) !== parseInt(data.qty_original||0)) return res.status(400).json({ error: 'جمع برابر تعداد اولیه نیست' });
    data.qty_repaired = qty_repaired; data.qty_unrepairable = qty_unrepairable; data.qty_needs_review = qty_needs_review;
    data.workshop_report = { qty_repaired, qty_unrepairable, qty_needs_review, note: note || '', reported_at: new Date().toISOString() };
    data.status = 'pending_admin_decision';
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(data), req.params.id]);
    res.json({ message: 'گزارش ثبت شد' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/repair-returns/:id/decide', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { group, decision, note } = req.body;
  try {
    const row = await pool.query(`SELECT json FROM app_rows WHERE id=$1 AND collection='repair_returns'`, [req.params.id]);
    if (!row.rows.length) return res.status(404).json({ error: 'Not found' });
    const data = row.rows[0].json;
    let qty = group === 'repaired' ? data.qty_repaired : (group === 'unrepairable' ? data.qty_unrepairable : data.qty_needs_review);
    if (!qty || qty === 0) return res.status(400).json({ error: 'گروه خالی است' });
    if (!data.decisions) data.decisions = [];
    data.decisions = data.decisions.filter(d => d.group !== group);
    data.decisions.push({ group, decision, qty, note: note || '', decided_at: new Date().toISOString() });
    
    const dl = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='sewing_delivery_lines'`, [data.delivery_line_id]);
    if (dl.rows.length) {
      const line = dl.rows[0].json;
      if (group === 'repaired' && decision === 'accept') line.qty_accepted = parseInt(line.qty_accepted||0) + qty;
      else if (group === 'unrepairable' && decision === 'accept_as_scrap') line.qty_scrap = parseInt(line.qty_scrap||0) + qty;
      else if (group === 'needs_review' && decision === 'accept_repair') line.qty_accepted = parseInt(line.qty_accepted||0) + qty;
      else if (group === 'needs_review' && decision === 'accept_scrap') line.qty_scrap = parseInt(line.qty_scrap||0) + qty;
      line.qty_returned_pending = Math.max(0, parseInt(line.qty_returned_pending||0) - qty);
      await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(line), data.delivery_line_id]);
    }
    const allDecided = ['repaired', 'unrepairable', 'needs_review'].every(g => {
      const gq = g === 'repaired' ? data.qty_repaired : (g === 'unrepairable' ? data.qty_unrepairable : data.qty_needs_review);
      return !gq || gq === 0 || data.decisions.some(d => d.group === g);
    });
    data.status = allDecided ? 'completed' : 'pending_admin_decision';
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(data), req.params.id]);
    res.json({ message: 'ثبت شد' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/scrap', auth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const defectRows = await pool.query(`SELECT json FROM app_rows WHERE collection='cut_defects' AND json->>'status'='reviewed'`);
    const scrapFromDefects = [];
    for (const row of defectRows.rows) {
      const d = row.json;
      if (!isAdmin && wid && d.workshop_id !== wid && d.workshopId !== wid) continue;
      if (parseInt(d.approved_qty || 0) > 0) scrapFromDefects.push({ source: 'cut_defect', source_id: d.id, workshop_id: d.workshop_id || d.workshopId, product_id: d.product_id, size_id: d.size_id, qty: parseInt(d.approved_qty), reason: d.defect_type || 'خرابی برش', date: d.reviewed_at || d.created_at });
    }
    const returnRows = await pool.query(`SELECT json, COALESCE(json->'decisions', '[]'::jsonb) as decisions FROM app_rows WHERE collection='repair_returns' AND json->>'status'='completed'`);
    const scrapFromReturns = [];
    for (const row of returnRows.rows) {
      const r = row.json;
      if (!isAdmin && wid && r.workshop_id !== wid) continue;
      for (const dec of (row.decisions || [])) {
        if (((dec.group === 'unrepairable' && dec.decision === 'accept_as_scrap') || (dec.group === 'needs_review' && dec.decision === 'accept_scrap')) && dec.qty > 0) {
          scrapFromReturns.push({ source: 'repair_return', source_id: r.id, workshop_id: r.workshop_id, qty: parseInt(dec.qty), reason: r.reason || 'مرجوعی غیرقابل تعمیر', date: dec.decided_at });
        }
      }
    }
    res.json({ details: [...scrapFromDefects, ...scrapFromReturns] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chat/send', auth, async (req, res) => {
  const { receiver_id, text } = req.body;
  if (!receiver_id || !text) return res.status(400).json({ error: 'Missing' });
  const id = 'msg_' + Date.now(); const data = { id, sender_id: req.user.id, receiver_id, text, status: 'sent', created_at: new Date().toISOString() };
  await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)', [id, 'messages', data]); res.status(201).json(data);
});
app.get('/api/chat/messages/:contactId', auth, async (req, res) => {
  const myId = req.user.id, cid = req.params.contactId;
  await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"delivered"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status'='sent'`, [cid, myId]);
  const r = await pool.query(`SELECT json FROM app_rows WHERE collection='messages' AND ((json->>'sender_id'=$1 AND json->>'receiver_id'=$2) OR (json->>'sender_id'=$2 AND json->>'receiver_id'=$1)) ORDER BY (json->>'created_at') ASC`, [myId, cid]); res.json(r.rows.map(x => x.json));
});
app.put('/api/chat/seen/:contactId', auth, async (req, res) => {
  await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"seen"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status' IN ('sent','delivered')`, [req.params.contactId, req.user.id]); res.json({ message: 'Seen' });
});
app.get('/api/chat/contacts', auth, async (req, res) => {
  let q = 'SELECT id, username, role, workshop_id FROM users', p = []; if (req.user.role !== 'admin') { q += ' WHERE role=$1'; p.push('admin'); } const r = await pool.query(q, p); res.json(r.rows);
});
app.delete('/api/admin/reset-workshop/:workshopId', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); const wid = req.params.workshopId; const cols = ['dispatches','sewing_deliveries','repair_returns','wage_ledger','payments'];
  try {
    const dR = await pool.query(`SELECT id FROM app_rows WHERE collection='dispatches' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const dIds = dR.rows.map(r => r.id);
    const sR = await pool.query(`SELECT id FROM app_rows WHERE collection='sewing_deliveries' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const sIds = sR.rows.map(r => r.id);
    if (dIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('dispatch_lines','workshop_receipts','cut_defects','dispatch_size_qty') AND (json->>'dispatch_id'=ANY($1) OR json->>'dispatchId'=ANY($1))`, [dIds]);
    if (sIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('sewing_delivery_lines','repair_returns') AND (json->>'delivery_id'=ANY($1) OR json->>'deliveryId'=ANY($1))`, [sIds]);
    await pool.query(`DELETE FROM app_rows WHERE collection=ANY($1) AND (json->>'workshop_id'=$2 OR json->>'workshopId'=$2)`, [cols, wid]); res.json({ message: 'Reset complete' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/admin/clear-all-transactions', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); const cols = ['dispatches','dispatch_lines','dispatch_size_qty','workshop_receipts','workshop_receipt_lines','sewing_deliveries','sewing_delivery_lines','cut_defects','repair_returns','wage_ledger','payments','payment_allocations','adjustments','sync_queue','audit_log']; const r = await pool.query('DELETE FROM app_rows WHERE collection=ANY($1)', [cols]); res.json({ message: `Cleared ${r.rowCount} records` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));
