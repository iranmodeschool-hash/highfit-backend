const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

// 🛡️ محافظ‌های سراسری
process.on('unhandledRejection', (reason) => console.error('Unhandled:', reason));
process.on('uncaughtException', (err) => console.error('Uncaught:', err));

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// ⚙️ تنظیمات دیتابیس
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'highfit-core-db',
  ssl: process.env.DB_HOST ? false : { rejectUnauthorized: false },
  max: 15, idleTimeoutMillis: 60000, connectionTimeoutMillis: 15000,
});

pool.on('error', (err) => { console.error('Unexpected error on idle client', err); });

const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, 
        app_name VARCHAR(50) NOT NULL DEFAULT 'doakhtyar',
        username VARCHAR(50) NOT NULL, 
        email VARCHAR(100) NOT NULL, 
        password_hash VARCHAR(255) NOT NULL, 
        role VARCHAR(30) DEFAULT 'clerk', 
        workshop_id VARCHAR(50), 
        mobile VARCHAR(20),
        position VARCHAR(100),
        assigned_schools JSONB DEFAULT '[]'::jsonb,
        assigned_products JSONB DEFAULT '[]'::jsonb,
        allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS app_name VARCHAR(50) NOT NULL DEFAULT 'doakhtyar';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_schools JSONB DEFAULT '[]'::jsonb;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_products JSONB DEFAULT '[]'::jsonb;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mobile VARCHAR(20);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS position VARCHAR(100);`);
    
    await pool.query(`
      DO $$ BEGIN
        ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
        ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
      EXCEPTION WHEN OTHERS THEN NULL; END $$;
    `);
    await pool.query(`
      DO $$ BEGIN
        ALTER TABLE users ADD CONSTRAINT users_app_email_key UNIQUE (app_name, email);
      EXCEPTION WHEN OTHERS THEN NULL; END $$;
    `);
    await pool.query(`
      DO $$ BEGIN
        ALTER TABLE users ADD CONSTRAINT users_app_username_key UNIQUE (app_name, username);
      EXCEPTION WHEN OTHERS THEN NULL; END $$;
    `);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS app_rows (id VARCHAR(100) PRIMARY KEY, collection VARCHAR(50) NOT NULL, json JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
    console.log("Tables ready & Migrated successfully");
  } catch (err) { console.error("Error:", err); }
};
createTables();

// 🔑 احراز هویت
const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET || 'super-secret-key'); next(); }
  catch (err) { res.status(401).json({ error: 'Invalid token' }); }
};

// 🛡️ توابع کمکی
const safeParse = (data, dbId) => {
  let obj = data;
  if (typeof obj === 'string') { try { obj = JSON.parse(obj); } catch(e) { obj = {}; } }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) obj = {};
  return { ...obj, id: obj.id || dbId || Math.random().toString(36).substring(7) };
};

const parseJsonArray = (arr) => {
  let parsed = arr;
  if (typeof parsed === 'string') { try { parsed = JSON.parse(parsed); } catch(e) { parsed = []; } }
  return Array.isArray(parsed) ? parsed : [];
};

const toDbRole = (role) => {
  if (!role) return 'clerk';
  const r = role.toString().trim().toLowerCase();
  if (r === 'admin' || r === 'super_admin' || r === 'مدیر کل' || r === 'مدیر') return 'admin';
  if (r === 'financial_manager' || r === 'مدیر مالی' || r === 'supervisor') return 'financial_manager';
  if (r === 'clerk' || r === 'تنخواه گردان' || r === 'تنخواه‌گردان' || r === 'workshop_manager') return 'clerk';
  if (r === 'sales' || r === 'کارشناس فروش') return 'sales';
  return 'clerk';
};

const toDoakhtyarRole = (dbRole) => {
  if (dbRole === 'admin') return 'admin';
  if (dbRole === 'financial_manager') return 'supervisor';
  if (dbRole === 'clerk') return 'workshop_manager';
  return 'workshop_manager';
};

const toPettyCashRole = (dbRole) => {
  if (dbRole === 'admin') return 'admin';
  if (dbRole === 'financial_manager') return 'financial_manager';
  if (dbRole === 'clerk') return 'clerk';
  return 'clerk';
};

const toCrmRole = (dbRole) => {
  if (dbRole === 'admin') return 'admin';
  if (dbRole === 'sales') return 'sales';
  return 'sales';
};

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// 🚀 راه‌اندازی ادمین اولیه
app.get('/api/force-create-admin', async (req, res) => {
  const { email, password } = req.query;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const appsList = JSON.stringify(["doakhtyar","petty_cash","size_negar","highfit_crm","highfit_web"]);
    
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'doakhtyar', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'petty_cash', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'size_negar', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'highfit_crm', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'highfit_web', appsList]);
    
    res.send('Admin accounts created/reset for all 5 apps.');
  } catch (err) { res.status(500).send(err.message); }
});

// ورود
app.post('/api/login', async (req, res) => {
  const { email, password, app_name } = req.body;
  const targetApp = app_name || 'doakhtyar';
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1 AND app_name=$2', [email, targetApp]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials for this app' });
    const u = r.rows[0];
    if (!(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Invalid' });
    
    let responseRole = u.role;
    if (targetApp === 'doakhtyar') responseRole = toDoakhtyarRole(u.role);
    if (targetApp === 'petty_cash') responseRole = toPettyCashRole(u.role);
    if (targetApp === 'size_negar') responseRole = u.role;
    if (targetApp === 'highfit_crm') responseRole = toCrmRole(u.role);

    const token = jwt.sign({ 
      id: u.id, 
      role: responseRole, 
      workshop_id: u.workshop_id, 
      app_name: targetApp,
      assigned_schools: parseJsonArray(u.assigned_schools),
      assigned_products: parseJsonArray(u.assigned_products)
    }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    
    res.json({ 
      token, 
      user: { 
        id: u.id, 
        username: u.username, 
        email: u.email, 
        role: responseRole, 
        workshop_id: u.workshop_id, 
        mobile: u.mobile,
        position: u.position,
        assigned_schools: parseJsonArray(u.assigned_schools),
        assigned_products: parseJsonArray(u.assigned_products),
        allowed_apps: parseJsonArray(u.allowed_apps) 
      } 
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Store عمومی =====
app.get('/api/store/:collection', auth, async (req, res) => {
  try {
    const collection = req.params.collection;
    let query = 'SELECT id, json FROM app_rows WHERE collection=$1';
    let params = [collection];

    if (req.user.role === 'measurer' && (collection === 'size_negar_orders' || collection === 'size_negar_students')) {
      const assignedSchools = parseJsonArray(req.user.assigned_schools);
      const legacyWorkshopId = req.user.workshop_id;
      
      if (assignedSchools.length > 0) {
        query += ` AND (json->>'school' = ANY($2) OR json->>'workshop_id' = ANY($2))`;
        params.push(assignedSchools);
      } else if (legacyWorkshopId) {
        query += ` AND (json->>'school' = $2 OR json->>'workshop_id' = $2)`;
        params.push(legacyWorkshopId);
      } else {
        return res.json([]);
      }
    }

    if (req.user.app_name === 'highfit_crm' && req.user.role === 'sales') {
      const userId = String(req.user.id);
      if (collection === 'crm_schools') {
        const assigned = parseJsonArray(req.user.assigned_schools);
        if (assigned.length > 0) {
          query += ` AND (json->>'id' = ANY($2) OR json->>'ownerId' = $3)`;
          params.push(assigned, userId);
        } else {
          query += ` AND json->>'ownerId' = $2`;
          params.push(userId);
        }
      } else if (collection === 'crm_contracts') {
        query += ` AND json->>'ownerId' = $2`;
        params.push(userId);
      } else if (collection === 'crm_opportunities') {
        query += ` AND (json->>'ownerId' = $2)`;
        params.push(userId);
      }
    }

    const r = await pool.query(query, params);
    res.json(r.rows.map(x => safeParse(x.json, x.id)));
  } catch (err) { 
    console.error("GET Store Error:", err);
    res.status(500).json({ error: err.message }); 
  }
});

app.post('/api/store/:collection', auth, async (req, res) => {
  try {
    const collection = req.params.collection;
    let data = req.body;
    if (!data || Object.keys(data).length === 0) return res.status(400).json({ error: 'سند خالی قابل ثبت نیست.' });
    if (typeof data === 'string') { try { data = JSON.parse(data); } catch (e) { return res.status(400).json({ error: 'فرمت داده نامعتبر است' }); } }

    if (Array.isArray(data)) {
      const savedItems = [];
      for (let item of data) {
        const id = String(item.id || Date.now() + Math.random());
        item.id = id;
        await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json', [id, collection, JSON.stringify(item)]);
        savedItems.push(item);
      }
      return res.json({ message: 'Saved', data: savedItems });
    } else {
      const id = String(data.id || Date.now());
      data.id = id;
      await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json', [id, collection, JSON.stringify(data)]);
      return res.json({ ...data, message: 'Saved' });
    }
  } catch (err) { 
    console.error("POST Store Error:", err);
    res.status(500).json({ error: err.message }); 
  }
});

app.delete('/api/store/:collection/:id', auth, async (req, res) => {
  try { await pool.query('DELETE FROM app_rows WHERE id=$1', [req.params.id]); res.json({ message: 'Deleted' }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== چت =====
app.post('/api/chat/send', auth, async (req, res) => {
  const { receiver_id, text, image, audio } = req.body;
  if (!receiver_id || (!text && !image && !audio)) return res.status(400).json({ error: 'Missing' });
  const id = 'msg_' + Date.now() + '_' + Math.random().toString(36).substring(7); 
  const data = { id, sender_id: req.user.id, receiver_id, text: text || '', image: image || null, audio: audio || null, status: 'sent', app_name: req.user.app_name, created_at: new Date().toISOString() };
  try { await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)', [id, 'messages', JSON.stringify(data)]); res.status(201).json(data); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/messages/:contactId', auth, async (req, res) => {
  const myId = req.user.id, cid = req.params.contactId;
  const appName = req.user.app_name;
  try {
    await pool.query(
      `UPDATE app_rows SET json=jsonb_set(json,'{status}','"delivered"') 
       WHERE collection='messages' 
       AND json->>'sender_id'=$1 
       AND json->>'receiver_id'=$2 
       AND json->>'status'='sent'
       AND json->>'app_name'=$3`, 
      [cid, myId, appName]
    );
    const r = await pool.query(
      `SELECT id, json FROM app_rows 
       WHERE collection='messages' 
       AND json->>'app_name'=$3
       AND (
         (json->>'sender_id'=$1 AND json->>'receiver_id'=$2) 
         OR (json->>'sender_id'=$2 AND json->>'receiver_id'=$1)
       ) 
       ORDER BY (json->>'created_at') ASC`, 
      [myId, cid, appName]
    );
    res.json(r.rows.map(x => safeParse(x.json, x.id)));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/chat/seen/:contactId', auth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE app_rows SET json=jsonb_set(json,'{status}','"seen"') 
       WHERE collection='messages' 
       AND json->>'sender_id'=$1 
       AND json->>'receiver_id'=$2 
       AND json->>'app_name'=$3
       AND json->>'status' IN ('sent','delivered')`, 
      [req.params.contactId, req.user.id, req.user.app_name]
    ); 
    res.json({ message: 'Seen' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/chat/messages/:messageId', auth, async (req, res) => {
  try {
    const check = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='messages'`, [req.params.messageId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Not found' });
    const msg = safeParse(check.rows[0].json, check.rows[0].id);
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'You can only delete your own messages' });
    await pool.query('DELETE FROM app_rows WHERE id=$1', [req.params.messageId]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/chat/messages/:messageId', auth, async (req, res) => {
  try {
    const { text } = req.body;
    const check = await pool.query(`SELECT id, json FROM app_rows WHERE id=$1 AND collection='messages'`, [req.params.messageId]);
    if (!check.rows.length) return res.status(404).json({ error: 'Not found' });
    const msg = safeParse(check.rows[0].json, check.rows[0].id);
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'You can only edit your own messages' });
    msg.text = text;
    await pool.query('UPDATE app_rows SET json=$1 WHERE id=$2', [JSON.stringify(msg), req.params.messageId]);
    res.json({ message: 'Updated', data: msg });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== راه‌اندازی سرور =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server on ${PORT}`);
});
