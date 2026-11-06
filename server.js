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
        assigned_schools JSONB DEFAULT '[]'::jsonb,
        assigned_products JSONB DEFAULT '[]'::jsonb,
        allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS app_name VARCHAR(50) NOT NULL DEFAULT 'doakhtyar';`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_schools JSONB DEFAULT '[]'::jsonb;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_products JSONB DEFAULT '[]'::jsonb;`);
    
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
    await pool.query(`
      INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps, app_name, created_at)
      SELECT username, email, password_hash, role, workshop_id, allowed_apps, 'petty_cash', created_at
      FROM users WHERE app_name = 'doakhtyar'
      ON CONFLICT (app_name, email) DO NOTHING;
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
  if (r === 'admin' || r === 'super_admin' || r === 'مدیر کل') return 'admin';
  if (r === 'financial_manager' || r === 'مدیر مالی' || r === 'supervisor') return 'financial_manager';
  if (r === 'clerk' || r === 'تنخواه گردان' || r === 'تنخواه‌گردان' || r === 'workshop_manager') return 'clerk';
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

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// 🚀 راه‌اندازی ادمین اولیه
app.get('/api/force-create-admin', async (req, res) => {
  const { email, password } = req.query;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const appsList = JSON.stringify(["doakhtyar","petty_cash","size_negar"]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'doakhtyar', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'petty_cash', appsList]);
    await pool.query(`INSERT INTO users (username, email, password_hash, role, app_name, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app_name, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`, ['HAMID', email, hashed, 'admin', 'size_negar', appsList]);
    res.send('Admin accounts created/reset for all 3 apps.');
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
        assigned_schools: parseJsonArray(u.assigned_schools),
        assigned_products: parseJsonArray(u.assigned_products),
        allowed_apps: parseJsonArray(u.allowed_apps) 
      } 
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== مدیریت کاربران (دوختیار) =====
app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, assigned_schools, assigned_products, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['doakhtyar']);
    res.json(r.rows.map(u => ({ ...u, role: toDoakhtyarRole(u.role), allowed_apps: parseJsonArray(u.allowed_apps), assigned_schools: parseJsonArray(u.assigned_schools), assigned_products: parseJsonArray(u.assigned_products) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["doakhtyar"];
    const dbRole = toDbRole(role);
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, username, email, role, workshop_id, allowed_apps', [username, email, hashed, dbRole, workshop_id || null, JSON.stringify(apps), 'doakhtyar']);
    res.status(201).json({ ...r.rows[0], role: toDoakhtyarRole(r.rows[0].role), allowed_apps: apps });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'doakhtyar']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const dbRole = role !== undefined ? toDbRole(role) : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, allowed_apps=$5 WHERE id=$6 AND app_name=$7', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalApps, req.params.id, 'doakhtyar']);
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  await pool.query('DELETE FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'doakhtyar']);
  res.json({ message: 'Deleted' });
});

// ===== مدیریت کاربران (تنخواه‌یار) =====
app.get('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['petty_cash']);
    res.json(r.rows.map(u => ({ ...u, role: toPettyCashRole(u.role), allowed_apps: parseJsonArray(u.allowed_apps) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["doakhtyar", "petty_cash", "size_negar"];
    const dbRole = toDbRole(role);
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, username, email, role, allowed_apps', [username || email.split('@')[0], email, hashed, dbRole, workshop_id || null, JSON.stringify(apps), 'petty_cash']);
    res.status(201).json({ ...r.rows[0], role: toPettyCashRole(r.rows[0].role), allowed_apps: apps });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, password, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'petty_cash']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const dbRole = role !== undefined ? toDbRole(role) : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, allowed_apps=$5, password_hash=$6 WHERE id=$7 AND app_name=$8', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalApps, hashed, req.params.id, 'petty_cash']);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, allowed_apps=$5 WHERE id=$6 AND app_name=$7', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalApps, req.params.id, 'petty_cash']);
    }
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'petty_cash']);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== مدیریت کاربران (سایز نگار) =====
app.get('/api/size-negar/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, assigned_schools, assigned_products, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['size_negar']);
    res.json(r.rows.map(u => ({ 
      ...u, 
      allowed_apps: parseJsonArray(u.allowed_apps),
      assigned_schools: parseJsonArray(u.assigned_schools),
      assigned_products: parseJsonArray(u.assigned_products)
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/size-negar/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, assigned_schools, assigned_products, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["size_negar"];
    const schools = parseJsonArray(assigned_schools);
    const products = parseJsonArray(assigned_products);
    const r = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id, assigned_schools, assigned_products, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, username, email, role, workshop_id, assigned_schools, assigned_products, allowed_apps', 
      [username || email.split('@')[0], email, hashed, role || 'measurer', workshop_id || null, JSON.stringify(schools), JSON.stringify(products), JSON.stringify(apps), 'size_negar']
    );
    res.status(201).json({ 
      ...r.rows[0], 
      allowed_apps: apps,
      assigned_schools: schools,
      assigned_products: products
    });
  } catch (err) { 
    if (err.code === '23505') return res.status(400).json({ error: 'این ایمیل یا نام کاربری قبلا در سایز نگار ثبت شده است.' });
    res.status(500).json({ error: err.message }); 
  }
});

app.put('/api/size-negar/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, password, assigned_schools, assigned_products, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'size_negar']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const finalRole = role !== undefined ? role : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    const finalSchools = JSON.stringify(parseJsonArray(assigned_schools !== undefined ? assigned_schools : u.assigned_schools));
    const finalProducts = JSON.stringify(parseJsonArray(assigned_products !== undefined ? assigned_products : u.assigned_products));
    
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, assigned_schools=$5, assigned_products=$6, allowed_apps=$7, password_hash=$8 WHERE id=$9 AND app_name=$10', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalSchools, finalProducts, finalApps, hashed, req.params.id, 'size_negar']);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, assigned_schools=$5, assigned_products=$6, allowed_apps=$7 WHERE id=$8 AND app_name=$9', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalSchools, finalProducts, finalApps, req.params.id, 'size_negar']);
    }
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/size-negar/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'size_negar']);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Store عمومی با امنیت چند مدرسه‌ای =====
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

app.delete('/api/store/:collection/bulk', auth, async (req, res) => {
  try {
    const collection = req.params.collection;
    const { school } = req.query;
    
    if (!school) return res.status(400).json({ error: 'نام مدرسه یا ALL الزامی است.' });
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'فقط مدیر کل مجاز است.' });

    if (school === 'ALL') {
      await pool.query(`DELETE FROM app_rows WHERE collection=$1`, [collection]);
    } else {
      await pool.query(`DELETE FROM app_rows WHERE collection=$1 AND (json->>'school' = $2 OR json->>'workshop_id' = $2)`, [collection, school]);
    }
    
    res.json({ message: 'Bulk delete successful' });
  } catch (err) { 
    console.error("Bulk Delete Error:", err);
    res.status(500).json({ error: err.message }); 
  }
});

app.delete('/api/store/:collection/:id', auth, async (req, res) => {
  try { await pool.query('DELETE FROM app_rows WHERE id=$1', [req.params.id]); res.json({ message: 'Deleted' }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== تنظیمات اختصاصی اپ‌ها (لینک بروزرسانی) =====
app.post('/api/settings/update-link', auth, async (req, res) => {
  try {
    const { url, app_name } = req.body;
    if (!url || !app_name) return res.status(400).json({ error: 'URL و app_name الزامی هستند.' });
    
    const id = `update_link_${app_name}`;
    await pool.query(
      'INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json',
      [id, 'app_settings', JSON.stringify({ id, url, app_name, updated_at: new Date().toISOString() })]
    );
    
    console.log(`✅ Update link saved for ${app_name}: ${url}`);
    res.json({ message: 'Saved', url });
  } catch (err) {
    console.error("Save Update Link Error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/settings/update-link/:app_name', auth, async (req, res) => {
  try {
    const { app_name } = req.params;
    const id = `update_link_${app_name}`;
    const r = await pool.query('SELECT json FROM app_rows WHERE id=$1', [id]);
    if (!r.rows.length) return res.json({ url: null });
    const data = safeParse(r.rows[0].json);
    res.json({ url: data.url || null });
  } catch (err) {
    console.error("Get Update Link Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===== 🔔 اعلان‌ها (خلاصه برای Badge و اعلان سیستمی) =====
app.get('/api/notifications/summary', auth, async (req, res) => {
  try {
    const myId = String(req.user.id);
    const appName = req.user.app_name;
    
    // ۱. پیام‌های چت خوانده‌نشده (که من گیرنده هستم و وضعیت seen نیست)
    const msgResult = await pool.query(
      `SELECT COUNT(*) FROM app_rows WHERE collection='messages' AND json->>'receiver_id' = $1 AND json->>'status' != 'seen'`,
      [myId]
    );
    const chatUnread = parseInt(msgResult.rows[0].count) || 0;
    
    // ۲. اقلام در انتظار تایید (بسته به اپ)
    let pendingCount = 0;
    
    if (appName === 'size_negar' && (req.user.role === 'admin' || req.user.role === 'supervisor')) {
      const r = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='size_negar_orders' AND json->>'status' = 'pending'`);
      pendingCount = parseInt(r.rows[0].count) || 0;
    } else if (appName === 'petty_cash' && (req.user.role === 'admin' || req.user.role === 'financial_manager')) {
      const r = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='petty_cash_payments' AND json->>'status' = 'pending'`);
      pendingCount = parseInt(r.rows[0].count) || 0;
    }
    
    res.json({ chatUnread, pendingCount, total: chatUnread + pendingCount });
  } catch (err) { 
    console.error("Notification Summary Error:", err);
    res.status(500).json({ error: err.message }); 
  }
});

// ===== آمار داشبورد =====
app.get('/api/dashboard/stats', auth, async (req, res) => {
  let response = { users: 0, workshops: 0, products: 0, dispatches: 0, deliveries: 0, defects: 0, total_wage: 0 };
  try {
    const isAdmin = req.user.role === 'admin' || req.user.role === 'super_admin';
    const wid = req.user.workshop_id;
    const filter = !isAdmin && wid ? ` AND (json->>'workshop_id' = '${wid}' OR json->>'workshopId' = '${wid}')` : '';
    if (isAdmin) { const u = await pool.query('SELECT COUNT(*) FROM users WHERE app_name=$1', [req.user.app_name]); response.users = parseInt(u.rows[0].count) || 0; }
    const w = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='workshops'${filter}`); response.workshops = parseInt(w.rows[0].count) || 0;
    const p = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='products'${filter}`); response.products = parseInt(p.rows[0].count) || 0;
    const d = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='dispatches'${filter}`); response.dispatches = parseInt(d.rows[0].count) || 0;
    const dl = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='sewing_deliveries'${filter}`); response.deliveries = parseInt(dl.rows[0].count) || 0;
    const df = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='cut_defects'${filter}`); response.defects = parseInt(df.rows[0].count) || 0;
  } catch (err) { console.error("Dashboard Stats Error:", err); }
  res.json(response);
});

// ===== چت =====
app.post('/api/chat/send', auth, async (req, res) => {
  const { receiver_id, text, image } = req.body;
  if (!receiver_id || (!text && !image)) return res.status(400).json({ error: 'Missing' });
  const id = 'msg_' + Date.now(); 
  const data = { id, sender_id: req.user.id, receiver_id, text: text || '', image: image || null, status: 'sent', created_at: new Date().toISOString() };
  try { await pool.query('INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)', [id, 'messages', data]); res.status(201).json(data); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/messages/:contactId', auth, async (req, res) => {
  const myId = req.user.id, cid = req.params.contactId;
  try {
    await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"delivered"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status'='sent'`, [cid, myId]);
    const r = await pool.query(`SELECT id, json FROM app_rows WHERE collection='messages' AND ((json->>'sender_id'=$1 AND json->>'receiver_id'=$2) OR (json->>'sender_id'=$2 AND json->>'receiver_id'=$1)) ORDER BY (json->>'created_at') ASC`, [myId, cid]);
    res.json(r.rows.map(x => safeParse(x.json, x.id)));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/chat/seen/:contactId', auth, async (req, res) => {
  try {
    await pool.query(`UPDATE app_rows SET json=jsonb_set(json,'{status}','"seen"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status' IN ('sent','delivered')`, [req.params.contactId, req.user.id]); 
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

app.get('/api/chat/contacts', auth, async (req, res) => {
  try {
    const targetApp = req.user.app_name || 'doakhtyar';
    let q = 'SELECT id, username, role, workshop_id FROM users WHERE app_name=$1', p = [targetApp]; 
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') { q += ' AND role=$2'; p.push('admin'); } 
    const r = await pool.query(q, p); 
    res.json(r.rows.map(u => ({ ...u, role: targetApp === 'doakhtyar' ? toDoakhtyarRole(u.role) : toPettyCashRole(u.role) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Reset =====
app.delete('/api/admin/reset-workshop/:workshopId', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' }); const wid = req.params.workshopId; const cols = ['dispatches','sewing_deliveries','wage_ledger','payments'];
  try {
    const dR = await pool.query(`SELECT id FROM app_rows WHERE collection='dispatches' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const dIds = dR.rows.map(r => r.id);
    const sR = await pool.query(`SELECT id FROM app_rows WHERE collection='sewing_deliveries' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`, [wid]); const sIds = sR.rows.map(r => r.id);
    if (dIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('dispatch_lines','workshop_receipts','cut_defects','dispatch_size_qty') AND (json->>'dispatch_id'=ANY($1) OR json->>'dispatchId'=ANY($1))`, [dIds]);
    if (sIds.length) await pool.query(`DELETE FROM app_rows WHERE collection IN ('sewing_delivery_lines') AND (json->>'delivery_id'=ANY($1) OR json->>'deliveryId'=ANY($1))`, [sIds]);
    await pool.query(`DELETE FROM app_rows WHERE collection=ANY($1) AND (json->>'workshop_id'=$2 OR json->>'workshopId'=$2)`, [cols, wid]); res.json({ message: 'Reset complete' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/clear-all-transactions', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' }); const cols = ['dispatches','dispatch_lines','dispatch_size_qty','workshop_receipts','workshop_receipt_lines','sewing_deliveries','sewing_delivery_lines','cut_defects','wage_ledger','payments','payment_allocations','adjustments','sync_queue','audit_log']; const r = await pool.query('DELETE FROM app_rows WHERE collection=ANY($1)', [cols]); res.json({ message: `Cleared ${r.rowCount} records` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));
