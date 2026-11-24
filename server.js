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

// 🚀 راه‌اندازی ادمین اولیه (آپدیت شده برای 5 اپ)
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

// ===== مدیریت کاربران (دوختیار) =====
app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, mobile, position, assigned_schools, assigned_products, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['doakhtyar']);
    res.json(r.rows.map(u => ({ ...u, role: toDoakhtyarRole(u.role), allowed_apps: parseJsonArray(u.allowed_apps), assigned_schools: parseJsonArray(u.assigned_schools), assigned_products: parseJsonArray(u.assigned_products) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, mobile, position, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["doakhtyar"];
    const dbRole = toDbRole(role);
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, mobile, position, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, username, email, role, workshop_id, mobile, position, allowed_apps', [username, email, hashed, dbRole, workshop_id || null, mobile || null, position || null, JSON.stringify(apps), 'doakhtyar']);
    res.status(201).json({ ...r.rows[0], role: toDoakhtyarRole(r.rows[0].role), allowed_apps: apps });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, mobile, position, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'doakhtyar']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const dbRole = role !== undefined ? toDbRole(role) : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalMobile = mobile !== undefined ? mobile : u.mobile;
    const finalPosition = position !== undefined ? position : u.position;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, allowed_apps=$7 WHERE id=$8 AND app_name=$9', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalMobile, finalPosition, finalApps, req.params.id, 'doakhtyar']);
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
    const r = await pool.query('SELECT id, username, email, role, workshop_id, mobile, position, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['petty_cash']);
    res.json(r.rows.map(u => ({ ...u, role: toPettyCashRole(u.role), allowed_apps: parseJsonArray(u.allowed_apps) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, mobile, position, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["doakhtyar", "petty_cash", "size_negar", "highfit_crm", "highfit_web"];
    const dbRole = toDbRole(role);
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, mobile, position, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, username, email, role, mobile, position, allowed_apps', [username || email.split('@')[0], email, hashed, dbRole, workshop_id || null, mobile || null, position || null, JSON.stringify(apps), 'petty_cash']);
    res.status(201).json({ ...r.rows[0], role: toPettyCashRole(r.rows[0].role), allowed_apps: apps });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, password, mobile, position, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'petty_cash']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const dbRole = role !== undefined ? toDbRole(role) : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalMobile = mobile !== undefined ? mobile : u.mobile;
    const finalPosition = position !== undefined ? position : u.position;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, allowed_apps=$7, password_hash=$8 WHERE id=$9 AND app_name=$10', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalMobile, finalPosition, finalApps, hashed, req.params.id, 'petty_cash']);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, allowed_apps=$7 WHERE id=$8 AND app_name=$9', [finalUsername, finalEmail, dbRole, finalWorkshopId, finalMobile, finalPosition, finalApps, req.params.id, 'petty_cash']);
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
    const r = await pool.query('SELECT id, username, email, role, workshop_id, mobile, position, assigned_schools, assigned_products, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['size_negar']);
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
  const { username, email, password, role, workshop_id, mobile, position, assigned_schools, assigned_products, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["size_negar"];
    const schools = parseJsonArray(assigned_schools);
    const products = parseJsonArray(assigned_products);
    const r = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id, mobile, position, assigned_schools, assigned_products, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id, username, email, role, workshop_id, mobile, position, assigned_schools, assigned_products, allowed_apps', 
      [username || email.split('@')[0], email, hashed, role || 'measurer', workshop_id || null, mobile || null, position || null, JSON.stringify(schools), JSON.stringify(products), JSON.stringify(apps), 'size_negar']
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
  const { username, email, role, workshop_id, password, mobile, position, assigned_schools, assigned_products, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'size_negar']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const finalRole = role !== undefined ? role : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalMobile = mobile !== undefined ? mobile : u.mobile;
    const finalPosition = position !== undefined ? position : u.position;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    const finalSchools = JSON.stringify(parseJsonArray(assigned_schools !== undefined ? assigned_schools : u.assigned_schools));
    const finalProducts = JSON.stringify(parseJsonArray(assigned_products !== undefined ? assigned_products : u.assigned_products));
    
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, assigned_schools=$7, assigned_products=$8, allowed_apps=$9, password_hash=$10 WHERE id=$11 AND app_name=$12', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalMobile, finalPosition, finalSchools, finalProducts, finalApps, hashed, req.params.id, 'size_negar']);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, assigned_schools=$7, assigned_products=$8, allowed_apps=$9 WHERE id=$10 AND app_name=$11', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalMobile, finalPosition, finalSchools, finalProducts, finalApps, req.params.id, 'size_negar']);
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

// ===== مدیریت کاربران (High Fit CRM) =====
app.get('/api/crm/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, mobile, position, assigned_schools, allowed_apps, created_at FROM users WHERE app_name = $1 ORDER BY id DESC', ['highfit_crm']);
    res.json(r.rows.map(u => ({ 
      ...u, 
      role: toCrmRole(u.role),
      assigned_schools: parseJsonArray(u.assigned_schools),
      allowed_apps: parseJsonArray(u.allowed_apps)
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/crm/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, mobile, position, assigned_schools, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const apps = parseJsonArray(allowed_apps).length ? parseJsonArray(allowed_apps) : ["highfit_crm"];
    const finalRole = (role === 'admin') ? 'admin' : 'sales';
    const schools = parseJsonArray(assigned_schools);
    const r = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id, mobile, position, assigned_schools, allowed_apps, app_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, username, email, role, mobile, position, assigned_schools, allowed_apps', 
      [username || email.split('@')[0], email, hashed, finalRole, workshop_id || null, mobile || null, position || null, JSON.stringify(schools), JSON.stringify(apps), 'highfit_crm']
    );
    res.status(201).json({ 
      ...r.rows[0], 
      role: toCrmRole(r.rows[0].role), 
      allowed_apps: apps,
      assigned_schools: schools
    });
  } catch (err) { 
    if (err.code === '23505') return res.status(400).json({ error: 'این ایمیل یا نام کاربری قبلا در CRM ثبت شده است.' });
    res.status(500).json({ error: err.message }); 
  }
});

app.put('/api/crm/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, password, mobile, position, assigned_schools, allowed_apps } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'highfit_crm']);
    if (!existing.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = existing.rows[0];
    const finalUsername = username !== undefined ? username : u.username;
    const finalEmail = email !== undefined ? email : u.email;
    const finalRole = role !== undefined ? ((role === 'admin') ? 'admin' : 'sales') : u.role;
    const finalWorkshopId = workshop_id !== undefined ? workshop_id : u.workshop_id;
    const finalMobile = mobile !== undefined ? mobile : u.mobile;
    const finalPosition = position !== undefined ? position : u.position;
    const finalApps = JSON.stringify(parseJsonArray(allowed_apps !== undefined ? allowed_apps : u.allowed_apps));
    const finalSchools = JSON.stringify(parseJsonArray(assigned_schools !== undefined ? assigned_schools : u.assigned_schools));
    
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, assigned_schools=$7, allowed_apps=$8, password_hash=$9 WHERE id=$10 AND app_name=$11', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalMobile, finalPosition, finalSchools, finalApps, hashed, req.params.id, 'highfit_crm']);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, mobile=$5, position=$6, assigned_schools=$7, allowed_apps=$8 WHERE id=$9 AND app_name=$10', 
        [finalUsername, finalEmail, finalRole, finalWorkshopId, finalMobile, finalPosition, finalSchools, finalApps, req.params.id, 'highfit_crm']);
    }
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/crm/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1 AND app_name=$2', [req.params.id, 'highfit_crm']);
    res.json({ message: 'Deleted' });
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
          query += ` AND (json->>'id' = ANY($2) OR json->>'ownerId' = $3)
