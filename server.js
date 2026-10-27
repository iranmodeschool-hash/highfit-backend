const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '50mb' })); // افزایش حجم برای ارسال داده‌های زیاد
app.use(cors());

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'highfit-core-db',
  ssl: process.env.DB_HOST ? false : { rejectUnauthorized: false }
});

// ساخت جداول
const createTables = async () => {
  try {
    // جدول کاربران
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(30) DEFAULT 'workshop_manager',
        workshop_id VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // جدول جدید برای ذخیره اسناد و داده‌های عملیاتی (توسط هوش مصنوعی پیشنهاد شد)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_rows (
        id VARCHAR(100) PRIMARY KEY,
        collection VARCHAR(50) NOT NULL,
        json JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Tables are ready");
  } catch (err) {
    console.error("Error creating tables", err);
  }
};
createTables();

// --- Middleware امنیتی ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-key');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// --- مسیرهای عمومی ---
app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// دکمه جادویی ادمین
app.get('/api/force-create-admin', async (req, res) => {
  const { email, password } = req.query;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const check = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (check.rows.length > 0) {
      await pool.query("UPDATE users SET role = 'admin', password_hash = $1 WHERE email = $2", [hashedPassword, email]);
      return res.send(`Admin password reset.`);
    }
    await pool.query('INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)', ['HAMID', email, hashedPassword, 'admin']);
    res.send(`Success! New admin created.`);
  } catch (err) { res.status(500).send(err.message); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role, workshop_id: user.workshop_id }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, workshop_id: user.workshop_id } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- مسیرهای ادمین ---
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const result = await pool.query('SELECT id, username, email, role, workshop_id, created_at FROM users ORDER BY id DESC');
  res.json(result.rows);
});

app.post('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, workshop_id',
      [username, email, hashedPassword, role || 'workshop_manager', workshop_id || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/role', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const result = await pool.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role', [req.body.role, req.params.id]);
  res.json(result.rows[0]);
});

app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ==========================================
// مسیرهای جدید برای همگام‌سازی داده‌های اپلیکیشن (Store)
// ==========================================
// دریافت همه رکوردهای یک مجموعه (مثلاً workshops, products, dispatches)
app.get('/api/store/:collection', authenticateToken, async (req, res) => {
  try {
    const { collection } = req.params;
    const result = await pool.query('SELECT id, json FROM app_rows WHERE collection = $1', [collection]);
    // برگرداندن به شکل آرایه‌ای از آبجکت‌ها
    const data = result.rows.map(row => row.json);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ذخیره یا آپدیت یک رکورد در مجموعه
app.post('/api/store/:collection', authenticateToken, async (req, res) => {
  try {
    const { collection } = req.params;
    const data = req.body; // خود آبجکت داده
    const id = data.id || Date.now().toString(); // اگر آیدی نداشت، بساز

    // آپدیت یا درج (UPSERT)
    await pool.query(`
      INSERT INTO app_rows (id, collection, json) 
      VALUES ($1, $2, $3) 
      ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json
    `, [id, collection, data]);

    res.json({ message: 'Saved successfully', id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// حذف یک رکورد
app.delete('/api/store/:collection/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM app_rows WHERE id = $1', [id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
