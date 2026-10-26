const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'highfit-core-db',
  ssl: process.env.DB_HOST ? false : { rejectUnauthorized: false }
});

const createTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        workshop_id VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS workshop_id VARCHAR(50);`);
    console.log("Table 'users' is ready and updated");
  } catch (err) {
    console.error("Error creating table", err);
  }
};
createTable();

// --- محافظ امنیتی (فقط ادمین‌ها) ---
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided. Access denied.' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid token format.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-key');
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// مسیر تست
app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// ثبت نام (عمومی)
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, role, workshop_id',
      [username, email, hashedPassword]
    );
    res.status(201).json({ message: 'User created', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user', details: err.message });
  }
});

// ورود
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const userWorkshop = user.workshop_id || 'WS-001';
    const token = jwt.sign({ id: user.id, role: user.role, workshop_id: userWorkshop }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, workshop_id: userWorkshop } });
  } catch (err) {
    res.status(500).json({ error: 'Error logging in', details: err.message });
  }
});

// لینک جادویی ادمین (فقط یک بار)
app.get('/api/setup-admin', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).send('Email is required');
  try {
    const adminCheck = await pool.query("SELECT * FROM users WHERE role = 'admin' LIMIT 1");
    if (adminCheck.rows.length > 0) return res.status(403).send('Admin already exists.');
    const result = await pool.query("UPDATE users SET role = 'admin' WHERE email = $1 RETURNING *", [email]);
    if (result.rows.length === 0) return res.status(404).send('User not found');
    res.send(`Success! User ${email} is now an admin.`);
  } catch (err) {
    res.status(500).send('Error updating user');
  }
});

// لینک بازنشانی رمز
app.get('/api/force-reset', async (req, res) => {
  const { email, newPassword } = req.query;
  if (!email || !newPassword) return res.status(400).send('Email and newPassword are required');
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const result = await pool.query("UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING *", [hashedPassword, email]);
    if (result.rows.length === 0) return res.status(404).send('User not found in database');
    res.send(`Success! Password for ${email} has been reset to: ${newPassword}`);
  } catch (err) {
    res.status(500).send('Error resetting password');
  }
});

// لیست کاربران (امن)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email, role, workshop_id, created_at FROM users ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching users', details: err.message });
  }
});

// تغییر نقش کاربر (امن)
app.put('/api/admin/users/:id/role', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  if (!['user', 'manager', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified.' });
  }

  try {
    const result = await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role',
      [role, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Role updated successfully', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error updating role', details: err.message });
  }
});

// ساخت کاربر جدید توسط ادمین (امن)
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
  const { username, email, password, role, workshop_id } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, workshop_id',
      [username, email, hashedPassword, role || 'user', workshop_id || null]
    );
    res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') { // کد خطای ایمیل تکراری در PostgreSQL
      return res.status(400).json({ error: 'Email already exists.' });
    }
    res.status(500).json({ error: 'Error creating user', details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
