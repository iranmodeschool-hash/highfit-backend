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
        role VARCHAR(30) DEFAULT 'workshop_manager',
        workshop_id VARCHAR(50),
        permissions JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Table 'users' is ready and updated");
  } catch (err) {
    console.error("Error creating table", err);
  }
};
createTable();

// --- Middleware امنیتی ---
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

// --- مسیرهای عمومی ---
app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// دکمه جادویی: ساخت ادمین جدید (برای مواقعی که کاربر پاک شده است)
app.get('/api/force-create-admin', async (req, res) => {
  const { email, password } = req.query;
  if (!email || !password) return res.status(400).send('Email and password are required');
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const check = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (check.rows.length > 0) {
      await pool.query("UPDATE users SET role = 'admin', password_hash = $1 WHERE email = $2", [hashedPassword, email]);
      return res.send(`User ${email} already existed. Password reset and role set to admin.`);
    }
    
    await pool.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)',
      ['HAMID', email, hashedPassword, 'admin']
    );
    res.send(`Success! New admin created with email ${email} and password ${password}.`);
  } catch (err) {
    res.status(500).send('Error creating admin: ' + err.message);
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const userWorkshop = user.workshop_id || 'WS-001';
    const token = jwt.sign(
      { id: user.id, role: user.role, workshop_id: userWorkshop, permissions: user.permissions }, 
      process.env.JWT_SECRET || 'super-secret-key', 
      { expiresIn: '1d' }
    );
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, workshop_id: userWorkshop, permissions: user.permissions } });
  } catch (err) {
    res.status(500).json({ error: 'Error logging in', details: err.message });
  }
});

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role, workshop_id',
      [username, email, hashedPassword, 'workshop_manager']
    );
    res.status(201).json({ message: 'User created', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user', details: err.message });
  }
});

// --- مسیرهای ادمین ---
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email, role, workshop_id, created_at FROM users ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching users', details: err.message });
  }
});

app.put('/api/admin/users/:id/role', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  const validRoles = ['admin', 'supervisor', 'workshop_manager'];
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role specified.' });

  try {
    const result = await pool.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role', [role, id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Role updated successfully', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error updating role', details: err.message });
  }
});

app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
  const { username, email, password, role, workshop_id } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Username, email, and password are required.' });
  const validRoles = ['admin', 'supervisor', 'workshop_manager'];
  const finalRole = validRoles.includes(role) ? role : 'workshop_manager';

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, workshop_id',
      [username, email, hashedPassword, finalRole, workshop_id || null]
    );
    res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists.' });
    res.status(500).json({ error: 'Error creating user', details: err.message });
  }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting user', details: err.message });
  }
});

app.put('/api/admin/users/:id/password', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const result = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id, username, email', [hashedPassword, id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error updating password', details: err.message });
  }
});

// --- پروفایل ---
app.put('/api/users/profile', async (req, res) => {
  const { email, newUsername } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET username = $1 WHERE email = $2 RETURNING id, username, email, role',
      [newUsername, email]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'پروفایل با موفقیت آپدیت شد', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error updating profile', details: err.message });
  }
});

app.put('/api/users/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'رمز عبور فعلی اشتباه است' });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hashedNewPassword, email]);
    
    res.json({ message: 'رمز عبور با موفقیت تغییر کرد' });
  } catch (err) {
    res.status(500).json({ error: 'Error changing password', details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
