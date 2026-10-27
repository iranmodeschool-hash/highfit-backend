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

const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(30) DEFAULT 'workshop_manager', workshop_id VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS workshops (
        id SERIAL PRIMARY KEY, code VARCHAR(50) UNIQUE NOT NULL, name VARCHAR(100) NOT NULL, phone VARCHAR(20), is_active BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY, code VARCHAR(50) UNIQUE NOT NULL, name VARCHAR(100) NOT NULL, is_active BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS product_components (
        id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id), code VARCHAR(50) NOT NULL, name VARCHAR(100) NOT NULL, is_active BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS workshop_rates (
        id SERIAL PRIMARY KEY, workshop_id INTEGER REFERENCES workshops(id), component_id INTEGER REFERENCES product_components(id), amount_toman INTEGER NOT NULL, effective_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP, effective_to TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS dispatches (
        id SERIAL PRIMARY KEY, serial VARCHAR(50) UNIQUE NOT NULL, dispatch_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, workshop_id INTEGER REFERENCES workshops(id), status VARCHAR(30) DEFAULT 'pending'
      );
      CREATE TABLE IF NOT EXISTS dispatch_lines (
        id SERIAL PRIMARY KEY, dispatch_id INTEGER REFERENCES dispatches(id), component_id INTEGER REFERENCES product_components(id), size VARCHAR(10), quantity INTEGER
      );
      CREATE TABLE IF NOT EXISTS receipts (
        id SERIAL PRIMARY KEY, dispatch_id INTEGER REFERENCES dispatches(id), received_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status VARCHAR(30) DEFAULT 'pending'
      );
      CREATE TABLE IF NOT EXISTS sewing_deliveries (
        id SERIAL PRIMARY KEY, dispatch_id INTEGER REFERENCES dispatches(id), workshop_id INTEGER REFERENCES workshops(id), delivery_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, qty_sewn INTEGER, qty_delivered INTEGER, status VARCHAR(30) DEFAULT 'pending'
      );
      CREATE TABLE IF NOT EXISTS wage_ledger (
        id SERIAL PRIMARY KEY, workshop_id INTEGER REFERENCES workshops(id), delivery_id INTEGER REFERENCES sewing_deliveries(id), qty_base INTEGER, rate_snapshot INTEGER, net_amount INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY, workshop_id INTEGER REFERENCES workshops(id), amount INTEGER, payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, method VARCHAR(50)
      );
    `);
    console.log("All tables are ready.");
  } catch (err) { console.error("Error creating tables", err); }
};
createTables();

const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-key');
    if (decoded.role !== 'manager' && decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Manager role required.' });
    }
    req.user = decoded; next();
  } catch (err) { res.status(401).json({ error: 'Invalid token.' }); }
};

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

// --- Auth ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role, workshop_id: user.workshop_id }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, workshop_id: user.workshop_id } });
  } catch (err) { res.status(500).json({ error: 'Error logging in' }); }
});

// --- Users ---
app.get('/api/users', authenticateAdmin, async (req, res) => {
  const result = await pool.query('SELECT id, username, email, role, workshop_id, created_at FROM users ORDER BY id DESC');
  res.json(result.rows);
});

app.post('/api/users', authenticateAdmin, async (req, res) => {
  const { username, email, password, role, workshop_id } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role',
      [username, email, hashedPassword, role || 'workshop_manager', workshop_id || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Error creating user', details: err.message }); }
});

// --- Workshops, Products, Components, Rates ---
app.get('/api/workshops', async (req, res) => { const r = await pool.query('SELECT * FROM workshops'); res.json(r.rows); });
app.post('/api/workshops', authenticateAdmin, async (req, res) => { const { code, name, phone } = req.body; const r = await pool.query('INSERT INTO workshops (code, name, phone) VALUES ($1, $2, $3) RETURNING *', [code, name, phone]); res.json(r.rows[0]); });
app.get('/api/products', async (req, res) => { const r = await pool.query('SELECT * FROM products'); res.json(r.rows); });
app.post('/api/products', authenticateAdmin, async (req, res) => { const { code, name } = req.body; const r = await pool.query('INSERT INTO products (code, name) VALUES ($1, $2) RETURNING *', [code, name]); res.json(r.rows[0]); });
app.get('/api/components', async (req, res) => { const r = await pool.query('SELECT * FROM product_components'); res.json(r.rows); });
app.post('/api/components', authenticateAdmin, async (req, res) => { const { product_id, code, name } = req.body; const r = await pool.query('INSERT INTO product_components (product_id, code, name) VALUES ($1, $2, $3) RETURNING *', [product_id, code, name]); res.json(r.rows[0]); });
app.get('/api/rates', async (req, res) => { const r = await pool.query('SELECT * FROM workshop_rates'); res.json(r.rows); });
app.post('/api/rates', authenticateAdmin, async (req, res) => { const { workshop_id, component_id, amount_toman } = req.body; const r = await pool.query('INSERT INTO workshop_rates (workshop_id, component_id, amount_toman) VALUES ($1, $2, $3) RETURNING *', [workshop_id, component_id, amount_toman]); res.json(r.rows[0]); });

// --- Dispatches & Lines ---
app.get('/api/dispatches', async (req, res) => { const r = await pool.query('SELECT * FROM dispatches ORDER BY id DESC'); res.json(r.rows); });
app.post('/api/dispatches', authenticateAdmin, async (req, res) => { const { serial, workshop_id } = req.body; const r = await pool.query('INSERT INTO dispatches (serial, workshop_id) VALUES ($1, $2) RETURNING *', [serial, workshop_id]); res.json(r.rows[0]); });

app.get('/api/dispatch-lines', async (req, res) => { const r = await pool.query('SELECT * FROM dispatch_lines'); res.json(r.rows); });
app.post('/api/dispatch-lines', async (req, res) => { 
  const { dispatch_id, component_id, size, quantity } = req.body; 
  const r = await pool.query('INSERT INTO dispatch_lines (dispatch_id, component_id, size, quantity) VALUES ($1, $2, $3, $4) RETURNING *', [dispatch_id, component_id, size, quantity]); 
  res.json(r.rows[0]); 
});

// --- Receipts & Sewing ---
app.get('/api/receipts', async (req, res) => { const r = await pool.query('SELECT * FROM receipts'); res.json(r.rows); });
app.post('/api/receipts', async (req, res) => { const { dispatch_id } = req.body; const r = await pool.query('INSERT INTO receipts (dispatch_id) VALUES ($1) RETURNING *', [dispatch_id]); res.json(r.rows[0]); });

app.get('/api/sewing', async (req, res) => { const r = await pool.query('SELECT * FROM sewing_deliveries'); res.json(r.rows); });
app.get('/api/deliveries', async (req, res) => { const r = await pool.query('SELECT * FROM sewing_deliveries'); res.json(r.rows); });
app.post('/api/sewing', async (req, res) => { 
  const { dispatch_id, workshop_id, qty_sewn, qty_delivered } = req.body; 
  const r = await pool.query('INSERT INTO sewing_deliveries (dispatch_id, workshop_id, qty_sewn, qty_delivered) VALUES ($1, $2, $3, $4) RETURNING *', [dispatch_id, workshop_id, qty_sewn, qty_delivered]); 
  res.json(r.rows[0]); 
});

// --- Financials ---
app.get('/api/wages', async (req, res) => { const r = await pool.query('SELECT * FROM wage_ledger'); res.json(r.rows); });
app.get('/api/payments', async (req, res) => { const r = await pool.query('SELECT * FROM payments'); res.json(r.rows); });
app.post('/api/payments', async (req, res) => { const { workshop_id, amount, method } = req.body; const r = await pool.query('INSERT INTO payments (workshop_id, amount, method) VALUES ($1, $2, $3) RETURNING *', [workshop_id, amount, method]); res.json(r.rows[0]); });

// --- Temp Routes ---
app.get('/api/setup-admin', async (req, res) => {
  const { email } = req.query;
  try {
    const result = await pool.query("UPDATE users SET role = 'manager' WHERE email = $1 RETURNING *", [email]);
    if (result.rows.length === 0) return res.status(404).send('User not found');
    res.send(`Success! User ${email} is now a manager. You can login now.`);
  } catch (err) { res.status(500).send('Error updating user'); }
});
app.get('/api/reset-users', async (req, res) => {
  try { await pool.query('DELETE FROM users'); res.send('All users deleted successfully.'); } 
  catch (err) { res.status(500).send('Error deleting users'); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
