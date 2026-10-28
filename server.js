const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '50mb' }));
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
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(30) DEFAULT 'workshop_manager',
        workshop_id VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_rows (
        id VARCHAR(100) PRIMARY KEY,
        collection VARCHAR(50) NOT NULL,
        json JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Tables are ready");
  } catch (err) { console.error(err); }
};
createTables();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-key');
    req.user = decoded;
    next();
  } catch (err) { res.status(401).json({ error: 'Invalid token.' }); }
};

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

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

app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  const { username, email, role, workshop_id } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET username = $1, email = $2, role = $3, workshop_id = $4 WHERE id = $5 RETURNING id, username, email, role, workshop_id',
      [username, email, role, workshop_id || null, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/role', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const result = await pool.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role', [req.body.role, req.params.id]);
  res.json(result.rows[0]);
});

app.put('/api/admin/users/:id/password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, req.params.id]);
    res.json({ message: 'Password updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ==========================================
// همگام‌سازی داده‌ها (Store)
// ==========================================
app.get('/api/store/:collection', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, json FROM app_rows WHERE collection = $1', [req.params.collection]);
    res.json(result.rows.map(row => row.json));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/store/:collection', authenticateToken, async (req, res) => {
  try {
    const data = req.body;
    const id = data.id || Date.now().toString();
    await pool.query(`
      INSERT INTO app_rows (id, collection, json) 
      VALUES ($1, $2, $3) 
      ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json
    `, [id, req.params.collection, data]);
    res.json({ message: 'Saved successfully', id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/store/:collection/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM app_rows WHERE id = $1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// قابلیت‌های جدید: ریست و پاکسازی (فقط ادمین)
// ==========================================

// ۱. ریست کامل یک کارگاه (حذف تمام حواله‌ها، دوخت‌ها، پرداخت‌ها و...)
app.delete('/api/admin/reset-workshop/:workshopId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { workshopId } = req.params;
  
  try {
    // پیدا کردن شناسه حواله‌های این کارگاه
    const dispatchResult = await pool.query(
      `SELECT id FROM app_rows WHERE collection = 'dispatches' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`,
      [workshopId]
    );
    const dispatchIds = dispatchResult.rows.map(r => r.id);
    
    // پیدا کردن شناسه تحویل‌های این کارگاه
    const deliveryResult = await pool.query(
      `SELECT id FROM app_rows WHERE collection = 'sewing_deliveries' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`,
      [workshopId]
    );
    const deliveryIds = deliveryResult.rows.map(r => r.id);
    
    // پیدا کردن شناسه پرداخت‌های این کارگاه
    const paymentResult = await pool.query(
      `SELECT id FROM app_rows WHERE collection = 'payments' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`,
      [workshopId]
    );
    const paymentIds = paymentResult.rows.map(r => r.id);
    
    // حذف رکوردهای وابسته به حواله‌ها
    if (dispatchIds.length > 0) {
      await pool.query(
        `DELETE FROM app_rows WHERE collection IN ('dispatch_lines', 'workshop_receipts', 'cut_defects', 'dispatch_size_qty') 
         AND (json->>'dispatch_id' = ANY($1) OR json->>'dispatchId' = ANY($1))`,
        [dispatchIds]
      );
    }
    
    // حذف ردیف‌های تحویل
    if (deliveryIds.length > 0) {
      await pool.query(
        `DELETE FROM app_rows WHERE collection = 'sewing_delivery_lines' 
         AND (json->>'delivery_id' = ANY($1) OR json->>'deliveryId' = ANY($1))`,
        [deliveryIds]
      );
    }
    
    // حذف تخصیص‌های پرداخت
    if (paymentIds.length > 0) {
      await pool.query(
        `DELETE FROM app_rows WHERE collection = 'payment_allocations' 
         AND (json->>'payment_id' = ANY($1) OR json->>'paymentId' = ANY($1))`,
        [paymentIds]
      );
    }
    
    // حذف رکوردهای اصلی با workshop_id
    await pool.query(
      `DELETE FROM app_rows 
       WHERE collection IN ('dispatches', 'sewing_deliveries', 'repair_returns', 'wage_ledger', 'payments') 
       AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`,
      [workshopId]
    );
    
    res.json({ 
      message: 'Workshop reset successfully', 
      workshopId,
      deletedDispatches: dispatchIds.length,
      deletedDeliveries: deliveryIds.length,
      deletedPayments: paymentIds.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ۲. پاک کردن تمام تراکنش‌ها (برای شروع از صفر - فقط ادمین)
app.delete('/api/admin/clear-all-transactions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  
  const transactionalCollections = [
    'dispatches', 'dispatch_lines', 'dispatch_size_qty',
    'workshop_receipts', 'workshop_receipt_lines',
    'sewing_deliveries', 'sewing_delivery_lines',
    'cut_defects', 'repair_returns',
    'wage_ledger', 'payments', 'payment_allocations',
    'adjustments', 'sync_queue', 'audit_log'
  ];
  
  try {
    const result = await pool.query(
      'DELETE FROM app_rows WHERE collection = ANY($1)',
      [transactionalCollections]
    );
    res.json({ message: `Cleared ${result.rowCount} transaction records` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
