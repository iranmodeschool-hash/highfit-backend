const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
});

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
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
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
        allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS allowed_apps JSONB DEFAULT '["doakhtyar"]'::jsonb;`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_rows (
        id VARCHAR(100) PRIMARY KEY,
        collection VARCHAR(50) NOT NULL,
        json JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Tables are ready and updated");
  } catch (err) { console.error("Error creating tables:", err); }
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

// ... (مسیرهای لاگین، کاربران، فروشگاه و آمار بدون تغییر) ...

app.post('/api/login', async (req, res) => {
  const { email, password, app_name } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    if (app_name && user.role !== 'admin') {
      const allowedApps = user.allowed_apps || [];
      if (!allowedApps.includes(app_name)) {
        return res.status(403).json({ error: `شما به اپلیکیشن ${app_name} دسترسی ندارید.` });
      }
    }

    const token = jwt.sign({ id: user.id, role: user.role, workshop_id: user.workshop_id }, process.env.JWT_SECRET || 'super-secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, workshop_id: user.workshop_id, allowed_apps: user.allowed_apps } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('SELECT id, username, email, role, workshop_id, allowed_apps, created_at FROM users ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, email, role, workshop_id, allowed_apps',
      [username, email, hashedPassword, role || 'workshop_manager', workshop_id || null, allowed_apps || '["doakhtyar"]']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  const { username, email, role, workshop_id, allowed_apps } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET username = $1, email = $2, role = $3, workshop_id = $4, allowed_apps = $5 WHERE id = $6 RETURNING id, username, email, role, workshop_id, allowed_apps',
      [username, email, role, workshop_id || null, allowed_apps || '["doakhtyar"]', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/role', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role', [req.body.role, req.params.id]);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

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

app.delete('/api/admin/reset-workshop/:workshopId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { workshopId } = req.params;
  try {
    const dispatchResult = await pool.query(`SELECT id FROM app_rows WHERE collection = 'dispatches' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`, [workshopId]);
    const dispatchIds = dispatchResult.rows.map(r => r.id);
    const deliveryResult = await pool.query(`SELECT id FROM app_rows WHERE collection = 'sewing_deliveries' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`, [workshopId]);
    const deliveryIds = deliveryResult.rows.map(r => r.id);
    const paymentResult = await pool.query(`SELECT id FROM app_rows WHERE collection = 'payments' AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`, [workshopId]);
    const paymentIds = paymentResult.rows.map(r => r.id);

    if (dispatchIds.length > 0) {
      await pool.query(`DELETE FROM app_rows WHERE collection IN ('dispatch_lines', 'workshop_receipts', 'cut_defects', 'dispatch_size_qty') AND (json->>'dispatch_id' = ANY($1) OR json->>'dispatchId' = ANY($1))`, [dispatchIds]);
    }
    if (deliveryIds.length > 0) {
      await pool.query(`DELETE FROM app_rows WHERE collection = 'sewing_delivery_lines' AND (json->>'delivery_id' = ANY($1) OR json->>'deliveryId' = ANY($1))`, [deliveryIds]);
    }
    if (paymentIds.length > 0) {
      await pool.query(`DELETE FROM app_rows WHERE collection = 'payment_allocations' AND (json->>'payment_id' = ANY($1) OR json->>'paymentId' = ANY($1))`, [paymentIds]);
    }
    await pool.query(`DELETE FROM app_rows WHERE collection IN ('dispatches', 'sewing_deliveries', 'repair_returns', 'wage_ledger', 'payments') AND (json->>'workshop_id' = $1 OR json->>'workshopId' = $1)`, [workshopId]);
    res.json({ message: 'Workshop reset successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/clear-all-transactions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const transactionalCollections = ['dispatches', 'dispatch_lines', 'dispatch_size_qty', 'workshop_receipts', 'workshop_receipt_lines', 'sewing_deliveries', 'sewing_delivery_lines', 'cut_defects', 'repair_returns', 'wage_ledger', 'payments', 'payment_allocations', 'adjustments', 'sync_queue', 'audit_log'];
  try {
    const result = await pool.query('DELETE FROM app_rows WHERE collection = ANY($1)', [transactionalCollections]);
    res.json({ message: `Cleared ${result.rowCount} transaction records` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- چت آنلاین با قابلیت وضعیت (تیک) ---
app.post('/api/chat/send', authenticateToken, async (req, res) => {
  const { receiver_id, text } = req.body;
  const sender_id = req.user.id;
  if (!receiver_id || !text) return res.status(400).json({ error: 'Receiver and text are required' });

  try {
    const messageId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);
    const messageData = {
      id: messageId,
      sender_id,
      receiver_id,
      text,
      status: 'sent', // وضعیت‌ها: sent, delivered, seen
      created_at: new Date().toISOString()
    };
    await pool.query(
      `INSERT INTO app_rows (id, collection, json) VALUES ($1, $2, $3)`,
      [messageId, 'messages', messageData]
    );
    res.status(201).json(messageData);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/messages/:contactId', authenticateToken, async (req, res) => {
  const myId = req.user.id;
  const contactId = req.params.contactId;

  try {
    // علامت زدن پیام‌هایی که برای من فرستاده شده‌اند به عنوان «تحویل داده شده» (اگر قبلاً فقط sent بوده‌اند)
    await pool.query(
      `UPDATE app_rows 
       SET json = jsonb_set(json, '{status}', '"delivered"')
       WHERE collection = 'messages' 
       AND json->>'sender_id' = $1 
       AND json->>'receiver_id' = $2 
       AND json->>'status' = 'sent'`,
      [contactId.toString(), myId.toString()]
    );

    const result = await pool.query(
      `SELECT json FROM app_rows 
       WHERE collection = 'messages' 
       AND (
         (json->>'sender_id' = $1 AND json->>'receiver_id' = $2) OR 
         (json->>'sender_id' = $2 AND json->>'receiver_id' = $1)
       )
       ORDER BY (json->>'created_at') ASC`,
      [myId.toString(), contactId.toString()]
    );

    res.json(result.rows.map(row => row.json));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// مسیر جدید برای علامت زدن پیام‌ها به عنوان «دیده شده» (Seen)
app.put('/api/chat/seen/:contactId', authenticateToken, async (req, res) => {
  const myId = req.user.id;
  const contactId = req.params.contactId;
  try {
    await pool.query(
      `UPDATE app_rows 
       SET json = jsonb_set(json, '{status}', '"seen"')
       WHERE collection = 'messages' 
       AND json->>'sender_id' = $1 
       AND json->>'receiver_id' = $2 
       AND json->>'status' IN ('sent', 'delivered')`,
      [contactId.toString(), myId.toString()]
    );
    res.json({ message: 'Messages marked as seen' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/contacts', authenticateToken, async (req, res) => {
  try {
    let query = 'SELECT id, username, role, workshop_id FROM users';
    let params = [];
    if (req.user.role !== 'admin') {
      query += ' WHERE role = $1';
      params.push('admin');
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [users, workshops, products, dispatches, deliveries, defects] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection = 'workshops'`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection = 'products'`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection = 'dispatches'`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection = 'sewing_deliveries'`),
      pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection = 'cut_defects'`)
    ]);
    res.json({
      users: parseInt(users.rows[0].count),
      workshops: parseInt(workshops.rows[0].count),
      products: parseInt(products.rows[0].count),
      dispatches: parseInt(dispatches.rows[0].count),
      deliveries: parseInt(deliveries.rows[0].count),
      defects: parseInt(defects.rows[0].count)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
