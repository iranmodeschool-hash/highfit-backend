const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
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
  try {
    req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET || 'super-secret-key');
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const safeParse = (data, dbId) => {
  let obj = data;
  if (typeof obj === 'string') {
    try { obj = JSON.parse(obj); } catch (e) { obj = {}; }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) obj = {};
  return { ...obj, id: obj.id || dbId || Math.random().toString(36).substring(7) };
};

// ===== ابزارهای تراکنشی خرابی برش و مرجوعی تعمیراتی =====
const makeId = (prefix = 'row') => `${prefix}_${crypto.randomUUID()}`;
const isoNow = () => new Date().toISOString();
const asInt = (v) => Number.isSafeInteger(Number(v)) ? Number(v) : NaN;
const isNonNegativeInt = (v) => Number.isSafeInteger(v) && v >= 0;
const isPositiveInt = (v) => Number.isSafeInteger(v) && v > 0;
const sameId = (a, b) => String(a ?? '') === String(b ?? '');
const field = (obj, snake, camel) => obj?.[snake] ?? obj?.[camel];

async function txRows(client, collection) {
  const r = await client.query('SELECT id, json FROM app_rows WHERE collection=$1', [collection]);
  return r.rows.map(x => safeParse(x.json, x.id));
}

async function txFind(client, collection, id) {
  const r = await client.query(
    'SELECT id, json FROM app_rows WHERE id=$1 AND collection=$2 FOR UPDATE',
    [String(id), collection]
  );
  return r.rows.length ? safeParse(r.rows[0].json, r.rows[0].id) : null;
}

async function txSave(client, collection, obj) {
  const row = { ...obj, id: String(obj.id) };
  const r = await client.query(
    'INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json WHERE app_rows.collection=EXCLUDED.collection RETURNING id',
    [row.id, collection, JSON.stringify(row)]
  );
  if (!r.rowCount) throw new Error('شناسه با مجموعهٔ دیگری تداخل دارد.');
  return row;
}

function canonicalDefectStatus(status) {
  if (['pending', 'declared', 'pending_manager'].includes(String(status || ''))) return 'pending';
  if (['reviewed', 'approved', 'rejected', 'replacement', 'recut', 'scrapped'].includes(String(status || ''))) return 'reviewed';
  return 'pending';
}

function canonicalRepairStatus(status) {
  if (['submitted', 'pending_workshop_report'].includes(String(status || ''))) return 'pending_workshop_report';
  if (['ready_review', 'pending_admin_decision'].includes(String(status || ''))) return 'pending_admin_decision';
  if (['closed', 'completed'].includes(String(status || ''))) return 'completed';
  return 'pending_workshop_report';
}

function normalizeRepairRow(raw) {
  const row = safeParse(raw, raw?.id);

  if (Array.isArray(row.rounds) && row.rounds.length) {
    const round = row.rounds.find(x => String(x.id) === String(row.current_round_id)) || row.rounds[row.rounds.length - 1];
    return {
      ...row,
      status: canonicalRepairStatus(row.status),
      current_round_id: round.id,
      current_qty: Number(row.current_qty ?? round.qty ?? row.qty_original ?? row.qty ?? 0),
      qty_original: Number(row.qty_original ?? row.qty ?? 0),
      qty: Number(row.qty_original ?? row.qty ?? 0),
      workshop_report: round.workshop_report ?? row.workshop_report ?? null,
      qty_repaired: Number(round.workshop_report?.qty_repaired ?? row.qty_repaired ?? 0),
      qty_unrepairable: Number(round.workshop_report?.qty_unrepairable ?? row.qty_unrepairable ?? 0),
      qty_needs_review: Number(round.workshop_report?.qty_needs_review ?? row.qty_needs_review ?? 0),
      decisions: round.decisions ?? row.decisions ?? {},
      rounds: row.rounds,
    };
  }

  const status = canonicalRepairStatus(row.status);
  const original = Math.max(0, Number(row.qty_original ?? row.qty ?? row.quantity ?? 0) || 0);
  const legacyCounts = row.workshop_report || row.result_counts ||
    (row.qty_repaired != null || row.qty_unrepairable != null || row.qty_needs_review != null ? {
      qty_repaired: Number(row.qty_repaired || 0),
      qty_unrepairable: Number(row.qty_unrepairable || 0),
      qty_needs_review: Number(row.qty_needs_review || 0),
      note: row.result_note || ''
    } : null);

  const report = legacyCounts ? {
    qty_repaired: Number(legacyCounts.qty_repaired ?? legacyCounts.repaired ?? 0),
    qty_unrepairable: Number(legacyCounts.qty_unrepairable ?? legacyCounts.unrepairable ?? 0),
    qty_needs_review: Number(legacyCounts.qty_needs_review ?? legacyCounts.needs_review ?? 0),
    note: String(legacyCounts.note ?? row.result_note ?? ''),
    created_at: legacyCounts.created_at ?? row.reviewed_at ?? row.created_at,
  } : null;

  const roundQty = status === 'pending_admin_decision' && report
    ? Number(report.qty_repaired || 0) + Number(report.qty_unrepairable || 0) + Number(report.qty_needs_review || 0)
    : original;

  const round = {
    id: `legacy_${row.id}`,
    qty: roundQty || original,
    status,
    created_at: row.created_at || isoNow(),
    workshop_report: report,
    decisions: row.decisions || row.group_decisions || {}
  };

  const out = {
    ...row,
    status,
    qty: original,
    qty_original: original,
    current_round_id: round.id,
    current_qty: status === 'completed' ? 0 : status === 'pending_admin_decision' ? (roundQty || original) : original,
    rounds: [round],
    workshop_report: report,
    qty_repaired: Number(report?.qty_repaired || 0),
    qty_unrepairable: Number(report?.qty_unrepairable || 0),
    qty_needs_review: Number(report?.qty_needs_review || 0),
    decisions: round.decisions,
    wage_released_qty: Number(row.wage_released_qty || 0),
    wage_applied_qty: Number(row.wage_applied_qty || 0),
  };

  if (!row.document_id) out.document_id = row.id;
  return out;
}

function decisionValue(raw) {
  return typeof raw === 'string' ? raw : raw && typeof raw === 'object' ? raw.decision : '';
}

function reportForRound(round) {
  return round?.workshop_report || null;
}

function pendingRepairQty(raw) {
  const row = normalizeRepairRow(raw);
  if (row.status === 'pending_workshop_report') return Math.max(0, Number(row.current_qty || 0));
  if (row.status !== 'pending_admin_decision') return 0;

  const round = row.rounds.find(x => String(x.id) === String(row.current_round_id)) || row.rounds[row.rounds.length - 1];
  const report = reportForRound(round);
  if (!report) return Math.max(0, Number(row.current_qty || 0));

  const groups = [
    ['repaired', Number(report.qty_repaired || 0)],
    ['unrepairable', Number(report.qty_unrepairable || 0)],
    ['needs_review', Number(report.qty_needs_review || 0)],
  ];

  return groups.reduce((sum, [group, qty]) => {
    if (!qty) return sum;
    const decision = decisionValue(round.decisions?.[group]);
    const finalRepair = (group === 'repaired' && decision === 'accept') ||
      (group === 'needs_review' && decision === 'accept_repair');
    const finalScrap = (group === 'unrepairable' && decision === 'accept_as_scrap') ||
      (group === 'needs_review' && decision === 'accept_scrap');
    return sum + (finalRepair || finalScrap ? 0 : Number(qty));
  }, 0);
}

function scrapRepairQty(raw) {
  const original = safeParse(raw, raw?.id);
  if (!Array.isArray(original.rounds)) {
    if (['closed', 'completed'].includes(String(original.status)) && original.wage_effect === 'deduction') {
      const counts = original.result_counts || {};
      return Number(counts.qty_unrepairable ?? counts.unrepairable ?? original.qty ?? 0) || 0;
    }
    return 0;
  }

  const row = normalizeRepairRow(original);
  return row.rounds.reduce((sum, round) => {
    const report = round.workshop_report || {};
    const decisions = round.decisions || {};
    const unrepairable = Number(report.qty_unrepairable || 0);
    const needsReview = Number(report.qty_needs_review || 0);
    return sum + (decisionValue(decisions.unrepairable) === 'accept_as_scrap' ? unrepairable : 0)
      + (['accept_scrap', 'accept_as_scrap'].includes(decisionValue(decisions.needs_review)) ? needsReview : 0);
  }, 0);
}

function documentStatus(lines) {
  if (lines.some(x => canonicalRepairStatus(x.status) === 'pending_workshop_report')) return 'pending_workshop_report';
  if (lines.some(x => canonicalRepairStatus(x.status) === 'pending_admin_decision')) return 'pending_admin_decision';
  return 'completed';
}

function groupRepairDocuments(rawRows) {
  const groups = new Map();
  for (const raw of rawRows) {
    const row = normalizeRepairRow(raw);
    const docId = String(row.document_id || row.id);
    if (!groups.has(docId)) groups.set(docId, []);
    groups.get(docId).push(row);
  }

  return [...groups.entries()].map(([docId, lines]) => {
    const first = lines[0];
    const total = lines.reduce((s, x) => s + (Number(x.qty_original ?? x.qty ?? 0) || 0), 0);
    return {
      id: docId,
      document_id: docId,
      serial: first.document_number || first.serial || docId,
      document_number: first.document_number || first.serial || docId,
      dispatch_id: first.dispatch_id,
      workshop_id: first.workshop_id,
      workshop_name: first.workshop_name,
      created_at: lines.map(x => x.created_at).filter(Boolean).sort()[0] || isoNow(),
      qty: total,
      qty_original: total,
      status: documentStatus(lines),
      lines,
    };
  }).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

async function paidForLedger(client, ledgerId) {
  const rows = await txRows(client, 'payment_allocations');
  return rows.filter(x => sameId(x.wage_ledger_id, ledgerId))
    .reduce((n, x) => n + (Number(x.allocated_amount) || 0), 0);
}

async function syncRepairWageHold(client, rawRepair) {
  let repair = normalizeRepairRow(rawRepair);
  const qtyOriginal = Math.max(0, Number(repair.qty_original ?? repair.qty ?? 0) || 0);
  const released = Math.max(0, Number(repair.wage_released_qty || 0) || 0);
  const desiredHeld = Math.max(0, qtyOriginal - released);
  const appliedHeld = Math.max(0, Number(repair.wage_applied_qty || 0) || 0);
  const deltaQty = desiredHeld - appliedHeld;
  const ledgerRows = await txRows(client, 'wage_ledger');
  const ledger = ledgerRows.find(x => sameId(x.source_id, repair.delivery_line_id));
  if (!ledger) return repair;
  if (!deltaQty) return repair;

  const unit = Number.isSafeInteger(Number(ledger.rate_amount_snapshot)) && Number(ledger.rate_amount_snapshot) >= 0
    ? Number(ledger.rate_amount_snapshot)
    : (Number(ledger.qty_base) > 0
      ? Math.round(Number(ledger.gross_amount || 0) / Number(ledger.qty_base))
      : NaN);

  if (!Number.isSafeInteger(unit) || unit < 0) {
    throw new Error('نرخ تاریخی دستمزد برای اعمال اثر مرجوعی معتبر نیست.');
  }

  const deltaAmount = -deltaQty * unit;
  if (!Number.isSafeInteger(deltaAmount)) {
    throw new Error('مبلغ اثر مرجوعی معتبر نیست.');
  }

  const nextNet = (Number(ledger.net_amount ?? ledger.gross_amount) || 0) + deltaAmount;
  const nextAdjustment = (Number(ledger.adjustment_amount) || 0) + deltaAmount;
  const paid = await paidForLedger(client, ledger.id);
  const payment_status = nextNet < paid ? 'recovery_due'
    : nextNet === paid ? 'paid'
    : paid > 0 ? 'partial' : 'unpaid';

  await txSave(client, 'wage_ledger', {
    ...ledger,
    net_amount: nextNet,
    adjustment_amount: nextAdjustment,
    payment_status
  });

  const adjustment = {
    id: makeId('adj'),
    target_type: 'wage_ledger',
    target_id: String(ledger.id),
    repair_return_id: String(repair.id),
    amount: deltaAmount,
    reason: `اثر دستمزد مرجوعی تعمیراتی ${repair.document_number || repair.document_id || repair.id}`,
    status: 'approved',
    category: 'repair_wage_hold',
    created_at: isoNow(),
  };

  await txSave(client, 'adjustments', adjustment);

  repair = { ...repair, wage_applied_qty: desiredHeld, wage_unit_rate: unit };
  await txSave(client, 'repair_returns', repair);
  return repair;
}

async function recalcDeliveryLineReturnSummary(client, deliveryLineId) {
  const [repairRows, deliveryLines] = await Promise.all([
    txRows(client, 'repair_returns'),
    txRows(client, 'sewing_delivery_lines')
  ]);

  const pending = repairRows
    .filter(x => sameId(x.delivery_line_id, deliveryLineId))
    .reduce((sum, x) => sum + pendingRepairQty(x), 0);

  const scrap = repairRows
    .filter(x => sameId(x.delivery_line_id, deliveryLineId))
    .reduce((sum, x) => sum + scrapRepairQty(x), 0);

  const line = deliveryLines.find(x => sameId(x.id, deliveryLineId));
  if (line) {
    await txSave(client, 'sewing_delivery_lines', {
      ...line,
      qty_returned_pending: pending,
      qty_scrap: scrap
    });
  }
}

async function serializableTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('LOCK TABLE app_rows IN SHARE ROW EXCLUSIVE MODE');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw error;
  } finally {
    client.release();
  }
}

app.get('/', (req, res) => res.send('HighFit Backend is running perfectly!'));

app.post('/api/force-create-admin', async (req, res) => {
  const expected = String(process.env.ADMIN_SETUP_SECRET || '');
  const supplied = String(req.headers['x-admin-setup-secret'] || '');
  const expectedBytes = Buffer.from(expected);
  const suppliedBytes = Buffer.from(supplied);

  if (
    !expected || !supplied ||
    expectedBytes.length !== suppliedBytes.length ||
    !crypto.timingSafeEqual(expectedBytes, suppliedBytes)
  ) {
    return res.status(404).json({ message: 'مسیر یافت نشد.' });
  }

  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || password.length > 200) {
    return res.status(400).json({ message: 'ایمیل معتبر و گذرواژه‌ای با حداقل ۱۲ نویسه لازم است.' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const check = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (check.rows.length > 0) {
      await pool.query("UPDATE users SET role='admin', password_hash=$1 WHERE email=$2", [hashed, email]);
      return res.json({ message: 'دسترسی مدیر به‌روزرسانی شد.' });
    }

    const baseUsername = 'HAMID';
    const usernameExists = await pool.query('SELECT id FROM users WHERE username=$1', [baseUsername]);
    const username = usernameExists.rows.length
      ? `ADMIN_${crypto.randomBytes(4).toString('hex').toUpperCase()}`
      : baseUsername;

    await pool.query(
      'INSERT INTO users (username, email, password_hash, role, allowed_apps) VALUES ($1,$2,$3,$4,$5)',
      [username, email, hashed, 'admin', '["doakhtyar","petty_cash"]']
    );

    return res.status(201).json({ message: 'مدیر جدید ایجاد شد.' });
  } catch (err) {
    console.error('Admin setup failed:', err);
    return res.status(500).json({ message: 'راه‌اندازی مدیر انجام نشد.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password, app_name } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid' });
    const u = r.rows[0];
    if (!(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Invalid' });
    if (app_name && u.role !== 'admin' && !(u.allowed_apps || []).includes(app_name)) {
      return res.status(403).json({ error: 'No access' });
    }

    const token = jwt.sign(
      { id: u.id, role: u.role, workshop_id: u.workshop_id },
      process.env.JWT_SECRET || 'super-secret-key',
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: {
        id: u.id,
        username: u.username,
        email: u.email,
        role: u.role,
        workshop_id: u.workshop_id,
        allowed_apps: u.allowed_apps
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== مدیریت کاربران =====
app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const r = await pool.query(
    'SELECT id, username, email, role, workshop_id, allowed_apps, created_at FROM users ORDER BY id DESC'
  );
  res.json(r.rows);
});

app.post('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, email, role, workshop_id, allowed_apps',
      [username, email, hashed, role || 'workshop_manager', workshop_id || null, allowed_apps || '["doakhtyar"]']
    );
    res.status(201).json(r.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, allowed_apps } = req.body;

  try {
    const r = await pool.query(
      'UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, allowed_apps=$5 WHERE id=$6 RETURNING id, username, email, role, workshop_id, allowed_apps',
      [username, email, role, workshop_id || null, allowed_apps || '["doakhtyar"]', req.params.id]
    );
    res.json(r.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

// اعلام خرابی برش: فقط مسئول کارگاه
app.post('/api/store/cut_defects', auth, async (req, res) => {
  if (req.user.role !== 'workshop_manager') {
    return res.status(403).json({ message: 'اعلام خرابی برش فقط برای مسئول کارگاه مجاز است.' });
  }

  const fields = req.body || {};
  const dispatchId = String(fields.dispatch_id ?? '');
  const lineId = String(fields.dispatch_line_id ?? '');
  const sizeId = String(fields.size_id ?? '');
  const count = asInt(fields.declared_qty);
  const note = String(fields.note ?? '').trim();

  if (!dispatchId || !lineId || !sizeId || !isPositiveInt(count) || note.length > 500) {
    return res.status(400).json({
      message: 'حواله، ردیف، سایز و تعداد صحیح مثبت الزامی است؛ توضیح حداکثر ۵۰۰ نویسه باشد.'
    });
  }

  try {
    const saved = await serializableTransaction(async client => {
      const [dispatches, lines, quantities, receiptHeads, receiptLines, defects, deliveries, deliveryLines] =
        await Promise.all([
          txRows(client, 'dispatches'),
          txRows(client, 'dispatch_lines'),
          txRows(client, 'dispatch_size_qty'),
          txRows(client, 'workshop_receipts'),
          txRows(client, 'workshop_receipt_lines'),
          txRows(client, 'cut_defects'),
          txRows(client, 'sewing_deliveries'),
          txRows(client, 'sewing_delivery_lines')
        ]);

      const dispatch = dispatches.find(x => sameId(x.id, dispatchId));
      const sourceLine = lines.find(x =>
        sameId(x.id, lineId) && sameId(x.dispatch_id, dispatchId)
      );
      const sizeLine = quantities.find(x =>
        sameId(x.dispatch_line_id, lineId) && sameId(x.size_id, sizeId)
      );

      if (
        !dispatch ||
        !['partial_received', 'fully_received'].includes(dispatch.status) ||
        !sameId(dispatch.workshop_id, req.user.workshop_id) ||
        !sourceLine ||
        !sizeLine
      ) {
        throw Object.assign(
          new Error('ردیف یا سایز متعلق به حوالهٔ دریافتی همین کارگاه نیست.'),
          { status: 403 }
        );
      }

      const received = receiptLines
        .filter(x =>
          sameId(x.dispatch_line_id, lineId) &&
          sameId(x.size_id, sizeId) &&
          receiptHeads.some(r => sameId(r.id, x.receipt_id) && r.status === 'approved')
        )
        .reduce((sum, x) => sum + (Number(x.actual_qty) || 0), 0);

      const approvedScrap = defects
        .filter(x =>
          sameId(x.dispatch_line_id, lineId) &&
          sameId(x.size_id, sizeId) &&
          ['reviewed', 'approved', 'scrapped'].includes(String(x.status))
        )
        .reduce((sum, x) =>
          sum + (Number(x.approved_qty) || (x.status === 'scrapped' ? Number(x.declared_qty) || 0 : 0)), 0
        );

      const approvedSewn = deliveryLines
        .filter(x =>
          sameId(x.dispatch_line_id, lineId) &&
          sameId(x.size_id, sizeId) &&
          deliveries.some(d => sameId(d.id, x.delivery_id) && d.status === 'approved')
        )
        .reduce((sum, x) => sum + (Number(x.qty_accepted) || 0), 0);

      const pendingSewn = deliveryLines
        .filter(x =>
          sameId(x.dispatch_line_id, lineId) &&
          sameId(x.size_id, sizeId) &&
          deliveries.some(d => sameId(d.id, x.delivery_id) && d.status === 'pending_approval')
        )
        .reduce((sum, x) => sum + (Number(x.qty_sewn ?? x.qty_delivered) || 0), 0);

      const pendingClaims = defects
        .filter(x =>
          sameId(x.dispatch_line_id, lineId) &&
          sameId(x.size_id, sizeId) &&
          ['pending', 'declared', 'pending_manager'].includes(String(x.status))
        )
        .reduce((sum, x) => sum + (Number(x.declared_qty) || 0), 0);

      const available = Math.max(
        0,
        received - approvedScrap - approvedSewn - pendingSewn - pendingClaims
      );

      if (count > available) {
        throw Object.assign(
          new Error(`تعداد اعلامی از ماندهٔ قابل تخصیص بیشتر است. حداکثر مجاز: ${available}`),
          { status: 409 }
        );
      }

      const created = {
        id: makeId('defect'),
        dispatch_id: dispatchId,
        dispatch_line_id: lineId,
        size_id: sizeId,
        declared_qty: count,
        approved_qty: null,
        rejected_qty: null,
        corrected_qty: null,
        defect_type: 'cut',
        responsibility: 'unknown',
        note,
        status: 'pending',
        review_note: '',
        created_at: isoNow(),
        reviewed_at: null,
        created_by: String(req.user.id || ''),
        workshop_id: String(dispatch.workshop_id)
      };

      await txSave(client, 'cut_defects', created);
      return created;
    });

    res.status(201).json(saved);
  } catch (err) {
    const status = err.status || 500;
    console.error('Cut defect declaration failed:', err);
    res.status(status).json({
      message: status === 500 ? 'ثبت خرابی برش انجام نشد.' : err.message
    });
  }
});

// ===== Store عمومی =====
app.get('/api/store/:collection', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, json FROM app_rows WHERE collection=$1',
      [req.params.collection]
    );
    res.json(r.rows.map(x => safeParse(x.json, x.id)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/store/:collection', auth, async (req, res) => {
  try {
    const collection = req.params.collection;

    if (['cut_defects', 'repair_returns'].includes(collection)) {
      return res.status(405).json({
        message: 'تغییر این اطلاعات فقط از مسیر اختصاصی و معتبر مجاز است.'
      });
    }

    const data = req.body;
    if (!data || Object.keys(data).length === 0) {
      return res.status(400).json({ error: 'سند خالی قابل ثبت نیست.' });
    }

    const id = data.id || Date.now().toString();
    await pool.query(
      'INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET json=EXCLUDED.json WHERE app_rows.collection=EXCLUDED.collection',
      [id, collection, JSON.stringify({ ...data, id })]
    );

    if (collection === 'wage_ledger') {
      try {
        await serializableTransaction(async client => {
          const repairs = (await txRows(client, 'repair_returns'))
            .filter(x => sameId(x.delivery_line_id, data.source_id));
          for (const repair of repairs) await syncRepairWageHold(client, repair);
        });
      } catch (holdError) {
        console.error('Could not reconcile pending repair wage hold:', holdError);
      }
    }

    res.json({ message: 'Saved', id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/store/:collection/:id', auth, async (req, res) => {
  try {
    if (['cut_defects', 'repair_returns'].includes(String(req.params.collection))) {
      return res.status(405).json({
        message: 'حذف مستقیم سوابق خرابی برش و مرجوعی مجاز نیست.'
      });
    }
    await pool.query(
      'DELETE FROM app_rows WHERE id=$1 AND collection=$2',
      [req.params.id, req.params.collection]
    );
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// فهرست خرابی‌های برش؛ فقط مدیر کل
app.get('/api/cut-defects', auth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'بررسی خرابی برش فقط برای مدیر کل مجاز است.' });
  }

  try {
    const rows = await pool.query("SELECT id, json FROM app_rows WHERE collection='cut_defects'");
    const result = rows.rows.map(x => {
      const row = safeParse(x.json, x.id);
      return { ...row, status: canonicalDefectStatus(row.status) };
    }).sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

    res.json(result);
  } catch (err) {
    console.error('Cut defects list failed:', err);
    res.status(500).json({ message: 'خواندن فهرست خرابی‌های برش انجام نشد.' });
  }
});

// تصمیم خرابی برش؛ فقط مدیر کل
app.put('/api/cut-defects/:id/decide', auth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'تصمیم خرابی برش فقط برای مدیر کل مجاز است.' });
  }

  const { approved_qty, rejected_qty, corrected_qty } = req.body || {};
  const note = String(req.body?.note ?? '').trim();

  if (![approved_qty, rejected_qty, corrected_qty].every(isNonNegativeInt) || note.length > 500) {
    return res.status(400).json({ message: 'سه تعداد صحیح نامنفی و یادداشت معتبر وارد کنید.' });
  }

  try {
    const updated = await serializableTransaction(async client => {
      const row = await txFind(client, 'cut_defects', req.params.id);
      if (!row) {
        throw Object.assign(new Error('رکورد خرابی یافت نشد.'), { status: 404 });
      }

      if (!['pending', 'declared', 'pending_manager'].includes(String(row.status || ''))) {
        throw Object.assign(new Error('این خرابی قبلاً بررسی شده یا در انتظار تصمیم نیست.'), { status: 409 });
      }

      const total = Number(row.declared_qty);
      if (!isPositiveInt(total) || approved_qty + rejected_qty + corrected_qty !== total) {
        throw Object.assign(
          new Error(`جمع تأیید (${approved_qty}) + رد (${rejected_qty}) + اصلاح‌شده (${corrected_qty}) باید دقیقاً برابر تعداد اعلامی (${total}) باشد.`),
          { status: 400 }
        );
      }

      const next = {
        ...row,
        approved_qty,
        rejected_qty,
        corrected_qty,
        status: 'reviewed',
        review_note: note,
        reviewed_at: isoNow(),
        reviewed_by: String(req.user.id || '')
      };

      await txSave(client, 'cut_defects', next);
      return next;
    });

    res.json({ message: 'تصمیم خرابی برش ثبت شد.', record: updated });
  } catch (err) {
    const status = err.status || 500;
    console.error('Cut defect decision failed:', err);
    res.status(status).json({
      message: status === 500 ? 'ثبت تصمیم خرابی برش انجام نشد.' : err.message
    });
  }
});

// ===== آمار داشبورد =====
app.get('/api/dashboard/stats', auth, async (req, res) => {
  let response = {
    users: 0, workshops: 0, products: 0, dispatches: 0,
    actual_dispatched: 0, deliveries: 0, actual_delivered: 0,
    pending_returns: 0, pending_defects: 0, total_wage: 0,
    total_scrap: 0, scrap_from_cut: 0, scrap_from_sewing: 0
  };

  try {
    const isAdmin = req.user.role === 'admin';
    const wid = req.user.workshop_id;
    const filter = !isAdmin && wid
      ? ` AND (json->>'workshop_id' = '${wid}' OR json->>'workshopId' = '${wid}')`
      : '';

    if (isAdmin) {
      const u = await pool.query('SELECT COUNT(*) FROM users');
      response.users = parseInt(u.rows[0].count) || 0;
    }

    const w = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='workshops'${filter}`);
    response.workshops = parseInt(w.rows[0].count) || 0;

    const p = await pool.query(`SELECT COUNT(*) FROM app_rows WHERE collection='products'${filter}`);
    response.products = parseInt(p.rows[0].count) || 0;

    let totalDispatched = 0;
    const dq = await pool.query("SELECT json FROM app_rows WHERE collection='dispatch_size_qty'");
    for (const row of dq.rows) {
      const p = safeParse(row.json, row.id);
      totalDispatched += parseInt(p.qty) || 0;
    }
    response.dispatches = totalDispatched;

    let pendingDefectsCount = 0;
    let scrapFromCut = 0;
    const df = await pool.query("SELECT id, json FROM app_rows WHERE collection='cut_defects'");

    for (const row of df.rows) {
      const p = safeParse(row.json, row.id);
      if (['reviewed', 'approved', 'scrapped'].includes(String(p.status || ''))) {
        scrapFromCut += parseInt(p.approved_qty || (p.status === 'scrapped' ? p.declared_qty : 0)) || 0;
      }
      if (['pending', 'declared', 'pending_manager'].includes(String(p.status || ''))) {
        pendingDefectsCount++;
      }
    }

    response.actual_dispatched = Math.max(0, response.dispatches - scrapFromCut);
    response.pending_defects = pendingDefectsCount;
    response.scrap_from_cut = scrapFromCut;

    const [deliveryLineResult, deliveryResult, repairResult] = await Promise.all([
      pool.query("SELECT id, json FROM app_rows WHERE collection='sewing_delivery_lines'"),
      pool.query("SELECT id, json FROM app_rows WHERE collection='sewing_deliveries'"),
      pool.query("SELECT id, json FROM app_rows WHERE collection='repair_returns'")
    ]);

    const deliveryLines = deliveryLineResult.rows.map(row => safeParse(row.json, row.id));
    const deliveries = deliveryResult.rows.map(row => safeParse(row.json, row.id));
    const repairRows = repairResult.rows.map(row => safeParse(row.json, row.id));

    let totalDelivered = 0;
    let actualDelivered = 0;
    let scrapFromSewing = 0;
    let pendingReturnsCount = 0;

    for (const line of deliveryLines) {
      const head = deliveries.find(d => sameId(d.id, line.delivery_id));
      if (!head || head.status !== 'approved') continue;

      const initial = Math.max(0, parseInt(line.qty_delivered ?? line.qty_sewn) || 0);
      const linkedReturns = repairRows.filter(r => sameId(r.delivery_line_id, line.id));

      const pending = line.qty_returned_pending == null
        ? linkedReturns.reduce((sum, r) => sum + pendingRepairQty(r), 0)
        : Math.max(0, Number(line.qty_returned_pending) || 0);

      const scrap = line.qty_scrap == null
        ? linkedReturns.reduce((sum, r) => sum + scrapRepairQty(r), 0)
        : Math.max(0, Number(line.qty_scrap) || 0);

      totalDelivered += initial;
      actualDelivered += Math.max(0, initial - pending - scrap);
      scrapFromSewing += scrap;
      pendingReturnsCount += linkedReturns.filter(r => pendingRepairQty(r) > 0).length;
    }

    response.deliveries = totalDelivered;
    response.actual_delivered = actualDelivered;
    response.pending_returns = pendingReturnsCount;
    response.scrap_from_sewing = scrapFromSewing;

    let totalWage = 0;
    const tw = await pool.query("SELECT json FROM app_rows WHERE collection='wage_ledger'");
    for (const row of tw.rows) {
      const p = safeParse(row.json, row.id);
      totalWage += parseFloat(p.net_amount) || 0;
    }

    response.total_wage = totalWage;
    response.total_scrap = scrapFromCut + scrapFromSewing;
  } catch (err) {
    console.error('Dashboard Stats Error:', err);
  }

  res.json(response);
});

app.get('/api/dashboard/alerts', auth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const alerts = [];

    if (isAdmin) {
      const pd = await pool.query(
        "SELECT COUNT(*) FROM app_rows WHERE collection='cut_defects' AND (json->>'status' IS NULL OR json->>'status' IN ('pending','declared','pending_manager'))"
      );

      if (parseInt(pd.rows[0].count) > 0) {
        alerts.push({
          type: 'defect',
          title: 'خرابی برش در انتظار تأیید',
          count: parseInt(pd.rows[0].count),
          link: '/cut-defects',
          color: 'orange'
        });
      }

      const pdv = await pool.query(
        "SELECT COUNT(*) FROM app_rows WHERE collection='sewing_deliveries' AND json->>'status'='pending_approval'"
      );

      if (parseInt(pdv.rows[0].count) > 0) {
        alerts.push({
          type: 'delivery',
          title: 'تحویل دوخت در انتظار تأیید',
          count: parseInt(pdv.rows[0].count),
          link: '/deliveries',
          color: 'green'
        });
      }
    }

    res.json(alerts);
  } catch (err) {
    res.json([]);
  }
});

// فهرست مرجوعی‌ها، گروه‌بندی‌شده بر اساس شناسه سند
app.get('/api/repair-returns', auth, async (req, res) => {
  if (!['admin', 'workshop_manager'].includes(req.user.role)) {
    return res.status(403).json({ message: 'دسترسی به مرجوعی تعمیراتی مجاز نیست.' });
  }

  try {
    const rows = (await pool.query(
      "SELECT id, json FROM app_rows WHERE collection='repair_returns'"
    )).rows.map(x => safeParse(x.json, x.id));

    const visible = req.user.role === 'admin'
      ? rows
      : rows.filter(x => sameId(x.workshop_id ?? x.workshopId, req.user.workshop_id));

    res.json(groupRepairDocuments(visible));
  } catch (err) {
    console.error('Repair list failed:', err);
    res.status(500).json({ message: 'خواندن فهرست مرجوعی‌ها انجام نشد.' });
  }
});

// ثبت سند مرجوعی؛ فقط مدیر کل
app.post('/api/repair-returns', auth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'ثبت مرجوعی فقط برای مدیر کل مجاز است.' });
  }

  const dispatchId = String(req.body?.dispatch_id ?? '');
  const linesInput = req.body?.lines;

  if (!dispatchId || !Array.isArray(linesInput) || !linesInput.length || linesInput.length > 100) {
    return res.status(400).json({ message: 'حواله و دست‌کم یک ردیف معتبر الزامی است.' });
  }

  const normalized = [];

  for (const line of linesInput) {
    const deliveryLineId = String(line?.delivery_line_id ?? '');
    const qty = asInt(line?.qty);
    const reason = String(line?.reason ?? '').trim();

    if (!deliveryLineId || !isPositiveInt(qty) || !reason || reason.length > 500) {
      return res.status(400).json({ message: 'ردیف، تعداد صحیح مثبت و دلیل حداکثر ۵۰۰ نویسه الزامی است.' });
    }

    normalized.push({ delivery_line_id: deliveryLineId, qty, reason });
  }

  try {
    const result = await serializableTransaction(async client => {
      const [dispatches, dispatchLines, deliveries, deliveryLines, repairRows] = await Promise.all([
        txRows(client, 'dispatches'),
        txRows(client, 'dispatch_lines'),
        txRows(client, 'sewing_deliveries'),
        txRows(client, 'sewing_delivery_lines'),
        txRows(client, 'repair_returns')
      ]);

      const dispatch = dispatches.find(x => sameId(x.id, dispatchId));
      if (!dispatch) throw Object.assign(new Error('حواله یافت نشد.'), { status: 404 });

      const aggregate = new Map();
      for (const item of normalized) {
        aggregate.set(
          item.delivery_line_id,
          (aggregate.get(item.delivery_line_id) || 0) + item.qty
        );
      }

      for (const [deliveryLineId, requested] of aggregate) {
        const line = deliveryLines.find(x => sameId(x.id, deliveryLineId));
        const delivery = line && deliveries.find(x => sameId(x.id, line.delivery_id));
        const sourceLine = line && dispatchLines.find(x => sameId(x.id, line.dispatch_line_id));

        if (
          !line ||
          !delivery ||
          delivery.status !== 'approved' ||
          !sameId(delivery.dispatch_id, dispatchId) ||
          !sourceLine ||
          !sameId(sourceLine.dispatch_id, dispatchId)
        ) {
          throw Object.assign(
            new Error('فقط ردیف تحویل تأییدشدهٔ همین حواله قابل مرجوعی است.'),
            { status: 400 }
          );
        }

        const accepted = Number(line.qty_accepted);
        if (!isNonNegativeInt(accepted) || accepted <= 0) {
          throw Object.assign(
            new Error('ردیف انتخاب‌شده تعداد تأییدشدهٔ معتبری ندارد.'),
            { status: 400 }
          );
        }

        const existing = repairRows.filter(x => sameId(x.delivery_line_id, deliveryLineId));
        const active = existing.reduce((sum, x) => sum + pendingRepairQty(x), 0);
        const scrap = existing.reduce((sum, x) => sum + scrapRepairQty(x), 0);
        const available = Math.max(0, accepted - active - scrap);

        if (requested > available) {
          throw Object.assign(
            new Error(`تعداد مرجوعی از تعداد تأییدشدهٔ آزاد بیشتر است. حداکثر مجاز: ${available}`),
            { status: 409 }
          );
        }
      }

      const documentId = makeId('repairdoc');
      const documentNumber = `MR-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
      const created = [];

      for (const item of normalized) {
        const line = deliveryLines.find(x => sameId(x.id, item.delivery_line_id));
        const delivery = deliveries.find(x => sameId(x.id, line.delivery_id));
        const roundId = makeId('round');
        const rowId = makeId('repair');

        const row = {
          id: rowId,
          document_id: documentId,
          document_number: documentNumber,
          serial: documentNumber,
          dispatch_id: dispatchId,
          delivery_id: delivery.id,
          delivery_line_id: line.id,
          dispatch_line_id: line.dispatch_line_id,
          size_id: line.size_id,
          workshop_id: String(delivery.workshop_id),
          qty: item.qty,
          qty_original: item.qty,
          current_qty: item.qty,
          reason: item.reason,
          status: 'pending_workshop_report',
          created_at: isoNow(),
          reviewed_at: null,
          current_round_id: roundId,
          rounds: [{
            id: roundId,
            qty: item.qty,
            status: 'pending_workshop_report',
            created_at: isoNow(),
            workshop_report: null,
            decisions: {}
          }],
          workshop_report: null,
          qty_repaired: 0,
          qty_unrepairable: 0,
          qty_needs_review: 0,
          decisions: {},
          history: [{
            id: makeId('event'),
            at: isoNow(),
            role: 'admin',
            action: 'return_registered',
            qty: item.qty,
            note: item.reason
          }],
          wage_released_qty: 0,
          wage_applied_qty: 0
        };

        await txSave(client, 'repair_returns', row);
        const withHold = await syncRepairWageHold(client, row);
        created.push(withHold);
      }

      for (const id of new Set(normalized.map(x => x.delivery_line_id))) {
        await recalcDeliveryLineReturnSummary(client, id);
      }

      return {
        id: documentId,
        document_id: documentId,
        serial: documentNumber,
        document_number: documentNumber,
        dispatch_id: dispatchId,
        workshop_id: dispatch.workshop_id,
        created_at: isoNow(),
        qty: created.reduce((s, x) => s + x.qty_original, 0),
        qty_original: created.reduce((s, x) => s + x.qty_original, 0),
        status: 'pending_workshop_report',
        lines: created
      };
    });

    res.status(201).json(result);
  } catch (err) {
    const status = err.status || 500;
    console.error('Repair creation failed:', err);
    res.status(status).json({
      message: status === 500 ? (err.message || 'ثبت مرجوعی تعمیراتی انجام نشد.') : err.message
    });
  }
});

// گزارش کارگاه برای یک ردیف مرجوعی
app.put('/api/repair-returns/:id/workshop-report', auth, async (req, res) => {
  if (req.user.role !== 'workshop_manager') {
    return res.status(403).json({ message: 'ثبت گزارش تعمیر فقط برای مسئول کارگاه مجاز است.' });
  }

  const body = req.body || {};
  const counts = {
    qty_repaired: body.qty_repaired,
    qty_unrepairable: body.qty_unrepairable,
    qty_needs_review: body.qty_needs_review
  };
  const note = String(body.note ?? '').trim();

  if (!Object.values(counts).every(isNonNegativeInt) || note.length > 500) {
    return res.status(400).json({ message: 'تعدادهای صحیح نامنفی و یادداشت معتبر وارد کنید.' });
  }

  try {
    const updated = await serializableTransaction(async client => {
      let row = await txFind(client, 'repair_returns', req.params.id);
      if (!row) throw Object.assign(new Error('ردیف مرجوعی یافت نشد.'), { status: 404 });

      row = normalizeRepairRow(row);

      if (!sameId(row.workshop_id, req.user.workshop_id)) {
        throw Object.assign(new Error('این مرجوعی متعلق به کارگاه شما نیست.'), { status: 403 });
      }

      if (row.status !== 'pending_workshop_report') {
        throw Object.assign(new Error('این ردیف در انتظار گزارش کارگاه نیست.'), { status: 409 });
      }

      const roundIndex = row.rounds.findIndex(x => sameId(x.id, row.current_round_id));
      const round = row.rounds[roundIndex];
      const total = Number(round?.qty ?? row.current_qty ?? row.qty_original);
      const sum = counts.qty_repaired + counts.qty_unrepairable + counts.qty_needs_review;

      if (!isPositiveInt(total) || sum !== total) {
        throw Object.assign(
          new Error(`جمع تعمیرشده، غیرقابل تعمیر و نیازمند بررسی باید دقیقاً برابر ${total} باشد.`),
          { status: 400 }
        );
      }

      const report = {
        ...counts,
        note,
        created_at: isoNow(),
        reported_by: String(req.user.id || '')
      };

      const nextRound = {
        ...round,
        status: 'pending_admin_decision',
        workshop_report: report,
        decisions: {}
      };

      const rounds = [...row.rounds];
      rounds[roundIndex] = nextRound;

      row = {
        ...row,
        status: 'pending_admin_decision',
        current_qty: total,
        rounds,
        workshop_report: report,
        qty_repaired: counts.qty_repaired,
        qty_unrepairable: counts.qty_unrepairable,
        qty_needs_review: counts.qty_needs_review,
        decisions: {},
        history: [
          ...(row.history || []),
          {
            id: makeId('event'),
            at: isoNow(),
            role: 'workshop_manager',
            action: 'workshop_reported',
            counts,
            note
          }
        ]
      };

      await txSave(client, 'repair_returns', row);
      row = await syncRepairWageHold(client, row);
      await recalcDeliveryLineReturnSummary(client, row.delivery_line_id);

      return row;
    });

    res.json({ message: 'گزارش کارگاه ثبت شد و در انتظار تصمیم مدیر است.', record: updated });
  } catch (err) {
    const status = err.status || 500;
    console.error('Repair report failed:', err);
    res.status(status).json({
      message: status === 500 ? 'ثبت گزارش کارگاه انجام نشد.' : err.message
    });
  }
});

// تصمیم جداگانه مدیر برای هر گروه
app.put('/api/repair-returns/:id/decide', auth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'تصمیم مرجوعی فقط برای مدیر کل مجاز است.' });
  }

  const group = String(req.body?.group ?? '');
  const decision = String(req.body?.decision ?? '');
  const note = String(req.body?.note ?? '').trim();

  const choices = {
    repaired: ['accept', 'reject'],
    unrepairable: ['accept_as_scrap', 'return_to_workshop'],
    needs_review: ['accept_repair', 'accept_scrap', 'return_to_workshop']
  };

  if (!choices[group]?.includes(decision) || note.length > 500) {
    return res.status(400).json({ message: 'گروه، تصمیم یا یادداشت معتبر نیست.' });
  }

  try {
    const updated = await serializableTransaction(async client => {
      let row = await txFind(client, 'repair_returns', req.params.id);
      if (!row) throw Object.assign(new Error('ردیف مرجوعی یافت نشد.'), { status: 404 });

      row = normalizeRepairRow(row);
      if (row.status !== 'pending_admin_decision') {
        throw Object.assign(new Error('این ردیف در انتظار تصمیم مدیر نیست.'), { status: 409 });
      }

      const roundIndex = row.rounds.findIndex(x => sameId(x.id, row.current_round_id));
      const round = row.rounds[roundIndex];
      const report = round?.workshop_report;

      if (!report) {
        throw Object.assign(new Error('ابتدا باید گزارش کارگاه ثبت شود.'), { status: 409 });
      }

      const countsByGroup = {
        repaired: Number(report.qty_repaired || 0),
        unrepairable: Number(report.qty_unrepairable || 0),
        needs_review: Number(report.qty_needs_review || 0)
      };

      const qty = countsByGroup[group];

      if (!qty) {
        throw Object.assign(new Error('برای این گروه تعداد مثبتی ثبت نشده است.'), { status: 400 });
      }

      if (decisionValue(round.decisions?.[group])) {
        throw Object.assign(new Error('برای این گروه قبلاً تصمیم ثبت شده است.'), { status: 409 });
      }

      const decisions = {
        ...(round.decisions || {}),
        [group]: {
          decision,
          note,
          qty,
          created_at: isoNow(),
          decided_by: String(req.user.id || '')
        }
      };

      const nextRound = { ...round, decisions };
      const rounds = [...row.rounds];
      rounds[roundIndex] = nextRound;

      const acceptedRepair =
        (group === 'repaired' && decision === 'accept') ||
        (group === 'needs_review' && decision === 'accept_repair');

      const wageReleasedQty =
        Number(row.wage_released_qty || 0) + (acceptedRepair ? qty : 0);

      row = {
        ...row,
        rounds,
        decisions,
        history: [
          ...(row.history || []),
          {
            id: makeId('event'),
            at: isoNow(),
            role: 'admin',
            action: 'group_decision',
            group,
            decision,
            qty,
            note
          }
        ],
        wage_released_qty: wageReleasedQty
      };

      const allGroups = Object.entries(countsByGroup)
        .filter(([, count]) => count > 0)
        .map(([key]) => key);

      const allDecided = allGroups.every(key => !!decisionValue(decisions[key]));

      if (allDecided) {
        rounds[roundIndex] = { ...rounds[roundIndex], status: 'completed', completed_at: isoNow() };

        const nextQty = Object.entries(countsByGroup).reduce((sum, [key, count]) => {
          const d = decisionValue(decisions[key]);

          const retry =
            (key === 'repaired' && d === 'reject') ||
            (key === 'unrepairable' && d === 'return_to_workshop') ||
            (key === 'needs_review' && d === 'return_to_workshop');

          return sum + (retry ? count : 0);
        }, 0);

        if (nextQty > 0) {
          const nextRoundId = makeId('round');

          rounds.push({
            id: nextRoundId,
            qty: nextQty,
            status: 'pending_workshop_report',
            created_at: isoNow(),
            workshop_report: null,
            decisions: {}
          });

          row = {
            ...row,
            rounds,
            current_round_id: nextRoundId,
            current_qty: nextQty,
            status: 'pending_workshop_report',
            workshop_report: null,
            qty_repaired: 0,
            qty_unrepairable: 0,
            qty_needs_review: 0,
            decisions: {},
            reviewed_at: null
          };
        } else {
          row = { ...row, rounds, current_qty: 0, status: 'completed', reviewed_at: isoNow() };
        }
      } else {
        row = {
          ...row,
          status: 'pending_admin_decision',
          current_qty: Number(round.qty || row.current_qty || 0),
          workshop_report: report,
          qty_repaired: countsByGroup.repaired,
          qty_unrepairable: countsByGroup.unrepairable,
          qty_needs_review: countsByGroup.needs_review,
          decisions
        };
      }

      await txSave(client, 'repair_returns', row);
      row = await syncRepairWageHold(client, row);
      await recalcDeliveryLineReturnSummary(client, row.delivery_line_id);

      return row;
    });

    res.json({ message: 'تصمیم گروه ثبت شد.', record: updated });
  } catch (err) {
    const status = err.status || 500;
    console.error('Repair decision failed:', err);
    res.status(status).json({
      message: status === 500 ? 'ثبت تصمیم مرجوعی انجام نشد.' : err.message
    });
  }
});

// ===== چت =====
app.post('/api/chat/send', auth, async (req, res) => {
  const { receiver_id, text } = req.body;
  if (!receiver_id || !text) return res.status(400).json({ error: 'Missing' });

  const id = 'msg_' + Date.now();
  const data = {
    id,
    sender_id: req.user.id,
    receiver_id,
    text,
    status: 'sent',
    created_at: new Date().toISOString()
  };

  await pool.query(
    'INSERT INTO app_rows (id, collection, json) VALUES ($1,$2,$3)',
    [id, 'messages', data]
  );
  res.status(201).json(data);
});

app.get('/api/chat/messages/:contactId', auth, async (req, res) => {
  const myId = req.user.id;
  const cid = req.params.contactId;

  await pool.query(
    `UPDATE app_rows SET json=jsonb_set(json,'{status}','"delivered"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status'='sent'`,
    [cid, myId]
  );

  const r = await pool.query(
    `SELECT id, json FROM app_rows WHERE collection='messages' AND ((json->>'sender_id'=$1 AND json->>'receiver_id'=$2) OR (json->>'sender_id'=$2 AND json->>'receiver_id'=$1)) ORDER BY (json->>'created_at') ASC`,
    [myId, cid]
  );

  res.json(r.rows.map(x => safeParse(x.json, x.id)));
});

app.put('/api/chat/seen/:contactId', auth, async (req, res) => {
  await pool.query(
    `UPDATE app_rows SET json=jsonb_set(json,'{status}','"seen"') WHERE collection='messages' AND json->>'sender_id'=$1 AND json->>'receiver_id'=$2 AND json->>'status' IN ('sent','delivered')`,
    [req.params.contactId, req.user.id]
  );
  res.json({ message: 'Seen' });
});

app.get('/api/chat/contacts', auth, async (req, res) => {
  let q = 'SELECT id, username, role, workshop_id FROM users';
  const p = [];

  if (req.user.role !== 'admin') {
    q += ' WHERE role=$1';
    p.push('admin');
  }

  const r = await pool.query(q, p);
  res.json(r.rows);
});

app.delete('/api/admin/reset-workshop/:workshopId', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  const wid = req.params.workshopId;
  const cols = ['dispatches', 'sewing_deliveries', 'wage_ledger', 'payments'];

  try {
    const dR = await pool.query(
      `SELECT id FROM app_rows WHERE collection='dispatches' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`,
      [wid]
    );
    const dIds = dR.rows.map(r => r.id);

    const sR = await pool.query(
      `SELECT id FROM app_rows WHERE collection='sewing_deliveries' AND (json->>'workshop_id'=$1 OR json->>'workshopId'=$1)`,
      [wid]
    );
    const sIds = sR.rows.map(r => r.id);

    if (dIds.length) {
      await pool.query(
        `DELETE FROM app_rows WHERE collection IN ('dispatch_lines','workshop_receipts','cut_defects','dispatch_size_qty') AND (json->>'dispatch_id'=ANY($1) OR json->>'dispatchId'=ANY($1))`,
        [dIds]
      );
    }

    if (sIds.length) {
      await pool.query(
        `DELETE FROM app_rows WHERE collection IN ('sewing_delivery_lines') AND (json->>'delivery_id'=ANY($1) OR json->>'deliveryId'=ANY($1))`,
        [sIds]
      );
    }

    await pool.query(
      `DELETE FROM app_rows WHERE collection=ANY($1) AND (json->>'workshop_id'=$2 OR json->>'workshopId'=$2)`,
      [cols, wid]
    );

    res.json({ message: 'Reset complete' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/clear-all-transactions', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  const cols = [
    'dispatches', 'dispatch_lines', 'dispatch_size_qty',
    'workshop_receipts', 'workshop_receipt_lines',
    'sewing_deliveries', 'sewing_delivery_lines',
    'cut_defects', 'wage_ledger', 'payments',
    'payment_allocations', 'adjustments', 'sync_queue', 'audit_log'
  ];

  const r = await pool.query(
    'DELETE FROM app_rows WHERE collection=ANY($1)',
    [cols]
  );

  res.json({ message: `Cleared ${r.rowCount} records` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));
