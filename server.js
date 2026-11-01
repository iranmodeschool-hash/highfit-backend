// ===== مدیریت کاربران (برای اپ تنخواه‌یار) =====
// این بخش با آدرس‌های درخواستی فرانت‌اند تنخواه‌یار هماهنگ است

app.get('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query('SELECT id, username, email, role, workshop_id, allowed_apps, created_at FROM users ORDER BY id DESC');
    res.json(r.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, password, role, workshop_id, allowed_apps } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    // پیش‌فرض دسترسی برای کاربر جدید در هر دو اپ
    const apps = allowed_apps || '["doakhtyar","petty_cash"]';
    const r = await pool.query('INSERT INTO users (username, email, password_hash, role, workshop_id, allowed_apps) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, email, role', 
      [username || email.split('@')[0], email, hashed, role || 'clerk', workshop_id || null, apps]);
    res.status(201).json(r.rows[0]);
  } catch (err) { 
    if (err.code === '23505') return res.status(400).json({ error: 'این ایمیل قبلا ثبت شده است.' });
    res.status(500).json({ error: err.message }); 
  }
});

app.put('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  const { username, email, role, workshop_id, password } = req.body;
  try {
    if (password && password.trim() !== '') {
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4, password_hash=$5 WHERE id=$6', 
        [username, email, role, workshop_id || null, hashed, req.params.id]);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, workshop_id=$4 WHERE id=$5', 
        [username, email, role, workshop_id || null, req.params.id]);
    }
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// ==========================================
