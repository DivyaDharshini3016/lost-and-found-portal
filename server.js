const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const CATEGORIES = ['Phone / Electronics', 'Wallet / Cards', 'Keys', 'Bag', 'Books / Stationery', 'ID Card', 'Clothing / Accessories', 'Other'];

const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new DatabaseSync(path.join(__dirname, 'lostfound.db'));
db.exec(`CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  location TEXT NOT NULL,
  date TEXT NOT NULL,
  description TEXT DEFAULT '',
  contact TEXT NOT NULL,
  photo TEXT,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | returned
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

// ---------- photo upload ----------
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, file, cb) => cb(null, crypto.randomBytes(10).toString('hex') + EXT[file.mimetype]),
  }),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(EXT[file.mimetype] ? null : new Error('Only JPG, PNG or WEBP images are allowed'), !!EXT[file.mimetype]),
});

// ---------- admin auth (signed, expiring token) ----------
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
function makeToken() {
  const exp = String(Date.now() + 8 * 3600 * 1000);
  return exp + '.' + sign(exp);
}
function adminOnly(req, res, next) {
  const [exp, sig] = (req.get('x-admin-token') || '').split('.');
  const ok = exp && sig && Number(exp) > Date.now() &&
    sig.length === 64 && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(exp)));
  if (!ok) return res.status(401).json({ error: 'Admin login required' });
  next();
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS));

const PUBLIC_COLS = 'id,type,title,category,location,date,description,photo,status';

// ---------- public API ----------
app.get('/api/categories', (req, res) => res.json(CATEGORIES));

app.get('/api/items', (req, res) => {
  const { q = '', type = '', category = '', status = 'open' } = req.query;
  const where = [], args = [];
  where.push(status === 'done' ? "status='returned'" : status === 'all' ? "status IN ('approved','returned')" : "status='approved'");
  if (type === 'lost' || type === 'found') { where.push('type=?'); args.push(type); }
  if (category) { where.push('category=?'); args.push(category); }
  if (q) { where.push('(title LIKE ? OR location LIKE ? OR description LIKE ?)'); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  const rows = db.prepare(`SELECT ${PUBLIC_COLS} FROM items WHERE ${where.join(' AND ')} ORDER BY date DESC, id DESC`).all(...args);
  res.json(rows);
});

app.get('/api/stats', (req, res) => {
  const n = (sql) => db.prepare(sql).get().c;
  res.json({
    lost: n("SELECT COUNT(*) c FROM items WHERE type='lost' AND status='approved'"),
    found: n("SELECT COUNT(*) c FROM items WHERE type='found' AND status='approved'"),
    returned: n("SELECT COUNT(*) c FROM items WHERE status='returned'"),
  });
});

// contact is only revealed on request, never in the list
app.get('/api/items/:id/contact', (req, res) => {
  const row = db.prepare("SELECT contact FROM items WHERE id=? AND status IN ('approved','returned')").get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

app.post('/api/items', upload.single('photo'), (req, res) => {
  const b = req.body, clean = (v, n) => String(v || '').trim().slice(0, n);
  const item = {
    type: b.type, title: clean(b.title, 60), category: b.category, location: clean(b.location, 80),
    date: clean(b.date, 10), description: clean(b.description, 300), contact: clean(b.contact, 80),
  };
  const bad = !['lost', 'found'].includes(item.type) || !CATEGORIES.includes(item.category) ||
    !item.title || !item.location || !/^\d{4}-\d{2}-\d{2}$/.test(item.date) || !item.contact;
  if (bad) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'Please fill all required fields correctly' });
  }
  db.prepare(`INSERT INTO items (type,title,category,location,date,description,contact,photo)
              VALUES (@type,@title,@category,@location,@date,@description,@contact,@photo)`)
    .run({ ...item, photo: req.file ? req.file.filename : null });
  res.status(201).json({ ok: true, message: 'Submitted! It will appear after admin approval.' });
});

// ---------- admin API ----------
app.post('/api/admin/login', (req, res) => {
  const a = Buffer.from(String(req.body.password || '')), b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Wrong password' });
  res.json({ token: makeToken() });
});

app.get('/api/admin/items', adminOnly, (req, res) => {
  res.json(db.prepare(`SELECT * FROM items ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, id DESC`).all());
});

app.post('/api/admin/items/:id/:action', adminOnly, (req, res) => {
  const status = { approve: 'approved', return: 'returned' }[req.params.action];
  if (!status) return res.status(400).json({ error: 'Unknown action' });
  db.prepare('UPDATE items SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/items/:id', adminOnly, (req, res) => {
  const row = db.prepare('SELECT photo FROM items WHERE id=?').get(req.params.id);
  if (row && row.photo) fs.unlink(path.join(UPLOADS, row.photo), () => {});
  db.prepare('DELETE FROM items WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- errors ----------
app.use((err, req, res, next) => {
  const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Photo must be under 3 MB' : err.message || 'Server error';
  res.status(400).json({ error: msg });
});

app.listen(PORT, () => {
  console.log(`Lost & Found running at http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'admin123') console.log('Using default admin password "admin123". Set ADMIN_PASSWORD to change it.');
});
