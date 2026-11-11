const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const DATA = process.env.DATA_DIR || __dirname;           // set DATA_DIR to a persistent disk when hosting
const CATEGORIES = ['Phone / Electronics', 'Wallet / Cards', 'Keys', 'Bag', 'Books / Stationery', 'ID Card', 'Clothing / Accessories', 'Other'];

const UPLOADS = path.join(DATA, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });
const db = new DatabaseSync(path.join(DATA, 'lostfound.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  phone TEXT DEFAULT '', salt TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL,
  location TEXT NOT NULL, date TEXT NOT NULL, description TEXT DEFAULT '', contact TEXT NOT NULL, photo TEXT,
  status TEXT NOT NULL DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
if (!db.prepare('PRAGMA table_info(items)').all().some(c => c.name === 'user_id'))
  db.exec('ALTER TABLE items ADD COLUMN user_id INTEGER');   // upgrade older databases

for (const [c, d] of [['user_type', "TEXT DEFAULT 'Student'"], ['department', "TEXT DEFAULT ''"], ['sec_q', "TEXT DEFAULT ''"], ['sec_salt', "TEXT DEFAULT ''"], ['sec_hash', "TEXT DEFAULT ''"]])
  if (!db.prepare('PRAGMA table_info(users)').all().some(x => x.name === c)) db.exec(`ALTER TABLE users ADD COLUMN ${c} ${d}`);
const QUESTIONS = ['What is your pet’s name?', 'What is your mother’s first name?', 'What was your first school’s name?', 'Who is your favourite teacher?', 'In which city were you born?'];
const USER_TYPES = ['Student', 'Staff', 'Public'];
const norm = (a) => String(a || '').trim().toLowerCase();

// ---------- helpers ----------
const clean = (v, n) => String(v || '').trim().slice(0, n);
const rmPhoto = (f) => f && fs.unlink(path.join(UPLOADS, f), () => { });
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const pwOk = (pw, u) => { const a = Buffer.from(hashPw(pw, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex'); return crypto.timingSafeEqual(a, b); };
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const makeToken = (role, id) => { const p = `${role}:${id}:${Date.now() + 8 * 3600 * 1000}`; return p + '.' + sign(p); };
function readToken(t, role) {
  t = String(t || ''); const i = t.lastIndexOf('.'); if (i < 0) return null;
  const p = t.slice(0, i), sig = t.slice(i + 1);
  if (!/^[0-9a-f]{64}$/.test(sig) || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(p)))) return null;
  const [r, id, exp] = p.split(':');
  return r === role && Number(exp) > Date.now() ? id : null;
}
const tries = new Map();   // simple brute-force limiter: 10 failures / 15 min / IP
function blocked(req, res) {
  const now = Date.now(), a = (tries.get(req.ip) || []).filter(t => now - t < 15 * 60000);
  tries.set(req.ip, a);
  if (a.length >= 10) { res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' }); return true; }
  return false;
}
const fail = (req) => tries.get(req.ip).push(Date.now());

function userOnly(req, res, next) {
  const id = readToken(req.get('x-user-token'), 'user');
  const u = id && db.prepare('SELECT id,name,email,phone,user_type,department FROM users WHERE id=?').get(id);
  if (!u) return res.status(401).json({ error: 'Please log in first' });
  req.user = u; next();
}
function adminOnly(req, res, next) {
  if (readToken(req.get('x-admin-token'), 'admin') === null) return res.status(401).json({ error: 'Admin login required' });
  next();
}

const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({ destination: UPLOADS, filename: (r, f, cb) => cb(null, crypto.randomBytes(10).toString('hex') + EXT[f.mimetype]) }),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(EXT[f.mimetype] ? null : new Error('Only JPG, PNG or WEBP images are allowed'), !!EXT[f.mimetype]),
});

function itemFields(b) {
  const it = {
    type: b.type, title: clean(b.title, 60), category: b.category, location: clean(b.location, 80),
    date: clean(b.date, 10), description: clean(b.description, 300), contact: clean(b.contact, 80)
  };
  const ok = ['lost', 'found'].includes(it.type) && CATEGORIES.includes(it.category) && it.title && it.location &&
    /^\d{4}-\d{2}-\d{2}$/.test(it.date) && it.contact;
  return ok ? it : null;
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS));

const PUB = `SELECT i.id,i.type,i.title,i.category,i.location,i.date,i.description,i.photo,i.status,i.created_at,u.name AS poster
  FROM items i LEFT JOIN users u ON u.id=i.user_id`;

// ---------- public ----------
app.get('/api/categories', (req, res) => res.json(CATEGORIES));

app.get('/api/items', (req, res) => {
  const { q = '', type = '', category = '', status = 'open' } = req.query, w = [], a = [];
  w.push(status === 'done' ? "i.status='returned'" : status === 'all' ? "i.status IN ('approved','returned')" : "i.status='approved'");
  if (type === 'lost' || type === 'found') { w.push('i.type=?'); a.push(type); }
  if (category) { w.push('i.category=?'); a.push(category); }
  if (q) { w.push('(i.title LIKE ? OR i.location LIKE ? OR i.description LIKE ?)'); a.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  res.json(db.prepare(`${PUB} WHERE ${w.join(' AND ')} ORDER BY i.date DESC, i.id DESC`).all(...a));
});

app.get('/api/items/:id', (req, res) => {
  const row = db.prepare(`${PUB} WHERE i.id=? AND i.status IN ('approved','returned')`).get(req.params.id);
  row ? res.json(row) : res.status(404).json({ error: 'Not found' });
});

app.get('/api/stats', (req, res) => {
  const n = (s) => db.prepare(s).get().c;
  res.json({
    lost: n("SELECT COUNT(*) c FROM items WHERE type='lost' AND status='approved'"),
    found: n("SELECT COUNT(*) c FROM items WHERE type='found' AND status='approved'"),
    returned: n("SELECT COUNT(*) c FROM items WHERE status='returned'")
  });
});

// contact details are visible to logged-in users only
app.get('/api/items/:id/contact', userOnly, (req, res) => {
  const row = db.prepare("SELECT contact FROM items WHERE id=? AND status IN ('approved','returned')").get(req.params.id);
  row ? res.json(row) : res.status(404).json({ error: 'Not found' });
});

app.get('/api/items/:id/matches', (req, res) => {   // possible matches: same category, opposite type
  const it = db.prepare("SELECT type,category FROM items WHERE id=? AND status IN ('approved','returned')").get(req.params.id);
  if (!it) return res.json([]);
  res.json(db.prepare(`${PUB} WHERE i.status='approved' AND i.category=? AND i.type=? AND i.id<>? ORDER BY i.date DESC LIMIT 3`)
    .all(it.category, it.type === 'lost' ? 'found' : 'lost', req.params.id));
});

// ---------- accounts ----------
app.post('/api/register', (req, res) => {
  if (blocked(req, res)) return;
  const b = req.body, name = clean(b.name, 50), email = clean(b.email, 80).toLowerCase(), phone = clean(b.phone, 20), pw = String(b.password || '');
  const type = USER_TYPES.includes(b.userType) ? b.userType : 'Student', dept = clean(b.department, 60), q = b.secQ, ans = norm(b.secA);
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || pw.length < 6) return res.status(400).json({ error: 'Enter a name, a valid email and a password of at least 6 characters' });
  if (!QUESTIONS.includes(q) || ans.length < 2) return res.status(400).json({ error: 'Choose a security question and give an answer (used if you forget your password)' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(400).json({ error: 'This email is already registered' });
  const salt = crypto.randomBytes(16).toString('hex'), ssalt = crypto.randomBytes(16).toString('hex');
  const r = db.prepare('INSERT INTO users (name,email,phone,user_type,department,salt,hash,sec_q,sec_salt,sec_hash) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(name, email, phone, type, dept, salt, hashPw(pw, salt), q, ssalt, hashPw(ans, ssalt));
  res.status(201).json({ token: makeToken('user', r.lastInsertRowid) });
});

app.post('/api/login', (req, res) => {
  if (blocked(req, res)) return;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(clean(req.body.email, 80).toLowerCase());
  if (!u || !pwOk(String(req.body.password || ''), u)) { fail(req); return res.status(401).json({ error: 'Wrong email or password' }); }
  res.json({ token: makeToken('user', u.id) });
});

app.get('/api/security-questions', (req, res) => res.json(QUESTIONS));

app.post('/api/forgot/question', (req, res) => {
  if (blocked(req, res)) return;
  const u = db.prepare('SELECT sec_q FROM users WHERE email=?').get(clean(req.body.email, 80).toLowerCase());
  if (!u) { fail(req); return res.status(404).json({ error: 'No account found with this email' }); }
  if (!u.sec_q) return res.status(400).json({ error: 'This account has no recovery question. Please contact the admin.' });
  res.json({ question: u.sec_q });
});

app.post('/api/forgot/reset', (req, res) => {
  if (blocked(req, res)) return;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(clean(req.body.email, 80).toLowerCase());
  const np = String(req.body.newPassword || '');
  if (!u || !u.sec_hash) return res.status(400).json({ error: 'Could not reset the password' });
  if (np.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const a = Buffer.from(hashPw(norm(req.body.answer), u.sec_salt), 'hex'), b = Buffer.from(u.sec_hash, 'hex');
  if (!crypto.timingSafeEqual(a, b)) { fail(req); return res.status(400).json({ error: 'Wrong answer' }); }
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(salt, hashPw(np, salt), u.id);
  res.json({ ok: true, message: 'Password changed. You can log in now.' });
});

app.get('/api/me', userOnly, (req, res) => res.json(req.user));

app.put('/api/me', userOnly, (req, res) => {
  const name = clean(req.body.name, 50), phone = clean(req.body.phone, 20), np = String(req.body.newPassword || '');
  const type = USER_TYPES.includes(req.body.userType) ? req.body.userType : 'Student', dept = clean(req.body.department, 60);
  if (!name) return res.status(400).json({ error: 'Name is required' });
  db.prepare('UPDATE users SET name=?, phone=?, user_type=?, department=? WHERE id=?').run(name, phone, type, dept, req.user.id);
  if (np) {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (np.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    if (!pwOk(String(req.body.currentPassword || ''), u)) return res.status(400).json({ error: 'Current password is wrong' });
    const salt = crypto.randomBytes(16).toString('hex');
    db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(salt, hashPw(np, salt), req.user.id);
  }
  res.json({ ok: true, message: 'Profile updated' });
});

// ---------- user's own items ----------
app.post('/api/items', userOnly, upload.single('photo'), (req, res) => {
  const it = itemFields(req.body);
  if (!it) { if (req.file) rmPhoto(req.file.filename); return res.status(400).json({ error: 'Please fill all required fields correctly' }); }
  db.prepare(`INSERT INTO items (type,title,category,location,date,description,contact,photo,user_id) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(it.type, it.title, it.category, it.location, it.date, it.description, it.contact, req.file ? req.file.filename : null, req.user.id);
  res.status(201).json({ ok: true, message: 'Submitted! It will appear after admin approval.' });
});

app.get('/api/my/items', userOnly, (req, res) =>
  res.json(db.prepare('SELECT * FROM items WHERE user_id=? ORDER BY id DESC').all(req.user.id)));

app.put('/api/my/items/:id', userOnly, upload.single('photo'), (req, res) => {
  const row = db.prepare('SELECT * FROM items WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  const it = itemFields(req.body);
  if (!row || !it) { if (req.file) rmPhoto(req.file.filename); return res.status(row ? 400 : 404).json({ error: row ? 'Please fill all required fields correctly' : 'Not found' }); }
  if (req.file) rmPhoto(row.photo);
  const status = row.status === 'returned' ? 'returned' : 'pending';   // edits need re-approval
  db.prepare('UPDATE items SET type=?,title=?,category=?,location=?,date=?,description=?,contact=?,photo=?,status=? WHERE id=?')
    .run(it.type, it.title, it.category, it.location, it.date, it.description, it.contact, req.file ? req.file.filename : row.photo, status, row.id);
  res.json({ ok: true, message: status === 'pending' ? 'Updated. It will show again after admin approval.' : 'Updated.' });
});

app.post('/api/my/items/:id/return', userOnly, (req, res) => {
  db.prepare("UPDATE items SET status='returned' WHERE id=? AND user_id=? AND status='approved'").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/my/items/:id', userOnly, (req, res) => {
  const row = db.prepare('SELECT photo FROM items WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (row) { rmPhoto(row.photo); db.prepare('DELETE FROM items WHERE id=?').run(req.params.id); }
  res.json({ ok: true });
});

// ---------- admin ----------
app.post('/api/admin/login', (req, res) => {
  if (blocked(req, res)) return;
  const a = Buffer.from(String(req.body.password || '')), b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) { fail(req); return res.status(401).json({ error: 'Wrong password' }); }
  res.json({ token: makeToken('admin', 0) });
});

app.get('/api/admin/items', adminOnly, (req, res) => res.json(db.prepare(
  `SELECT i.*, u.name AS poster FROM items i LEFT JOIN users u ON u.id=i.user_id
   ORDER BY CASE i.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, i.id DESC`).all()));

app.post('/api/admin/items/:id/:action', adminOnly, (req, res) => {
  const status = { approve: 'approved', return: 'returned' }[req.params.action];
  if (!status) return res.status(400).json({ error: 'Unknown action' });
  db.prepare('UPDATE items SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/items/:id', adminOnly, (req, res) => {
  const row = db.prepare('SELECT photo FROM items WHERE id=?').get(req.params.id);
  if (row) rmPhoto(row.photo);
  db.prepare('DELETE FROM items WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.use((err, req, res, next) =>
  res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Photo must be under 3 MB' : err.message || 'Server error' }));

app.listen(PORT, () => {
  console.log(`Lost & Found running at http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'admin123') console.log('Using default admin password "admin123". Set ADMIN_PASSWORD to change it.');
});
