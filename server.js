'use strict';
const express = require('express'), path = require('path'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), cookieParser = require('cookie-parser'), Database = require('better-sqlite3');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('Set JWT_SECRET (32+ characters) in .env'); process.exit(1); }
const PROD = process.env.NODE_ENV === 'production';

const db = new Database(process.env.DB_PATH || 'users.db');
db.exec(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP)`);
const byEmail = db.prepare('SELECT * FROM users WHERE email = ?'), byId = db.prepare('SELECT id,name,email FROM users WHERE id = ?');
const insert = db.prepare('INSERT INTO users(name,email,hash) VALUES(?,?,?)');
const DUMMY = bcrypt.hashSync('not-a-real-password', 12);   // keeps login timing similar for unknown emails

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' } });

function startSession(res, user) {
  const token = jwt.sign({ sub: user.id }, SECRET, { expiresIn: '7d' });
  res.cookie('sid', token, { httpOnly: true, sameSite: 'strict', secure: PROD, maxAge: 7 * 24 * 3600 * 1000 });
}
function auth(req, res, next) {                            // use on any route that needs a signed-in user
  try { req.user = byId.get(jwt.verify(req.cookies.sid, SECRET).sub); } catch (e) {}
  req.user ? next() : res.status(401).json({ error: 'Not signed in.' });
}
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

app.post('/api/register', limiter, (req, res) => {
  const name = String(req.body.name || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (name.length < 2 || name.length > 50) return res.status(400).json({ error: 'Name must be 2 to 50 characters.' });
  if (!EMAIL.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (pw.length < 10 || pw.length > 128) return res.status(400).json({ error: 'Password must be 10 to 128 characters.' });
  if (byEmail.get(email)) return res.status(409).json({ error: 'An account with this email already exists.' });
  const info = insert.run(name, email, bcrypt.hashSync(pw, 12));
  startSession(res, { id: info.lastInsertRowid });
  res.status(201).json({ name });
});

app.post('/api/login', limiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = byEmail.get(email);
  const ok = bcrypt.compareSync(pw, u ? u.hash : DUMMY);
  if (!u || !ok) return res.status(401).json({ error: 'Incorrect email or password.' });
  startSession(res, u);
  res.json({ name: u.name });
});

app.post('/api/logout', (req, res) => { res.clearCookie('sid'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ name: req.user.name, email: req.user.email }));

app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('Running on http://localhost:' + (process.env.PORT || 3000)));
