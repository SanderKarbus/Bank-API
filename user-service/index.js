'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, 'users.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  full_name  TEXT NOT NULL,
  email      TEXT UNIQUE,
  api_key    TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL
)`);

function fmt(u) {
  const o = { userId: u.id, fullName: u.full_name, createdAt: u.created_at, apiKey: u.api_key };
  if (u.email) o.email = u.email;
  return o;
}

app.post('/users', (req, res) => {
  const { fullName, email } = req.body || {};
  if (!fullName || String(fullName).trim().length < 2)
    return res.status(400).json({ code: 'INVALID_REQUEST', message: 'fullName is required (min 2 chars)' });
  const id  = 'user-' + uuidv4();
  const api_key = uuidv4().replace(/-/g,'') + uuidv4().replace(/-/g,'');
  const now = new Date().toISOString();
  try {
    db.prepare('INSERT INTO users (id,full_name,email,api_key,created_at) VALUES (?,?,?,?,?)')
      .run(id, fullName.trim(), email?.trim()||null, api_key, now);
  } catch(e) {
    if (e.message.includes('UNIQUE'))
      return res.status(409).json({ code: 'DUPLICATE_USER', message: 'A user with this email is already registered' });
    return res.status(500).json({ code: 'INTERNAL_ERROR', message: e.message });
  }
  return res.status(201).json(fmt(db.prepare('SELECT * FROM users WHERE id=?').get(id)));
});

app.get('/users/:userId', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.userId);
  if (!u) return res.status(404).json({ code: 'USER_NOT_FOUND', message: 'User not found' });
  return res.json(fmt(u));
});

app.get('/internal/users/by-api-key/:key', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE api_key=?').get(decodeURIComponent(req.params.key));
  if (!u) return res.status(404).json({ code: 'INVALID_API_KEY', message: 'Invalid API key' });
  return res.json(fmt(u));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`[user-service] :${PORT}`));
