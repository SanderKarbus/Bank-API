'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const { SignJWT, importPKCS8 } = require('jose');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// Private key for signing Bearer JWTs
const PRIVATE_KEY_CONTENT = process.env.PRIVATE_KEY_CONTENT || null;
const PRIVATE_KEY_PATH    = process.env.JWT_PRIVATE_KEY_PATH || path.join(__dirname, '..', 'gateway', 'keys', 'private.pem');

let _privKey = null;
async function getPrivKey() {
  if (_privKey) return _privKey;
  const pem = PRIVATE_KEY_CONTENT ? PRIVATE_KEY_CONTENT.trim() : fs.readFileSync(PRIVATE_KEY_PATH, 'utf8').trim();
  _privKey = await importPKCS8(pem, 'ES256');
  return _privKey;
}

async function makeJWT(userId) {
  const key = await getPrivKey();
  return new SignJWT({ userId })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setExpirationTime('90d')
    .sign(key);
}

// DB
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

// POST /users
app.post('/users', async (req, res) => {
  const { fullName, email } = req.body || {};
  if (!fullName || String(fullName).trim().length < 2)
    return res.status(400).json({ code: 'INVALID_REQUEST', message: 'fullName is required (min 2 chars)' });

  const id  = 'user-' + uuidv4();
  const now = new Date().toISOString();

  // Bearer token is a signed JWT containing userId per spec
  let jwt;
  try { jwt = await makeJWT(id); }
  catch(e) { return res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to sign token: ' + e.message }); }

  try {
    db.prepare('INSERT INTO users (id,full_name,email,api_key,created_at) VALUES (?,?,?,?,?)')
      .run(id, fullName.trim(), email?.trim() || null, jwt, now);
  } catch(e) {
    if (e.message.includes('UNIQUE'))
      return res.status(409).json({ code: 'DUPLICATE_USER', message: 'A user with this email is already registered' });
    return res.status(500).json({ code: 'INTERNAL_ERROR', message: e.message });
  }
  return res.status(201).json(fmt(db.prepare('SELECT * FROM users WHERE id=?').get(id)));
});

// GET /users/:userId
app.get('/users/:userId', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.userId);
  if (!u) return res.status(404).json({ code: 'USER_NOT_FOUND', message: 'User not found' });
  return res.json(fmt(u));
});

// GET /internal/users/by-api-key/:key
app.get('/internal/users/by-api-key/:key', (req, res) => {
  const key = decodeURIComponent(req.params.key);
  const u = db.prepare('SELECT * FROM users WHERE api_key=?').get(key);
  if (!u) return res.status(404).json({ code: 'INVALID_API_KEY', message: 'Invalid API key' });
  return res.json(fmt(u));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`[user-service] :${PORT}`));
