'use strict';
const express   = require('express');
const fetch     = require('node-fetch');
const swaggerUi = require('swagger-ui-express');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const BANK_ID          = process.env.BANK_ID          || 'MIN001';
const BANK_NAME        = process.env.BANK_NAME        || 'MIN001 Branch Bank';
const BANK_ADDRESS     = (process.env.BANK_ADDRESS    || 'http://localhost:3000/api/v1').replace(/\/+$/, '');
const CENTRAL_BANK_URL = (process.env.CENTRAL_BANK_URL|| 'https://test.diarainfra.com/central-bank').replace(/\/+$/, '');
const USER_SVC         = (process.env.USER_SERVICE_URL     || 'http://localhost:3001').replace(/\/+$/, '');
const ACCOUNT_SVC      = (process.env.ACCOUNT_SERVICE_URL  || 'http://localhost:3002').replace(/\/+$/, '');
const TRANSFER_SVC     = (process.env.TRANSFER_SERVICE_URL || 'http://localhost:3003').replace(/\/+$/, '');
const PUB_KEY_PATH     = process.env.JWT_PUBLIC_KEY_PATH   || path.join(__dirname, 'keys', 'public.pem');

// ── Swagger UI ─────────────────────────────────────────────────────────────
const swaggerDoc = JSON.parse(fs.readFileSync(path.join(__dirname, 'swagger.json'), 'utf8'));
// Set live server URL into the spec
const apiBase = BANK_ADDRESS.endsWith('/api/v1') ? BANK_ADDRESS : BANK_ADDRESS + '/api/v1';
swaggerDoc.servers = [{ url: apiBase, description: 'Live server' }];
swaggerDoc.info.title = `${BANK_NAME} API`;

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc, {
  customSiteTitle: BANK_NAME + ' — API Docs',
  swaggerOptions: { persistAuthorization: true, displayRequestDuration: true }
}));
app.get('/api-docs.json', (_req, res) => res.json(swaggerDoc));

// ── Auth middleware ────────────────────────────────────────────────────────
async function auth(req, res, next) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer '))
    return res.status(401).json({ code:'UNAUTHORIZED', message:'Missing Authorization: Bearer <apiKey>' });
  try {
    const r = await fetch(`${USER_SVC}/internal/users/by-api-key/${encodeURIComponent(h.slice(7).trim())}`, { timeout:5000 });
    if (!r.ok) return res.status(401).json({ code:'UNAUTHORIZED', message:'Invalid API key' });
    req.user = await r.json();
    next();
  } catch(e) {
    return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:'Auth service unreachable' });
  }
}

// ── Proxy helpers ──────────────────────────────────────────────────────────
async function pGet(url, res) {
  try {
    const r = await fetch(url, { timeout:8000 });
    return res.status(r.status).json(await r.json());
  } catch(e) { return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:e.message }); }
}

async function pPost(url, body, res) {
  try {
    const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body), timeout:15000 });
    return res.status(r.status).json(await r.json());
  } catch(e) { return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:e.message }); }
}

// ── Routes ─────────────────────────────────────────────────────────────────
const api = express.Router();

api.get('/health', (_req, res) =>
  res.json({ status:'ok', bankId:BANK_ID, bankName:BANK_NAME, timestamp:new Date().toISOString() })
);

// Users
api.post('/users', (req, res) => pPost(`${USER_SVC}/users`, req.body, res));
api.get('/users/:userId', (req, res) => pGet(`${USER_SVC}/users/${req.params.userId}`, res));

// Accounts — create
api.post('/users/:userId/accounts', auth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.userId !== userId)
    return res.status(403).json({ code:'FORBIDDEN', message:'API key does not belong to this user' });
  try {
    const ur = await fetch(`${USER_SVC}/users/${userId}`, { timeout:5000 });
    if (!ur.ok) return res.status(404).json({ code:'USER_NOT_FOUND', message:`User '${userId}' not found` });
    const user = await ur.json();
    return pPost(`${ACCOUNT_SVC}/accounts`, { ownerId:userId, ownerName:user.fullName, currency:req.body?.currency||'EUR' }, res);
  } catch(e) { return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:e.message }); }
});

// Accounts — list
api.get('/users/:userId/accounts', auth, (req, res) => {
  if (req.user.userId !== req.params.userId)
    return res.status(403).json({ code:'FORBIDDEN', message:'Forbidden' });
  return pGet(`${ACCOUNT_SVC}/accounts/owner/${req.params.userId}`, res);
});

// Account lookup — public
api.get('/accounts/:accountNumber', (req, res) =>
  pGet(`${ACCOUNT_SVC}/accounts/${req.params.accountNumber.toUpperCase()}`, res)
);

// Transfers — initiate
api.post('/transfers', auth, async (req, res) => {
  const srcAcn = (req.body?.sourceAccount || '').toUpperCase();
  if (!srcAcn) return res.status(400).json({ code:'INVALID_REQUEST', message:'sourceAccount required' });
  try {
    const ar = await fetch(`${ACCOUNT_SVC}/accounts/${srcAcn}`, { timeout:5000 });
    if (!ar.ok) return res.status(404).json({ code:'ACCOUNT_NOT_FOUND', message:`Account '${srcAcn}' not found` });
    const acc = await ar.json();
    if (acc.ownerId !== req.user.userId)
      return res.status(403).json({ code:'FORBIDDEN', message:'Source account does not belong to you' });
  } catch(e) { return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:e.message }); }
  return pPost(`${TRANSFER_SVC}/transfers`, req.body, res);
});

// Transfers/receive — NO auth, JWT in body — MUST be before /:transferId
api.post('/transfers/receive', async (req, res) => {
  try {
    const r = await fetch(`${TRANSFER_SVC}/transfers/receive`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify(req.body), timeout:15000
    });
    return res.status(r.status).json(await r.json());
  } catch(e) { return res.status(503).json({ code:'SERVICE_UNAVAILABLE', message:e.message }); }
});

// Transfer status
api.get('/transfers/:transferId', auth, (req, res) =>
  pGet(`${TRANSFER_SVC}/transfers/${req.params.transferId}`, res)
);

// Transfer history
api.get('/users/:userId/transfers', auth, (req, res) => {
  if (req.user.userId !== req.params.userId)
    return res.status(403).json({ code:'FORBIDDEN', message:'Forbidden' });
  return pGet(`${TRANSFER_SVC}/transfers/user/${req.params.userId}`, res);
});

app.use('/api/v1', api);

// ── Central Bank ───────────────────────────────────────────────────────────
async function register() {
  let publicKey = '';
  // Support env var for Railway (no file system access to keys)
  if (process.env.PUBLIC_KEY_CONTENT) {
    publicKey = process.env.PUBLIC_KEY_CONTENT.trim();
  } else {
    try { publicKey = fs.readFileSync(PUB_KEY_PATH, 'utf8').trim(); }
    catch(e) { console.error('[gateway] Cannot read public key:', e.message); }
  }

  try {
    const r = await fetch(`${CENTRAL_BANK_URL}/api/v1/banks`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name:BANK_NAME, address:BANK_ADDRESS, publicKey }),
      timeout:10000
    });
    const b = await r.json();
    if (r.status === 201) console.log(`[gateway] Registered ✓  bankId:${b.bankId}  expires:${b.expiresAt}`);
    else if (r.status === 409) console.log('[gateway] Already registered (409) — sending heartbeat');
    else console.error('[gateway] Registration failed:', r.status, b);
  } catch(e) { console.error('[gateway] Registration error:', e.message); }
}

async function heartbeat() {
  try {
    const r = await fetch(`${CENTRAL_BANK_URL}/api/v1/banks/${BANK_ID}/heartbeat`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ timestamp: new Date().toISOString() }),
      timeout:8000
    });
    if (r.ok) {
      const b = await r.json();
      console.log(`[gateway] Heartbeat ✓  expires:${b.expiresAt}`);
    } else if (r.status === 404 || r.status === 410) {
      console.warn('[gateway] Heartbeat →', r.status, '— re-registering');
      await register();
    } else {
      console.error('[gateway] Heartbeat failed:', r.status);
    }
  } catch(e) { console.error('[gateway] Heartbeat error:', e.message); }
}

// ── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`[gateway] :${PORT}`);
  console.log(`[gateway] Swagger → ${BANK_ADDRESS.replace(/\/api\/v1$/, '')}/docs`);
  console.log(`[gateway] API     → ${BANK_ADDRESS}`);
  await register();
  setInterval(heartbeat, 25 * 60 * 1000); // every 25 min
});
