'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const fetch    = require('node-fetch');
const { SignJWT, importPKCS8, importSPKI, jwtVerify } = require('jose');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const BANK_ID          = process.env.BANK_ID          || 'MIN001';
const BANK_PREFIX      = BANK_ID.substring(0, 3).toUpperCase();
const CENTRAL_BANK_URL = (process.env.CENTRAL_BANK_URL || 'https://test.diarainfra.com/central-bank').replace(/\/$/, '');
const ACCOUNT_SVC      = (process.env.ACCOUNT_SERVICE_URL || 'http://localhost:3002').replace(/\/$/, '');
const PRIVATE_KEY_PATH = process.env.JWT_PRIVATE_KEY_PATH || path.join(__dirname, 'keys', 'private.pem');

const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, 'transfers.db'));
db.exec(`CREATE TABLE IF NOT EXISTS transfers (
  transfer_id         TEXT PRIMARY KEY,
  source_account      TEXT NOT NULL,
  destination_account TEXT NOT NULL,
  amount              TEXT NOT NULL,
  currency            TEXT NOT NULL,
  converted_amount    TEXT,
  exchange_rate       TEXT,
  rate_captured_at    TEXT,
  status              TEXT NOT NULL,
  error_message       TEXT,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
)`);

// ── Caches ────────────────────────────────────────────────────────────────────
let _banks = [], _banksAt = 0;
let _rates = {}, _ratesAt = 0, _ratesCaptAt = null;
const TTL = 5 * 60 * 1000;

async function getBanks() {
  if (Date.now() - _banksAt < TTL && _banks.length) return _banks;
  try {
    const r = await fetch(`${CENTRAL_BANK_URL}/api/v1/banks`, { timeout: 8000 });
    if (r.ok) {
      const b = await r.json();
      _banks  = Array.isArray(b) ? b : (b.banks || []);
      _banksAt = Date.now();
    }
  } catch(e) { console.warn('[transfer] bank fetch failed:', e.message); }
  return _banks;
}

async function getRates() {
  if (Date.now() - _ratesAt < TTL && Object.keys(_rates).length) return _rates;
  try {
    const r = await fetch(`${CENTRAL_BANK_URL}/api/v1/exchange-rates`, { timeout: 8000 });
    if (r.ok) {
      const b = await r.json();
      // { baseCurrency: "EUR", rates: { GBP: "0.850000", USD: "1.080000" }, timestamp: "..." }
      _rates = { EUR: 1.0 };
      _ratesCaptAt = b.timestamp || new Date().toISOString();
      for (const [k, v] of Object.entries(b.rates || {})) _rates[k] = parseFloat(v);
      _ratesAt = Date.now();
    }
  } catch(e) { console.warn('[transfer] rates fetch failed:', e.message); }
  return _rates;
}

async function convert(amount, from, to) {
  if (from === to) return { converted: parseFloat(amount).toFixed(2), rate: '1.000000', capturedAt: new Date().toISOString() };
  const rates = await getRates();
  const fRate = rates[from] || 1.0;
  const tRate = rates[to]   || 1.0;
  return {
    converted:  ((parseFloat(amount) / fRate) * tRate).toFixed(2),
    rate:       (tRate / fRate).toFixed(6),
    capturedAt: _ratesCaptAt || new Date().toISOString()
  };
}

// ── Account helpers ───────────────────────────────────────────────────────────
async function getAcc(acn) {
  try {
    const r = await fetch(`${ACCOUNT_SVC}/accounts/${acn}`, { timeout: 5000 });
    return r.ok ? r.json() : null;
  } catch { return null; }
}

async function debit(acn, amount) {
  const r = await fetch(`${ACCOUNT_SVC}/accounts/${acn}/debit`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ amount: String(amount) }), timeout: 5000
  });
  return { ok: r.ok, body: await r.json() };
}

async function credit(acn, amount) {
  const r = await fetch(`${ACCOUNT_SVC}/accounts/${acn}/credit`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ amount: String(amount) }), timeout: 5000
  });
  return { ok: r.ok, body: await r.json() };
}

// ── JWT ───────────────────────────────────────────────────────────────────────
let _privKey = null;
async function privKey() {
  if (_privKey) return _privKey;
  // Support env var for Railway (no file system access to keys)
  const pem = process.env.PRIVATE_KEY_CONTENT
    ? process.env.PRIVATE_KEY_CONTENT.trim()
    : fs.readFileSync(PRIVATE_KEY_PATH, 'utf8').trim();
  _privKey = await importPKCS8(pem, 'ES256');
  return _privKey;
}

async function signJWT(payload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(await privKey());
}

async function verifyJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT');
  const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (!p.senderBankId) throw new Error('Missing senderBankId in JWT');
  const banks = await getBanks();
  const bank  = banks.find(b => b.bankId === p.senderBankId);
  if (!bank)           throw new Error(`Unknown bank: ${p.senderBankId}`);
  if (!bank.publicKey) throw new Error(`No publicKey for bank: ${p.senderBankId}`);
  const pub = await importSPKI(bank.publicKey, 'ES256');
  const { payload } = await jwtVerify(token, pub, { algorithms: ['ES256'] });
  return payload;
}

// ── DB helpers ────────────────────────────────────────────────────────────────
function save(t) {
  db.prepare(`INSERT INTO transfers
    (transfer_id,source_account,destination_account,amount,currency,
     converted_amount,exchange_rate,rate_captured_at,status,error_message,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(t.transferId, t.sourceAccount, t.destinationAccount, t.amount, t.currency,
        t.convertedAmount||null, t.exchangeRate||null, t.rateCapturedAt||null,
        t.status, t.errorMessage||null, t.createdAt, t.updatedAt);
}

function fmt(r) {
  const o = {
    transferId: r.transfer_id, status: r.status,
    sourceAccount: r.source_account, destinationAccount: r.destination_account,
    amount: r.amount, timestamp: r.updated_at
  };
  if (r.exchange_rate && r.exchange_rate !== '1.000000') {
    o.convertedAmount = r.converted_amount;
    o.exchangeRate    = r.exchange_rate;
    o.rateCapturedAt  = r.rate_captured_at;
  }
  if (r.error_message) o.errorMessage = r.error_message;
  return o;
}

// ── Routes ────────────────────────────────────────────────────────────────────

// POST /transfers
app.post('/transfers', async (req, res) => {
  const { transferId, sourceAccount, destinationAccount, amount } = req.body || {};
  if (!transferId||!sourceAccount||!destinationAccount||!amount)
    return res.status(400).json({ code:'INVALID_REQUEST', message:'transferId, sourceAccount, destinationAccount, amount required' });

  // Idempotency
  const existing = db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(transferId);
  if (existing) {
    if (existing.status === 'pending')
      return res.status(409).json({ code:'TRANSFER_ALREADY_PENDING', message:`Transfer '${transferId}' already pending` });
    return res.status(409).json({ code:'DUPLICATE_TRANSFER', message:`Transfer '${transferId}' already exists` });
  }

  const srcAcc = await getAcc(sourceAccount);
  if (!srcAcc) return res.status(404).json({ code:'ACCOUNT_NOT_FOUND', message:`Source account '${sourceAccount}' not found` });

  const destPrefix = destinationAccount.substring(0, 3).toUpperCase();
  const now = new Date().toISOString();

  // ── Same-bank ──────────────────────────────────────────────────────────────
  if (destPrefix === BANK_PREFIX) {
    const dstAcc = await getAcc(destinationAccount);
    if (!dstAcc) return res.status(404).json({ code:'ACCOUNT_NOT_FOUND', message:`Destination account '${destinationAccount}' not found` });

    const { converted, rate, capturedAt } = await convert(amount, srcAcc.currency, dstAcc.currency);

    const dr = await debit(sourceAccount, amount);
    if (!dr.ok) return res.status(422).json({ code:'INSUFFICIENT_FUNDS', message: dr.body.message||'Insufficient funds' });

    const cr = await credit(destinationAccount, converted);
    if (!cr.ok) {
      await credit(sourceAccount, amount); // rollback
      return res.status(500).json({ code:'INTERNAL_ERROR', message:'Credit failed; debit reversed' });
    }

    save({ transferId, sourceAccount, destinationAccount,
           amount: parseFloat(amount).toFixed(2), currency: srcAcc.currency,
           convertedAmount: converted, exchangeRate: rate, rateCapturedAt: capturedAt,
           status:'completed', createdAt: now, updatedAt: now });

    return res.status(201).json(fmt(db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(transferId)));
  }

  // ── Cross-bank ─────────────────────────────────────────────────────────────
  const banks    = await getBanks();
  const destBank = banks.find(b => b.bankId.startsWith(destPrefix) || destPrefix.startsWith(b.bankId.substring(0,3)));

  if (!destBank) {
    save({ transferId, sourceAccount, destinationAccount,
           amount: parseFloat(amount).toFixed(2), currency: srcAcc.currency,
           status:'pending', errorMessage:'Destination bank not found in directory',
           createdAt: now, updatedAt: now });
    return res.status(201).json(fmt(db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(transferId)));
  }

  // Debit first
  const dr = await debit(sourceAccount, amount);
  if (!dr.ok) return res.status(422).json({ code:'INSUFFICIENT_FUNDS', message: dr.body.message||'Insufficient funds' });

  try {
    const jwt = await signJWT({
      transferId,
      sourceAccount,
      destinationAccount,
      amount: parseFloat(amount).toFixed(2),
      currency: srcAcc.currency,
      sourceBankId: BANK_ID,
      destinationBankId: destBankId,
      timestamp: new Date().toISOString(),
      nonce: Math.random().toString(36).substring(2)
    });

    // destBank.address = the bank's public API base e.g. https://xxx.up.railway.app/api/v1
    const destUrl = destBank.address.replace(/\/+$/, '');
    const sr = await fetch(`${destUrl}/transfers/receive`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ jwt }), timeout: 12000
    });

    if (sr.ok) {
      save({ transferId, sourceAccount, destinationAccount,
             amount: parseFloat(amount).toFixed(2), currency: srcAcc.currency,
             convertedAmount: parseFloat(amount).toFixed(2), exchangeRate:'1.000000', rateCapturedAt: now,
             status:'completed', createdAt: now, updatedAt: now });
    } else {
      const errText = await sr.text();
      await credit(sourceAccount, amount); // refund
      save({ transferId, sourceAccount, destinationAccount,
             amount: parseFloat(amount).toFixed(2), currency: srcAcc.currency,
             status:'pending', errorMessage:`Dest bank HTTP ${sr.status}: ${errText.substring(0,100)}`,
             createdAt: now, updatedAt: now });
    }
  } catch(e) {
    await credit(sourceAccount, amount); // refund
    save({ transferId, sourceAccount, destinationAccount,
           amount: parseFloat(amount).toFixed(2), currency: srcAcc.currency,
           status:'pending', errorMessage: e.message,
           createdAt: now, updatedAt: now });
  }

  return res.status(201).json(fmt(db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(transferId)));
});

// POST /transfers/receive  — spec: security:[], body: { jwt }
// MUST be registered before /:transferId
app.post('/transfers/receive', async (req, res) => {
  const { jwt } = req.body || {};
  if (!jwt) return res.status(400).json({ code:'INVALID_REQUEST', message:'Body must contain { jwt }' });

  let payload;
  try { payload = await verifyJWT(jwt); }
  catch(e) { return res.status(401).json({ code:'UNAUTHORIZED', message:`JWT verification failed: ${e.message}` }); }

  const { transferId, sourceAccount, destinationAccount, amount, currency } = payload;
  if (!transferId||!destinationAccount||!amount)
    return res.status(400).json({ code:'INVALID_REQUEST', message:'JWT payload missing required fields' });

  if (db.prepare('SELECT 1 FROM transfers WHERE transfer_id=?').get(transferId))
    return res.status(409).json({ code:'DUPLICATE_TRANSFER', message:'Transfer already received' });

  const dstAcc = await getAcc(destinationAccount);
  if (!dstAcc) return res.status(404).json({ code:'ACCOUNT_NOT_FOUND', message:`Destination account '${destinationAccount}' not found` });

  const { converted, rate, capturedAt } = await convert(amount, currency||'EUR', dstAcc.currency);

  const cr = await credit(destinationAccount, converted);
  if (!cr.ok) return res.status(500).json({ code:'INTERNAL_ERROR', message:'Failed to credit destination account' });

  const now = new Date().toISOString();
  save({ transferId, sourceAccount: sourceAccount||'external', destinationAccount,
         amount: parseFloat(amount).toFixed(2), currency: currency||'EUR',
         convertedAmount: converted, exchangeRate: rate, rateCapturedAt: capturedAt,
         status:'completed', createdAt: now, updatedAt: now });

  return res.status(200).json({ transferId, status:'completed', destinationAccount, amount: converted, timestamp: now });
});

// GET /transfers/:transferId
app.get('/transfers/:transferId', (req, res) => {
  const r = db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(req.params.transferId);
  if (!r) return res.status(404).json({ code:'TRANSFER_NOT_FOUND', message:`Transfer '${req.params.transferId}' not found` });
  return res.json(fmt(r));
});

// GET /transfers/user/:userId
app.get('/transfers/user/:userId', async (req, res) => {
  try {
    const r = await fetch(`${ACCOUNT_SVC}/accounts/owner/${req.params.userId}`, { timeout: 5000 });
    if (!r.ok) return res.json([]);
    const accs = await r.json();
    if (!accs.length) return res.json([]);
    const nums = accs.map(a => a.accountNumber);
    const ph   = nums.map(() => '?').join(',');
    return res.json(
      db.prepare(`SELECT * FROM transfers WHERE source_account IN (${ph}) OR destination_account IN (${ph}) ORDER BY created_at DESC`)
        .all([...nums,...nums]).map(fmt)
    );
  } catch(e) { return res.status(500).json({ code:'INTERNAL_ERROR', message: e.message }); }
});

// Debug endpoint — show cache contents
app.get('/debug/banks', async (req, res) => {
  const banks = await getBanks();
  res.json({ count: banks.length, banks: banks.map(b => ({ bankId: b.bankId, address: b.address })) });
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, async () => {
  console.log(`[transfer-service] :${PORT}`);
  // Pre-warm caches on startup
  await getBanks();
  await getRates();
  console.log(`[transfer-service] Caches warmed — ${_banks.length} banks loaded`);
});
