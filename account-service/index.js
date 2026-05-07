'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PREFIX = (process.env.BANK_ID || 'MIN').substring(0, 3).toUpperCase();
const CHARS  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SUPPORTED = new Set(['EUR','USD','GBP','SEK','NOK','DKK','CHF','JPY','PLN','CZK']);

const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, 'accounts.db'));
db.exec(`CREATE TABLE IF NOT EXISTS accounts (
  account_number TEXT PRIMARY KEY,
  owner_id       TEXT NOT NULL,
  owner_name     TEXT NOT NULL,
  currency       TEXT NOT NULL,
  balance        TEXT NOT NULL DEFAULT '0.00',
  created_at     TEXT NOT NULL
)`);

function genAccNum() {
  let s = '';
  for (let i = 0; i < 5; i++) s += CHARS[Math.floor(Math.random() * CHARS.length)];
  return PREFIX + s;
}

function fmt(a) {
  return { accountNumber: a.account_number, ownerId: a.owner_id, ownerName: a.owner_name,
           currency: a.currency, balance: a.balance, createdAt: a.created_at };
}

// POST /accounts  (internal)
app.post('/accounts', (req, res) => {
  const { ownerId, ownerName, currency } = req.body || {};
  if (!ownerId)   return res.status(400).json({ code: 'INVALID_REQUEST', message: 'ownerId required' });
  if (!ownerName) return res.status(400).json({ code: 'INVALID_REQUEST', message: 'ownerName required' });
  const cur = (currency || 'EUR').toUpperCase();
  if (!SUPPORTED.has(cur))
    return res.status(400).json({ code: 'UNSUPPORTED_CURRENCY', message: `Currency '${cur}' is not supported` });

  let acn;
  for (let i = 0; i < 20; i++) {
    const c = genAccNum();
    if (!db.prepare('SELECT 1 FROM accounts WHERE account_number=?').get(c)) { acn = c; break; }
  }
  if (!acn) return res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Could not generate unique account number' });

  const now = new Date().toISOString();
  db.prepare('INSERT INTO accounts (account_number,owner_id,owner_name,currency,balance,created_at) VALUES (?,?,?,?,?,?)')
    .run(acn, ownerId, ownerName, cur, '0.00', now);
  return res.status(201).json(fmt(db.prepare('SELECT * FROM accounts WHERE account_number=?').get(acn)));
});

// GET /accounts/owner/:ownerId  (internal — BEFORE /:accountNumber)
app.get('/accounts/owner/:ownerId', (req, res) => {
  return res.json(db.prepare('SELECT * FROM accounts WHERE owner_id=? ORDER BY created_at').all(req.params.ownerId).map(fmt));
});

// GET /accounts/:accountNumber  (public)
app.get('/accounts/:accountNumber', (req, res) => {
  const acn = req.params.accountNumber.toUpperCase();
  const a = db.prepare('SELECT * FROM accounts WHERE account_number=?').get(acn);
  if (!a) return res.status(404).json({ code: 'ACCOUNT_NOT_FOUND', message: `Account '${acn}' not found` });
  return res.json(fmt(a));
});

// POST /accounts/:accountNumber/debit  (internal)
app.post('/accounts/:accountNumber/debit', (req, res) => {
  const acn = req.params.accountNumber.toUpperCase();
  const amount = parseFloat(req.body?.amount);
  if (!amount || amount <= 0) return res.status(400).json({ code: 'INVALID_AMOUNT', message: 'Invalid amount' });
  const a = db.prepare('SELECT * FROM accounts WHERE account_number=?').get(acn);
  if (!a) return res.status(404).json({ code: 'ACCOUNT_NOT_FOUND', message: 'Account not found' });
  const bal = parseFloat(a.balance);
  if (bal < amount) return res.status(422).json({ code: 'INSUFFICIENT_FUNDS', message: 'Insufficient funds' });
  const newBal = (bal - amount).toFixed(2);
  db.prepare('UPDATE accounts SET balance=? WHERE account_number=?').run(newBal, acn);
  return res.json({ accountNumber: acn, balance: newBal });
});

// POST /accounts/:accountNumber/credit  (internal)
app.post('/accounts/:accountNumber/credit', (req, res) => {
  const acn = req.params.accountNumber.toUpperCase();
  const amount = parseFloat(req.body?.amount);
  if (!amount || amount <= 0) return res.status(400).json({ code: 'INVALID_AMOUNT', message: 'Invalid amount' });
  const a = db.prepare('SELECT * FROM accounts WHERE account_number=?').get(acn);
  if (!a) return res.status(404).json({ code: 'ACCOUNT_NOT_FOUND', message: 'Account not found' });
  const newBal = (parseFloat(a.balance) + amount).toFixed(2);
  db.prepare('UPDATE accounts SET balance=? WHERE account_number=?').run(newBal, acn);
  return res.json({ accountNumber: acn, balance: newBal });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`[account-service] :${PORT}`));

// TEMP: fund account for testing (remove in production)
app.post('/accounts/:accountNumber/fund', (req, res) => {
  const acn = req.params.accountNumber.toUpperCase();
  const amount = parseFloat(req.body?.amount || '1000');
  const a = db.prepare('SELECT * FROM accounts WHERE account_number=?').get(acn);
  if (!a) return res.status(404).json({ error: 'Account not found' });
  const newBal = (parseFloat(a.balance) + amount).toFixed(2);
  db.prepare('UPDATE accounts SET balance=? WHERE account_number=?').run(newBal, acn);
  return res.json({ accountNumber: acn, balance: newBal });
});
