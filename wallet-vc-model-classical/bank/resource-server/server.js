/**
 * Mock Banking Resource Server (Classical Model)
 *
 * Validates access tokens from:
 *   1. Keycloak (JWT, ES384 — original FAPI 2.0 flow)
 *   2. Bank Issuer (opaque token via /introspect — VC Presentation Grant flow)
 *
 * Endpoints:
 *   GET  /api/accounts                  — List user's bank accounts
 *   GET  /api/accounts/:id              — Get specific account details
 *   GET  /api/accounts/:id/transactions — List transactions
 *   GET  /api/accounts/:id/cards        — List cards
 *   GET  /api/accounts/:id/loans        — List loans
 *   GET  /api/transfers                 — List recent transfers
 *   POST /api/transfers                 — Create a new transfer
 *   GET  /api/profile                   — Get user profile
 */

require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const express = require('express');
const { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } = require('jose');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
  keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
  realm: process.env.REALM || 'fapi-demo',
  bankIssuerUrl: process.env.BANK_ISSUER_URL || 'http://localhost:7000',
  port: parseInt(process.env.PORT || '4000', 10),
  resourceServerAudience: process.env.RS_AUDIENCE || 'http://localhost:4000',
  tlsKeyPath: process.env.TLS_KEY_PATH || path.join(__dirname, '../certs/rs.key'),
  tlsCertPath: process.env.TLS_CERT_PATH || path.join(__dirname, '../certs/rs.crt'),
};

const KEYCLOAK_ISSUER = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}`;
const KEYCLOAK_JWKS_URI = `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`;
const BANK_ISSUER_JWKS_URI = `${CONFIG.bankIssuerUrl}/.well-known/jwks.json`;

let keycloakJwks = null;
let bankJwks = null;

function getKeycloakJwks() {
  if (!keycloakJwks) {
    try {
      keycloakJwks = createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URI), {
        cacheMaxAge: 600000,
        cooldownDuration: 30000,
      });
    } catch (e) {
      console.warn('[JWKS] Keycloak JWKS not initialized:', e.message);
    }
  }
  return keycloakJwks;
}

function getBankJwks() {
  if (!bankJwks) {
    try {
      bankJwks = createRemoteJWKSet(new URL(BANK_ISSUER_JWKS_URI), {
        cacheMaxAge: 600000,
        cooldownDuration: 30000,
      });
    } catch (e) {
      console.warn('[JWKS] Bank Issuer JWKS not initialized:', e.message);
    }
  }
  return bankJwks;
}

// ============================================================
// Database & Berka Dataset Integration
// ============================================================
const dbPath = path.join(__dirname, 'berka.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[DB] Failed to connect to berka.db:', err.message);
  } else {
    console.log('[DB] Connected to berka.db SQLite database (Classical Model).');
    ensureDatabaseSchema();
  }
});

function ensureDatabaseSchema() {
  db.all('PRAGMA table_info(trans)', [], (err, rows) => {
    if (err) {
      console.warn('[DB] Could not inspect trans schema:', err.message);
      return;
    }
    const cols = (rows || []).map(r => r.name);
    if (!cols.includes('bank')) {
      db.run("ALTER TABLE trans ADD COLUMN bank TEXT DEFAULT 'MOCK_BANK'", (aErr) => {
        if (!aErr) console.log('[DB] Auto-migration: added column bank to trans.');
      });
    }
    if (!cols.includes('account')) {
      db.run("ALTER TABLE trans ADD COLUMN account TEXT DEFAULT '987654321'", (aErr) => {
        if (!aErr) console.log('[DB] Auto-migration: added column account to trans.');
      });
    }
  });
}

function queryDB(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function runDB(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function getClientIdFromToken(payload) {
  const username = payload.preferred_username || payload.sub || '';
  if (username === 'testuser') return 1;
  const match = username.match(/^user(\d+)$/i);
  if (match) {
    const parsedId = parseInt(match[1], 10);
    if (!isNaN(parsedId) && parsedId > 0) return parsedId;
  }
  return 1;
}

// ============================================================
// CORS Middleware
// ============================================================
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Client-Cert-Thumbprint');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// Extract RFC 8705 client certificate thumbprint (C-TLS-5, C-TLS-6, AT-05)
function extractClientCertThumbprint(req) {
  // 1. Forwarded client certificate from TLS-terminating reverse proxy (e.g. Nginx ssl-client-cert)
  const sslClientCertHeader = req.headers['ssl-client-cert'] || req.headers['x-forwarded-client-cert'];
  if (sslClientCertHeader) {
    try {
      const decodedPem = decodeURIComponent(sslClientCertHeader);
      const base64Der = decodedPem
        .replace(/-----BEGIN [^-]+-----/g, '')
        .replace(/-----END [^-]+-----/g, '')
        .replace(/\s+/g, '');
      if (base64Der) {
        const derBuffer = Buffer.from(base64Der, 'base64');
        return crypto.createHash('sha256').update(derBuffer).digest('base64url');
      }
    } catch (e) {
      console.warn('[mTLS] Failed to parse ssl-client-cert header:', e.message);
    }
  }

  // 2. Direct TLS socket peer certificate
  if (req.socket && typeof req.socket.getPeerCertificate === 'function') {
    const peerCert = req.socket.getPeerCertificate();
    if (peerCert && peerCert.raw) {
      return crypto.createHash('sha256').update(peerCert.raw).digest('base64url');
    }
  }

  // 3. Pre-computed header from trusted upstream or test fixture
  if (req.headers['x-client-cert-thumbprint']) {
    return req.headers['x-client-cert-thumbprint'];
  }

  return null;
}

// ============================================================
// Token Validation Middleware (VDAM F6 Local Zero-Roundtrip)
// ============================================================
async function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid Authorization header. Expected: Bearer <token>',
    });
  }

  const token = authHeader.split(' ')[1];
  const parts = token.split('.');
  const isJwt = parts.length === 3;

  const clientCertThumbprint = extractClientCertThumbprint(req);

  // ── Strategy 1: Local JWT Verification (VDAM Specification Section 6.5 & Eq 6.12 Accept_RS) ──
  if (isJwt) {
    // 1a. Try Bank Issuer JWKS (VDAM Self-Contained Access Token Flow)
    try {
      const bankJwksSet = getBankJwks();
      if (bankJwksSet) {
        const { payload, protectedHeader } = await jwtVerify(token, bankJwksSet);

        // Eq 6.12 Accept_RS: Validate Audience (Fail-Closed)
        if (!payload.aud) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token missing required audience (aud) claim',
          });
        }
        const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        const matchesAud = audList.some(a =>
          a === CONFIG.resourceServerAudience ||
          a === `http://localhost:${CONFIG.port}` ||
          a === `https://localhost:${CONFIG.port}` ||
          a === 'http://localhost:4000' ||
          a === 'https://localhost:4000' ||
          (process.env.BANK_HOST && (a === `http://${process.env.BANK_HOST}:4000` || a === `https://${process.env.BANK_HOST}:4000`))
        );
        if (!matchesAud) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: `Token audience mismatch. Expected ${CONFIG.resourceServerAudience}, got: ${JSON.stringify(payload.aud)}`,
          });
        }

        // Eq 6.12 Accept_RS: Validate mTLS Certificate-Bound Sender Constraint (AT-05) - Mandatory Fail-Closed
        let cnf = payload.cnf;
        if (typeof cnf === 'string') {
          try {
            cnf = JSON.parse(cnf);
          } catch (e) {}
        }
        if (!cnf || !cnf['x5t#S256']) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Certificate-bound access token mandatory under VDAM: missing cnf x5t#S256 (AT-05)',
          });
        }
        const expectedThumbprint = cnf['x5t#S256'];
        if (!clientCertThumbprint) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'mTLS client certificate required for certificate-bound access token (AT-05)',
          });
        }
        if (clientCertThumbprint !== expectedThumbprint) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'mTLS sender constraint verification failed: Client cert thumbprint mismatch with token cnf (AT-05)',
          });
        }

        req.tokenPayload = payload;
        req.tokenHeader = protectedHeader;
        req.tokenRaw = token;
        req.tokenSource = 'bank-issuer';
        return next();
      }
    } catch (bankErr) {
      // Not signed by Bank Issuer or verification failed, fall through to Keycloak
    }

    // 1b. Try Keycloak JWKS (Traditional FAPI Baseline Flow)
    try {
      const kcJwksSet = getKeycloakJwks();
      if (kcJwksSet) {
        const { payload, protectedHeader } = await jwtVerify(token, kcJwksSet);
        const allowedIssuers = new Set([
          KEYCLOAK_ISSUER,
          `http://localhost:8080/realms/${CONFIG.realm}`,
          `https://localhost:8443/realms/${CONFIG.realm}`,
          `http://keycloak:8080/realms/${CONFIG.realm}`,
          `https://keycloak:8443/realms/${CONFIG.realm}`,
        ]);
        if (process.env.BANK_HOST) {
          allowedIssuers.add(`http://${process.env.BANK_HOST}:8080/realms/${CONFIG.realm}`);
          allowedIssuers.add(`https://${process.env.BANK_HOST}:8443/realms/${CONFIG.realm}`);
        }
        const isValidIssuer = allowedIssuers.has(payload.iss) ||
          (typeof payload.iss === 'string' && payload.iss.endsWith(`/realms/${CONFIG.realm}`));
        if (!isValidIssuer) {
          throw new Error(`Unexpected Keycloak issuer: ${payload.iss}`);
        }

        // Eq 6.12 Accept_RS: Validate mTLS Certificate-Bound Sender Constraint (AT-05) - Mandatory Fail-Closed
        let kcCnf = payload.cnf;
        if (typeof kcCnf === 'string') {
          try {
            kcCnf = JSON.parse(kcCnf);
          } catch (e) {}
        }
        if (!kcCnf || !kcCnf['x5t#S256']) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Certificate-bound access token mandatory under FAPI 2.0: missing cnf x5t#S256 (AT-05)',
          });
        }
        const expectedThumbprint = kcCnf['x5t#S256'];
        if (!clientCertThumbprint) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'mTLS client certificate required for certificate-bound access token (AT-05)',
          });
        }
        if (clientCertThumbprint !== expectedThumbprint) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'mTLS sender constraint verification failed: Client cert thumbprint mismatch with token cnf (AT-05)',
          });
        }

        req.tokenPayload = payload;
        req.tokenHeader = protectedHeader;
        req.tokenRaw = token;
        req.tokenSource = 'keycloak';
        return next();
      }
    } catch (kcErr) {
      // Keycloak verification also failed
    }
  }

  return res.status(401).json({
    error: 'invalid_token',
    error_description: 'Token validation failed (invalid token signature, expired, or unrecognized issuer)',
  });
}

const SCOPE_SYNONYMS = {
  'accounts:read': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadAccountsBasic': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadAccountsDetail': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadBalances': ['accounts:read', 'ReadBalances', 'ReadAccountsDetail'],
  'transactions:read': ['transactions:read', 'transfers:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
  'transfers:read': ['transfers:read', 'transactions:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
  'ReadTransactionsBasic': ['transfers:read', 'transactions:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
  'ReadTransactionsDetail': ['transfers:read', 'transactions:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
  'transfers:write': ['transfers:write', 'CreateDomesticPayment'],
  'CreateDomesticPayment': ['transfers:write', 'CreateDomesticPayment'],
  'cards:read': ['cards:read', 'accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'loans:read': ['loans:read', 'accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'profile:read': ['profile:read', 'profile', 'openid'],
};

function requireScope(scope) {
  return (req, res, next) => {
    const tokenScope = req.tokenPayload.scope || '';
    const scopes = tokenScope.split(' ');
    const allowedScopes = SCOPE_SYNONYMS[scope] || [scope];

    const hasScope = scopes.some(s => allowedScopes.includes(s) || s === 'banking' || s === '*');

    if (!hasScope) {
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: `This endpoint requires the '${scope}' scope. Your token has: [${tokenScope}]`,
        required_scope: scope,
        current_scopes: scopes,
        token_source: req.tokenSource || 'unknown',
      });
    }
    next();
  };
}

// Canonical AIS identifiers (ACC-NNN) map one-to-one onto Berka internal account ids.
function toCanonicalAccountId(internalId) {
  return `ACC-${String(internalId).padStart(3, '0')}`;
}

function toInternalAccountId(canonicalId) {
  const match = /^ACC-(\d+)$/.exec(String(canonicalId));
  const parsed = match ? parseInt(match[1], 10) : Number(canonicalId);
  return Number.isSafeInteger(parsed) ? parsed : NaN;
}

// Canonical AIS record for one owned account, built from authoritative Berka rows: the account's most
// recent booked movement. Never synthesised from the access token.
async function canonicalAccountRecord(account) {
  const latest = await queryDB(
    'SELECT date, type, operation, amount, balance FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1',
    [account.account_id]
  );
  const movement = latest.length > 0 ? latest[0] : {};
  const rawDate = String(movement.date !== undefined ? movement.date : (account.created_date || ''));
  return {
    account_id: toCanonicalAccountId(account.account_id),
    amount: movement.amount !== undefined ? Number(parseFloat(movement.amount).toFixed(2)) : 0,
    balance: movement.balance !== undefined ? Number(parseFloat(movement.balance).toFixed(2)) : 0,
    date: rawDate.length === 6
      ? `19${rawDate.slice(0, 2)}-${rawDate.slice(2, 4)}-${rawDate.slice(4, 6)}`
      : rawDate,
    operation: movement.operation || 'UNKNOWN',
    type: movement.type === 'PRIJEM' ? 'Credit' : 'Debit'
  };
}

function projectFields(record, fields) {
  if (!Array.isArray(fields) || fields.length === 0) return record;
  const projected = {};
  fields.forEach(field => {
    if (Object.prototype.hasOwnProperty.call(record, field)) projected[field] = record[field];
  });
  return projected;
}

async function typedAuthorityProjection(tokenPayload, rows) {
  const authority = tokenPayload.typed_authority;
  if (!authority) return null;
  const evaluationTime = Number(tokenPayload.typed_authority_evaluation_time || Math.floor(Date.now() / 1000));
  if (!authority.validity || evaluationTime < authority.validity.start || evaluationTime > authority.validity.end) {
    const error = new Error('REJECT_TYPED_AUTHORITY_OUTSIDE_VALIDITY');
    error.status = 403;
    throw error;
  }
  const accounts = Array.isArray(authority.accounts) ? authority.accounts : [];
  const fields = authority.data && Array.isArray(authority.data.fields) ? authority.data.fields : [];
  const pageSize = authority.data ? Number(authority.data.page_size) : 0;
  if (accounts.length === 0 || fields.length === 0 || pageSize <= 0) {
    const error = new Error('REJECT_INVALID_TYPED_AUTHORITY');
    error.status = 403;
    throw error;
  }
  // Effective authority narrows what the holder actually owns; it never creates accounts. Only accounts
  // present in both the authority and the authoritative entitlement rows are projected.
  const authorized = new Set(accounts.map(toInternalAccountId).filter(Number.isSafeInteger));
  const entitled = rows
    .filter(account => authorized.has(Number(account.account_id)))
    .sort((left, right) => Number(left.account_id) - Number(right.account_id))
    .slice(0, pageSize);

  const records = [];
  for (const account of entitled) {
    records.push(projectFields(await canonicalAccountRecord(account), fields));
  }
  return records;
}

// ============================================================
// API Endpoints
// ============================================================

app.get('/', (req, res) => {
  res.redirect('/api');
});

app.get('/health', (req, res) => {
  res.json({ status: 'UP', service: 'banking-resource-server-classical', timestamp: new Date().toISOString() });
});

app.get('/api', (req, res) => {
  res.json({
    service: 'Classical FAPI Banking Resource Server',
    version: '2.0.0',
    dataset: 'Berka Financial Dataset',
    endpoints: [
      { method: 'GET', path: '/api/accounts', scope: 'accounts:read', description: 'List user accounts' },
      { method: 'GET', path: '/api/accounts/:id', scope: 'accounts:read', description: 'Account details' },
      { method: 'GET', path: '/api/accounts/:id/transactions', scope: 'transactions:read', description: 'Account transactions' },
      { method: 'GET', path: '/api/accounts/:id/cards', scope: 'accounts:read', description: 'Account cards' },
      { method: 'GET', path: '/api/accounts/:id/loans', scope: 'accounts:read', description: 'Account loans' },
      { method: 'GET', path: '/api/transfers', scope: 'transfers:read', description: 'List recent transfers' },
      { method: 'POST', path: '/api/transfers', scope: 'transfers:write', description: 'Create transfer' },
      { method: 'GET', path: '/api/profile', scope: 'profile:read', description: 'User profile' },
    ]
  });
});

// GET /api/accounts
app.get(['/api/accounts', '/api/v1/accounts'], validateToken, requireScope('accounts:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  try {
    const rows = await queryDB(`
      SELECT a.account_id, a.district_id, a.frequency, a.date as created_date, d.type as disp_type
      FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ?
    `, [clientId]);

    // Attach latest balance for convenience
    for (const acc of rows) {
      const trans = await queryDB(`
        SELECT balance, date FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1
      `, [acc.account_id]);
      acc.balance = trans.length > 0 ? trans[0].balance : 0;
      acc.currency = 'CZK';
    }

    let requestedFields = null;
    if (req.query.fields) {
      requestedFields = req.query.fields.split(',').map(f => f.trim()).filter(Boolean);
    } else if (req.query.workload && req.query.workload.toLowerCase() === 'small') {
      requestedFields = ['account_id', 'balance'];
    } else if (req.tokenPayload && req.tokenPayload.authorization_details) {
      const authDetails = Array.isArray(req.tokenPayload.authorization_details) ? req.tokenPayload.authorization_details : [];
      for (const ad of authDetails) {
        if (ad.datatypes && Array.isArray(ad.datatypes)) {
          if (ad.datatypes.includes('account_id') || ad.datatypes.includes('balance')) {
            requestedFields = ad.datatypes;
            break;
          }
        }
      }
    }

    let accountProjection = await typedAuthorityProjection(req.tokenPayload, rows);
    if (!accountProjection) {
      accountProjection = [];
      for (const acc of rows) {
        const record = projectFields(await canonicalAccountRecord(acc), requestedFields);
        if (requestedFields && !record.account_id) record.account_id = toCanonicalAccountId(acc.account_id);
        accountProjection.push(record);
      }
    }
    res.json({
      Data: {
        Account: accountProjection
      },
      Links: {
        Self: '/api/v1/accounts'
      },
      Meta: {
        TotalPages: 1,
        TotalResults: accountProjection.length
      }
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? 'forbidden' : 'server_error', error_description: err.message });
  }
});

// GET /api/accounts/:id
app.get(['/api/accounts/:id', '/api/v1/accounts/:id'], validateToken, requireScope('accounts:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  let accountId = req.params.id;
  if (typeof accountId === 'string' && accountId.startsWith('ACC')) {
    const num = parseInt(accountId.replace(/\D/g, ''));
    if (!isNaN(num)) accountId = num;
  }
  try {
    const rows = await queryDB(`
      SELECT a.account_id, a.district_id, a.frequency, a.date as created_date, d.type as disp_type
      FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ? AND a.account_id = ?
    `, [clientId, accountId]);

    if (rows.length === 0) {
      // Separate "does not exist" from "exists but is not yours": a not-found answer is not evidence that
      // an authorization boundary was enforced.
      const existing = await queryDB('SELECT account_id FROM accounts WHERE account_id = ?', [accountId]);
      if (existing.length > 0) {
        return res.status(403).json({
          error: 'forbidden',
          error_code: 'REJECT_RESOURCE_ACCESS_OUT_OF_BOUNDS',
          error_description: `Account ${accountId} is outside the authority granted to this client.`,
        });
      }
      return res.status(404).json({ error: 'not_found', error_description: `Account ${accountId} does not exist.` });
    }

    res.json({
      data: rows[0],
      meta: { timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/accounts/:id/transactions
app.get(['/api/accounts/:id/transactions', '/api/v1/accounts/:id/transactions'], validateToken, requireScope('transactions:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;
  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) return res.status(403).json({ error: 'forbidden', details: 'Not owner of account' });

    const rows = await queryDB(`
      SELECT trans_id, date, type, operation, amount, balance, k_symbol
      FROM trans
      WHERE account_id = ?
      ORDER BY date DESC, trans_id DESC
      LIMIT 50
    `, [accountId]);

    res.json({
      data: rows,
      meta: { total: rows.length, accountId, timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/accounts/:id/cards
app.get(['/api/accounts/:id/cards', '/api/v1/accounts/:id/cards'], validateToken, requireScope('accounts:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;
  try {
    const rows = await queryDB(`
      SELECT c.card_id, c.type as card_type, c.issued, d.type as disp_type
      FROM cards c
      JOIN disp d ON c.disp_id = d.disp_id
      WHERE d.account_id = ? AND d.client_id = ?
    `, [accountId, clientId]);

    res.json({
      data: rows,
      meta: { total: rows.length, accountId, timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/accounts/:id/loans
app.get(['/api/accounts/:id/loans', '/api/v1/accounts/:id/loans'], validateToken, requireScope('accounts:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;
  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) return res.status(403).json({ error: 'forbidden', details: 'Not owner of account' });

    const rows = await queryDB(`
      SELECT loan_id, date, amount, duration, payments, status
      FROM loans
      WHERE account_id = ?
    `, [accountId]);

    res.json({
      data: rows,
      meta: { total: rows.length, accountId, timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/transfers
app.get(['/api/transfers', '/api/v1/transfers'], validateToken, (req, res, next) => {
  const tokenScope = req.tokenPayload.scope || '';
  const scopes = tokenScope.split(' ');
  if (!scopes.includes('transfers:read') && !scopes.includes('accounts:read') && !scopes.includes('transfers:write') && !scopes.includes('banking')) {
    return res.status(403).json({
      error: 'insufficient_scope',
      error_description: `This endpoint requires 'transfers:read' or 'accounts:read' scope. Your token has: [${tokenScope}]`,
      required_scope: 'transfers:read',
      current_scopes: scopes,
    });
  }
  next();
}, async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  try {
    const accounts = await queryDB(`
      SELECT a.account_id 
      FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ?
    `, [clientId]);

    if (accounts.length === 0) {
      return res.json({ data: [], meta: { total: 0, clientId, timestamp: new Date().toISOString() } });
    }

    const accountIds = accounts.map(a => a.account_id);
    const placeholders = accountIds.map(() => '?').join(',');

    const rows = await queryDB(`
      SELECT trans_id, account_id, date, type, operation, amount, balance, k_symbol
      FROM trans
      WHERE account_id IN (${placeholders})
      ORDER BY date DESC, trans_id DESC
      LIMIT 50
    `, accountIds);

    res.json({
      data: rows,
      meta: { total: rows.length, clientId, timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// POST /api/transfers
app.post(['/api/transfers', '/api/v1/transfers'], validateToken, requireScope('transfers:write'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const { fromAccount, toAccount, amount, bank = 'XY', description = '' } = req.body;

  if (!fromAccount || !toAccount || !amount) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing fromAccount, toAccount, or amount' });
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, fromAccount]);
    if (disp.length === 0) return res.status(403).json({ error: 'forbidden', details: 'Not owner of account' });

    const lastTrans = await queryDB('SELECT balance FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1', [fromAccount]);
    let currentBalance = 10000;
    if (lastTrans.length > 0) currentBalance = parseFloat(lastTrans[0].balance);

    const newBalance = currentBalance - parseFloat(amount);
    if (newBalance < 0) return res.status(400).json({ error: 'insufficient_funds' });

    const transId = Math.floor(Math.random() * 10000000) + 2000000;
    const now = new Date();
    const dateStr = `${String(now.getFullYear()).slice(2)}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`;

    await runDB(`
      INSERT INTO trans (trans_id, account_id, date, type, operation, amount, balance, k_symbol, bank, account)
      VALUES (?, ?, ?, 'VYDAJ', 'PREVOD NA UCET', ?, ?, 'POJISTNE', ?, ?)
    `, [transId, fromAccount, dateStr, amount, newBalance, bank, toAccount]);

    res.status(201).json({
      success: true,
      message: 'Transfer executed successfully',
      data: {
        trans_id: transId,
        from_account: fromAccount,
        to_account: toAccount,
        to_bank: bank,
        amount: parseFloat(amount),
        previous_balance: currentBalance,
        new_balance: newBalance,
        date: dateStr,
        description,
      },
      meta: { timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/profile
app.get(['/api/profile', '/api/v1/user/profile', '/api/v1/profile'], validateToken, requireScope('profile:read'), async (req, res) => {
  const payload = req.tokenPayload;
  const clientId = getClientIdFromToken(payload);
  try {
    const rows = await queryDB(`
      SELECT c.*, d.name as district_name, d.region
      FROM clients c
      LEFT JOIN district d ON c.district_id = d.district_id
      WHERE c.client_id = ?
    `, [clientId]);

    const clientProfile = rows.length > 0 ? rows[0] : null;

    res.json({
      data: {
        sub: payload.sub,
        preferred_username: payload.preferred_username || payload.sub,
        email: (clientProfile && clientProfile.email) || payload.email || `${payload.sub || 'user'}@fapi-demo.local`,
        name: (clientProfile && clientProfile.name) || payload.name || 'Test User',
        client_id: clientId,
        token_source: req.tokenSource,
        scope: payload.scope,
        berka_profile: clientProfile,
      },
      meta: { timestamp: new Date().toISOString() }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// ============================================================
// Open Banking UK v3.1 / v4.0 Standard Endpoints (Classical VDAM)
// ============================================================

// GET /open-banking/v3.1/meta - Open Banking Capabilities
app.get('/open-banking/v3.1/meta', (req, res) => {
  res.json({
    standard: 'Open Banking UK Read/Write API Specification',
    spec_version: 'v3.1.11 / v4.0.1',
    profile: 'VDAM Classical ECDSA P-384 + RFC 8705 Sender-Constrained',
    bank_issuer: CONFIG.bankIssuerUrl,
    supported_services: ['AISP (Account Information)', 'PISP (Payment Initiation)'],
    endpoints: {
      accounts: '/open-banking/v3.1/aisp/accounts',
      balances: '/open-banking/v3.1/aisp/accounts/{AccountId}/balances',
      transactions: '/open-banking/v3.1/aisp/accounts/{AccountId}/transactions',
      domestic_payments: '/open-banking/v3.1/pisp/domestic-payments',
    },
    permissions: [
      'ReadAccountsDetail',
      'ReadBalances',
      'ReadTransactionsDetail',
      'CreateDomesticPayment'
    ]
  });
});

// GET /open-banking/v3.1/aisp/accounts - Standard OB Accounts List
app.get('/open-banking/v3.1/aisp/accounts', validateToken, requireScope('ReadAccountsDetail'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  try {
    const rows = await queryDB(`
      SELECT a.account_id, a.district_id, a.frequency, a.date as created_date, d.type as disp_type
      FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ?
    `, [clientId]);

    const obAccounts = [];
    for (const acc of rows) {
      const trans = await queryDB(`
        SELECT balance, date FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1
      `, [acc.account_id]);
      const bal = trans.length > 0 ? trans[0].balance : 0;

      obAccounts.push({
        AccountId: String(acc.account_id),
        Currency: 'CZK',
        AccountType: 'Personal',
        AccountSubType: 'CurrentAccount',
        Description: `Berka Classical Account ${acc.account_id}`,
        Nickname: `Account #${acc.account_id}`,
        OpeningDate: String(acc.created_date),
        Account: [
          {
            SchemeName: 'UK.OBIE.SortCodeAccountNumber',
            Identification: String(acc.account_id),
            Name: req.tokenPayload.name || 'Bank Customer'
          }
        ],
        _currentBalance: bal
      });
    }

    res.json({
      Data: { Account: obAccounts },
      Links: { Self: '/open-banking/v3.1/aisp/accounts' },
      Meta: {
        TotalPages: 1,
        Timestamp: new Date().toISOString(),
        AppliedProtocol: 'VDAM Classical ECDSA P-384'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /open-banking/v3.1/aisp/accounts/:id - Standard OB Account Details
app.get('/open-banking/v3.1/aisp/accounts/:id', validateToken, requireScope('ReadAccountsDetail'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  let accountId = req.params.id;
  if (typeof accountId === 'string' && accountId.startsWith('ACC')) {
    const num = parseInt(accountId.replace(/\D/g, ''));
    if (!isNaN(num)) accountId = num;
  }

  try {
    const rows = await queryDB(`
      SELECT a.account_id, a.district_id, a.frequency, a.date as created_date, d.type as disp_type
      FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ? AND a.account_id = ?
    `, [clientId, accountId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'not_found', error_description: `Account ${accountId} not found or not authorized.` });
    }

    const acc = rows[0];
    res.json({
      Data: {
        Account: [
          {
            AccountId: String(acc.account_id),
            Currency: 'CZK',
            AccountType: 'Personal',
            AccountSubType: 'CurrentAccount',
            Description: `Berka Classical Account ${acc.account_id}`,
            Nickname: `Account #${acc.account_id}`,
            OpeningDate: String(acc.created_date),
            Account: [
              {
                SchemeName: 'UK.OBIE.SortCodeAccountNumber',
                Identification: String(acc.account_id),
                Name: req.tokenPayload.name || 'Bank Customer'
              }
            ]
          }
        ]
      },
      Links: { Self: `/open-banking/v3.1/aisp/accounts/${accountId}` },
      Meta: { TotalPages: 1 }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /open-banking/v3.1/aisp/accounts/:id/balances - Standard OB Balances
app.get('/open-banking/v3.1/aisp/accounts/:id/balances', validateToken, requireScope('ReadBalances'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  let accountId = req.params.id;
  if (typeof accountId === 'string' && accountId.startsWith('ACC')) {
    const num = parseInt(accountId.replace(/\D/g, ''));
    if (!isNaN(num)) accountId = num;
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Account does not belong to user.' });
    }

    const trans = await queryDB(`
      SELECT balance, date FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1
    `, [accountId]);
    const currentBalance = trans.length > 0 ? trans[0].balance : 0;

    res.json({
      Data: {
        Balance: [
          {
            AccountId: String(accountId),
            Amount: {
              Amount: currentBalance.toFixed(2),
              Currency: 'CZK'
            },
            CreditDebitIndicator: currentBalance >= 0 ? 'Credit' : 'Debit',
            Type: 'InterimAvailable',
            DateTime: new Date().toISOString()
          }
        ]
      },
      Links: { Self: `/open-banking/v3.1/aisp/accounts/${accountId}/balances` },
      Meta: { TotalPages: 1, AppliedProtocol: 'VDAM Classical ECDSA P-384' }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /open-banking/v3.1/aisp/accounts/:id/transactions - Standard OB Transactions (with D dimension date filter)
app.get('/open-banking/v3.1/aisp/accounts/:id/transactions', validateToken, requireScope('ReadTransactionsDetail'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  let accountId = req.params.id;
  if (typeof accountId === 'string' && accountId.startsWith('ACC')) {
    const num = parseInt(accountId.replace(/\D/g, ''));
    if (!isNaN(num)) accountId = num;
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Account does not belong to user.' });
    }

    const limit = parseInt(req.query.limit || '50', 10);
    const fromDate = req.query.fromBookingDateTime || req.query.fromDate;
    const toDate = req.query.toBookingDateTime || req.query.toDate;

    let sql = 'SELECT trans_id, date, type, operation, amount, balance, k_symbol, account, bank FROM trans WHERE account_id = ?';
    const params = [accountId];

    if (fromDate) {
      const cleanFrom = parseInt(String(fromDate).replace(/\D/g, '').slice(2, 8) || '0', 10);
      if (cleanFrom > 0) {
        sql += ' AND date >= ?';
        params.push(cleanFrom);
      }
    }
    if (toDate) {
      const cleanTo = parseInt(String(toDate).replace(/\D/g, '').slice(2, 8) || '999999', 10);
      if (cleanTo > 0) {
        sql += ' AND date <= ?';
        params.push(cleanTo);
      }
    }

    sql += ' ORDER BY date DESC, trans_id DESC LIMIT ?';
    params.push(limit);

    const rows = await queryDB(sql, params);

    const obTransactions = rows.map(r => ({
      AccountId: String(accountId),
      TransactionId: String(r.trans_id),
      TransactionReference: `TX-${r.trans_id}`,
      Amount: {
        Amount: parseFloat(r.amount).toFixed(2),
        Currency: 'CZK'
      },
      CreditDebitIndicator: r.type === 'PRIJEM' ? 'Credit' : 'Debit',
      Status: 'Booked',
      BookingDateTime: `19${String(r.date).slice(0, 2)}-${String(r.date).slice(2, 4)}-${String(r.date).slice(4, 6)}T12:00:00Z`,
      TransactionInformation: `${r.operation || 'TRANSACTION'} - ${r.k_symbol || 'GENERAL'}`,
      Balance: {
        Amount: { Amount: parseFloat(r.balance).toFixed(2), Currency: 'CZK' },
        CreditDebitIndicator: r.balance >= 0 ? 'Credit' : 'Debit',
        Type: 'InterimBooked'
      }
    }));

    res.json({
      Data: { Transaction: obTransactions },
      Links: { Self: `/open-banking/v3.1/aisp/accounts/${accountId}/transactions` },
      Meta: {
        TotalPages: 1,
        Count: obTransactions.length,
        HistoryWindowApplied: { from: fromDate || 'UNBOUNDED', to: toDate || 'UNBOUNDED' },
        AppliedProtocol: 'VDAM Classical ECDSA P-384'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// POST /open-banking/v3.1/pisp/domestic-payments - Standard OB Domestic Payment Initiation
app.post('/open-banking/v3.1/pisp/domestic-payments', validateToken, requireScope('CreateDomesticPayment'), async (req, res) => {
  const initiation = req.body?.Data?.Initiation || {};
  const fromAccount = initiation?.DebtorAccount?.Identification || req.body?.from_account || req.body?.account_id;
  const toAccount = initiation?.CreditorAccount?.Identification || req.body?.to_account || req.body?.recipient_account;
  const bank = req.body?.to_bank || req.body?.recipient_bank || 'MOCK_BANK';
  const amount = initiation?.InstructedAmount?.Amount || req.body?.amount;
  const currency = initiation?.InstructedAmount?.Currency || req.body?.currency || 'CZK';
  const description = initiation?.RemittanceInformation?.Unstructured || req.body?.description || 'Open Banking Domestic Transfer';

  if (!fromAccount || !toAccount || !amount) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'from_account, to_account, and amount are required'
    });
  }

  const clientId = getClientIdFromToken(req.tokenPayload);

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, fromAccount]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Debtor account does not belong to user.' });
    }

    const latest = await queryDB('SELECT balance FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1', [fromAccount]);
    const currentBalance = latest.length > 0 ? latest[0].balance : 0;
    const numAmount = parseFloat(amount);

    if (currentBalance < numAmount) {
      return res.status(400).json({
        error: 'insufficient_funds',
        error_description: `Current balance (${currentBalance} CZK) is insufficient for transfer of ${numAmount} CZK.`,
      });
    }

    const newBalance = currentBalance - numAmount;
    const dateStr = new Date().toISOString().slice(2, 10).replace(/-/g, '');
    const paymentId = `DOM-CLASSICAL-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    const insertResult = await runDB(`
      INSERT INTO trans (account_id, date, type, operation, amount, balance, k_symbol, bank, account)
      VALUES (?, ?, 'VYDAJ', 'PREVOD NA UCET', ?, ?, 'PAYMENT', ?, ?)
    `, [fromAccount, parseInt(dateStr, 10), numAmount, newBalance, bank, toAccount]);

    res.status(201).json({
      Data: {
        DomesticPaymentId: paymentId,
        ConsentId: req.body?.Data?.ConsentId || `CONSENT-CLASSICAL-${Date.now()}`,
        CreationDateTime: new Date().toISOString(),
        Status: 'AcceptedSettlementInProcess',
        StatusUpdateDateTime: new Date().toISOString(),
        Initiation: {
          InstructionIdentification: initiation?.InstructionIdentification || `INSTR-${insertResult.lastID}`,
          EndToEndIdentification: initiation?.EndToEndIdentification || `E2E-${paymentId}`,
          InstructedAmount: { Amount: numAmount.toFixed(2), Currency: currency },
          DebtorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(fromAccount) },
          CreditorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(toAccount) }
        },
        _transaction_id: insertResult.lastID,
        _new_balance: newBalance
      },
      Links: { Self: `/open-banking/v3.1/pisp/domestic-payments/${paymentId}` },
      Meta: { TotalPages: 1, AppliedProtocol: 'VDAM Classical ECDSA P-384' }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

if (fs.existsSync(CONFIG.tlsKeyPath) && fs.existsSync(CONFIG.tlsCertPath)) {
  const httpsOptions = {
    key: fs.readFileSync(CONFIG.tlsKeyPath),
    cert: fs.readFileSync(CONFIG.tlsCertPath),
    requestCert: true,
    rejectUnauthorized: false,
  };
  https.createServer(httpsOptions, app).listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`[RS Classical] Resource Server running on HTTPS port ${CONFIG.port}`);
  });
} else {
  app.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`[RS Classical] Resource Server running on HTTP port ${CONFIG.port}`);
  });
}
