/**
 * Banking Resource Server (Traditional FAPI 2.0)
 *
 * Enforces:
 *   1. JWT Access Token signature verification against Keycloak JWKS (PS256/RS256/ES256)
 *   2. Traditional OAuth 2.0 Scopes (accounts:read, transfers:read, transfers:write, ReadAccountsDetail, ReadBalances, ReadTransactionsDetail, CreateDomesticPayment)
 *
 * Dataset:
 *   Berka Financial SQLite Database (accounts, transactions, loans, cards, clients)
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } = require('jose');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
  port: parseInt(process.env.PORT || '4000', 10),
  keycloakUrl: process.env.KEYCLOAK_URL || 'https://localhost:8443',
  realm: process.env.REALM || 'traditional-fapi',
  resourceServerAudience: process.env.RS_AUDIENCE || 'resource-server-client',
  tlsKeyPath: process.env.TLS_KEY_PATH || (fs.existsSync('/app/certs/rs.key') ? '/app/certs/rs.key' : path.join(__dirname, '../certs/rs.key')),
  tlsCertPath: process.env.TLS_CERT_PATH || (fs.existsSync('/app/certs/rs.crt') ? '/app/certs/rs.crt' : path.join(__dirname, '../certs/rs.crt')),
  tlsCaPath: process.env.TLS_CA_PATH || (fs.existsSync('/app/certs/ca.crt') ? '/app/certs/ca.crt' : path.join(__dirname, '../certs/ca.crt')),
};

const KEYCLOAK_ISSUER = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}`;
const JWKS_URI = `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`;

console.log(`[Config] Keycloak Issuer: ${KEYCLOAK_ISSUER}`);
console.log(`[Config] Keycloak JWKS:   ${JWKS_URI}`);

// ============================================================
// JWKS Remote Key Set
// ============================================================
let jwksRemote = null;

function getJwks() {
  if (!jwksRemote) {
    jwksRemote = createRemoteJWKSet(new URL(JWKS_URI), {
      cacheMaxAge: 600000, // 10 minutes
      cooldownDuration: 30000,
    });
  }
  return jwksRemote;
}

// ============================================================
// Database (Berka Dataset)
// ============================================================
const dbPath = path.join(__dirname, 'berka.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[DB ERROR] Cannot open berka.db:', err.message);
  } else {
    console.log(`[DB] Connected to SQLite database: ${dbPath}`);
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

// Map keycloak user to Berka client_id
function getClientIdFromToken(payload) {
  const username = payload.preferred_username || payload.sub || '';
  if (username === 'testuser') return 1;
  if (username === 'john_doe') return 2;
  const match = username.match(/^user(\d+)$/i);
  if (match) {
    const parsedId = parseInt(match[1], 10);
    if (!isNaN(parsedId) && parsedId > 0) return parsedId;
  }
  return 1; // Default fallback
}

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

  return null;
}

// ============================================================
// Token Validation Middleware (FAPI Standard)
// ============================================================
async function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('Auth header:', authHeader);
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid Authorization header. Expected: Bearer <token>',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const header = decodeProtectedHeader(token);
    const jwks = getJwks();

    // Verify token cryptographic signature with Keycloak JWKS
    const { payload, protectedHeader } = await jwtVerify(token, jwks);

    // Validate Issuer claim (support HTTPS 8443, HTTP 8080, Docker DNS, and VM hosts)
    const allowedIssuers = new Set([
      KEYCLOAK_ISSUER,
      `https://localhost:8443/realms/${CONFIG.realm}`,
      `http://localhost:8080/realms/${CONFIG.realm}`,
      `https://keycloak-fapi:8443/realms/${CONFIG.realm}`,
      `http://keycloak-fapi:8443/realms/${CONFIG.realm}`,
      `http://keycloak:8080/realms/${CONFIG.realm}`,
      `https://keycloak:8443/realms/${CONFIG.realm}`,
    ]);
    if (process.env.KEYCLOAK_PUBLIC_URL) {
      allowedIssuers.add(`${process.env.KEYCLOAK_PUBLIC_URL}/realms/${CONFIG.realm}`);
    }
    if (process.env.KEYCLOAK_HOST) {
      allowedIssuers.add(`https://${process.env.KEYCLOAK_HOST}:8443/realms/${CONFIG.realm}`);
      allowedIssuers.add(`http://${process.env.KEYCLOAK_HOST}:8080/realms/${CONFIG.realm}`);
    }

    const isValidIssuer = allowedIssuers.has(payload.iss) ||
      (typeof payload.iss === 'string' && payload.iss.endsWith(`/realms/${CONFIG.realm}`));

    if (!isValidIssuer) {
      console.error(`[Token Error] Unexpected issuer: "${payload.iss}". Expected realm: /realms/${CONFIG.realm}`);
      return res.status(401).json({
        error: 'invalid_token',
        error_description: `Token validation failed: unexpected "iss" claim value (${payload.iss})`,
      });
    }

    // Strictly validate audience (Fail-Closed, F-05)
    if (!payload.aud) {
      console.log('Audience not found');
      return res.status(401).json({
        error: 'invalid_token',
        error_code: 'REJECT_INVALID_AUDIENCE',
        error_description: 'Token missing required audience (aud) claim',
      });
    }
    const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const matchesAud = audList.some(a =>
      a === CONFIG.resourceServerAudience ||
      a === 'resource-server-client' ||
      a === 'tpp-client' ||
      a === 'short-lived-client' ||
      a === 'account' ||
      a === 'https://resource-server-fapi:4000' ||
      a === 'http://resource-server-fapi:4000' ||
      a === `http://localhost:${CONFIG.port}` ||
      a === `https://localhost:${CONFIG.port}` ||
      a === 'http://localhost:4000' ||
      a === 'https://localhost:4000' ||
      (process.env.KEYCLOAK_HOST && (a === `http://${process.env.KEYCLOAK_HOST}:4000` || a === `https://${process.env.KEYCLOAK_HOST}:4000`)) ||
      (process.env.BANK_HOST && (a === `http://${process.env.BANK_HOST}:4000` || a === `https://${process.env.BANK_HOST}:4000`))
    );
    if (!matchesAud) {
      console.log('Audience mismatch');
      return res.status(401).json({
        error: 'invalid_token',
        error_code: 'REJECT_INVALID_AUDIENCE',
        error_description: `Token audience mismatch. Expected ${CONFIG.resourceServerAudience}, got: ${JSON.stringify(payload.aud)}`,
      });
    }

    // Helper to extract RFC 8705 DER SHA-256 base64url thumbprint (C-TLS-5, AT-05)
    const clientCertThumbprint = extractClientCertThumbprint(req);

    // RFC 8705 Certificate-Bound Access Token Verification (AT-05) - Mandatory Fail-Closed
    let cnf = payload.cnf;
    if (typeof cnf === 'string') {
      try {
        cnf = JSON.parse(cnf);
      } catch (e) {
        // Retain raw string if parse fails
      }
    }

    if (!cnf || !cnf['x5t#S256']) {
      console.log('Certificate-bound access token mandatory under FAPI 2.0: missing cnf x5t#S256 (AT-05)');
      return res.status(401).json({
        error: 'invalid_token',
        error_code: 'REJECT_INVALID_TOKEN_BINDING',
        error_description: 'Certificate-bound access token mandatory under FAPI 2.0: missing cnf x5t#S256 (AT-05)',
      });
    }
    const expectedThumbprint = cnf['x5t#S256'];
    if (!clientCertThumbprint) {
      console.log('mTLS client certificate required for certificate-bound access token (AT-05)')
      return res.status(401).json({
        error: 'invalid_token',
        error_code: 'REJECT_INVALID_TOKEN_BINDING',
        error_description: 'mTLS client certificate required for certificate-bound access token (AT-05)',
      });
    }
    if (clientCertThumbprint !== expectedThumbprint) {
      console.log('mTLS sender constraint verification failed: Client cert thumbprint mismatch with token cnf (AT-05)')
      return res.status(401).json({
        error: 'invalid_token',
        error_code: 'REJECT_INVALID_TOKEN_BINDING',
        error_description: 'mTLS sender constraint verification failed: Client cert thumbprint mismatch with token cnf (AT-05)',
      });
    }

    req.tokenPayload = payload;
    req.tokenHeader = protectedHeader;
    req.rawToken = token;

    return next();
  } catch (err) {
    console.error('[Token Validation Failed]:', err.message);
    const errorCode = err && (err.code === 'ERR_JWT_EXPIRED' || err.name === 'JWTExpired')
      ? 'REJECT_EXPIRED_TOKEN'
      : 'REJECT_INVALID_TOKEN_SIGNATURE';
    console.log('Error code:', errorCode);
    return res.status(401).json({
      error: 'invalid_token',
      error_code: errorCode,
      error_description: `Token validation failed: ${err.message}`,
    });
  }
}

// ============================================================
// Authorization & Scope Enforcement Helper
// ============================================================
const SCOPE_SYNONYMS = {
  'accounts:read': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadAccountsBasic': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadAccountsDetail': ['accounts:read', 'ReadAccountsBasic', 'ReadAccountsDetail'],
  'ReadBalances': ['accounts:read', 'ReadBalances', 'ReadAccountsDetail'],
  'transfers:read': ['transfers:read', 'transactions:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
  'transactions:read': ['transfers:read', 'transactions:read', 'ReadTransactionsBasic', 'ReadTransactionsDetail'],
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
    const tokenScopes = (req.tokenPayload.scope || '').split(' ');
    const allowedScopes = SCOPE_SYNONYMS[scope] || [scope];

    const hasScope = tokenScopes.some(s => allowedScopes.includes(s) || s === 'banking' || s === '*');
    if (!hasScope) {
      return res.status(403).json({
        error: 'insufficient_scope',
        error_code: 'REJECT_INSUFFICIENT_SCOPE',
        error_description: `This endpoint requires scope '${scope}'. Current token scopes: [${tokenScopes.join(', ')}]`,
        required_scope: scope,
        granted_scopes: tokenScopes,
      });
    }

    next();
  };
}

// ============================================================
// API Endpoints
// ============================================================

app.get('/', (req, res) => {
  res.json({
    service: 'Traditional FAPI 2.0 Banking Resource Server',
    status: 'ACTIVE',
    version: '1.0.0',
    model: 'Centralized OAuth 2.0 / FAPI 2.0',
    endpoints: [
      { path: '/health', method: 'GET', description: 'Health check' },
      { path: '/api/v1/meta', method: 'GET', description: 'Server metadata' },
      { path: '/api/v1/accounts', method: 'GET', scope: 'accounts:read' },
      { path: '/api/v1/accounts/:id', method: 'GET', scope: 'accounts:read' },
      { path: '/api/v1/accounts/:id/transactions', method: 'GET', scope: 'transfers:read' },
      { path: '/api/v1/accounts/:id/cards', method: 'GET', scope: 'accounts:read' },
      { path: '/api/v1/accounts/:id/loans', method: 'GET', scope: 'accounts:read' },
      { path: '/api/v1/transfers', method: 'GET', scope: 'transfers:read' },
      { path: '/api/v1/transfers', method: 'POST', scope: 'transfers:write' },
      { path: '/api/v1/user/profile', method: 'GET', scope: 'openid', description: 'User identity profile' },
    ],
  });
});

app.get(['/health', '/api/v1/health'], (req, res) => {
  res.json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    database: 'berka.db',
    fapi_conformance: 'FAPI 2.0',
  });
});

app.get('/api/v1/meta', (req, res) => {
  res.json({
    model_type: 'Traditional Centralized FAPI 2.0',
    auth_server: CONFIG.keycloakUrl,
    realm: CONFIG.realm,
    signature_algorithms: ['PS256', 'ES256', 'RS256'],
  });
});

// Canonical AIS identifiers (ACC-NNN) map one-to-one onto Berka internal account ids.
function toCanonicalAccountId(internalId) {
  return `ACC-${String(internalId).padStart(3, '0')}`;
}

function toInternalAccountId(canonicalId) {
  const match = /^ACC-(\d+)$/.exec(String(canonicalId));
  const parsed = match ? parseInt(match[1], 10) : Number(canonicalId);
  return Number.isSafeInteger(parsed) ? parsed : NaN;
}

/**
 * Accounts the grant is restricted to, as internal ids, or null when the grant carries no account
 * constraint. Reads RFC 9396 authorization_details first, then the flat `accounts` claim.
 */
function rarAccountConstraint(tokenPayload) {
  const collected = new Set();
  let constrained = false;
  const details = Array.isArray(tokenPayload.authorization_details) ? tokenPayload.authorization_details : [];
  for (const detail of details) {
    if (detail && Array.isArray(detail.accounts) && detail.accounts.length > 0) {
      constrained = true;
      detail.accounts.forEach(id => {
        const internal = toInternalAccountId(id);
        if (Number.isSafeInteger(internal)) collected.add(internal);
      });
    }
  }
  if (!constrained) {
    const claim = tokenPayload.accounts;
    const list = Array.isArray(claim) ? claim : (typeof claim === 'string' && claim ? claim.split(/[\s,]+/) : []);
    if (list.length > 0) {
      constrained = true;
      list.forEach(id => {
        const internal = toInternalAccountId(id);
        if (Number.isSafeInteger(internal)) collected.add(internal);
      });
    }
  }
  if (!constrained) {
    // Per-account consent is expressed by granted holder-approved-acc-NNN scopes. Their union is the
    // account constraint; absent any of them the grant covers everything the holder is entitled to.
    const granted = typeof tokenPayload.scope === 'string' ? tokenPayload.scope.split(/\s+/) : [];
    for (const scope of granted) {
      const match = /^holder-approved-acc-(\d+)$/.exec(scope);
      if (match) {
        constrained = true;
        collected.add(parseInt(match[1], 10));
      }
    }
  }
  return constrained ? collected : null;
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

// GET /api/v1/accounts - List all authorized bank accounts
app.get(['/api/v1/accounts', '/api/accounts'], validateToken, requireScope('accounts:read'), async (req, res) => {
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

    // RFC 9396 authorization_details may narrow the granted accounts. The grant never widens what the
    // holder owns: only entitlement rows that are also inside the grant are projected.
    const grantedAccounts = rarAccountConstraint(req.tokenPayload);
    const entitled = rows
      .filter(acc => grantedAccounts === null || grantedAccounts.has(Number(acc.account_id)))
      .sort((left, right) => Number(left.account_id) - Number(right.account_id));

    const baseAccounts = [];
    for (const acc of entitled) {
      const record = projectFields(await canonicalAccountRecord(acc), requestedFields);
      if (requestedFields && !record.account_id) record.account_id = toCanonicalAccountId(acc.account_id);
      baseAccounts.push(record);
    }

    res.json({
      Data: {
        Account: baseAccounts
      },
      Links: {
        Self: '/api/v1/accounts'
      },
      Meta: {
        TotalPages: 1,
        TotalResults: baseAccounts.length
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/accounts/:id - Account details & balance
app.get(['/api/v1/accounts/:id', '/api/accounts/:id'], validateToken, requireScope('accounts:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;

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

    const account = rows[0];
    const trans = await queryDB(`
      SELECT balance, date FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1
    `, [accountId]);
    account.balance = trans.length > 0 ? trans[0].balance : 0;
    account.currency = 'CZK';

    res.json({
      status: 'success',
      data: account,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/accounts/:id/transactions - Account transactions
app.get(['/api/v1/accounts/:id/transactions', '/api/accounts/:id/transactions'], validateToken, requireScope('transfers:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'User does not own this account.' });
    }

    const limit = parseInt(req.query.limit || '50', 10);
    const rows = await queryDB(`
      SELECT trans_id, date, type, operation, amount, balance, k_symbol, account as recipient_account, bank as recipient_bank
      FROM trans
      WHERE account_id = ?
      ORDER BY date DESC, trans_id DESC
      LIMIT ?
    `, [accountId, limit]);

    res.json({
      status: 'success',
      account_id: accountId,
      count: rows.length,
      data: rows,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/accounts/:id/cards
app.get(['/api/v1/accounts/:id/cards', '/api/accounts/:id/cards'], validateToken, requireScope('accounts:read'), async (req, res) => {
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
      status: 'success',
      account_id: accountId,
      count: rows.length,
      data: rows,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/accounts/:id/loans
app.get(['/api/v1/accounts/:id/loans', '/api/accounts/:id/loans'], validateToken, requireScope('accounts:read'), async (req, res) => {
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
      status: 'success',
      account_id: accountId,
      count: rows.length,
      data: rows,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/transfers - Recent transfers across user accounts
app.get(['/api/v1/transfers', '/api/transfers'], validateToken, requireScope('transfers:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  try {
    const accounts = await queryDB(`
      SELECT a.account_id FROM accounts a
      JOIN disp d ON a.account_id = d.account_id
      WHERE d.client_id = ?
    `, [clientId]);

    if (accounts.length === 0) {
      return res.json({ status: 'success', count: 0, data: [] });
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
      status: 'success',
      count: rows.length,
      data: rows,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// POST /api/v1/transfers - Initiate transfer
app.post(['/api/v1/transfers', '/api/transfers'], validateToken, requireScope('transfers:write'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const { account_id, amount, recipient_account, recipient_bank, message } = req.body;

  if (!account_id || !amount || !recipient_account) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Fields account_id, amount, and recipient_account are required.',
    });
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, account_id]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Account does not belong to user.' });
    }

    const latest = await queryDB('SELECT balance FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1', [account_id]);
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

    const result = await runDB(`
      INSERT INTO trans (account_id, date, type, operation, amount, balance, k_symbol, bank, account)
      VALUES (?, ?, 'VYDAJ', 'PREVOD NA UCET', ?, ?, 'PAYMENT', ?, ?)
    `, [account_id, parseInt(dateStr, 10), numAmount, newBalance, recipient_bank || 'MOCK_BANK', recipient_account]);

    res.status(201).json({
      status: 'success',
      message: 'Transfer initiated successfully via FAPI 2.0 authorization',
      data: {
        transaction_id: result.lastID,
        account_id,
        amount: numAmount,
        currency: 'CZK',
        new_balance: newBalance,
        recipient_account,
        recipient_bank: recipient_bank || 'MOCK_BANK',
        description: message || 'Open Banking Transfer',
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /api/v1/user/profile - User Profile
app.get(['/api/v1/user/profile', '/api/profile'], validateToken, requireScope('profile:read'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  try {
    const clients = await queryDB('SELECT * FROM clients WHERE client_id = ?', [clientId]);
    const clientData = clients.length > 0 ? clients[0] : {};

    res.json({
      status: 'success',
      data: {
        sub: req.tokenPayload.sub,
        username: req.tokenPayload.preferred_username || req.tokenPayload.sub,
        email: clientData.email || req.tokenPayload.email || 'customer@bank.local',
        name: clientData.name || req.tokenPayload.name || 'Bank Customer',
        phone_number: clientData.phone_number,
        national_id: clientData.national_id,
        address: clientData.address,
        dob: clientData.dob,
        gender: clientData.gender,
        client_id: clientId,
        district_id: clientData.district_id,
        birth_number: clientData.birth_number,
        token_issuer: req.tokenPayload.iss,
        token_expires_at: new Date(req.tokenPayload.exp * 1000).toISOString(),
        berka_profile: clientData,
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// ============================================================
// Open Banking UK v3.1 / v4.0 Standard Endpoints
// ============================================================

// GET /open-banking/v3.1/meta - Open Banking Capabilities
app.get('/open-banking/v3.1/meta', (req, res) => {
  res.json({
    standard: 'Open Banking UK Read/Write API Specification',
    spec_version: 'v3.1.11 / v4.0.1',
    profile: 'Traditional FAPI 2.0',
    auth_server: CONFIG.keycloakUrl,
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
        Description: `Berka Standard Account ${acc.account_id}`,
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
        AppliedProtocol: 'Traditional FAPI 2.0'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /open-banking/v3.1/aisp/accounts/:id - Standard OB Account Details
app.get('/open-banking/v3.1/aisp/accounts/:id', validateToken, requireScope('ReadAccountsDetail'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const accountId = req.params.id;

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

    const acc = rows[0];
    res.json({
      Data: {
        Account: [
          {
            AccountId: String(acc.account_id),
            Currency: 'CZK',
            AccountType: 'Personal',
            AccountSubType: 'CurrentAccount',
            Description: `Berka Standard Account ${acc.account_id}`,
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
  const accountId = req.params.id;

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
      Meta: { TotalPages: 1, AppliedProtocol: 'Traditional FAPI 2.0' }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// GET /open-banking/v3.1/aisp/accounts/:id/transactions - Standard OB Transactions (with D dimension date filter)
app.get('/open-banking/v3.1/aisp/accounts/:id/transactions', validateToken, requireScope('ReadTransactionsDetail'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);
  const externalAccountId = req.params.id;
  const externalMatch = /^ACC-(\d{3})$/.exec(externalAccountId);
  const accountId = externalMatch ? parseInt(externalMatch[1], 10) : Number(externalAccountId);

  if (!Number.isSafeInteger(accountId) || accountId <= 0) {
    return res.status(400).json({
      error: 'invalid_account_identifier',
      error_code: 'REJECT_INVALID_ACCOUNT_IDENTIFIER',
      error_description: 'Account identifier must be a positive internal ID or canonical ACC-NNN identifier.',
    });
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, accountId]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Account does not belong to user.' });
    }

    const limit = parseInt(req.query.limit || '50', 10);
    const page = parseInt(req.query.page || '1', 10);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(page) || page < 1) {
      return res.status(400).json({
        error: 'invalid_pagination',
        error_code: 'REJECT_INVALID_PAGINATION',
        error_description: 'Pagination requires page >= 1 and limit between 1 and 100.',
      });
    }
    const fromDate = req.query.fromBookingDateTime || req.query.fromDate;
    const toDate = req.query.toBookingDateTime || req.query.toDate;

    let whereSql = ' FROM trans WHERE account_id = ?';
    const filterParams = [accountId];

    if (fromDate) {
      const cleanFrom = parseInt(String(fromDate).replace(/\D/g, '').slice(2, 8) || '0', 10);
      if (cleanFrom > 0) {
        whereSql += ' AND date >= ?';
        filterParams.push(cleanFrom);
      }
    }
    if (toDate) {
      const cleanTo = parseInt(String(toDate).replace(/\D/g, '').slice(2, 8) || '999999', 10);
      if (cleanTo > 0) {
        whereSql += ' AND date <= ?';
        filterParams.push(cleanTo);
      }
    }

    const countRows = await queryDB(`SELECT COUNT(*) AS total${whereSql}`, filterParams);
    const totalResults = Number(countRows[0]?.total || 0);
    const totalPages = Math.ceil(totalResults / limit);
    const offset = (page - 1) * limit;
    const sql = `SELECT trans_id, date, type, operation, amount, balance, k_symbol, account, bank${whereSql} ORDER BY date DESC, trans_id DESC LIMIT ? OFFSET ?`;
    const params = [...filterParams, limit, offset];

    const rows = await queryDB(sql, params);

    const obTransactions = rows.map(r => ({
      AccountId: externalMatch ? externalAccountId : String(accountId),
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
      Links: { Self: `/open-banking/v3.1/aisp/accounts/${externalAccountId}/transactions?page=${page}&limit=${limit}` },
      Meta: {
        Page: page,
        PageSize: limit,
        TotalPages: totalPages,
        TotalResults: totalResults,
        Count: obTransactions.length,
        HistoryWindowApplied: { from: fromDate || 'UNBOUNDED', to: toDate || 'UNBOUNDED' },
        AppliedProtocol: 'Traditional FAPI 2.0'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// POST /open-banking/v3.1/pisp/domestic-payments - Standard OB Domestic Payment Initiation
app.post('/open-banking/v3.1/pisp/domestic-payments', validateToken, requireScope('CreateDomesticPayment'), async (req, res) => {
  const clientId = getClientIdFromToken(req.tokenPayload);

  // Normalize request payload from either OB format or flat format
  const initiation = req.body?.Data?.Initiation || {};
  const account_id = initiation?.DebtorAccount?.Identification || req.body?.account_id;
  const amount = initiation?.InstructedAmount?.Amount || req.body?.amount;
  const currency = initiation?.InstructedAmount?.Currency || req.body?.currency || 'CZK';
  const recipient_account = initiation?.CreditorAccount?.Identification || req.body?.recipient_account;
  const recipient_bank = req.body?.recipient_bank || 'MOCK_BANK';

  if (!account_id || !amount || !recipient_account) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Fields DebtorAccount, InstructedAmount, and CreditorAccount are required.',
    });
  }

  try {
    const disp = await queryDB('SELECT type FROM disp WHERE client_id = ? AND account_id = ?', [clientId, account_id]);
    if (disp.length === 0) {
      return res.status(403).json({ error: 'forbidden', error_description: 'Debtor account does not belong to user.' });
    }

    const latest = await queryDB('SELECT balance FROM trans WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1', [account_id]);
    const currentBalance = latest.length > 0 ? latest[0].balance : 0;
    const numAmount = parseFloat(amount);

    if (currentBalance < numAmount) {
      return res.status(400).json({
        error: 'insufficient_funds',
        error_description: `Current balance (${currentBalance} CZK) is insufficient for payment of ${numAmount} CZK.`,
      });
    }

    const newBalance = currentBalance - numAmount;
    const dateStr = new Date().toISOString().slice(2, 10).replace(/-/g, '');
    const paymentId = `DOM-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    const result = await runDB(`
      INSERT INTO trans (account_id, date, type, operation, amount, balance, k_symbol, bank, account)
      VALUES (?, ?, 'VYDAJ', 'PREVOD NA UCET', ?, ?, 'PAYMENT', ?, ?)
    `, [account_id, parseInt(dateStr, 10), numAmount, newBalance, recipient_bank, recipient_account]);

    res.status(201).json({
      Data: {
        DomesticPaymentId: paymentId,
        ConsentId: req.body?.Data?.ConsentId || `CONSENT-${Date.now()}`,
        CreationDateTime: new Date().toISOString(),
        Status: 'AcceptedSettlementInProcess',
        StatusUpdateDateTime: new Date().toISOString(),
        Initiation: {
          InstructionIdentification: initiation?.InstructionIdentification || `INSTR-${result.lastID}`,
          EndToEndIdentification: initiation?.EndToEndIdentification || `E2E-${paymentId}`,
          InstructedAmount: { Amount: numAmount.toFixed(2), Currency: currency },
          DebtorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(account_id) },
          CreditorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(recipient_account) }
        },
        _transaction_id: result.lastID,
        _new_balance: newBalance
      },
      Links: { Self: `/open-banking/v3.1/pisp/domestic-payments/${paymentId}` },
      Meta: { TotalPages: 1, AppliedProtocol: 'Traditional FAPI 2.0' }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// Start Server (HTTPS if certificates available)
if (fs.existsSync(CONFIG.tlsKeyPath) && fs.existsSync(CONFIG.tlsCertPath) && fs.existsSync(CONFIG.tlsCaPath)) {
  const httpsOptions = {
    key: fs.readFileSync(CONFIG.tlsKeyPath),
    cert: fs.readFileSync(CONFIG.tlsCertPath),
    ca: fs.readFileSync(CONFIG.tlsCaPath),
    requestCert: true,
    rejectUnauthorized: true,
  };
  https.createServer(httpsOptions, app).listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`====================================================`);
    console.log(`Banking Resource Server running on HTTPS port ${CONFIG.port}`);
    console.log(`   Base URL: https://localhost:${CONFIG.port}`);
    console.log(`   Model: Centralized OAuth 2.0 / FAPI 2.0`);
    console.log(`====================================================`);
  });
} else {
  app.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`====================================================`);
    console.log(`Banking Resource Server running on HTTP port ${CONFIG.port}`);
    console.log(`   Base URL: http://localhost:${CONFIG.port}`);
    console.log(`   Model: Centralized OAuth 2.0 / FAPI 2.0`);
    console.log(`====================================================`);
  });
}
