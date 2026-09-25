/**
 * TPP Client Application Backend Server
 * Traditional Centralized Model (OAuth 2.0 / FAPI 2.0)
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { decodeJwt, decodeProtectedHeader } = require('jose');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));

const conformanceConsentRecords = new Map();
const CONFORMANCE_ALLOWED_ACCOUNTS = new Set(['ACC-001', 'ACC-002', 'ACC-003', 'ACC-004', 'ACC-005']);
const CONFORMANCE_ALLOWED_SCOPES = new Set([
  'openid', 'profile', 'email', 'accounts:read', 'ReadAccountsDetail',
  'ReadBalances', 'ReadTransactionsDetail',
  'holder-approved-acc-001', 'holder-approved-acc-002',
]);

function requireConformanceProfile(req, res, next) {
  if (process.env.CONFORMANCE_TEST_MODE !== 'true') {
    return res.status(404).json({
      error: 'not_found',
      error_description: 'Conformance control endpoint is disabled.',
    });
  }
  return next();
}

app.post('/api/conformance/holder-consent', requireConformanceProfile, (req, res) => {
  const requestedAccounts = Array.isArray(req.body.requested_accounts) ? req.body.requested_accounts : [];
  const requestedScopes = Array.isArray(req.body.requested_scopes) ? req.body.requested_scopes : [];
  const approvedAccounts = Array.isArray(req.body.approved_accounts) ? req.body.approved_accounts : [];
  const approvedScopes = Array.isArray(req.body.approved_scopes) ? req.body.approved_scopes : [];

  const knownInputs = [...requestedAccounts, ...approvedAccounts].every(value => CONFORMANCE_ALLOWED_ACCOUNTS.has(value))
    && [...requestedScopes, ...approvedScopes].every(value => CONFORMANCE_ALLOWED_SCOPES.has(value));
  const accountSubset = approvedAccounts.length > 0 && approvedAccounts.every(value => requestedAccounts.includes(value));
  const scopeSubset = approvedScopes.length > 0 && approvedScopes.every(value => requestedScopes.includes(value));
  const actuallyReduced = approvedAccounts.length < requestedAccounts.length || approvedScopes.length < requestedScopes.length;
  if (!knownInputs || !accountSubset || !scopeSubset || !actuallyReduced) {
    return res.status(400).json({
      error: 'invalid_consent',
      error_code: 'REJECT_INVALID_CONSENT_REDUCTION',
      error_description: 'Approved authority must be a strict, non-empty subset of the requested authority.',
    });
  }

  const consentId = `consent-${crypto.randomUUID()}`;
  const record = Object.freeze({
    consent_id: consentId,
    subject: 'testuser',
    requested_accounts: [...requestedAccounts],
    requested_scopes: [...requestedScopes],
    approved_accounts: [...approvedAccounts],
    approved_scopes: [...approvedScopes],
    decided_at: new Date().toISOString(),
  });
  conformanceConsentRecords.set(consentId, record);
  return res.status(201).json(record);
});

app.get('/api/conformance/holder-consent/:id', requireConformanceProfile, (req, res) => {
  const record = conformanceConsentRecords.get(req.params.id);
  if (!record) {
    return res.status(404).json({
      error: 'not_found',
      error_code: 'REJECT_MISSING_CONSENT_RECORD',
      error_description: 'Holder consent record was not found.',
    });
  }
  return res.json(record);
});

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
  port: parseInt(process.env.PORT || '3000', 10),
  keycloakPublicUrl: process.env.KEYCLOAK_PUBLIC_URL || 'https://localhost:8443',
  keycloakInternalUrl: process.env.KEYCLOAK_INTERNAL_URL || process.env.KEYCLOAK_PUBLIC_URL || 'https://localhost:8443',
  realm: process.env.REALM || 'traditional-fapi',
  clientId: process.env.CLIENT_ID || 'tpp-client',
  clientSecret: process.env.CLIENT_SECRET || 'tpp-client-secret-key-12345',
  redirectUri: process.env.REDIRECT_URI || 'https://localhost:3000/callback',
  resourceServerUrl: process.env.RESOURCE_SERVER_URL || 'https://localhost:4000',
  tlsKeyPath: process.env.TLS_KEY_PATH || path.join(__dirname, '../certs/tpp.key'),
  tlsCertPath: process.env.TLS_CERT_PATH || path.join(__dirname, '../certs/tpp.crt'),
};

const KEYCLOAK_AUTH_ENDPOINT = `${CONFIG.keycloakPublicUrl}/realms/${CONFIG.realm}/protocol/openid-connect/auth`;
const KEYCLOAK_TOKEN_ENDPOINT = `${CONFIG.keycloakInternalUrl}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
const KEYCLOAK_PAR_ENDPOINT = `${CONFIG.keycloakInternalUrl}/realms/${CONFIG.realm}/protocol/openid-connect/ext/par/request`;

// In-memory session store for simplicity
const sessions = new Map();

// Helper for PKCE
function base64UrlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generatePkce() {
  const verifier = base64UrlEncode(crypto.randomBytes(32));
  const challenge = base64UrlEncode(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// Pre-compute RFC 8705 client certificate thumbprint (SHA-256 base64url) for sender-constrained tokens (AT-05)
let clientCertThumbprint = process.env.CLIENT_CERT_THUMBPRINT || null;
if (!clientCertThumbprint && fs.existsSync(CONFIG.tlsCertPath)) {
  try {
    const certPem = fs.readFileSync(CONFIG.tlsCertPath, 'utf8');
    const base64Der = certPem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    if (base64Der) {
      const derBuffer = Buffer.from(base64Der, 'base64');
      clientCertThumbprint = crypto.createHash('sha256').update(derBuffer).digest('base64url');
      console.log(`[TPP] Loaded client certificate thumbprint (SHA-256 base64url): ${clientCertThumbprint}`);
    }
  } catch (e) {
    console.warn('[TPP] Failed to compute client certificate thumbprint:', e.message);
  }
}

function getRsHeaders(token, extraHeaders = {}) {
  const headers = {
    Authorization: `Bearer ${token}`,
    ...extraHeaders,
  };
  if (clientCertThumbprint) {
    headers['x-client-cert-thumbprint'] = clientCertThumbprint;
  }
  return headers;
}

// mTLS Form Post Helper for Keycloak PAR and Token Endpoints (RFC 8705)
function postMtlsForm(targetUrl, params) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const bodyStr = params.toString();
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
      rejectUnauthorized: false,
    };
    if (fs.existsSync(CONFIG.tlsCertPath) && fs.existsSync(CONFIG.tlsKeyPath)) {
      reqOptions.cert = fs.readFileSync(CONFIG.tlsCertPath);
      reqOptions.key = fs.readFileSync(CONFIG.tlsKeyPath);
    }
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { }
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: () => Promise.resolve(json || { raw: data }),
          text: () => Promise.resolve(data),
        });
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

// mTLS Request Helper for Resource Server calls through the bank gateway (RFC 8705).
// Node's global fetch() cannot present the TPP client certificate, so every RS
// call must go through this helper or the gateway forwards an empty client cert.
function mtlsRequest(targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const body = options.body == null ? null : Buffer.isBuffer(options.body) ? options.body : Buffer.from(options.body);
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: { ...options.headers },
      rejectUnauthorized: false,
    };
    if (body !== null) {
      reqOptions.headers['Content-Length'] = Buffer.byteLength(body);
    }
    if (fs.existsSync(CONFIG.tlsCertPath) && fs.existsSync(CONFIG.tlsKeyPath)) {
      reqOptions.cert = fs.readFileSync(CONFIG.tlsCertPath);
      reqOptions.key = fs.readFileSync(CONFIG.tlsKeyPath);
    }
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { }
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: () => Promise.resolve(json || { raw: data }),
          text: () => Promise.resolve(data),
        });
      });
    });
    req.on('error', reject);
    if (body !== null) {
      req.write(body);
    }
    req.end();
  });
}

// ============================================================
// API Endpoints
// ============================================================

// 1. Config Endpoint for Frontend
app.get('/api/config', (req, res) => {
  res.json({
    realm: CONFIG.realm,
    clientId: CONFIG.clientId,
    keycloakUrl: CONFIG.keycloakPublicUrl,
    resourceServerUrl: CONFIG.resourceServerUrl,
    redirectUri: CONFIG.redirectUri,
  });
});

// 2. Initiate FAPI Authorization Flow
app.post('/api/auth/initiate', async (req, res) => {
  try {
    const { scope } = req.body;
    const state = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    const { verifier, challenge } = generatePkce();

    // Requested OAuth Scopes
    const requestedApplicationScope = scope || 'openid profile email accounts:read transfers:read';
    const requestedScope = requestedApplicationScope.split(/\s+/).includes('rs-audience')
      ? requestedApplicationScope
      : `${requestedApplicationScope} rs-audience`;

    // Store in session
    sessions.set(state, {
      state,
      nonce,
      verifier,
      requestedScope,
      createdAt: Date.now(),
    });

    let redirectUrl = `${KEYCLOAK_AUTH_ENDPOINT}?client_id=${encodeURIComponent(CONFIG.clientId)}&response_type=code&scope=${encodeURIComponent(requestedScope)}&redirect_uri=${encodeURIComponent(CONFIG.redirectUri)}&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256`;

    // Pushed Authorization Request (PAR) — FAPI 2.0 Security Profile
    let usedPar = false;
    try {
      const parBody = new URLSearchParams({
        response_type: 'code',
        client_id: CONFIG.clientId,
        client_secret: CONFIG.clientSecret,
        redirect_uri: CONFIG.redirectUri,
        scope: requestedScope,
        state: state,
        nonce: nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });

      const parResponse = await postMtlsForm(KEYCLOAK_PAR_ENDPOINT, parBody);

      if (parResponse.ok) {
        const parData = await parResponse.json();
        if (parData.request_uri) {
          redirectUrl = `${KEYCLOAK_AUTH_ENDPOINT}?client_id=${encodeURIComponent(CONFIG.clientId)}&request_uri=${encodeURIComponent(parData.request_uri)}`;
          usedPar = true;
          console.log('[PAR] Successfully pushed authorization request:', parData.request_uri);
        }
      } else {
        const errText = await parResponse.text();
        console.warn('[PAR] Keycloak PAR returned status:', parResponse.status, errText);
      }
    } catch (parErr) {
      console.warn('[PAR] PAR request error:', parErr.message);
    }

    res.json({
      status: 'success',
      redirectUrl,
      state,
      usedPar,
      pkceChallenge: challenge,
    });
  } catch (err) {
    console.error('[Initiate Auth Error]:', err.message);
    res.status(500).json({ error: 'failed_to_initiate_auth', details: err.message });
  }
});

// 3. Callback Handler: Exchange Code for Access Token
app.post('/api/auth/token-exchange', async (req, res) => {
  const { code, state } = req.body;

  if (!code || !state) {
    return res.status(400).json({ error: 'missing_params', error_description: 'Code and state are required.' });
  }

  const session = sessions.get(state);
  if (!session) {
    return res.status(400).json({ error: 'invalid_state', error_description: 'Session state expired or not found.' });
  }

  try {
    const tokenRequestBody = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CONFIG.clientId,
      client_secret: CONFIG.clientSecret,
      code: code,
      redirect_uri: CONFIG.redirectUri,
      code_verifier: session.verifier,
    });

    const tokenResponse = await postMtlsForm(KEYCLOAK_TOKEN_ENDPOINT, tokenRequestBody);

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error('[Token Exchange Failed]:', tokenData);
      return res.status(tokenResponse.status).json({
        error: 'token_exchange_failed',
        details: tokenData,
      });
    }

    // Decode tokens for UI inspection
    const decodedAccessToken = decodeJwt(tokenData.access_token);
    const decodedHeader = decodeProtectedHeader(tokenData.access_token);
    let decodedIdToken = null;
    if (tokenData.id_token) {
      decodedIdToken = decodeJwt(tokenData.id_token);
    }

    // Save tokens in session
    session.accessToken = tokenData.access_token;
    session.refreshToken = tokenData.refresh_token;
    session.idToken = tokenData.id_token;
    session.tokenPayload = decodedAccessToken;
    session.tokenHeader = decodedHeader;
    sessions.set(state, session);

    res.json({
      status: 'success',
      message: 'Successfully authenticated via FAPI 2.0!',
      tokens: {
        access_token: tokenData.access_token,
        token_type: tokenData.token_type,
        expires_in: tokenData.expires_in,
        scope: tokenData.scope,
      },
      decodedAccessToken,
      decodedHeader,
      decodedIdToken,
    });
  } catch (err) {
    console.error('[Token Exchange Exception]:', err.message);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// Helper to get token from header or query or session
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1];
  }
  const state = req.headers['x-session-state'] || req.query.state;
  if (state && sessions.has(state)) {
    return sessions.get(state).accessToken;
  }
  return null;
}

// 4. Proxy to Resource Server: Accounts List
app.get('/api/bank/accounts', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized', error_description: 'No active access token.' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/api/v1/accounts`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 4b. Standard Open Banking UK AISP: Accounts List
app.get(['/api/bank/open-banking/v3.1/aisp/accounts', '/open-banking/v3.1/aisp/accounts'], async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized', error_description: 'No active access token.' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/open-banking/v3.1/aisp/accounts`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 5. Proxy to Resource Server: Account Details & Balance
app.get('/api/bank/accounts/:id', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/api/v1/accounts/${req.params.id}`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 5b. Standard Open Banking UK AISP: Account Details
app.get(['/api/bank/open-banking/v3.1/aisp/accounts/:id', '/open-banking/v3.1/aisp/accounts/:id'], async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/open-banking/v3.1/aisp/accounts/${req.params.id}`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 5c. Standard Open Banking UK AISP: Account Balances
app.get(['/api/bank/open-banking/v3.1/aisp/accounts/:id/balances', '/open-banking/v3.1/aisp/accounts/:id/balances'], async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/open-banking/v3.1/aisp/accounts/${req.params.id}/balances`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 6. Proxy to Resource Server: Transactions
app.get('/api/bank/accounts/:id/transactions', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/api/v1/accounts/${req.params.id}/transactions?limit=25`, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 6b. Standard Open Banking UK AISP: Account Transactions
app.get(['/api/bank/open-banking/v3.1/aisp/accounts/:id/transactions', '/open-banking/v3.1/aisp/accounts/:id/transactions'], async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  const queryString = new URLSearchParams(req.query).toString();
  const targetUrl = `${CONFIG.resourceServerUrl}/open-banking/v3.1/aisp/accounts/${req.params.id}/transactions${queryString ? '?' + queryString : ''}`;

  try {
    const rsResponse = await mtlsRequest(targetUrl, {
      headers: getRsHeaders(token),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 7. Proxy to Resource Server: Transfers
app.post('/api/bank/transfers', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/api/v1/transfers`, {
      method: 'POST',
      headers: getRsHeaders(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify(req.body),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 7b. Standard Open Banking UK PISP: Domestic Payments
app.post(['/api/bank/open-banking/v3.1/pisp/domestic-payments', '/open-banking/v3.1/pisp/domestic-payments'], async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const rsResponse = await mtlsRequest(`${CONFIG.resourceServerUrl}/open-banking/v3.1/pisp/domestic-payments`, {
      method: 'POST',
      headers: getRsHeaders(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify(req.body),
    });

    const data = await rsResponse.json();
    res.status(rsResponse.status).json(data);
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 8b. Unified Call Banking API proxy (Matching Baseline Interface)
app.post('/api/call-banking-api', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized', message: 'No active access token.' });

  const { endpoint, method, payload } = req.body;
  try {
    const targetUrl = `${CONFIG.resourceServerUrl}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;
    const options = {
      method: method || 'GET',
      headers: getRsHeaders(token, { 'Content-Type': 'application/json' }),
    };
    if (payload && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(payload);
    }

    const rsResponse = await mtlsRequest(targetUrl, options);
    const data = await rsResponse.json();
    res.status(rsResponse.status).json({ data, status: rsResponse.status });
  } catch (err) {
    res.status(500).json({ error: 'resource_server_unreachable', details: err.message });
  }
});

// 9. Session Info
app.get('/api/session', (req, res) => {
  const state = req.headers['x-session-state'] || req.query.state;
  if (state && sessions.has(state)) {
    const session = sessions.get(state);
    return res.json({
      authenticated: !!session.accessToken,
      tokenPayload: session.tokenPayload,
      tokenHeader: session.tokenHeader,
    });
  }
  res.json({ authenticated: false });
});

// 10. Clear Session / Logout
app.post(['/api/auth/logout', '/api/reset', '/api/auth/reset'], (req, res) => {
  const state = req.headers['x-session-state'] || req.body?.state;
  if (state) sessions.delete(state);
  res.json({ status: 'logged_out' });
});

// Single Page Application Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server (HTTPS if certificates available)
if (fs.existsSync(CONFIG.tlsKeyPath) && fs.existsSync(CONFIG.tlsCertPath)) {
  const httpsOptions = {
    key: fs.readFileSync(CONFIG.tlsKeyPath),
    cert: fs.readFileSync(CONFIG.tlsCertPath),
  };
  https.createServer(httpsOptions, app).listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`====================================================`);
    console.log(`TPP Application running on HTTPS port ${CONFIG.port}`);
    console.log(`   Web UI URL: https://localhost:${CONFIG.port}`);
    console.log(`   Model: Centralized OAuth 2.0 / FAPI 2.0`);
    console.log(`====================================================`);
  });
} else {
  app.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`====================================================`);
    console.log(`TPP Application running on HTTP port ${CONFIG.port}`);
    console.log(`   Web UI URL: http://localhost:${CONFIG.port}`);
    console.log(`   Model: Centralized OAuth 2.0 / FAPI 2.0`);
    console.log(`====================================================`);
  });
}
