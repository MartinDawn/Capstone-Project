/**
 * TPP Client Application Logic
 * Traditional Centralized Model (OAuth 2.0 / FAPI 2.0)
 */

let activeService = localStorage.getItem('tpp_active_service') || 'accounts';
let currentSessionState = localStorage.getItem('tpp_session_state') || null;
let currentAccessToken = null;
let selectedAccountId = null;
let accountsData = [];

// Open Banking UK standard mapping & OAuth 2.0 Scopes
const SERVICE_CONFIGS = {
  accounts: {
    title: 'Account Information Service (AISP)',
    desc: 'Accessing authorized user accounts and real-time balances',
    scopes: ['ReadAccountsDetail', 'ReadBalances'],
    oauthScope: 'openid profile email accounts:read',
  },
  analytics: {
    title: 'Spending Analytics & History (AISP)',
    desc: 'Analyzing historical transaction ledger with account filtering',
    scopes: ['ReadAccountsDetail', 'ReadBalances', 'ReadTransactionsDetail'],
    oauthScope: 'openid profile email accounts:read transfers:read',
  },
  payments: {
    title: 'Payment Initiation Service (PISP)',
    desc: 'Executing authenticated domestic payment transfer',
    scopes: ['CreateDomesticPayment', 'ReadAccountsDetail'],
    oauthScope: 'openid profile email accounts:read transfers:write',
  },
};

// ============================================================
// 1. Flow Stepper & Modal Handlers
// ============================================================
function setStep(num) {
  for (let i = 1; i <= 4; i++) {
    const item = document.getElementById(`step${i}`);
    if (!item) continue;
    item.classList.remove('active', 'done');
    if (i < num) item.classList.add('done');
    if (i === num) item.classList.add('active');
  }
}

function startServiceFlow(serviceKey) {
  activeService = serviceKey;
  localStorage.setItem('tpp_active_service', serviceKey);
  const config = SERVICE_CONFIGS[serviceKey];
  document.getElementById('flowModalTitle').textContent = `Authorize: ${config.title}`;
  document.getElementById('flowModal').classList.remove('hidden');
  renderStep1(config);
}

function closeModal() {
  document.getElementById('flowModal').classList.add('hidden');
}

function renderStep1(config) {
  setStep(1);
  const content = document.getElementById('flowStepContent');
  content.innerHTML = `
    <div style="background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:1.25rem; margin-bottom:1.5rem;">
      <h4 style="font-size:0.95rem; margin-bottom:0.75rem; color:#93c5fd;">Open Banking Authorization Scopes</h4>
      <div style="font-size:0.85rem; color:var(--text2); line-height:1.7;">
        <div><strong>OBIE Scopes:</strong> ${config.scopes.map((s) => `<span class="perm-badge">${s}</span>`).join(' ')}</div>
        <div><strong>OAuth 2.0 Scope:</strong> <code>${config.oauthScope}</code></div>
      </div>
    </div>

    <div style="display:flex; justify-content:flex-end; gap:0.75rem;">
      <button class="btn btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="initiateKeycloakAuth()">
        Authorize via Bank (Keycloak) →
      </button>
    </div>
  `;
}

async function initiateKeycloakAuth() {
  setStep(2);
  const config = SERVICE_CONFIGS[activeService];
  const content = document.getElementById('flowStepContent');
  content.innerHTML = `
    <div style="text-align:center; padding:2rem 1rem;">
      <div style="display:inline-block; animation:spin 1s linear infinite; margin-bottom:1rem;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2">
          <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
        </svg>
      </div>
      <h4 style="font-size:1.1rem; margin-bottom:0.5rem;">Redirecting to Bank Authorization Server (Keycloak)...</h4>
      <p style="font-size:0.85rem; color:var(--text2); max-width:500px; margin:0 auto 1.5rem;">
        Initiating Pushed Authorization Request (PAR) with PKCE S256 and OAuth scopes.
      </p>
    </div>
  `;

  try {
    const res = await fetch('/api/auth/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: config.oauthScope,
      }),
    });

    const data = await res.json();
    if (data.status === 'success' && data.redirectUrl) {
      localStorage.setItem('tpp_session_state', data.state);
      window.location.href = data.redirectUrl;
    } else {
      content.innerHTML = `<div class="code-box" style="color:#fca5a5;">Failed to initiate PAR authorization: ${JSON.stringify(data)}</div>`;
    }
  } catch (err) {
    content.innerHTML = `<div class="code-box" style="color:#fca5a5;">Network error initiating auth: ${err.message}</div>`;
  }
}

// ============================================================
// 2. Callback Handling: Check URL params on page load
// ============================================================
async function checkAuthCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');

  if (code && state) {
    document.getElementById('flowModalTitle').textContent = 'Authenticating via FAPI 2.0';
    document.getElementById('flowModal').classList.remove('hidden');
    setStep(3);

    const content = document.getElementById('flowStepContent');
    content.innerHTML = `
      <div style="text-align:center; padding:2rem 1rem;">
        <div style="display:inline-block; animation:spin 1s linear infinite; margin-bottom:1rem;">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
        </div>
        <h4 style="font-size:1.1rem; margin-bottom:0.5rem;">Exchanging Authorization Code for FAPI Access Token...</h4>
        <p style="font-size:0.85rem; color:var(--text2);">
          Validating PKCE code verifier with Bank Authorization Server via PS256 Client Authentication.
        </p>
      </div>
    `;

    try {
      const res = await fetch('/api/auth/token-exchange', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, state }),
      });

      const data = await res.json();
      if (data.status === 'success') {
        currentSessionState = state;
        currentAccessToken = data.tokens.access_token;
        localStorage.setItem('tpp_session_state', state);

        window.history.replaceState({}, document.title, window.location.pathname);
        finishAndShowDashboard(data);
      } else {
        content.innerHTML = `<div class="code-box" style="color:#fca5a5;">Token exchange failed: ${JSON.stringify(data)}</div>`;
      }
    } catch (err) {
      content.innerHTML = `<div class="code-box" style="color:#fca5a5;">Network error exchanging token: ${err.message}</div>`;
    }
    return true;
  }
  return false;
}

// ============================================================
// 3. Connected Dashboard & Presentation
// ============================================================
function finishAndShowDashboard(authData) {
  setStep(4);
  setTimeout(() => {
    closeModal();
    document.getElementById('servicesCatalogSection').classList.add('hidden');
    document.getElementById('dashboardSection').classList.remove('hidden');

    const statusIndicator = document.getElementById('connectionStatus');
    statusIndicator.className = 'status-indicator connected';
    document.getElementById('statusLabel').textContent = 'Bank Connected (Traditional FAPI 2.0)';
    document.getElementById('disconnectBtn').classList.remove('hidden');

    const config = SERVICE_CONFIGS[activeService] || SERVICE_CONFIGS['accounts'];
    document.getElementById('activeServiceTitle').textContent = config.title;
    document.getElementById('activeServiceDesc').textContent = config.desc;

    if (activeService === 'payments') {
      document.getElementById('paymentSection').classList.remove('hidden');
    } else {
      document.getElementById('paymentSection').classList.add('hidden');
    }

    if (authData) {
      if (authData.tokens && authData.tokens.access_token) {
        const size = new Blob([authData.tokens.access_token]).size;
        document.getElementById('inspectTokenSize').textContent = `~${size} Bytes`;
      }
      if (authData.tokens && authData.tokens.scope) {
        document.getElementById('grantedScopes').textContent = authData.tokens.scope;
      } else if (authData.decodedAccessToken && authData.decodedAccessToken.scope) {
        document.getElementById('grantedScopes').textContent = authData.decodedAccessToken.scope;
      }
      if (authData.decodedAccessToken) {
        document.getElementById('tokenClaims').textContent = JSON.stringify(authData.decodedAccessToken, null, 2);
      }
    }

    fetchAccounts();
  }, 600);
}

// ============================================================
// 4. Banking APIs & Data Presentation
// ============================================================
async function fetchAccounts() {
  try {
    const res = await fetch('/api/call-banking-api', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-session-state': currentSessionState || '',
      },
      body: JSON.stringify({ endpoint: '/open-banking/v3.1/aisp/accounts', method: 'GET' }),
    });
    const resp = await res.json();
    const accounts = resp.data?.Data?.Account || resp.data?.data || [];
    accountsData = accounts;
    renderAccounts(accounts);
  } catch (err) {
    document.getElementById('accountsGrid').innerHTML = `<div class="code-box">Error loading accounts: ${err.message}</div>`;
  }
}

function renderAccounts(accounts) {
  const grid = document.getElementById('accountsGrid');
  const debtorSelect = document.getElementById('payDebtorAccount');
  if (debtorSelect) debtorSelect.innerHTML = '';

  if (!accounts || accounts.length === 0) {
    grid.innerHTML = '<div style="color:var(--text-muted); padding:1rem;">No accounts returned by Bank Resource Server</div>';
    return;
  }

  grid.innerHTML = accounts
    .map((acc, idx) => {
      const id = acc.AccountId || acc.account_id;
      const bal = acc._currentBalance || acc.balance || 0;
      if (debtorSelect) {
        debtorSelect.innerHTML += `<option value="${id}">Account #${id} (${bal} CZK)</option>`;
      }
      return `
        <div class="account-box ${idx === 0 ? 'selected' : ''}" onclick="selectAccount('${id}')" id="accBox_${id}">
          <div class="acc-header">
            <span class="acc-number">Account #${id}</span>
            <span class="acc-badge">Standard OB</span>
          </div>
          <div class="acc-balance">${Number(bal).toLocaleString('en-US')} <small style="font-size:0.8rem; color:var(--text-muted);">CZK</small></div>
        </div>
      `;
    })
    .join('');

  if (accounts.length > 0) {
    selectAccount(accounts[0].AccountId || accounts[0].account_id);
  }
}

async function selectAccount(accId) {
  selectedAccountId = accId;
  document.querySelectorAll('.account-box').forEach((b) => b.classList.remove('selected'));
  const activeBox = document.getElementById(`accBox_${accId}`);
  if (activeBox) activeBox.classList.add('selected');

  const tbody = document.getElementById('transactionsTbody');
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text2);">Loading transactions for Account #${accId}...</td></tr>`;

  try {
    const res = await fetch('/api/call-banking-api', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-session-state': currentSessionState || '',
      },
      body: JSON.stringify({
        endpoint: `/open-banking/v3.1/aisp/accounts/${accId}/transactions?limit=25`,
        method: 'GET',
      }),
    });
    const resp = await res.json();
    const txList = resp.data?.Data?.Transaction || resp.data?.data || [];

    if (txList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No transactions recorded for Account #${accId}</td></tr>`;
      return;
    }

    tbody.innerHTML = txList
      .map((tx) => {
        const id = tx.TransactionId || tx.trans_id;
        const isCredit = tx.CreditDebitIndicator === 'Credit' || tx.type === 'PRIJEM';
        const amt = tx.Amount?.Amount || tx.amount || 0;
        const bal = tx.Balance?.Amount?.Amount || tx.balance || 0;
        const info = tx.TransactionInformation || tx.operation || 'TRANSFER';
        const date = tx.BookingDateTime ? tx.BookingDateTime.slice(0, 10) : tx.date;

        return `
          <tr>
            <td><code>#${id}</code></td>
            <td>${date}</td>
            <td>${info}</td>
            <td><span class="${isCredit ? 'badge-pos' : 'badge-neg'}">${isCredit ? 'CREDIT' : 'DEBIT'}</span></td>
            <td class="${isCredit ? 'badge-pos' : 'badge-neg'}">${isCredit ? '+' : '-'}${Number(amt).toLocaleString('en-US')} CZK</td>
            <td>${Number(bal).toLocaleString('en-US')} CZK</td>
          </tr>
        `;
      })
      .join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:#fca5a5;">Failed to load transactions: ${err.message}</td></tr>`;
  }
}

async function submitDomesticPayment() {
  const fromAcc = document.getElementById('payDebtorAccount').value;
  const toAcc = document.getElementById('payCreditorAccount').value;
  const amt = document.getElementById('payAmount').value;

  const payload = {
    Data: {
      Initiation: {
        InstructionIdentification: `INSTR-${Date.now()}`,
        EndToEndIdentification: `E2E-${Date.now()}`,
        InstructedAmount: { Amount: String(amt), Currency: 'CZK' },
        DebtorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(fromAcc) },
        CreditorAccount: { SchemeName: 'UK.OBIE.SortCodeAccountNumber', Identification: String(toAcc) },
      },
    },
  };

  const resultBox = document.getElementById('paymentResult');
  resultBox.className = 'code-box';
  resultBox.textContent = 'Submitting payment to Open Banking Resource Server...';
  resultBox.classList.remove('hidden');

  try {
    const res = await fetch('/api/call-banking-api', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-session-state': currentSessionState || '',
      },
      body: JSON.stringify({
        endpoint: '/open-banking/v3.1/pisp/domestic-payments',
        method: 'POST',
        payload: payload,
      }),
    });
    const resp = await res.json();
    resultBox.textContent = JSON.stringify(resp, null, 2);
    fetchAccounts();
  } catch (err) {
    resultBox.textContent = `Payment Error: ${err.message}`;
  }
}

function toggleDebugLogs() {
  const sec = document.getElementById('debugLogsSection');
  sec.classList.toggle('hidden');
}

async function resetSession() {
  await fetch('/api/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ state: currentSessionState }),
  });
  localStorage.removeItem('tpp_session_state');
  window.location.reload();
}

// On load: check if returning from Keycloak redirect
window.addEventListener('DOMContentLoaded', () => {
  const isHandlingCallback = checkAuthCallback();
  if (!isHandlingCallback && currentSessionState) {
    // If we have an existing session, restore dashboard view
    fetch('/api/session', {
      headers: { 'x-session-state': currentSessionState },
    })
      .then((r) => r.json())
      .then((sess) => {
        if (sess.authenticated) {
          finishAndShowDashboard({
            tokens: { access_token: 'active_session_token' },
            decodedAccessToken: sess.tokenPayload,
          });
        }
      })
      .catch(() => { });
  }
});
