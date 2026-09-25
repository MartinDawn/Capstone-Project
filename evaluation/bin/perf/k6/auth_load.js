// REINSTATED (BP-20260922-v5, decision DEC-020): E-LOAD offered-load protocol evidence, driven by
// evaluation/bin/perf/run_perf.py. Blocked from pilot/final until BLK-004 and BLK-013 are closed.
// Open-loop authorization transactions at a fixed offered rate (one call = one offered rate).
//
// One run = one model at one offered rate (TPS). It measures ONLY the authorization
// phase, from the first authorization request to access-token issuance. k6 plays the user's
// side only (a browser, or the local app that talks to the wallet); every server-to-server hop
// is performed by the real services:
//   B0-C0        TPP /api/auth/initiate (TPP does PAR over mTLS) -> browser login at Keycloak
//                -> TPP /api/auth/token-exchange (TPP does the mTLS token exchange)
//   B1-C0/B1-C2  TPP request-delegate -> wallet fetch + approve (wallet submits to the TPP and
//                calls the Bank) -> TPP token (TPP calls the Bank)
// F1 (root VC issuance) and the resource server are never called here. The root VC jti
// is provisioned by run_perf.py before k6 starts and passed in through AUTHZ_VC_JTI.
//
// Scenarios (both open-loop, constant-arrival-rate):
//   warmup   WARMUP_SECONDS at the same rate, then WARMUP_DRAIN_SECONDS to finish stragglers
//   measure  MEASUREMENT_SECONDS, then DRAIN_SECONDS graceful stop for in-flight work
//
// Recorded metrics (all tagged phase=warmup|measure):
//   auth_duration  Trend, ms, successful transactions only
//   auth_ok        Counter, completed successfully
//   auth_fail      Counter, tagged with the stage that failed
//   dropped_iterations (built-in) arrivals that could not start because maxVUs was reached
//
// All parameters come from environment variables set by run_perf.py.

import http from 'k6/http';
import exec from 'k6/execution';
import { parseHTML } from 'k6/html';
import { Counter, Trend } from 'k6/metrics';

const env = (name, fallback) =>
  __ENV[name] !== undefined && __ENV[name] !== '' ? __ENV[name] : fallback;

const MODEL = env('MODEL', 'B0-C0');
const IS_B0 = MODEL === 'B0-C0';

const RATE = parseInt(env('OFFERED_RATE_TPS', '1'), 10);
const WARMUP_S = parseInt(env('WARMUP_SECONDS', '30'), 10);
const WARMUP_DRAIN_S = parseInt(env('WARMUP_DRAIN_SECONDS', '10'), 10);
const MEASURE_S = parseInt(env('MEASUREMENT_SECONDS', '120'), 10);
const DRAIN_S = parseInt(env('DRAIN_SECONDS', '30'), 10);
const PRE_ALLOCATED_VUS = parseInt(env('PRE_ALLOCATED_VUS', '50'), 10);
const MAX_VUS = parseInt(env('MAX_VUS', '1000'), 10);
const REQUEST_TIMEOUT = env('REQUEST_TIMEOUT', '10s');
const SUMMARY_PATH = env('SUMMARY_PATH', '');

const KEYCLOAK_HOST = env('KEYCLOAK_HOST', env('BANK_HOST', 'localhost'));
const TPP_HOST = env('TPP_HOST', 'localhost');
const WALLET_HOST = env('WALLET_HOST', 'localhost');
const TPP_URL = env('TPP_URL', `https://${TPP_HOST}:4443`);
const WALLET_URL = env('WALLET_URL', `https://${WALLET_HOST}:3443`);
const B0_TPP_URL = env('B0_TPP_URL', `https://${TPP_HOST}:4443`);

// B0 parameters (computed from the workload fixture by run_perf.py)
const B0_SCOPE = env('B0_SCOPE', 'openid accounts:read');
const B0_USERNAME = env('B0_USERNAME', 'testuser');
const B0_PASSWORD = env('B0_PASSWORD', 'password');

// VDAM parameters
const VDAM_SCOPES = JSON.parse(env('VDAM_SCOPES', '[]'));
const AUTHZ_VC_JTI = env('AUTHZ_VC_JTI', '');

const authDuration = new Trend('auth_duration', true);
const authOk = new Counter('auth_ok');
const authFail = new Counter('auth_fail');

function arrivalScenario(startTime, durationSeconds, gracefulStopSeconds) {
  return {
    executor: 'constant-arrival-rate',
    exec: 'authTx',
    rate: RATE,
    timeUnit: '1s',
    duration: `${durationSeconds}s`,
    startTime: `${startTime}s`,
    gracefulStop: `${gracefulStopSeconds}s`,
    preAllocatedVUs: Math.min(PRE_ALLOCATED_VUS, MAX_VUS),
    maxVUs: MAX_VUS,
  };
}

export const options = {
  insecureSkipTLSVerify: true,
  summaryTrendStats: ['min', 'med', 'avg', 'p(95)', 'p(99)', 'max', 'count'],
  scenarios: {
    warmup: arrivalScenario(0, WARMUP_S, WARMUP_DRAIN_S),
    measure: arrivalScenario(WARMUP_S + WARMUP_DRAIN_S, MEASURE_S, DRAIN_S),
  },
};

// ---- helpers ---------------------------------------------------------------

function resolveUrl(base, ref) {
  if (/^https?:\/\//i.test(ref)) return ref;
  const m = /^(https?:\/\/[^/]+)(\/[^?#]*)?/.exec(base);
  const origin = m[1];
  if (ref.startsWith('/')) return origin + ref;
  const path = m[2] || '/';
  return origin + path.substring(0, path.lastIndexOf('/') + 1) + ref;
}

// Keycloak may advertise a different hostname in form actions; pin it to KEYCLOAK_HOST.
function pinKeycloakHost(url) {
  const m = /^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/.exec(url);
  if (m && m[2] !== KEYCLOAK_HOST && url.indexOf('realms/traditional-fapi') !== -1) {
    return `${m[1]}://${KEYCLOAK_HOST}:${m[3] || '8443'}${m[4] || ''}`;
  }
  return url;
}

function codeFrom(location) {
  if (!location) return null;
  const m = /[?&]code=([^&#]+)/.exec(location);
  return m ? decodeURIComponent(m[1]) : null;
}

function bodyJson(res) {
  try {
    return res.json();
  } catch (e) {
    return null;
  }
}

function request(method, url, body, params) {
  return http.request(method, url, body, Object.assign({ timeout: REQUEST_TIMEOUT }, params));
}

// ---- B0: FAPI 2.0 authorization code + PKCE + PAR + mTLS ------------------
// The TPP backend owns PKCE, PAR (mTLS) and the token exchange (mTLS). This client only plays
// the browser: start authorization at the TPP, log in at Keycloak, hand the code back to the TPP.

function b0Transaction() {
  const jar = new http.CookieJar();
  const jsonHeaders = { 'Content-Type': 'application/json' };

  // 1. The TPP starts authorization and pushes the request (PAR) itself.
  const init = request('POST', `${B0_TPP_URL}/api/auth/initiate`, JSON.stringify({ scope: B0_SCOPE }), {
    headers: jsonHeaders, tags: { name: 'b0_initiate' },
  });
  const initBody = bodyJson(init) || {};
  if (init.status !== 200 || !initBody.usedPar || !initBody.redirectUrl || !initBody.state) {
    return { ok: false, stage: 'initiate' };
  }

  // 2. Browser -> Keycloak: authorization page, login, consent -> authorization code
  const authUrl = pinKeycloakHost(initBody.redirectUrl);
  const authPage = request('GET', authUrl, null, { jar, redirects: 0, tags: { name: 'b0_authorize' } });

  let code = codeFrom(authPage.headers['Location']);
  if (!code) {
    if (authPage.status !== 200) return { ok: false, stage: 'authorize' };
    const loginAction = parseHTML(authPage.body).find('form').attr('action');
    if (!loginAction) return { ok: false, stage: 'login_form_missing' };
    const loginUrl = pinKeycloakHost(resolveUrl(authUrl, loginAction));

    const login = request(
      'POST', loginUrl,
      { username: B0_USERNAME, password: B0_PASSWORD, credentialId: '' },
      { jar, redirects: 0, tags: { name: 'b0_login' } },
    );
    code = codeFrom(login.headers['Location']);

    if (!code) {
      // Consent. The very first login of a user is answered with a redirect to the consent required
      // action; once consent is stored Keycloak answers with the code directly.
      let consentPage = login;
      let consentBase = loginUrl;
      const next = login.headers['Location'];
      if (login.status >= 300 && login.status < 400 && next) {
        consentBase = pinKeycloakHost(resolveUrl(loginUrl, next));
        consentPage = request('GET', consentBase, null, { jar, redirects: 0, tags: { name: 'b0_consent_page' } });
        code = codeFrom(consentPage.headers['Location']);
      }
      if (!code) {
        if (consentPage.status !== 200) return { ok: false, stage: 'login' };
        const consentDoc = parseHTML(consentPage.body);
        const consentAction = consentDoc.find('form').attr('action');
        if (!consentAction) return { ok: false, stage: 'consent_form_missing' };
        const consentUrl = pinKeycloakHost(resolveUrl(consentBase, consentAction));
        const consentData = { accept: 'Yes' };
        const hiddenCode = consentDoc.find('input[name=code]').attr('value');
        if (hiddenCode) consentData.code = hiddenCode;

        const consent = request('POST', consentUrl, consentData, {
          jar, redirects: 0, tags: { name: 'b0_consent' },
        });
        code = codeFrom(consent.headers['Location']);
        if (!code) return { ok: false, stage: 'consent' };
      }
    }
  }

  // 3. Callback: hand the code and state back to the TPP, which does the mTLS token exchange.
  const token = request(
    'POST', `${B0_TPP_URL}/api/auth/token-exchange`,
    JSON.stringify({ code, state: initBody.state }),
    { headers: jsonHeaders, tags: { name: 'b0_token_exchange' } },
  );
  const tokens = (bodyJson(token) || {}).tokens || {};
  if (token.status !== 200 || !tokens.access_token) return { ok: false, stage: 'token' };
  return { ok: true };
}

// ---- B1-C0 / B1-C2: VDAM delegation (F2-F4) --------------------------------

function vdamTransaction() {
  const tppUrl = TPP_URL;
  const walletUrl = WALLET_URL;
  const jsonHeaders = { 'Content-Type': 'application/json' };

  // F2: TPP creates the delegation request
  const del = request('POST', `${tppUrl}/api/request-delegate`, JSON.stringify({ requestedScopes: VDAM_SCOPES }), {
    headers: jsonHeaders, tags: { name: 'vdam_request_delegate' },
  });
  const requestId = (bodyJson(del) || {}).requestId;
  if (del.status !== 200 || !requestId) return { ok: false, stage: 'request_delegate' };

  // F3: wallet fetches the request, then approves (and signs) the delegation
  const fetched = request(
    'GET', `${walletUrl}/api/fetch-tpp-request?requestId=${encodeURIComponent(requestId)}`,
    null, { tags: { name: 'vdam_fetch_request' } },
  );
  if (fetched.status !== 200) return { ok: false, stage: 'fetch_request' };

  const approveBody = { requestId, approvedScopes: VDAM_SCOPES };
  if (AUTHZ_VC_JTI) approveBody.authzVcJti = AUTHZ_VC_JTI;
  const approve = request('POST', `${walletUrl}/api/approve-delegate`, JSON.stringify(approveBody), {
    headers: jsonHeaders, tags: { name: 'vdam_approve_delegate' },
  });
  if (approve.status !== 200) return { ok: false, stage: 'approve_delegate' };

  // F4: TPP exchanges the delegation for the PoP access token
  // requestId selects this transaction's state in the TPP (state is kept per request).
  const token = request('POST', `${tppUrl}/api/token`, JSON.stringify({ requestId }), {
    headers: jsonHeaders, tags: { name: 'vdam_token' },
  });
  const tokenBody = bodyJson(token) || {};
  if (token.status !== 200 || !(tokenBody.access_token || tokenBody.token)) {
    return { ok: false, stage: 'token' };
  }
  return { ok: true };
}

// ---- scenario entry point -------------------------------------------------

export function authTx() {
  const phase = exec.scenario.name;
  // Sub-millisecond clock: Date.now() would round every latency to whole milliseconds.
  const started = exec.instance.currentTestRunDuration;
  let result;
  try {
    result = IS_B0 ? b0Transaction() : vdamTransaction();
  } catch (e) {
    result = { ok: false, stage: 'exception' };
  }
  const elapsed = exec.instance.currentTestRunDuration - started;

  if (result.ok) {
    authDuration.add(elapsed, { phase });
    authOk.add(1, { phase });
  } else {
    authFail.add(1, { phase, stage: result.stage });
  }
}

export function handleSummary(data) {
  // Returning no 'stdout' key keeps k6 quiet; the wrapper reads the summary file and raw points.
  const out = {};
  if (SUMMARY_PATH) out[SUMMARY_PATH] = JSON.stringify(data, null, 2);
  return out;
}
