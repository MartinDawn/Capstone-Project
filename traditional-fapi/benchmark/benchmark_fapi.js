/**
 * Automated Performance & Overhead Benchmark Script
 * Evaluates Traditional FAPI 2.0 vs Decentralized PQC Wallet Model
 */

const { performance } = require('perf_hooks');

const CONFIG = {
  keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
  realm: process.env.REALM || 'traditional-fapi',
  resourceServerUrl: process.env.RESOURCE_SERVER_URL || 'http://localhost:4000',
  clientId: 'tpp-client',
  clientSecret: 'tpp-client-secret-key-12345',
  username: 'testuser',
  password: 'password',
  iterations: 20,
};

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runBenchmark() {
  console.log(`================================================================`);
  console.log(`🚀 STARTING BENCHMARK: Traditional FAPI 2.0`);
  console.log(`   Target Auth Server:   ${CONFIG.keycloakUrl}/realms/${CONFIG.realm}`);
  console.log(`   Target Resource Server: ${CONFIG.resourceServerUrl}`);
  console.log(`   Test Iterations:      ${CONFIG.iterations}`);
  console.log(`================================================================\n`);

  const tokenUrl = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/token`;

  // 1. Measure Token Issuance Latency
  console.log(`[1/3] Benchmarking Keycloak Token Issuance (${CONFIG.iterations} runs)...`);
  const tokenLatencies = [];
  let sampleToken = null;

  for (let i = 0; i < CONFIG.iterations; i++) {
    const t0 = performance.now();
    try {
      const res = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          client_id: CONFIG.clientId,
          client_secret: CONFIG.clientSecret,
          username: CONFIG.username,
          password: CONFIG.password,
          scope: 'openid profile email accounts:read transfers:read',
        }),
      });

      const t1 = performance.now();
      if (res.ok) {
        tokenLatencies.push(t1 - t0);
        if (!sampleToken) {
          const data = await res.json();
          sampleToken = data.access_token;
        }
      } else {
        console.warn(`  [Warning] Token request failed on run ${i + 1}: ${res.status}`);
      }
    } catch (e) {
      console.warn(`  [Warning] Network error on run ${i + 1}: ${e.message}`);
    }
    await sleep(20);
  }

  // 2. Measure Token Payload Size Breakdown
  console.log(`\n[2/3] Analyzing Token Payload & Cryptographic Overhead...`);
  let tokenSizeStats = { totalBytes: 0, headerBytes: 0, payloadBytes: 0, signatureBytes: 0, alg: 'Unknown' };

  if (sampleToken) {
    const parts = sampleToken.split('.');
    tokenSizeStats.totalBytes = Buffer.byteLength(sampleToken, 'utf8');
    tokenSizeStats.headerBytes = Buffer.byteLength(parts[0], 'utf8');
    tokenSizeStats.payloadBytes = Buffer.byteLength(parts[1], 'utf8');
    tokenSizeStats.signatureBytes = Buffer.byteLength(parts[2], 'utf8');

    try {
      const headerJson = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      tokenSizeStats.alg = headerJson.alg || 'PS256';
    } catch (e) {}

    console.log(`  - Algorithm:           ${tokenSizeStats.alg} (Classical)`);
    console.log(`  - Total Token Size:    ${tokenSizeStats.totalBytes} bytes`);
    console.log(`  - Header:              ${tokenSizeStats.headerBytes} bytes`);
    console.log(`  - Payload (Claims):    ${tokenSizeStats.payloadBytes} bytes`);
    console.log(`  - Signature:           ${tokenSizeStats.signatureBytes} bytes`);
  } else {
    console.log(`  [Note] Make sure Keycloak is running at ${CONFIG.keycloakUrl} to gather live token metrics.`);
  }

  // 3. Measure Resource Server API Latency (Token Verification + Scope Check + SQL Query)
  console.log(`\n[3/3] Benchmarking Resource Server API Response Latency (${CONFIG.iterations} runs)...`);
  const apiLatencies = [];

  if (sampleToken) {
    for (let i = 0; i < CONFIG.iterations; i++) {
      const t0 = performance.now();
      try {
        const res = await fetch(`${CONFIG.resourceServerUrl}/api/v1/accounts`, {
          headers: {
            Authorization: `Bearer ${sampleToken}`,
          },
        });
        const t1 = performance.now();
        if (res.ok) {
          apiLatencies.push(t1 - t0);
        }
      } catch (e) {
        console.warn(`  [Warning] API call failed on run ${i + 1}: ${e.message}`);
      }
      await sleep(20);
    }
  }

  // Calculate Statistics Helper
  function calcStats(arr) {
    if (arr.length === 0) return { avg: 0, min: 0, max: 0, p95: 0 };
    const sorted = [...arr].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const avg = sum / sorted.length;
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    return { avg: avg.toFixed(2), min: min.toFixed(2), max: max.toFixed(2), p95: p95.toFixed(2) };
  }

  const tokenStats = calcStats(tokenLatencies);
  const apiStats = calcStats(apiLatencies);

  // 4. Output Summary Table
  console.log(`\n================================================================`);
  console.log(`📊 BENCHMARK RESULTS SUMMARY (Traditional FAPI 2.0)`);
  console.log(`================================================================`);
  console.log(`1. Token Issuance (Keycloak AS):`);
  console.log(`   - Successful Runs: ${tokenLatencies.length}/${CONFIG.iterations}`);
  console.log(`   - Avg Latency:     ${tokenStats.avg} ms`);
  console.log(`   - Min / Max / P95: ${tokenStats.min} / ${tokenStats.max} / ${tokenStats.p95} ms`);

  console.log(`\n2. Resource Server (API + Scope Enforcement):`);
  console.log(`   - Successful Runs: ${apiLatencies.length}/${CONFIG.iterations}`);
  console.log(`   - Avg Latency:     ${apiStats.avg} ms`);
  console.log(`   - Min / Max / P95: ${apiStats.min} / ${apiStats.max} / ${apiStats.p95} ms`);

  // 5. Comparative Evaluation Table with PQC Wallet Model
  console.log(`\n================================================================`);
  console.log(`🔬 COMPARATIVE EVALUATION MATRIX FOR THESIS / REPORT`);
  console.log(`================================================================`);
  console.log(`| Metric / Dimension          | Traditional FAPI 2.0      | Decentralized PQC Wallet  |`);
  console.log(`|-----------------------------|---------------------------|---------------------------|`);
  console.log(`| Architecture                | 3-Party (TPP, AS, RS)     | 4-Party (Wallet, TPP, Issuer, RS)|`);
  console.log(`| Authorization Mechanism     | Standard OAuth 2.0 Scopes | Selective Disclosure (VP) |`);
  console.log(`| Cryptography                | Classical PS256 / RSA     | Post-Quantum ML-DSA-65    |`);
  console.log(`| Quantum Resistance          | ❌ Vulnerable (Shor Alg)  | ✅ Quantum-Resistant      |`);
  console.log(`| Token/Credential Size       | ~${tokenSizeStats.totalBytes || 1200} Bytes               | ~5500 Bytes (PQC Sig+Key) |`);
  console.log(`| Signature Size              | ~${tokenSizeStats.signatureBytes || 344} Bytes (PS256)         | ~3309 Bytes (ML-DSA-65)   |`);
  console.log(`| User Data Sovereignty       | Rely on AS Consent        | Self-Sovereign in Wallet  |`);
  console.log(`================================================================\n`);
}

runBenchmark().catch(console.error);
