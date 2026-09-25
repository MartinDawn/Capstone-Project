// REINSTATED (BP-20260922-v5, decision DEC-020) as a calibration aid for E-LOAD.
// Exploratory saturation probe (NOT protocol evidence).
//
// One k6 run climbs a ladder of offered rates. Each rung is its own open-loop
// constant-arrival-rate scenario, so every transaction is tagged with the rung that started it.
// The transaction itself is imported unchanged from auth_load.js (same B0 and VDAM flows), so the
// probe exercises exactly the lifecycle the protocol runs.
//
// The run aborts itself as soon as a rung crosses a stop threshold: too many failed
// transactions, too many arrivals that found no free VU (generator limited), or a p95 above the
// latency ceiling. Aborting saves time and avoids hammering an already saturated system.
//
// Parameters come from environment variables set by probe_saturation.py:
//   PROBE_STEPS         JSON array of {"name", "rate", "duration"} rungs, in ascending order
//   PROBE_WARMUP_S      warm-up seconds at the first rung's rate (results ignored)
//   PROBE_DRAIN_S       seconds each rung may keep finishing in-flight work before the next rung
//   PROBE_MAX_FAIL_PCT  abort when failed transactions exceed this percent of a rung's arrivals
//   PROBE_STOP_P95_MS   abort when a rung's p95 exceeds this many milliseconds
//   PROBE_MAX_VUS, PROBE_PRE_ALLOCATED_VUS, SUMMARY_PATH

import { authTx } from './auth_load.js';

export { authTx };

const env = (name, fallback) =>
  __ENV[name] !== undefined && __ENV[name] !== '' ? __ENV[name] : fallback;

const STEPS = JSON.parse(env('PROBE_STEPS', '[]'));
const WARMUP_S = parseInt(env('PROBE_WARMUP_S', '15'), 10);
const DRAIN_S = parseInt(env('PROBE_DRAIN_S', '10'), 10);
const MAX_FAIL_PCT = parseFloat(env('PROBE_MAX_FAIL_PCT', '10'));
const STOP_P95_MS = parseFloat(env('PROBE_STOP_P95_MS', '15000'));
const MAX_VUS = parseInt(env('PROBE_MAX_VUS', '1000'), 10);
const PRE_ALLOCATED_VUS = Math.min(parseInt(env('PROBE_PRE_ALLOCATED_VUS', '50'), 10), MAX_VUS);
const SUMMARY_PATH = env('SUMMARY_PATH', '');

if (STEPS.length === 0) {
  throw new Error('PROBE_STEPS must contain at least one rung');
}

function scenario(startTime, rate, duration) {
  return {
    executor: 'constant-arrival-rate',
    exec: 'authTx',
    rate,
    timeUnit: '1s',
    duration: `${duration}s`,
    startTime: `${startTime}s`,
    gracefulStop: `${DRAIN_S}s`,
    preAllocatedVUs: PRE_ALLOCATED_VUS,
    maxVUs: MAX_VUS,
  };
}

const scenarios = {};
const thresholds = {};

// The warm-up runs at the first rung's rate. Its scenario name is the phase tag, so nothing
// below reads it.
scenarios.warmup = scenario(0, STEPS[0].rate, WARMUP_S);
let cursor = WARMUP_S + DRAIN_S;

for (const step of STEPS) {
  scenarios[step.name] = scenario(cursor, step.rate, step.duration);
  cursor += step.duration + DRAIN_S;

  const arrivals = step.rate * step.duration;
  const failMax = Math.max(3, Math.ceil((MAX_FAIL_PCT / 100) * arrivals));
  const dropMax = Math.max(1, Math.ceil(0.02 * arrivals));
  const abort = { abortOnFail: true, delayAbortEval: '3s' };

  // Every threshold below also makes k6 export the per-rung sub-metric to the end-of-test summary.
  thresholds[`auth_fail{phase:${step.name}}`] = [{ threshold: `count<${failMax}`, ...abort }];
  thresholds[`dropped_iterations{scenario:${step.name}}`] = [{ threshold: `count<${dropMax}`, ...abort }];
  thresholds[`auth_duration{phase:${step.name}}`] = [{ threshold: `p(95)<${STOP_P95_MS}`, ...abort }];
  thresholds[`auth_ok{phase:${step.name}}`] = ['count>=0'];
}

export const options = {
  insecureSkipTLSVerify: true,
  summaryTrendStats: ['min', 'med', 'avg', 'p(95)', 'p(99)', 'max', 'count'],
  scenarios,
  thresholds,
};

export function handleSummary(data) {
  const out = {};
  if (SUMMARY_PATH) out[SUMMARY_PATH] = JSON.stringify(data, null, 2);
  return out;
}
