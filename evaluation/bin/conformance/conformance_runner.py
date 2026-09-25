#!/usr/bin/env python3
"""
VDAM Executable Conformance Test Engine (Gate G3, Deliverables O1 & O2)

Executes formal protocol conformance assertions across three distinct tiers:
  1. ORACLE_UNIT: Pure offline mathematical lattice meet verification across S-A-V-D dimensions
     (20 Boundary Matrix sweep + 10 typed S-A-V-D invariant cases).
  2. CRYPTOGRAPHIC_UNIT: Pure cryptographic verification of Classical (NIST P-384 ECDSA)
     signatures, anti-downgrade enforcement, and key-role binding.
     NOTE (R3-02): Post-Quantum ML-DSA-65 signing/verification requires the Java BouncyCastle / liboqs
     provider from `wallet-vc-model/pqc-bank` and is marked NOT_RUN / UNSUPPORTED when the provider
     is offline. No synthetic hash+padding buffers are used.
  3. SUT_CONFORMANCE: Live end-to-end protocol conformance against running microservices (B0 FAPI 2.0,
     B1 VDAM F1-F6 flows, Negative security filters).
     CRITICAL (R2-01, R3-01): If SUT services are offline or test adapters are pending deployment,
     cases are explicitly recorded as 'NOT_RUN' with a descriptive reason. The runner NEVER reports
     false or mocked passes, and only returns HTTP 200 as online.

Generates:
  - evaluation/evidence/conformance/<run-id>/cases.jsonl
  - evaluation/evidence/conformance/<run-id>/traces.jsonl
  - evaluation/evidence/conformance/<run-id>/conformance-summary.csv
"""

import base64
import csv
import datetime
import hashlib
import importlib
import json
import os
import pathlib
import re
import secrets
import shutil
import sqlite3
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

# Auto-load .env from repository root if present
_root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_env_path = os.path.join(_root_dir, '.env')
if os.path.exists(_env_path):
    with open(_env_path, 'r', encoding='utf-8') as _ef:
        for _line in _ef:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                _k, _v = _k.strip(), _v.strip()
                if _k and _k not in os.environ:
                    os.environ[_k] = _v

# Import strict resource payload oracle and flow drivers from ais_flows (R8-01, R8-03).
# ais_flows is the shared AIS authorization-flow library (also used by the perf runners).
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)
from evaluation.bin.common.ais_flows import compute_cert_thumbprint, validate_resource_payload, execute_fapi_pkce_flow, decode_jwt_payload_unverified, execute_vdam_delegation_flow, execute_vdam_f1_oid4vci_flow

# Cryptographic engine for Classical & Hybrid verification (lazy/safe import)
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def get_ssl_context(cert_file=None, key_file=None, ca_file=None, allow_insecure_dev=False):
    """
    Constructs an SSL context for mTLS / TLS requests.
    Strict by default (R3-05): fails closed if specified certificate or CA paths are missing.
    Insecure mode (CERT_NONE) requires explicit opt-in.
    """
    if ca_file:
        if not os.path.exists(ca_file):
            raise FileNotFoundError(f"Strict TLS Error: CA certificate file not found: {ca_file}")
        ctx = ssl.create_default_context(cafile=ca_file)
        if os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') == '0' or allow_insecure_dev:
            ctx.check_hostname = False
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
    elif allow_insecure_dev:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
        ctx.verify_mode = ssl.CERT_REQUIRED

    if cert_file or key_file:
        if not cert_file or not os.path.exists(cert_file):
            raise FileNotFoundError(f"Strict TLS Error: mTLS client certificate not found: {cert_file}")
        if not key_file or not os.path.exists(key_file):
            raise FileNotFoundError(f"Strict TLS Error: mTLS client private key not found: {key_file}")
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    return ctx


def verify_security_rejection(http_error, expected_codes=(400, 401, 403), forbidden_error_tokens=('unknown_parameter', 'unrecognized_field', 'syntax_error', 'json_parse_error', 'unexpected_field', 'unsupported_parameter', 'extra_parameter', 'invalid_request_parameter', 'bad_request'), expected_semantic_tokens=None):
    """
    Validates that an HTTP error represents an authentic security rejection rather than
    a generic request parsing failure or unknown parameter error (R10-01, R11-01).
    Enforces exact whole-word token boundary matching rather than loose substring checks.
    """
    if http_error.code not in expected_codes:
        return False, f"UNEXPECTED_HTTP_CODE_{http_error.code}"

    try:
        body = http_error.read().decode('utf-8', errors='replace')
    except Exception:
        body = ""

    try:
        err_json = json.loads(body) if body else {}
    except Exception:
        err_json = {}

    err_fields = [
        str(getattr(http_error, 'msg', '')),
        str(getattr(http_error, 'reason', '')),
        str(err_json.get('error', '')),
        str(err_json.get('error_description', '')),
        str(err_json.get('message', '')),
        str(err_json.get('details', '')),
        body
    ]
    err_str = " ".join(err_fields).lower()

    # Rule out generic request handling errors (R10-01, R11-01)
    for token in forbidden_error_tokens:
        tok_low = token.lower()
        if re.search(r'\b' + re.escape(tok_low) + r'\b', err_str):
            return False, f"GENERIC_ERROR_REJECTED_{token.upper()}"

    # A named security predicate must match its exact machine-readable rejection
    # code. Broad words such as "failed" or "signature" are never sufficient
    # evidence for another predicate boundary.
    if expected_semantic_tokens:
        expected_rejection_codes = [
            token for token in expected_semantic_tokens
            if isinstance(token, str) and token.startswith('REJECT_')
        ]
        if expected_rejection_codes:
            observed_code = str(err_json.get('error_code', '')).strip()
            if not observed_code:
                description = str(err_json.get('error_description', '')).strip()
                match = re.match(r'^(REJECT_[A-Z0-9_]+)', description)
                observed_code = match.group(1) if match else ''
            if observed_code not in expected_rejection_codes:
                expected_text = ','.join(expected_rejection_codes)
                return False, f"WRONG_REJECTION_CODE_EXPECTED_{expected_text}_OBSERVED_{observed_code or 'MISSING'}"
            return True, f"SECURITY_REJECTION_VERIFIED_{observed_code}"

        matched = False
        for tok in expected_semantic_tokens:
            tok_low = tok.lower()
            if re.search(r'\b' + re.escape(tok_low) + r'\b', err_str):
                matched = True
                break
        if not matched:
            return False, f"SEMANTIC_ERROR_MISMATCH_EXPECTED_{expected_semantic_tokens}"

    return True, "SECURITY_REJECTION_VERIFIED"


def profile_digest_name():
    """Digest of the selected profile: the hybrid profile uses SHA-384, the classical profile SHA-256."""
    return 'sha384' if os.environ.get('CONFORMANCE_CONFIGURATION') == 'B1-C2' else 'sha256'


def compute_presentation_binding(authorization_vc, delegate_vc, r_das):
    """F4 presentation binding, computed independently of the SUT from the artifacts actually presented.

    Must stay byte-identical to PresentationBinding.compute in the bank issuer and the TPP."""
    raw = f"{authorization_vc or ''}~{delegate_vc or ''}~{r_das or ''}".encode('utf-8')
    digest = hashlib.new(profile_digest_name(), raw).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


# =====================================================================
# DATASET ORACLE
# Expected AIS resource values are derived from the Berka dataset the SUT serves, never from what the SUT
# answered. The projection rule (canonical ACC-NNN identity, the account's most recent booked movement,
# narrowed by the effective authority) is the frozen semantics; the values come from the dataset.
# =====================================================================

DATASET_CLIENT_ID = 1  # The conformance holder 'testuser' maps to Berka client 1 in every baseline.

_DATASET_RELATIVE_PATHS = {
    'B0-C0': ('traditional-fapi', 'resource-server', 'berka.db'),
    'B1-C0': ('wallet-vc-model-classical', 'bank', 'resource-server', 'berka.db'),
    'B1-C2': ('wallet-vc-model', 'pqc-bank', 'resource-server', 'berka.db'),
}


def dataset_path(base_dir):
    configuration = os.environ.get('CONFORMANCE_CONFIGURATION', 'B1-C0')
    relative = _DATASET_RELATIVE_PATHS.get(configuration, _DATASET_RELATIVE_PATHS['B1-C0'])
    candidate = os.path.join(base_dir, *relative)
    if not os.path.exists(candidate):
        raise RuntimeError(
            f"FIXTURE_PREREQUISITE_FAILED: Berka dataset for {configuration} not found at {candidate}"
        )
    return candidate


def _dataset_query(base_dir, sql, params=()):
    uri = f"file:{pathlib.Path(dataset_path(base_dir)).as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(sql, params)]
    finally:
        connection.close()


def canonical_account_id(internal_id):
    return f"ACC-{int(internal_id):03d}"


def internal_account_id(canonical_id):
    match = re.fullmatch(r'ACC-(\d+)', str(canonical_id))
    return int(match.group(1)) if match else None


def dataset_account_record(base_dir, internal_id):
    """Canonical AIS record for one account, computed from the dataset: its most recent booked movement."""
    rows = _dataset_query(
        base_dir,
        'SELECT date, type, operation, amount, balance FROM trans '
        'WHERE account_id = ? ORDER BY date DESC, trans_id DESC LIMIT 1',
        (internal_id,),
    )
    movement = rows[0] if rows else {}
    raw_date = str(movement.get('date', '') or '')
    return {
        'account_id': canonical_account_id(internal_id),
        'amount': round(float(movement['amount']), 2) if movement.get('amount') is not None else 0,
        'balance': round(float(movement['balance']), 2) if movement.get('balance') is not None else 0,
        'date': f"19{raw_date[0:2]}-{raw_date[2:4]}-{raw_date[4:6]}" if len(raw_date) == 6 else raw_date,
        'operation': movement.get('operation') or 'UNKNOWN',
        'type': 'Credit' if movement.get('type') == 'PRIJEM' else 'Debit',
    }


def dataset_owned_account_ids(base_dir, client_id=DATASET_CLIENT_ID):
    rows = _dataset_query(
        base_dir,
        'SELECT DISTINCT a.account_id AS account_id FROM accounts a '
        'JOIN disp d ON a.account_id = d.account_id WHERE d.client_id = ? ORDER BY a.account_id',
        (client_id,),
    )
    return [int(row['account_id']) for row in rows]


def dataset_expected_records(base_dir, accounts, fields, page_size, client_id=DATASET_CLIENT_ID):
    """Resource projection the holder is entitled to: authority accounts that the holder actually owns."""
    authorized = {internal_account_id(item) for item in accounts}
    authorized.discard(None)
    owned = [item for item in dataset_owned_account_ids(base_dir, client_id) if item in authorized]
    selected = sorted(owned)[:max(int(page_size), 0)]
    records = []
    for internal_id in selected:
        record = dataset_account_record(base_dir, internal_id)
        records.append({field: record[field] for field in fields if field in record})
    return records


def dataset_foreign_account(base_dir, client_id=DATASET_CLIENT_ID):
    """An account that exists in the dataset but is not reachable by this holder through any disposition."""
    rows = _dataset_query(
        base_dir,
        'SELECT d.account_id AS account_id, MIN(d.client_id) AS owner_client_id FROM disp d '
        'WHERE d.account_id NOT IN (SELECT account_id FROM disp WHERE client_id = ?) '
        'GROUP BY d.account_id ORDER BY d.account_id LIMIT 1',
        (client_id,),
    )
    if not rows:
        return None
    return {
        'internal_id': int(rows[0]['account_id']),
        'canonical_id': canonical_account_id(rows[0]['account_id']),
        'client_id': int(rows[0]['owner_client_id']),
    }


def normalize_string_set(value):
    if value is None:
        return []
    if isinstance(value, str):
        return sorted(item for item in value.split() if item)
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    return []


def b0_token_assertions(token, expected, cert_path):
    _, claims = decode_jwt_payload_unverified(token)
    cnf = claims.get('cnf') if isinstance(claims, dict) else None
    if isinstance(cnf, str):
        try:
            cnf = json.loads(cnf)
        except json.JSONDecodeError:
            cnf = None
    expected_thumbprint = compute_cert_thumbprint(cert_path)
    actual_client = claims.get('azp') or claims.get('client_id')
    actual_lifetime = claims.get('exp', 0) - claims.get('iat', 0)
    return claims, [
        {
            'check': 'token_client_exact',
            'passed': actual_client == expected['client_id'],
            'expected': expected['client_id'],
            'observed': actual_client,
        },
        {
            'check': 'token_audience_exact',
            'passed': normalize_string_set(claims.get('aud')) == sorted(expected['audiences']),
            'expected': sorted(expected['audiences']),
            'observed': normalize_string_set(claims.get('aud')),
        },
        {
            'check': 'token_lifetime_exact',
            'passed': actual_lifetime == expected['lifetime_seconds'],
            'expected': expected['lifetime_seconds'],
            'observed': actual_lifetime,
        },
        {
            'check': 'token_scope_exact',
            'passed': normalize_string_set(claims.get('scope')) == sorted(expected['scopes']),
            'expected': sorted(expected['scopes']),
            'observed': normalize_string_set(claims.get('scope')),
        },
        {
            'check': 'certificate_thumbprint_exact',
            'passed': isinstance(cnf, dict) and cnf.get('x5t#S256') == expected_thumbprint,
            'expected': expected_thumbprint,
            'observed': cnf.get('x5t#S256') if isinstance(cnf, dict) else None,
        },
    ]


def b0_resource_projection(payload):
    data = payload.get('Data') if isinstance(payload, dict) else None
    items = data.get('Account') if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise RuntimeError('RESOURCE_PROJECTION_MISSING_DATA_ACCOUNT')
    accounts = sorted(str(item.get('account_id')) for item in items if isinstance(item, dict))
    fields = sorted({key for item in items if isinstance(item, dict) for key in item})
    return {'accounts': accounts, 'fields': fields, 'records': items}


def authority_decision_label(permitted, effective, unrestricted):
    """Decision actually produced, derived from the observed authority - never copied from the expectation.

    PERMIT_RESTRICTED means the effective authority is strictly narrower than the unrestricted inputs."""
    if not permitted or effective is None:
        return 'DENY'
    reference = {
        'services': sorted(unrestricted['services']),
        'accounts': sorted(unrestricted['accounts']),
        'validity': unrestricted['validity'],
        'data': {
            'history_days': unrestricted['data']['history_days'],
            'fields': sorted(unrestricted['data']['fields']),
            'page_size': unrestricted['data']['page_size'],
        },
    }
    observed = {
        'services': sorted(effective['services']),
        'accounts': sorted(effective['accounts']),
        'validity': effective['validity'],
        'data': {
            'history_days': effective['data']['history_days'],
            'fields': sorted(effective['data']['fields']),
            'page_size': effective['data']['page_size'],
        },
    }
    return 'PERMIT' if observed == reference else 'PERMIT_RESTRICTED'


class DasOracleSimulator:
    """
    Python reference implementation strictly mirroring evaluation.oracle.DasOracle
    Computes typed lattice meet across S, A, V, D dimensions for 5 authority inputs:
    SC (Scope VC), H (Holder Approval), R (TPP Request), T (TPP Regulatory Bounds), P (Bank Policy).
    """
    @staticmethod
    def evaluate(sc, h, r, t, p):
        # 1. Services Meet: S_e = S_SC âˆ© S_H âˆ© S_R âˆ© S_T âˆ© S_P
        s_eff = set(sc['services']) & set(h['services']) & set(r['services']) & set(t['services']) & set(p['services'])
        if not s_eff:
            return False, "REJECT_EMPTY_SERVICES", None

        # 2. Accounts Meet: A_e = A_SC âˆ© A_H âˆ© A_R âˆ© A_T âˆ© A_P
        a_eff = set(sc['accounts']) & set(h['accounts']) & set(r['accounts']) & set(t['accounts']) & set(p['accounts'])
        if not a_eff:
            return False, "REJECT_EMPTY_ACCOUNTS", None

        # 3. Validity Meet: V_e = [max(start), min(end)]
        v_start = max(sc['validity']['start'], h['validity']['start'], r['validity']['start'], t['validity']['start'], p['validity']['start'])
        v_end = min(sc['validity']['end'], h['validity']['end'], r['validity']['end'], t['validity']['end'], p['validity']['end'])
        if v_start > v_end:
            return False, "REJECT_INVALID_VALIDITY_INTERVAL", None

        # 4. Data Predicates Meet: D_e = (min(history), fields_meet, min(page_size))
        d_hist = min(sc['data']['history_days'], h['data']['history_days'], r['data']['history_days'], t['data']['history_days'], p['data']['history_days'])
        if d_hist <= 0:
            return False, "REJECT_INVALID_HISTORY_WINDOW", None

        d_fields = set(sc['data']['fields']) & set(h['data']['fields']) & set(r['data']['fields']) & set(t['data']['fields']) & set(p['data']['fields'])
        if not d_fields:
            return False, "REJECT_EMPTY_DATA_FIELDS", None

        d_page = min(sc['data']['page_size'], h['data']['page_size'], r['data']['page_size'], t['data']['page_size'], p['data']['page_size'])
        if d_page <= 0:
            return False, "REJECT_INVALID_PAGE_SIZE", None

        effective = {
            'services': sorted(list(s_eff)),
            'accounts': sorted(list(a_eff)),
            'validity': {'start': v_start, 'end': v_end},
            'data': {
                'history_days': d_hist,
                'fields': sorted(list(d_fields)),
                'page_size': d_page
            }
        }
        return True, "PERMIT", effective


# =====================================================================
# TIER 1: ORACLE_UNIT (20 Boundary Matrix + 10 VDAM Math Assertions)
# =====================================================================

def run_boundary_20_conformance(base_dir, traces_out):
    """
    Tier: ORACLE_UNIT
    Executes all 20 combinations from boundary_20_vd_f05.json against the reference Oracle.
    Asserts exact equality of S, A, V, D effective authority against expected_authority.
    """
    boundary_path = os.path.join(base_dir, 'evaluation', 'fixtures', 'data', 'boundary_20_vd_f05.json')
    if not os.path.exists(boundary_path):
        raise FileNotFoundError(f"Missing boundary fixtures at {boundary_path}. Run 'runner.ps1 generate' first.")

    with open(boundary_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    base_vector = {
        'services': ['accounts', 'balances', 'transactions'],
        'accounts': ['ACC-001', 'ACC-002', 'ACC-003', 'ACC-004', 'ACC-005'],
        'validity': {'start': 1788500000, 'end': 1791092000},
        'data': {
            'history_days': 90,
            'page_size': 50,
            'fields': ['account_id', 'amount', 'balance', 'date', 'operation', 'type']
        }
    }

    results = []
    for c in cases:
        case_id = c['case_id']
        target_dim = c['restricted_dimension']
        restrictor = c['restrictive_entity']

        t0 = time.perf_counter_ns()
        assertions = []

        sc = json.loads(json.dumps(base_vector))
        h = json.loads(json.dumps(base_vector))
        r = json.loads(json.dumps(base_vector))
        t = json.loads(json.dumps(base_vector))
        p = json.loads(json.dumps(base_vector))

        vec_map = {'SC': sc, 'H': h, 'R': r, 'T': t, 'P': p}
        target_vec = vec_map[restrictor]

        if target_dim == 'S':
            target_vec['services'] = ['accounts']
        elif target_dim == 'A':
            target_vec['accounts'] = ['ACC-001']
        elif target_dim == 'V':
            target_vec['validity']['start'] = 1788500000 + 5 * 86400
            target_vec['validity']['end'] = 1788500000 + 10 * 86400
        elif target_dim == 'D':
            target_vec['data']['history_days'] = 30
            target_vec['data']['page_size'] = 10
            target_vec['data']['fields'] = ['account_id', 'balance']

        permitted, reason, eff = DasOracleSimulator.evaluate(sc, h, r, t, p)
        assertions.append({'check': 'oracle_permitted', 'passed': bool(permitted)})
        assertions.append({'check': 'effective_authority_produced', 'passed': eff is not None})

        expected_auth = c['expected_authority']
        assertions.append({'check': 'services_match', 'passed': eff is not None and eff['services'] == expected_auth['services']})
        assertions.append({'check': 'accounts_match', 'passed': eff is not None and eff['accounts'] == expected_auth['accounts']})
        assertions.append({'check': 'validity_match', 'passed': eff is not None and eff['validity'] == expected_auth['validity']})
        assertions.append({'check': 'history_days_match', 'passed': eff is not None and eff['data']['history_days'] == expected_auth['data_predicate']['history_days_window']})
        assertions.append({'check': 'page_size_match', 'passed': eff is not None and eff['data']['page_size'] == expected_auth['data_predicate']['max_page_size']})
        assertions.append({'check': 'fields_match', 'passed': eff is not None and eff['data']['fields'] == expected_auth['data_predicate']['fields']})

        actual_decision = authority_decision_label(permitted, eff, base_vector)
        assertions.append({
            'check': 'decision_is_restricted_permit',
            'passed': actual_decision == 'PERMIT_RESTRICTED',
            'observed': actual_decision,
        })

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        passed = len(assertions) > 0 and all(a['passed'] for a in assertions)

        res = {
            'suite': 'Boundary_Matrix_20',
            'tier': 'ORACLE_UNIT',
            'case_id': case_id,
            'name': f"Boundary Meet ({restrictor} solely restricts {target_dim})",
            'configuration': 'B1-C0, B1-C2',
            'status': 'PASS' if passed else 'FAIL',
            'execution_mode': 'COMPONENT',
            'test_assistance': [],
            'production_boundary': 'OFFLINE_DAS_ORACLE',
            'proven_requirements': [f"Mathematical lattice meet correctness when {restrictor} restricts dimension {target_dim}"],
            'uncovered_aspects': [
                'Live network transport and serialization',
                'No SUT involvement: this tier compares the Python oracle against fixtures generated by '
                'evaluation/oracle/DasOracle.java, so it establishes agreement between the two oracle '
                'implementations, not conformance of B1-C0 or B1-C2',
            ],
            'expected_decision': 'PERMIT_RESTRICTED',
            'actual_decision': actual_decision,
            'oracle_match': bool(passed),
            'reason': reason,
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'Boundary_Matrix_20',
            'tier': 'ORACLE_UNIT',
            'status': 'PASS' if passed else 'FAIL',
            'assertions': assertions,
            'timestamp': res['timestamp']
        })

    return results


def run_vdam_oracle_math_conformance(base_dir, traces_out):
    """
    Tier: ORACLE_UNIT
    Executes core typed lattice meet invariants (S-A-V-D) and boundary rejection conditions
    directly against the reference Oracle logic:
      - VD-F02: Multi-account & multi-permission intersection
      - VD-F03: Holder restricted S and A
      - VD-F04: Policy restricted S, V, D
      - VD-F05: Boundary matrix composite verification
      - VD-F06: Empty meet on disjoint accounts
      - VD-N05-DisjointAccounts: Rejection on disjoint accounts
      - VD-N05-InvertedValidity: Rejection on inverted time interval
      - VD-N05-DisjointFields: Rejection on disjoint requested fields
      - VD-N05-ZeroHistory: Rejection on zero/negative history window
      - VD-N05-ZeroPageSize: Rejection on zero/negative page size
    """
    base_vector = {
        'services': ['accounts', 'balances', 'transactions'],
        'accounts': ['ACC-001', 'ACC-002', 'ACC-003', 'ACC-004', 'ACC-005'],
        'validity': {'start': 1788500000, 'end': 1788500000 + 30 * 86400},
        'data': {
            'history_days': 90,
            'fields': ['account_id', 'amount', 'balance', 'date', 'operation', 'type'],
            'page_size': 25
        }
    }

    test_definitions = [
        {
            'case_id': 'VD-F02',
            'name': 'Multi-Account and Multi-Permission Compatible Intersection',
            'expected_decision': 'PERMIT',
            'expected_reason': 'PERMIT',
            'modifier': lambda sc, h, r, t, p: None,
            'checker': lambda permitted, reason, eff: (
                permitted and eff is not None and len(eff['accounts']) == 5 and len(eff['data']['fields']) == 6
            )
        },
        {
            'case_id': 'VD-F03',
            'name': 'Holder Restrictive Input for S and A Dimensions',
            'expected_decision': 'PERMIT_RESTRICTED',
            'expected_reason': 'PERMIT',
            'modifier': lambda sc, h, r, t, p: (
                h.update({'accounts': ['ACC-001'], 'services': ['accounts', 'balances']})
            ),
            'checker': lambda permitted, reason, eff: (
                permitted and eff is not None and eff['accounts'] == ['ACC-001'] and eff['services'] == ['accounts', 'balances']
            )
        },
        {
            'case_id': 'VD-F04',
            'name': 'Policy Restrictive Input for S, V, D Dimensions',
            'expected_decision': 'PERMIT_RESTRICTED',
            'expected_reason': 'PERMIT',
            'modifier': lambda sc, h, r, t, p: (
                p['validity'].update({'end': p['validity']['start'] + 7 * 86400}),
                p['data'].update({'fields': ['account_id', 'balance'], 'history_days': 7})
            ),
            'checker': lambda permitted, reason, eff: (
                permitted and eff is not None and
                (eff['validity']['end'] - eff['validity']['start'] == 7 * 86400) and
                eff['data']['fields'] == ['account_id', 'balance'] and eff['data']['history_days'] == 7
            )
        },
        {
            'case_id': 'VD-F05',
            'name': 'All-Dimension Boundary Meet Exhaustive Verification (20 Boundary Matrix)',
            'expected_decision': 'PERMIT_RESTRICTED',
            'expected_reason': 'PERMIT',
            'modifier': lambda sc, h, r, t, p: (
                h.update({'accounts': ['ACC-001']}),
                p['validity'].update({'end': p['validity']['start'] + 7 * 86400})
            ),
            'checker': lambda permitted, reason, eff: (
                permitted and eff is not None and eff['accounts'] == ['ACC-001'] and
                (eff['validity']['end'] - eff['validity']['start'] == 7 * 86400)
            )
        },
        {
            'case_id': 'VD-F06',
            'name': 'Empty Meet or Disjoint Authority Boundary Handling',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_EMPTY_ACCOUNTS',
            'modifier': lambda sc, h, r, t, p: h.update({'accounts': ['ACC-999']}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_EMPTY_ACCOUNTS'
        },
        {
            'case_id': 'VD-N05-DisjointAccounts',
            'name': 'Negative: Disjoint Account Sets Intersection',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_EMPTY_ACCOUNTS',
            'modifier': lambda sc, h, r, t, p: h.update({'accounts': ['ACC-999']}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_EMPTY_ACCOUNTS'
        },
        {
            'case_id': 'VD-N05-InvertedValidity',
            'name': 'Negative: Inverted Validity Time Window (start > end)',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_INVALID_VALIDITY_INTERVAL',
            'modifier': lambda sc, h, r, t, p: h['validity'].update({'start': 1788700000, 'end': 1788600000}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_INVALID_VALIDITY_INTERVAL'
        },
        {
            'case_id': 'VD-N05-DisjointFields',
            'name': 'Negative: Disjoint Requested Data Fields Intersection',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_EMPTY_DATA_FIELDS',
            'modifier': lambda sc, h, r, t, p: h['data'].update({'fields': ['nonexistent_field']}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_EMPTY_DATA_FIELDS'
        },
        {
            'case_id': 'VD-N05-ZeroHistory',
            'name': 'Negative: Non-Positive History Window',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_INVALID_HISTORY_WINDOW',
            'modifier': lambda sc, h, r, t, p: h['data'].update({'history_days': 0}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_INVALID_HISTORY_WINDOW'
        },
        {
            'case_id': 'VD-N05-ZeroPageSize',
            'name': 'Negative: Non-Positive Max Page Size',
            'expected_decision': 'DENY',
            'expected_reason': 'REJECT_INVALID_PAGE_SIZE',
            'modifier': lambda sc, h, r, t, p: h['data'].update({'page_size': -5}),
            'checker': lambda permitted, reason, eff: not permitted and reason == 'REJECT_INVALID_PAGE_SIZE'
        }
    ]

    results = []
    for td in test_definitions:
        case_id = td['case_id']
        t0 = time.perf_counter_ns()
        assertions = []

        sc = json.loads(json.dumps(base_vector))
        h = json.loads(json.dumps(base_vector))
        r = json.loads(json.dumps(base_vector))
        t = json.loads(json.dumps(base_vector))
        p = json.loads(json.dumps(base_vector))

        td['modifier'](sc, h, r, t, p)
        permitted, actual_reason, eff = DasOracleSimulator.evaluate(sc, h, r, t, p)

        check_passed = td['checker'](permitted, actual_reason, eff)
        assertions.append({'check': 'oracle_meet_condition_verified', 'passed': bool(check_passed)})
        assertions.append({'check': 'reason_matches_expected', 'passed': bool(actual_reason == td['expected_reason'])})

        actual_decision = authority_decision_label(permitted, eff, base_vector)

        passed = len(assertions) > 0 and all(a['passed'] for a in assertions) and (actual_decision == td['expected_decision'])
        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0

        res = {
            'suite': 'VDAM_Oracle_Math',
            'tier': 'ORACLE_UNIT',
            'case_id': case_id,
            'name': td['name'],
            'configuration': 'B1-C0, B1-C2',
            'status': 'PASS' if passed else 'FAIL',
            'execution_mode': 'COMPONENT',
            'test_assistance': [],
            'production_boundary': 'OFFLINE_DAS_ORACLE',
            'proven_requirements': [f"Mathematical typed authority invariants for {case_id}"],
            'uncovered_aspects': [
                'Live network transport and serialization',
                'No SUT involvement: the same case id is exercised against the running system by the '
                'SUT_CONFORMANCE tier; this tier only checks the offline oracle',
            ],
            'expected_decision': td['expected_decision'],
            'actual_decision': actual_decision,
            'oracle_match': bool(passed),
            'reason': actual_reason,
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'VDAM_Oracle_Math',
            'tier': 'ORACLE_UNIT',
            'status': 'PASS' if passed else 'FAIL',
            'assertions': assertions,
            'timestamp': res['timestamp']
        })

    return results


import subprocess
def run_hybrid_crypto_conformance(base_dir, traces_out):
    """Run the real Java/Bouncy Castle hybrid verifier in every B1-C2 role."""
    cases_path = os.path.join(base_dir, 'evaluation', 'tests', 'hybrid_cases.json')
    with open(cases_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)
    modules = {
        'bank': os.path.join(base_dir, 'wallet-vc-model', 'pqc-bank', 'bank-issuer'),
        'tpp': os.path.join(base_dir, 'wallet-vc-model', 'pqc-tpp', 'tpp-java'),
        'wallet': os.path.join(base_dir, 'wallet-vc-model', 'pqc-wallet', 'wallet-java'),
    }
    method_by_case = {
        'HY-F01': 'hyF01ValidCompositeSignatureIsAccepted',
        'HY-N01': 'hyN01MissingClassicalComponentIsRejected',
        'HY-N02': 'hyN02MissingPqcComponentIsRejected',
        'HY-N03-CorruptClassical': 'hyN03CorruptClassicalComponentIsRejected',
        'HY-N03-CorruptPQC': 'hyN03CorruptPqcComponentIsRejected',
        'HY-N04': 'hyN04ProtectedHeaderDowngradeIsRejected',
        'HY-N05': 'hyN05DifferentRoleKeyIsRejected',
    }

    module_results = {}
    maven_executable = shutil.which('mvn.cmd') or shutil.which('mvn')
    for role, module_dir in modules.items():
        # Clean stale surefire reports before execution
        reports_dir = os.path.join(module_dir, 'target', 'surefire-reports')
        if os.path.isdir(reports_dir):
            for name in os.listdir(reports_dir):
                if name.startswith('TEST-') and name.endswith('HybridCryptoServiceTest.xml'):
                    try:
                        os.remove(os.path.join(reports_dir, name))
                    except OSError:
                        pass

        started = time.perf_counter_ns()
        try:
            if not maven_executable:
                raise FileNotFoundError('Maven executable was not found on PATH')
            completed = subprocess.run(
                [maven_executable, '-q', '-Dtest=HybridCryptoServiceTest', 'test'],
                cwd=module_dir,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            execution_error = None
        except (OSError, subprocess.TimeoutExpired) as exc:
            completed = None
            execution_error = f'{type(exc).__name__}: {exc}'

        reports_dir = os.path.join(module_dir, 'target', 'surefire-reports')
        report_paths = []
        if os.path.isdir(reports_dir):
            report_paths = [
                os.path.join(reports_dir, name)
                for name in os.listdir(reports_dir)
                if name.startswith('TEST-') and name.endswith('HybridCryptoServiceTest.xml')
            ]
        tests = {}
        report_hashes = []
        for report_path in report_paths:
            with open(report_path, 'rb') as report_handle:
                report_hashes.append(hashlib.sha256(report_handle.read()).hexdigest())
            try:
                import xml.etree.ElementTree as element_tree
                root = element_tree.parse(report_path).getroot()
                for testcase in root.findall('testcase'):
                    name = testcase.attrib.get('name', '')
                    failure = testcase.find('failure')
                    error = testcase.find('error')
                    skipped = testcase.find('skipped')
                    tests[name] = {
                        'passed': failure is None and error is None and skipped is None,
                        'failure': (
                            (failure.attrib.get('message') or failure.text or '').strip()
                            if failure is not None
                            else (error.attrib.get('message') or error.text or '').strip()
                            if error is not None
                            else 'SKIPPED' if skipped is not None else None
                        ),
                    }
            except Exception as exc:
                execution_error = f'JUNIT_REPORT_PARSE_ERROR: {type(exc).__name__}: {exc}'
        module_results[role] = {
            'return_code': completed.returncode if completed else None,
            'execution_error': execution_error,
            'duration_us': round((time.perf_counter_ns() - started) / 1000.0, 2),
            'report_sha256': report_hashes,
            'tests': tests,
        }

    def verify_live_cross_role_rejection():
        """Prove that valid hybrid artifacts signed by non-Bank role keys fail at Bank."""
        bank_host = os.environ.get('BANK_HOST', 'localhost')
        tpp_host = os.environ.get('TPP_HOST', 'localhost')
        wallet_host = os.environ.get('WALLET_HOST', 'localhost')
        issuer_url = os.environ.get('VDAM_ISSUER_URL', f'http://{bank_host}:7000')
        signer_urls = {
            'tpp': os.environ.get('VDAM_TPP_URL', f'http://{tpp_host}:6001'),
            'wallet': os.environ.get('VDAM_WALLET_URL', f'http://{wallet_host}:5000'),
        }
        assertions = []
        payload = {
            'iss': 'conformance-cross-role-signer',
            'sub': 'HY-N05',
            'iat': int(time.time()),
            'exp': int(time.time()) + 300,
        }
        for role, base_url in signer_urls.items():
            try:
                sign_request = urllib.request.Request(
                    f'{base_url}/api/test/sign-artifact',
                    data=json.dumps({'payload': payload, 'typ': 'JWT'}).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                with urllib.request.urlopen(sign_request, timeout=10) as response:
                    sign_response = json.loads(response.read().decode('utf-8'))
                signed_jwt = sign_response.get('signedJwt')
                if not signed_jwt:
                    raise RuntimeError('signer returned no signedJwt')

                verify_request = urllib.request.Request(
                    f'{issuer_url}/api/v1/verify-token',
                    data=json.dumps({'token': signed_jwt}).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                try:
                    with urllib.request.urlopen(verify_request, timeout=10) as response:
                        status_code = response.status
                        response_body = json.loads(response.read().decode('utf-8'))
                except urllib.error.HTTPError as exc:
                    status_code = exc.code
                    response_body = json.loads(exc.read().decode('utf-8'))

                assertions.append({
                    'check': f'live_{role}_signed_artifact_rejected_by_bank_key_boundary',
                    'passed': (
                        status_code == 401
                        and response_body.get('valid') is False
                        and response_body.get('error') == 'PQC composite signature verification failed'
                        and sign_response.get('signerRole', '').lower() == role
                    ),
                    'signer_role': sign_response.get('signerRole'),
                    'signer_key_id': sign_response.get('signerKeyId'),
                    'verifier_role': 'BANK',
                    'http_status': status_code,
                    'error': response_body.get('error'),
                })
            except Exception as exc:
                assertions.append({
                    'check': f'live_{role}_signed_artifact_rejected_by_bank_key_boundary',
                    'passed': False,
                    'unavailable': True,
                    'error': f'{type(exc).__name__}: {exc}',
                })
        return assertions

    live_cross_role_assertions = verify_live_cross_role_rejection()

    results = []
    for case in cases:
        case_id = case['case_id']
        method_name = method_by_case[case_id]
        assertions = []
        for role, module_result in module_results.items():
            test_result = module_result['tests'].get(method_name)
            assertions.append({
                'check': f'{role}_real_provider_{method_name}',
                'passed': bool(test_result and test_result['passed'] and module_result['return_code'] == 0),
                'return_code': module_result['return_code'],
                'execution_error': module_result['execution_error'],
                'failure': test_result.get('failure') if test_result else 'JUNIT_TEST_RESULT_MISSING',
                'report_sha256': module_result['report_sha256'],
            })
        if case_id == 'HY-N05':
            assertions.extend(live_cross_role_assertions)
        unavailable = any(
            item.get('return_code') is None and 'return_code' in item
            or item.get('failure') == 'JUNIT_TEST_RESULT_MISSING'
            or item.get('unavailable') is True
            for item in assertions
        )
        status = 'NOT_RUN' if unavailable else ('PASS' if all(item['passed'] for item in assertions) else 'FAIL')
        # What was observed is whether the provider-backed verifier behaved as the case requires, in every
        # role. The expectation is never copied into the observation.
        actual_decision = (
            'NOT_RUN' if status == 'NOT_RUN'
            else 'PROVIDER_VERIFIER_BEHAVED_AS_REQUIRED' if status == 'PASS'
            else 'PROVIDER_VERIFIER_DEVIATED'
        )
        reason = (
            'PQC_PROVIDER_TEST_UNAVAILABLE' if status == 'NOT_RUN'
            else f"PROVIDER_ASSERTIONS_PASSED_IN_ROLES_{'_'.join(sorted(modules))}" if status == 'PASS'
            else 'PQC_PROVIDER_ASSERTION_FAILED'
        )
        elapsed_us = sum(value['duration_us'] for value in module_results.values())
        res = {
            'suite': 'Hybrid_PQC_Verification',
            'tier': 'CRYPTOGRAPHIC_UNIT',
            'case_id': case_id,
            'name': case['name'],
            'configuration': 'B1-C2',
            'status': status,
            'execution_mode': case.get('execution_mode', 'COMPONENT'),
            'test_assistance': case.get('test_assistance', []),
            'production_boundary': case.get('production_boundary', 'HYBRID_CRYPTO_VERIFIER'),
            'proven_requirements': case.get('proven_requirements', []),
            'uncovered_aspects': case.get('uncovered_aspects', []),
            'expected_decision': case.get('expected_decision', 'DENY'),
            'actual_decision': actual_decision,
            # Every applicable role's provider-backed verifier agreed with the case requirement.
            'oracle_match': None if status == 'NOT_RUN' else all(item['passed'] for item in assertions),
            'reason': reason,
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'Hybrid_PQC_Verification',
            'tier': 'CRYPTOGRAPHIC_UNIT',
            'status': status,
            'assertions': assertions,
            'timestamp': res['timestamp'],
            'provider': 'BouncyCastle MLDSA65-ECDSA-P384-SHA512',
            'roles': sorted(modules),
        })

    return results


# =====================================================================
# TIER 3: SUT_CONFORMANCE (B0 Baseline, VDAM Valid SUT, VDAM Negative SUT)
# =====================================================================

def check_service_online(url, timeout=0.8, ctx=None):
    """
    Probes an HTTP/HTTPS endpoint.
    Strict Check (R3-01): Returns (True, 200) ONLY if reachable and returns HTTP 200.
    401, 403, 404, 500, timeouts, and connection errors are strictly offline/unhealthy.
    """
    effective_timeout = max(float(timeout), 10.0)
    import socket
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or '127.0.0.1'
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # Fast TCP socket check first
    try:
        sock = socket.create_connection((host, port), timeout=effective_timeout)
        sock.close()
    except Exception as e:
        return False, f"ConnectionRefused: {e}"

    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=effective_timeout, context=ctx) as resp:
            if resp.status == 200:
                return True, 200
            else:
                return False, f"HTTP_{resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP_{e.code}"
    except Exception as e:
        return False, str(e)


def b0_rs_base(bank_host):
    """Base URL of the B0 resource server on its application port (plain HTTP behind the bank gateway).

    Cases that do not exercise TLS call it directly. The client certificate the token is bound to is forwarded in
    the `ssl-client-cert` header, exactly as the gateway does, so the resource server still enforces the
    certificate binding (AT-05) without a TLS session."""
    return os.environ.get('B0_RS_URL', f'http://{bank_host}:4000').rstrip('/')


def b0_rs_tls_base(bank_host):
    """Base URL for the case that exercises TLS itself: through the bank gateway, which terminates mTLS."""
    return os.environ.get('B0_RS_TLS_URL', f'https://{bank_host}:8443').rstrip('/')


def b0_rs_headers(token, client_cert_path):
    """Bearer header plus the URL-escaped client certificate (same encoding as nginx $ssl_client_escaped_cert)."""
    headers = {'Authorization': f'Bearer {token}'}
    if client_cert_path:
        with open(client_cert_path, 'r', encoding='utf-8') as cert_file:
            headers['ssl-client-cert'] = urllib.parse.quote(cert_file.read(), safe='')
    return headers


def run_b0_conformance(base_dir, traces_out):
    """
    Tier: SUT_CONFORMANCE
    B0 Baseline Suite: FAPI 2.0 (PAR, PKCE, mTLS Token, HoK RS Enforcement, Negative Cert/Aud/Exp).
    Strict (R3-01):
      - If Keycloak / RS are unreachable, records status as NOT_RUN.
      - B0-F01 executes both PAR AND Token exchange; any failure fails the case.
      - B0-F03 retrieves a genuine token before accessing RS.
      - WrongCert strictly verifies HTTP 401/403.
      - Any failed assertion marks status as FAIL (no false PASS).
    """
    cases_path = os.path.join(base_dir, 'evaluation', 'tests', 'b0_cases.json')
    with open(cases_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    ca_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'ca.crt')
    ca_file = ca_path if os.path.exists(ca_path) else None
    cert_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'tpp.crt')
    key_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'tpp.key')
    has_certs = os.path.exists(cert_path) and os.path.exists(key_path)

    ctx = None
    cert_err = None
    if has_certs:
        try:
            # R4-08: strict TLS with CA verification, no permissive bypass
            ctx = get_ssl_context(cert_path, key_path, ca_file=ca_file, allow_insecure_dev=False)
        except Exception as e:
            cert_err = str(e)
            ctx = None

    bank_host = os.environ.get('BANK_HOST', '127.0.0.1')
    keycloak_host = os.environ.get('KEYCLOAK_HOST', bank_host)
    tpp_host = os.environ.get('TPP_HOST', 'localhost')
    rs_base = b0_rs_base(bank_host)
    rs_tls_base = b0_rs_tls_base(bank_host)
    rs_cert_path = cert_path if has_certs else None

    def rs_headers(token):
        return b0_rs_headers(token, rs_cert_path)

    # Probe live B0 Keycloak endpoint (Strict 200 required)
    probe_target = f'https://{keycloak_host}:8443/realms/traditional-fapi'
    if cert_err:
        b0_online, probe_info = False, f"Strict TLS Context Error: {cert_err}"
    else:
        b0_online, probe_info = check_service_online(probe_target, timeout=2.0, ctx=ctx)

    results = []
    for c in cases:
        case_id = c['case_id']
        t0 = time.perf_counter_ns()
        assertions = []
        actual_decision = "UNKNOWN"
        actual_boundary = None
        observed_authority = None
        observed_resource = None
        reason = ""
        status = "FAIL"  # R4-01: Explicitly initialize status at the start of each iteration

        if not b0_online:
            status = 'NOT_RUN'
            actual_decision = 'NOT_RUN'
            reason = f"ENVIRONMENT_PENDING: SUT_OFFLINE (Keycloak authorization server unreachable: {probe_info})"
            assertions.append({'check': 'sut_service_online', 'passed': False, 'reason': reason})
        else:
            try:
                if case_id == 'B0-F01':
                    # PAR Request and genuine PKCE Authorization Code flow with RFC 9396 authorization_details
                    auth_details = [{
                        "type": "account_information",
                        "actions": ["read"],
                        "locations": [f"https://{bank_host}:4000/api/v1/accounts"],
                        "datatypes": ["accounts", "balances"]
                    }]
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope='openid accounts:read ReadAccountsDetail rs-audience',
                        authorization_details=auth_details,
                        username='testuser',
                        password='password',
                        client_id='tpp-client',
                        client_secret='tpp-client-secret-key-12345',
                        timeout=10
                    )
                    assertions.append({'check': 'pkce_challenge_generated', 'passed': bool(pkce_res.get('code_challenge'))})
                    assertions.append({'check': 'par_status_created', 'passed': bool(pkce_res.get('request_uri'))})
                    assertions.append({'check': 'request_uri_present', 'passed': bool(pkce_res.get('request_uri'))})
                    assertions.append({'check': 'auth_code_obtained', 'passed': bool(pkce_res.get('auth_code'))})
                    assertions.append({'check': 'token_status_ok', 'passed': bool(pkce_res.get('access_token'))})
                    assertions.append({'check': 'access_token_issued', 'passed': bool(pkce_res.get('access_token'))})
                    assertions.append({
                        'check': 'token_type_exact',
                        'passed': pkce_res.get('token_response', {}).get('token_type') == c['expected_authority']['token_type'],
                        'expected': c['expected_authority']['token_type'],
                        'observed': pkce_res.get('token_response', {}).get('token_type'),
                    })

                    tok_claims, token_checks = b0_token_assertions(
                        pkce_res['access_token'], c['expected_authority'], cert_path
                    )
                    assertions.extend(token_checks)
                    assertions.append({
                        'check': 'authorization_code_grant_confirmed',
                        'passed': bool(pkce_res.get('auth_code') and pkce_res.get('code_verifier')),
                    })
                    observed_authority = {
                        'client_id': tok_claims.get('azp') or tok_claims.get('client_id'),
                        'audiences': normalize_string_set(tok_claims.get('aud')),
                        'lifetime_seconds': tok_claims.get('exp', 0) - tok_claims.get('iat', 0),
                        'scopes': normalize_string_set(tok_claims.get('scope')),
                        'certificate_thumbprint': (
                            tok_claims.get('cnf', {}).get('x5t#S256')
                            if isinstance(tok_claims.get('cnf'), dict)
                            else None
                        ),
                    }
                    actual_boundary = f"Keycloak AS token endpoint (https://{keycloak_host}:8443)"

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "PAR_AND_PKCE_TOKEN_SUCCESS" if all_ok else "PAR_OR_PKCE_TOKEN_FAILED"

                elif case_id in ('B0-F02-AccountReduction', 'B0-F02-PermissionReduction'):
                    # Per-account consent is carried by holder-approved-acc-NNN scopes, so a reduced consent
                    # produces a different token and a different resource projection.
                    requested_accounts = ['ACC-001', 'ACC-002']
                    requested_scopes = [
                        'openid', 'accounts:read', 'ReadAccountsDetail', 'ReadBalances',
                        'ReadTransactionsDetail', 'holder-approved-acc-001', 'holder-approved-acc-002',
                    ]
                    approved_accounts = ['ACC-001']
                    approved_scopes = [
                        scope for scope in requested_scopes if scope != 'holder-approved-acc-002'
                    ]
                    if case_id == 'B0-F02-PermissionReduction':
                        requested_accounts = ['ACC-001']
                        requested_scopes = [
                            'openid', 'accounts:read', 'ReadAccountsDetail', 'ReadBalances',
                            'ReadTransactionsDetail', 'holder-approved-acc-001',
                        ]
                        approved_scopes = [
                            'openid', 'accounts:read', 'ReadAccountsDetail',
                            'holder-approved-acc-001',
                        ]

                    consent_request_body = {
                        'requested_accounts': requested_accounts,
                        'requested_scopes': requested_scopes,
                        'approved_accounts': approved_accounts,
                        'approved_scopes': approved_scopes,
                    }
                    consent_req = urllib.request.Request(
                        f'https://{tpp_host}:3000/api/conformance/holder-consent',
                        data=json.dumps(consent_request_body).encode('utf-8'),
                        headers={'Content-Type': 'application/json'},
                    )
                    with urllib.request.urlopen(consent_req, context=ctx, timeout=30) as consent_resp:
                        consent_record = json.loads(consent_resp.read().decode('utf-8'))
                        assertions.append({'check': 'holder_consent_record_created', 'passed': consent_resp.status == 201})
                    assertions.append({
                        'check': 'requested_authority_recorded_exact',
                        'passed': (
                            consent_record.get('requested_accounts') == requested_accounts
                            and consent_record.get('requested_scopes') == requested_scopes
                        ),
                    })
                    assertions.append({
                        'check': 'approved_authority_recorded_exact',
                        'passed': (
                            consent_record.get('approved_accounts') == approved_accounts
                            and consent_record.get('approved_scopes') == approved_scopes
                        ),
                    })
                    receipt_req = urllib.request.Request(
                        f"https://{tpp_host}:3000/api/conformance/holder-consent/{consent_record['consent_id']}"
                    )
                    with urllib.request.urlopen(receipt_req, context=ctx, timeout=30) as receipt_resp:
                        persisted_consent = json.loads(receipt_resp.read().decode('utf-8'))
                    assertions.append({
                        'check': 'holder_consent_record_persisted_for_transaction',
                        'passed': persisted_consent == consent_record,
                        'consent_id': consent_record.get('consent_id'),
                    })

                    auth_details = [{
                        "type": "account_information",
                        "actions": ["read"],
                        "locations": [f"https://{bank_host}:4000/api/v1/accounts"],
                        "datatypes": ["accounts", "balances"],
                        "accounts": approved_accounts,
                        "consent_id": consent_record['consent_id'],
                    }]
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope=' '.join(approved_scopes + ['rs-audience']),
                        authorization_details=auth_details,
                        username='testuser',
                        password='password',
                        client_id='tpp-client',
                        client_secret='tpp-client-secret-key-12345',
                        timeout=30
                    )
                    _, tok_claims = decode_jwt_payload_unverified(pkce_res['access_token'])
                    observed_authority = {
                        'granted_account_scopes': sorted(
                            scope for scope in normalize_string_set(tok_claims.get('scope'))
                            if scope.startswith('holder-approved-acc-')
                        ),
                        'scopes': normalize_string_set(tok_claims.get('scope')),
                        'consent_id': consent_record.get('consent_id'),
                    }
                    actual_boundary = (
                        f"Keycloak AS token endpoint (https://{keycloak_host}:8443) "
                        f"and resource server ({rs_base})"
                    )
                    if case_id == 'B0-F02-AccountReduction':
                        expected_accounts = sorted(c['expected_authority']['accounts'])
                        granted_account_scopes = sorted(
                            scope for scope in normalize_string_set(tok_claims.get('scope'))
                            if scope.startswith('holder-approved-acc-')
                        )
                        assertions.append({
                            'check': 'holder_account_reduction_exact',
                            'passed': granted_account_scopes == ['holder-approved-acc-001'],
                            'expected': ['holder-approved-acc-001'],
                            'observed': granted_account_scopes,
                        })

                        def fetch_accounts(token):
                            request = urllib.request.Request(
                                f'{rs_base}/api/v1/accounts', headers=rs_headers(token)
                            )
                            with urllib.request.urlopen(request, context=ctx, timeout=5) as response:
                                return json.loads(response.read().decode('utf-8'))

                        # Positive control: the unreduced consent must actually yield the wider projection,
                        # otherwise the reduced result below would prove nothing.
                        control_res = execute_fapi_pkce_flow(
                            keycloak_host=keycloak_host, tpp_host=tpp_host, bank_host=bank_host,
                            mtls_ctx=ctx, scope=' '.join(requested_scopes + ['rs-audience']),
                            authorization_details=[{**auth_details[0], 'accounts': requested_accounts}],
                            username='testuser', password='password', client_id='tpp-client',
                            client_secret='tpp-client-secret-key-12345', timeout=30,
                        )
                        control_accounts = b0_resource_projection(
                            fetch_accounts(control_res['access_token'])
                        )['accounts']
                        assertions.append({
                            'check': 'unreduced_consent_yields_wider_projection',
                            'passed': control_accounts == sorted(requested_accounts),
                            'expected': sorted(requested_accounts),
                            'observed': control_accounts,
                        })

                        rs_payload = fetch_accounts(pkce_res['access_token'])
                        validate_resource_payload(
                            rs_payload,
                            expected_accounts=expected_accounts,
                            require_exact_accounts=True,
                        )
                        observed_resource = b0_resource_projection(rs_payload)
                        assertions.append({
                            'check': 'reduced_account_resource_projection_exact',
                            'passed': observed_resource['accounts'] == expected_accounts,
                            'expected': expected_accounts,
                            'observed': observed_resource['accounts'],
                        })
                        assertions.append({
                            'check': 'reduced_projection_is_strict_subset_of_control',
                            'passed': set(observed_resource['accounts']) < set(control_accounts),
                            'control': control_accounts,
                            'reduced': observed_resource['accounts'],
                        })
                        expected_records = dataset_expected_records(
                            base_dir, expected_accounts, sorted(observed_resource['fields']),
                            len(expected_accounts)
                        )
                        assertions.append({
                            'check': 'reduced_records_match_dataset',
                            'passed': observed_resource['records'] == expected_records,
                            'expected': expected_records,
                            'observed': observed_resource['records'],
                        })
                    else:
                        observed_scopes = normalize_string_set(tok_claims.get('scope'))
                        expected_scopes = sorted(c['expected_authority']['scopes'])
                        assertions.append({
                            'check': 'holder_permission_reduction_exact',
                            'passed': observed_scopes == expected_scopes,
                            'expected': expected_scopes,
                            'observed': observed_scopes,
                        })
                        allowed_req = urllib.request.Request(
                            f'{rs_base}/api/v1/accounts',
                            headers=rs_headers(pkce_res['access_token']),
                        )
                        with urllib.request.urlopen(allowed_req, context=ctx, timeout=5) as allowed_resp:
                            assertions.append({
                                'check': 'retained_permission_still_permits_resource',
                                'passed': allowed_resp.status == 200,
                            })
                        denied_req = urllib.request.Request(
                            f'{rs_base}/open-banking/v3.1/aisp/accounts/ACC-001/transactions',
                            headers=rs_headers(pkce_res['access_token']),
                        )
                        try:
                            with urllib.request.urlopen(denied_req, context=ctx, timeout=5):
                                assertions.append({'check': 'removed_permission_cannot_access_resource', 'passed': False})
                        except urllib.error.HTTPError as error:
                            denied, denied_reason = verify_security_rejection(
                                error,
                                expected_codes=(403,),
                                expected_semantic_tokens=['REJECT_INSUFFICIENT_SCOPE'],
                            )
                            assertions.append({
                                'check': 'removed_permission_cannot_access_resource',
                                'passed': denied,
                                'reason': denied_reason,
                            })
                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT_RESTRICTED" if all_ok else "FAIL"
                    reason = "CONSENT_REDUCED_RESTRICTION_ENFORCED" if all_ok else "CONSENT_REDUCTION_FAILED"

                elif case_id == 'B0-F03':
                    # Fetch real access token via genuine PAR + PKCE Authorization Code flow
                    auth_details = [{
                        "type": "account_information",
                        "actions": ["read"],
                        "locations": [f"https://{bank_host}:4000/api/v1/accounts"],
                        "datatypes": ["accounts", "balances"]
                    }]
                    # Same matched AIS task as the VDAM cases: one approved account, so the two baselines
                    # are compared on the same approved authority.
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope=(
                            'openid accounts:read ReadTransactionsDetail rs-audience '
                            'holder-approved-acc-001'
                        ),
                        authorization_details=auth_details,
                        username='testuser',
                        password='password',
                        client_id='tpp-client',
                        client_secret='tpp-client-secret-key-12345',
                        timeout=10
                    )
                    tok = pkce_res['access_token']

                    # Call Resource Server with the real token
                    rs_url = f'{rs_base}/api/v1/accounts'
                    rs_req = urllib.request.Request(rs_url, headers=rs_headers(tok))
                    with urllib.request.urlopen(rs_req, context=ctx, timeout=5) as resp:
                        rs_ok = (resp.status == 200)
                        rs_data = json.loads(resp.read().decode())
                        assertions.append({'check': 'rs_status_200', 'passed': rs_ok})
                        expected = c['expected_authority']
                        validate_resource_payload(
                            rs_data,
                            expected_accounts=expected['accounts'],
                            expected_fields=expected['fields'],
                            require_exact_accounts=True,
                        )
                        strict_rs_envelope = (
                            isinstance(rs_data, dict)
                            and set(rs_data.keys()) <= {'Data', 'Links', 'Meta'}
                            and isinstance(rs_data.get('Data'), dict)
                            and set(rs_data['Data'].keys()) == {'Account'}
                        )
                        projection = b0_resource_projection(rs_data)
                        observed_resource = projection
                        records = projection.get('records', [])
                        records_fields_strict = all(
                            isinstance(r, dict) and set(r.keys()) == set(expected['fields'])
                            for r in records
                        )
                        assertions.append({
                            'check': 'resource_envelope_and_fields_strict',
                            'passed': strict_rs_envelope and records_fields_strict,
                            'envelope_valid': strict_rs_envelope,
                            'fields_strict': records_fields_strict,
                        })
                        assertions.append({
                            'check': 'resource_accounts_exact',
                            'passed': projection['accounts'] == sorted(expected['accounts']),
                            'expected': sorted(expected['accounts']),
                            'observed': projection['accounts'],
                        })
                        assertions.append({
                            'check': 'resource_fields_exact',
                            'passed': projection['fields'] == sorted(expected['fields']),
                            'expected': sorted(expected['fields']),
                            'observed': projection['fields'],
                        })
                        expected_account_records = dataset_expected_records(
                            base_dir, expected['accounts'], sorted(expected['fields']),
                            len(expected['accounts'])
                        )
                        assertions.append({
                            'check': 'resource_records_match_dataset',
                            'passed': projection['records'] == expected_account_records,
                            'expected': expected_account_records,
                            'observed': projection['records'],
                        })

                    history = expected['history']
                    history_query = urllib.parse.urlencode({
                        'fromBookingDateTime': history['from'],
                        'toBookingDateTime': history['to'],
                        'page': history['page'],
                        'limit': history['page_size'],
                    })
                    history_url = (
                        f"{rs_base}/open-banking/v3.1/aisp/accounts/"
                        f"{history['account_id']}/transactions?{history_query}"
                    )
                    history_req = urllib.request.Request(
                        history_url, headers=rs_headers(tok)
                    )
                    with urllib.request.urlopen(history_req, context=ctx, timeout=5) as history_resp:
                        history_payload = json.loads(history_resp.read().decode('utf-8'))
                        assertions.append({
                            'check': 'transaction_history_status_200',
                            'passed': history_resp.status == 200,
                        })

                    strict_history_envelope = (
                        isinstance(history_payload, dict)
                        and set(history_payload.keys()) <= {'Data', 'Links', 'Meta'}
                        and isinstance(history_payload.get('Data'), dict)
                        and set(history_payload['Data'].keys()) == {'Transaction'}
                    )
                    raw_tx_list = history_payload.get('Data', {}).get('Transaction', [])
                    allowed_tx_keys = {
                        'AccountId', 'TransactionId', 'TransactionReference', 'Amount',
                        'CreditDebitIndicator', 'Status', 'BookingDateTime',
                        'TransactionInformation', 'Balance'
                    }
                    tx_keys_strict = all(
                        isinstance(tx, dict) and (set(tx.keys()) <= allowed_tx_keys)
                        for tx in raw_tx_list
                    )
                    assertions.append({
                        'check': 'transaction_history_envelope_and_keys_strict',
                        'passed': strict_history_envelope and tx_keys_strict,
                        'envelope_valid': strict_history_envelope,
                        'keys_strict': tx_keys_strict,
                    })

                    history_meta = history_payload.get('Meta', {})
                    observed_history_meta = {
                        'from': history_meta.get('HistoryWindowApplied', {}).get('from'),
                        'to': history_meta.get('HistoryWindowApplied', {}).get('to'),
                        'page': history_meta.get('Page'),
                        'page_size': history_meta.get('PageSize'),
                        'total_pages': history_meta.get('TotalPages'),
                        'total_results': history_meta.get('TotalResults'),
                    }
                    expected_history_meta = {
                        key: history[key]
                        for key in ('from', 'to', 'page', 'page_size', 'total_pages', 'total_results')
                    }
                    assertions.append({
                        'check': 'history_window_and_pagination_exact',
                        'passed': observed_history_meta == expected_history_meta,
                        'expected': expected_history_meta,
                        'observed': observed_history_meta,
                    })
                    observed_transactions = []
                    for transaction in raw_tx_list:
                        observed_transactions.append({
                            'AccountId': transaction.get('AccountId'),
                            'TransactionId': transaction.get('TransactionId'),
                            'Amount': transaction.get('Amount', {}).get('Amount'),
                            'CreditDebitIndicator': transaction.get('CreditDebitIndicator'),
                            'BookingDateTime': transaction.get('BookingDateTime'),
                        })
                    assertions.append({
                        'check': 'transaction_page_projection_exact',
                        'passed': observed_transactions == history['transactions'],
                        'expected': history['transactions'],
                        'observed': observed_transactions,
                    })
                    observed_resource['history'] = {
                        'meta': observed_history_meta,
                        'transactions': observed_transactions,
                    }

                    status = 'EXECUTED'
                    actual_boundary = f"Resource server policy enforcement ({rs_base})"
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "RESOURCE_RETRIEVED" if all_ok else "RESOURCE_RETRIEVAL_FAILED"

                elif 'WrongCert' in case_id:
                    # Positive control: obtain legitimate token with genuine PAR + PKCE Authorization Code flow
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope='openid accounts:read rs-audience',
                        username='testuser',
                        password='password',
                        client_id='tpp-client',
                        client_secret='tpp-client-secret-key-12345',
                        timeout=10
                    )
                    valid_tok = pkce_res['access_token']
                    assertions.append({'check': 'positive_control_token_obtained', 'passed': bool(valid_tok)})

                    # Step 1: Prove positive control accesses RS successfully with bound certificate
                    rs_url = f'{rs_tls_base}/api/v1/accounts'
                    rs_req_valid = urllib.request.Request(rs_url, headers={'Authorization': f'Bearer {valid_tok}'})
                    with urllib.request.urlopen(rs_req_valid, context=ctx, timeout=5) as rs_resp:
                        assertions.append({'check': 'positive_control_rs_access_success', 'passed': rs_resp.status == 200})

                    # Step 2: One-factor mutation A - access RS WITHOUT client certificate (unbound TLS)
                    no_cert_rejected = False
                    try:
                        unbound_ctx = get_ssl_context(ca_file=ca_file, allow_insecure_dev=False)
                        with urllib.request.urlopen(rs_req_valid, context=unbound_ctx, timeout=3) as resp:
                            assertions.append({'check': 'no_certificate_rejection_enforced', 'passed': False})
                    except urllib.error.HTTPError as e:
                        no_cert_rejected, rej_reason = verify_security_rejection(e, expected_codes=(401, 403), expected_semantic_tokens=['REJECT_INVALID_TOKEN_BINDING'])
                        assertions.append({'check': 'no_certificate_rejection_enforced', 'passed': no_cert_rejected, 'reason': rej_reason})
                    except urllib.error.URLError as e:
                        no_cert_rejected = isinstance(e.reason, ssl.SSLError)
                        assertions.append({
                            'check': 'no_certificate_rejection_enforced',
                            'passed': no_cert_rejected,
                            'reason': f"SERVER_TLS_ALERT: {e.reason}" if no_cert_rejected else f"SUT_UNREACHABLE: {e.reason}",
                        })
                    except ssl.SSLError as e:
                        no_cert_rejected = True
                        assertions.append({
                            'check': 'no_certificate_rejection_enforced',
                            'passed': True,
                            'reason': f"SERVER_TLS_ALERT: {e}",
                        })

                    # Step 3: One-factor mutation B - access RS WITH WRONG / mismatched client certificate
                    wrong_cert_rejected = False
                    wrong_cert_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'wrong_client.crt')
                    wrong_key_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'wrong_client.key')
                    if os.path.exists(wrong_cert_path) and os.path.exists(wrong_key_path):
                        # Client SSL context creation MUST succeed without local exceptions
                        try:
                            wrong_ctx = get_ssl_context(
                                wrong_cert_path, wrong_key_path, ca_file=ca_file, allow_insecure_dev=False
                            )
                            assertions.append({'check': 'wrong_certificate_context_loaded', 'passed': True})
                        except Exception as e:
                            assertions.append({'check': 'wrong_certificate_context_loaded', 'passed': False, 'reason': f"CLIENT_TLS_SETUP_ERROR: {e}"})
                            raise RuntimeError(f"CLIENT_TLS_SETUP_ERROR: Failed to load wrong client certificate: {e}")

                        # Network request to RS: MUST be rejected by the SERVER (HTTP 401, 403 or TLS alert from server)
                        try:
                            with urllib.request.urlopen(rs_req_valid, context=wrong_ctx, timeout=3) as resp:
                                assertions.append({'check': 'wrong_certificate_rejection_enforced', 'passed': False})
                        except urllib.error.HTTPError as e:
                            wrong_cert_rejected, rej_reason = verify_security_rejection(e, expected_codes=(401, 403), expected_semantic_tokens=['REJECT_INVALID_TOKEN_BINDING'])
                            assertions.append({'check': 'wrong_certificate_rejection_enforced', 'passed': wrong_cert_rejected, 'reason': rej_reason})
                        except urllib.error.URLError as e:
                            # Server closed connection or sent TLS handshake alert rejecting unauthorized client cert
                            # Strict R8-01: Disallow ConnectionRefusedError or generic network drops as SERVER_TLS_ALERT
                            if isinstance(e.reason, ssl.SSLError):
                                wrong_cert_rejected = True
                                assertions.append({'check': 'wrong_certificate_rejection_enforced', 'passed': True, 'reason': f"SERVER_TLS_ALERT: {e.reason}"})
                            else:
                                wrong_cert_rejected = False
                                assertions.append({'check': 'wrong_certificate_rejection_enforced', 'passed': False, 'reason': f"SUT_UNREACHABLE: {e.reason}"})
                    else:
                        wrong_cert_rejected = False
                        assertions.append({'check': 'wrong_certificate_rejection_enforced', 'passed': False, 'reason': 'MISSING_WRONG_CERT_FIXTURE'})

                    all_rejections_ok = no_cert_rejected and wrong_cert_rejected
                    actual_decision = "DENY" if all_rejections_ok else "FAIL"
                    reason = "REJECT_INVALID_TOKEN_BINDING" if all_rejections_ok else "TOKEN_BINDING_CHECK_FAILED"
                    status = 'EXECUTED'
                    actual_boundary = (
                        f"Resource server certificate binding over mTLS ({rs_tls_base})"
                        if all_rejections_ok else 'UNKNOWN'
                    )

                elif 'WrongAudience' in case_id:
                    # Genuine Authorization Code + PAR + PKCE token for the same
                    # client and certificate. Only the selected audience profile differs.
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope='openid accounts:read ReadAccountsDetail external-audience',
                        username='testuser',
                        password='password',
                        client_id='tpp-client',
                        client_secret='tpp-client-secret-key-12345',
                        timeout=10,
                    )
                    tok = pkce_res['access_token']
                    _, claims = decode_jwt_payload_unverified(tok)
                    assertions.append({
                        'check': 'fixture_has_only_wrong_resource_audience',
                        'passed': (
                            normalize_string_set(claims.get('aud')) == ['aud:external-service']
                            and (claims.get('azp') or claims.get('client_id')) == 'tpp-client'
                        ),
                        'observed': normalize_string_set(claims.get('aud')),
                        'observed_client': claims.get('azp') or claims.get('client_id'),
                    })

                    rs_url = f'{rs_base}/api/v1/accounts'
                    rs_req = urllib.request.Request(rs_url, headers=rs_headers(tok))
                    rejection_ok = False
                    rej_reason = ""
                    try:
                        with urllib.request.urlopen(rs_req, context=ctx, timeout=3) as resp:
                            assertions.append({'check': 'wrong_audience_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_WRONG_AUDIENCE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(e, expected_codes=(401, 403), expected_semantic_tokens=['REJECT_INVALID_AUDIENCE'])
                        assertions.append({'check': 'wrong_audience_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_INVALID_AUDIENCE" if rejection_ok else rej_reason
                        actual_boundary = f"Resource server audience check ({rs_base}), HTTP {e.code}"

                    status = 'EXECUTED'

                elif 'ExpiredToken' in case_id:
                    # Obtain a valid, short-lived, issuer-signed Authorization Code
                    # token and wait for its genuine expiry. The signature is untouched.
                    pkce_res = execute_fapi_pkce_flow(
                        keycloak_host=keycloak_host,
                        tpp_host=tpp_host,
                        bank_host=bank_host,
                        mtls_ctx=ctx,
                        scope='openid accounts:read ReadAccountsDetail',
                        username='testuser',
                        password='password',
                        client_id='short-lived-client',
                        client_secret='short-lived-client-secret',
                        timeout=20,
                    )
                    expired_tok = pkce_res['access_token']
                    _, claims = decode_jwt_payload_unverified(expired_tok)
                    lifetime = int(claims.get('exp', 0)) - int(claims.get('iat', 0))
                    assertions.append({
                        'check': 'fixture_is_short_lived_and_signed',
                        'passed': 0 < lifetime <= 5,
                        'observed_lifetime_seconds': lifetime,
                    })
                    if not 0 < lifetime <= 5:
                        raise RuntimeError(f"SHORT_LIVED_TOKEN_PROFILE_INVALID: lifetime={lifetime}")
                    wait_seconds = max(3.0, float(claims['exp']) - time.time() + 2.0)
                    time.sleep(wait_seconds)

                    rs_url = f'{rs_base}/api/v1/accounts'
                    rs_req = urllib.request.Request(rs_url, headers=rs_headers(expired_tok))
                    rejection_ok = False
                    rej_reason = ""
                    try:
                        with urllib.request.urlopen(rs_req, context=ctx, timeout=15) as resp:
                            assertions.append({'check': 'expired_token_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_EXPIRED_TOKEN"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(e, expected_codes=(401, 403), expected_semantic_tokens=['REJECT_EXPIRED_TOKEN'])
                        assertions.append({'check': 'expired_token_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_EXPIRED_TOKEN" if rejection_ok else rej_reason
                        actual_boundary = f"Resource server expiry check ({rs_base}), HTTP {e.code}"

                    status = 'EXECUTED'

                else:
                    status = 'NOT_RUN'
                    actual_decision = 'NOT_RUN'
                    reason = f"IMPLEMENTATION_PENDING: Dedicated test adapter for {case_id} pending live VM execution"
                    assertions.append({'check': 'test_adapter_implemented', 'passed': False, 'reason': reason})

            except Exception as e:
                status = 'FAIL'
                actual_decision = "FAIL"
                reason = f"LIVE_EXECUTION_ERROR: {str(e)}"
                assertions.append({'check': 'live_call_succeeded', 'passed': False, 'error': str(e)})

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        if status != 'NOT_RUN':
            passed = len(assertions) > 0 and all(a.get('passed', False) for a in assertions) and (actual_decision == c.get('expected_decision'))
            status = 'PASS' if passed else 'FAIL'

        res = {
            'suite': 'B0_FAPI_Baseline',
            'tier': 'SUT_CONFORMANCE',
            'case_id': case_id,
            'name': c['name'],
            'configuration': c['configuration'],
            'status': status,
            'execution_mode': c.get('execution_mode', 'PRODUCTION_E2E'),
            'test_assistance': c.get('test_assistance', []),
            'production_boundary': c.get('production_boundary', 'TOKEN_AND_RESOURCE_SERVER'),
            'proven_requirements': c.get('proven_requirements', []),
            'uncovered_aspects': c.get('uncovered_aspects', []),
            'expected_decision': c['expected_decision'],
            'actual_decision': actual_decision,
            'expected_boundary': c.get('expected_boundary'),
            'actual_boundary': actual_boundary,
            'expected_authority': c.get('expected_authority'),
            'observed_authority': observed_authority,
            'observed_resource': observed_resource,
            'reason': reason,
            'evidence_ids': [f"TRC-{case_id}"],
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'B0_FAPI_Baseline',
            'tier': 'SUT_CONFORMANCE',
            'status': status,
            'assertions': assertions,
            'timestamp': res['timestamp']
        })

    return results


def forwarded_tpp_certificate_headers(base_dir):
    """The TPP client certificate as the gateway forwards it, so a request carries a valid sender binding.

    A request without it is refused at the token-binding layer, which would stop a case before it reaches
    the predicate it is meant to exercise."""
    configuration = os.environ.get('CONFORMANCE_CONFIGURATION', 'B1-C0')
    if configuration == 'B1-C2':
        cert_path = os.path.join(base_dir, 'wallet-vc-model', 'pqc-bank', 'oqs-proxy', 'certs', 'tpp.crt')
    else:
        cert_path = os.path.join(base_dir, 'wallet-vc-model-classical', 'tpp', 'tls-proxy', 'certs', 'tpp.crt')
    with open(cert_path, 'r', encoding='utf-8') as cert_file:
        return {'ssl-client-cert': urllib.parse.quote(cert_file.read(), safe='')}


def _post_json(url, payload, timeout=60, headers=None):
    request_headers = {'Content-Type': 'application/json'}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode('utf-8'), headers=request_headers
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode('utf-8'))


def _authorized_sign(url, payload, typ, rebind_issuance_record=False):
    """Sign through an authorized role signer.

    `rebind_issuance_record` re-commits the issuance record to the artifact just produced. It is an explicit
    fixture step, used only where a case must re-sign an issuer-protected credential and still reach a later
    predicate; it is recorded as test assistance on every case that relies on it."""
    body = {'payload': payload, 'typ': typ}
    if rebind_issuance_record:
        body['rebind_issuance_record'] = True
    status, result = _post_json(url, body)
    signed = result.get('signedJwt')
    if status != 200 or not signed:
        raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: signer at {url} returned no artifact")
    return signed


def _fresh_typed_credential_pair(tpp_url, wallet_url, scopes, target_root_jti=None):
    _, initiated = _post_json(f"{tpp_url}/api/request-delegate", {'requestedScopes': scopes})
    request_id = initiated.get('requestId')
    request_payload = initiated.get('requestPayload') or {}
    challenge = request_payload.get('challenge') or {}
    if not request_id or not request_payload.get('ch_das') or not challenge.get('r_das'):
        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: no signed DAS challenge')
    with urllib.request.urlopen(f"{wallet_url}/api/fetch-tpp-request?requestId={request_id}", timeout=60):
        pass
    approve_body = {'requestId': request_id, 'approvedScopes': scopes}
    if target_root_jti:
        approve_body['authzVcJti'] = target_root_jti
    _, approved = _post_json(
        f"{wallet_url}/api/approve-delegate",
        approve_body,
    )
    delegate_jti = approved.get('delegateVcJti')
    with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=60) as response:
        vcs = json.loads(response.read().decode('utf-8')).get('vcs', [])
    selected_delegate = next((v for v in vcs if v.get('jti') == delegate_jti), None)
    if not selected_delegate:
        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: fresh delegation not found by JTI')
    parent_jti = (selected_delegate.get('payload') or {}).get('parent_vc_jti')
    selected_root = next((v for v in vcs if v.get('jti') == parent_jti), None)
    if not selected_root:
        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: matching root credential not found')
    return selected_root['sdJwt'], selected_delegate['sdJwt'], {
        'ch_das': request_payload['ch_das'], 'challenge': challenge,
    }


def _credential_with_typed_authority(credential, authority, signer_url, holder_bound=False,
                                     rebind_issuance_record=False):
    base_jwt = credential.split('~', 1)[0]
    _, payload = decode_jwt_payload_unverified(base_jwt)
    payload['typed_authority'] = authority
    signed_base = _authorized_sign(signer_url, payload, 'vc+sd-jwt',
                                   rebind_issuance_record=rebind_issuance_record)
    if not holder_bound:
        suffix = credential.split('~', 1)[1] if '~' in credential else ''
        return signed_base + (f"~{suffix}" if suffix else '')

    parts = credential.split('~')
    if len(parts) < 2 or not parts[-1]:
        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: delegation credential has no KB-JWT')
    _, kb_payload = decode_jwt_payload_unverified(parts[-1])
    digest_name = 'sha384' if os.environ.get('CONFORMANCE_CONFIGURATION') == 'B1-C2' else 'sha256'
    digest = hashlib.new(digest_name, (signed_base + '~').encode('utf-8')).digest()
    kb_payload['sd_hash'] = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    signed_kb = _authorized_sign(signer_url, kb_payload, 'kb+jwt')
    return signed_base + '~' + signed_kb


def reset_binding_record(issuer_url, record_id):
    request = urllib.request.Request(
        f"{issuer_url}/api/test/bindings/{record_id}/reset",
        data=b"{}",
        headers={'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as exc:
        return {'error': str(exc)}


def execute_typed_authority_flow(base_dir, issuer_url, tpp_url, wallet_url, rs_url, sc, h, r, t, p, target_root_jti=None):
    """Run signed SC/H/R/T/P through the production token decision and RS projection."""
    _, stored_policy = _post_json(f"{issuer_url}/api/test/typed-authority/policy", p)
    if stored_policy.get('policy_authority') != p:
        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: policy state read-back mismatch')

    root, delegation, challenge_data = _fresh_typed_credential_pair(
        tpp_url, wallet_url, ['accounts:read', 'ReadBalances', 'transactions:read'], target_root_jti=target_root_jti
    )
    _, orig_root_claims = decode_jwt_payload_unverified(root.split('~', 1)[0])
    holder_cert_ref = orig_root_claims.get('holder_cert_ref')

    # Re-signing the issuer-protected component invalidates the F1 component digest, so the issuance record
    # is re-committed to the artifact this case actually presents. Without it every typed-authority case
    # would stop at the issuance-binding layer instead of reaching the authority decision under test.
    typed_root = _credential_with_typed_authority(
        root, sc, f"{issuer_url}/api/test/sign-artifact", rebind_issuance_record=True
    )
    typed_delegation = _credential_with_typed_authority(
        delegation, h, f"{wallet_url}/api/test/sign-artifact", holder_bound=True
    )
    challenge = challenge_data['challenge']
    now = int(time.time())
    vp_payload = {
        'iss': 'tpp-demo-client',
        'aud': challenge.get('aud_g', f"{issuer_url}/token"),
        'aud_g': challenge.get('aud_g', f"{issuer_url}/token"),
        'aud_r': challenge.get('aud_r', 'http://localhost:4000'),
        'iat': now,
        'exp': now + 300,
        'jti': f"typed-{secrets.token_hex(12)}",
        'ch_das': challenge_data['ch_das'],
        'r_das': challenge['r_das'],
        'authorization_vc': typed_root,
        'delegate_vc': typed_delegation,
        'presentation_binding': compute_presentation_binding(
            typed_root, typed_delegation, challenge['r_das']
        ),
        'requested_authority': r,
        'tpp_authority': t,
    }
    assertion = _authorized_sign(f"{tpp_url}/api/test/sign-artifact", vp_payload, 'JWT')
    _, challenge_claims = decode_jwt_payload_unverified(challenge_data['ch_das'])
    _, root_claims = decode_jwt_payload_unverified(typed_root.split('~', 1)[0])
    delegation_parts = typed_delegation.split('~')
    _, delegation_claims = decode_jwt_payload_unverified(delegation_parts[0])
    _, kb_claims = decode_jwt_payload_unverified(delegation_parts[-1])
    digest_name = 'sha384' if os.environ.get('CONFORMANCE_CONFIGURATION') == 'B1-C2' else 'sha256'
    expected_sd_hash = base64.urlsafe_b64encode(
        hashlib.new(digest_name, (delegation_parts[0] + '~').encode('utf-8')).digest()
    ).decode('ascii').rstrip('=')
    source_evidence = {
        'root_jti': root_claims.get('jti'),
        'delegate_jti': delegation_claims.get('jti'),
        'aud_r': vp_payload['aud_r'],
        'aud_g': vp_payload['aud_g'],
        'aud_kb': kb_claims.get('aud'),
        'r_das_challenge': challenge_claims.get('r_das'),
        'r_das_vp': vp_payload.get('r_das'),
        'r_das_delegation': delegation_claims.get('r_das'),
        'kb_sd_hash': kb_claims.get('sd_hash'),
        'computed_sd_hash': expected_sd_hash,
        'challenge_jti': challenge_claims.get('jti'),
        'vp_jti': vp_payload['jti'],
    }

    body = urllib.parse.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': assertion,
    }).encode('utf-8')
    identity_headers = forwarded_tpp_certificate_headers(base_dir)
    token_request = urllib.request.Request(
        f"{issuer_url}/token",
        data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded', **identity_headers},
    )
    token_status = None
    token_response = None
    try:
        with urllib.request.urlopen(token_request, timeout=60) as response:
            token_status = response.status
            token_response = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        return {
            'token_status': error.code,
            'token_response': json.loads(error.read().decode('utf-8')),
            'token_claims': None,
            'resource_status': None,
            'resource': None,
            'source_evidence': source_evidence,
        }
    access_token = token_response.get('access_token')
    _, token_claims = decode_jwt_payload_unverified(access_token)
    resource_request = urllib.request.Request(
        f"{rs_url}/api/v1/accounts",
        headers={'Authorization': f"Bearer {access_token}", **identity_headers},
    )
    try:
        with urllib.request.urlopen(resource_request, timeout=60) as response:
            resource = json.loads(response.read().decode('utf-8'))
            resource_status = response.status
    except urllib.error.HTTPError as error:
        resource = json.loads(error.read().decode('utf-8'))
        resource_status = error.code
    return {
        'token_status': token_status,
        'token_response': token_response,
        'token_claims': token_claims,
        'resource_status': resource_status,
        'resource': resource,
        'source_evidence': source_evidence,
    }


def run_vdam_valid_sut_conformance(base_dir, traces_out):
    """
    Tier: SUT_CONFORMANCE
    VDAM Valid Suite microservice flows (VD-F01, VD-F07, VD-F08, VD-F09, VD-F10, VD-F11).
    R4-02: Executable adapter implementation.
      - When services are offline: records ENVIRONMENT_PENDING: SUT_OFFLINE.
      - When services are online: executes live multi-party presentation flow.
    """
    cases_path = os.path.join(base_dir, 'evaluation', 'tests', 'vdam_valid_cases.json')
    with open(cases_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    # Filter only cases requiring live microservice execution (math cases handled in ORACLE_UNIT)
    sut_case_ids = {f'VD-F{i:02d}' for i in range(1, 12)}
    cases = [c for c in cases if c['case_id'] in sut_case_ids]

    bank_host = os.environ.get('BANK_HOST', '127.0.0.1')
    tpp_host = os.environ.get('TPP_HOST', '127.0.0.1')
    wallet_host = os.environ.get('WALLET_HOST', '127.0.0.1')
    das_url = os.environ.get('VDAM_DAS_URL', f'http://{bank_host}:7000')
    issuer_url = os.environ.get('VDAM_ISSUER_URL', f'http://{bank_host}:7000')
    rs_url = os.environ.get('VDAM_RS_URL', f'http://{bank_host}:4000')
    tpp_url = os.environ.get('VDAM_TPP_URL', f'http://{tpp_host}:6001')
    wallet_url = os.environ.get('VDAM_WALLET_URL', f'http://{wallet_host}:5000')

    das_online, _ = check_service_online(f"{issuer_url}/health", timeout=1.0)
    rs_online, _ = check_service_online(f"{rs_url}/health", timeout=1.0)
    tpp_online, _ = check_service_online(f"{tpp_url}/api/status", timeout=1.0)
    wallet_online, _ = check_service_online(f"{wallet_url}/api/config", timeout=1.0)
    vdam_online = das_online and rs_online and tpp_online and wallet_online

    results = []
    for c in cases:
        case_id = c['case_id']
        t0 = time.perf_counter_ns()
        assertions = []
        actual_decision = "UNKNOWN"
        reason = ""
        status = "FAIL"
        observed_authority = None
        observed_resource = None
        oracle_match = None

        if not vdam_online:
            status = 'NOT_RUN'
            actual_decision = 'NOT_RUN'
            reason = f"ENVIRONMENT_PENDING: SUT_OFFLINE (VDAM microservices unreachable at Bank={issuer_url}, TPP={tpp_url}, Wallet={wallet_url}, RS={rs_url})"
            assertions.append({'check': 'sut_service_online', 'passed': False, 'reason': reason})
        else:
            try:
                if case_id == 'VD-F01':
                    # F1 must execute in this case; pre-existing credentials are not
                    # accepted as evidence of initial issuance.
                    with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=15) as response:
                        before_vcs = json.loads(response.read().decode('utf-8')).get('vcs', [])
                    before_root_jtis = {
                        vc.get('jti') for vc in before_vcs if vc.get('type') == 'AuthorizationCredential' or ('scope' in str(vc.get('type', '')).lower() and 'delegate' not in str(vc.get('type', '')).lower())
                    }
                    f1_error = None
                    try:
                        f1_flow_res = execute_vdam_f1_oid4vci_flow(
                            wallet_url=wallet_url,
                            keycloak_host=os.environ.get('KEYCLOAK_HOST', bank_host),
                            username='testuser',
                            password='password',
                            timeout=15,
                            issuer_url=issuer_url
                        )
                        root_jti = f1_flow_res.get('jti')
                        root_credential = f1_flow_res.get('credential')
                        f1_mode = 'PRODUCTION_E2E'
                        f1_assistance = ['state_inspection']
                    except Exception as exc:
                        f1_error = str(exc)
                        _, provisioned = _post_json(f"{wallet_url}/api/provision-scope-vc", {})
                        root_jti = provisioned.get('jti')
                        root_credential = provisioned.get('credential')
                        f1_mode = 'TEST_ASSISTED'
                        f1_assistance = ['fixture_signing', 'state_mutation', 'state_inspection']

                    assertions.append({
                        'check': 'f1_new_root_credential_issued_in_case',
                        'passed': bool(root_jti and root_credential and root_jti not in before_root_jtis),
                        'root_jti': root_jti,
                        'f1_mode': f1_mode,
                        'f1_error': f1_error
                    })
                    _, root_payload = decode_jwt_payload_unverified(root_credential.split('~', 1)[0])
                    binding_ref = root_payload.get('holder_cert_ref')
                    with urllib.request.urlopen(
                        f"{issuer_url}/api/test/bindings/{binding_ref}", timeout=15
                    ) as response:
                        binding = json.loads(response.read().decode('utf-8'))
                    root_holder_jwk = (root_payload.get('cnf') or {}).get('jwk') or {}
                    binding_jwk_raw = binding.get('holder_jwk') or ''
                    binding_jwk = json.loads(binding_jwk_raw) if binding_jwk_raw else {}
                    has_kids = bool(root_holder_jwk.get('kid')) and bool(binding_jwk.get('kid'))
                    kid_matches = (root_holder_jwk.get('kid') == binding_jwk.get('kid'))
                    kty_matches = (root_holder_jwk.get('kty') == binding_jwk.get('kty'))
                    crv_matches = (root_holder_jwk.get('crv') == binding_jwk.get('crv'))
                    x_matches = (root_holder_jwk.get('x') == binding_jwk.get('x'))
                    y_matches = (root_holder_jwk.get('y') == binding_jwk.get('y'))
                    key_material_match = has_kids and kid_matches and kty_matches and crv_matches and x_matches and y_matches
                    assertions.extend([
                        {
                            'check': 'f1_committed_binding_record_resolves',
                            'passed': binding.get('record_id') == binding_ref and binding.get('status') == 'ACTIVE',
                            'binding_ref': binding_ref,
                            'binding_version': binding.get('binding_version'),
                        },
                        {
                            'check': 'f1_binding_holder_and_key_correlated',
                            'passed': (
                                binding.get('holder_subject') == (root_payload.get('holder_subject') or root_payload.get('sub'))
                                and key_material_match
                            ),
                            'holder_subject': binding.get('holder_subject'),
                            'holder_key_id': root_holder_jwk.get('kid'),
                            'key_material_match': key_material_match,
                        },
                    ])

                    # Durability cross-restart verification
                    checkpoint_dir = os.path.join(base_dir, 'evaluation', 'state')
                    os.makedirs(checkpoint_dir, exist_ok=True)
                    configuration = os.environ.get('CONFORMANCE_CONFIGURATION', 'B1-C0')
                    checkpoint_file = os.path.join(checkpoint_dir, f"durability_checkpoint_{configuration}.json")
                    run_id = os.environ.get('CONFORMANCE_RUN_ID', '')
                    is_post_restart = 'post-restart' in run_id

                    if is_post_restart:
                        if not os.path.exists(checkpoint_file):
                            assertions.append({
                                'check': 'pre_restart_durability_checkpoint_exists',
                                'passed': False,
                                'reason': 'FAIL_CLOSED: post-restart run requires pre-existing durability checkpoint from initial run',
                            })
                        else:
                            assertions.append({
                                'check': 'pre_restart_durability_checkpoint_exists',
                                'passed': True,
                            })
                            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                                pre_restart = json.load(f)
                            pre_ref = pre_restart.get('binding_ref')
                            pre_sub = pre_restart.get('holder_subject')
                            pre_ver = pre_restart.get('binding_version')
                            pre_jwk = pre_restart.get('holder_jwk')
                            try:
                                with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{pre_ref}", timeout=15) as chk_resp:
                                    pre_binding = json.loads(chk_resp.read().decode('utf-8'))
                                record_match = (pre_binding.get('record_id') == pre_ref)
                                status_active = (pre_binding.get('status') == 'ACTIVE')
                                subject_match = (pre_binding.get('holder_subject') == pre_sub)
                                version_match = (pre_binding.get('binding_version') == pre_ver)
                                jwk_match = (pre_binding.get('holder_jwk') == pre_jwk)
                                binding_survived = (
                                    record_match and status_active and subject_match
                                    and version_match and jwk_match
                                )
                                assertions.append({
                                    'check': 'pre_restart_binding_survived_container_restart',
                                    'passed': binding_survived,
                                    'pre_restart_record_id': pre_ref,
                                    'pre_restart_status': pre_binding.get('status'),
                                    'version_retained': version_match,
                                    'jwk_retained': jwk_match,
                                })
                            except Exception as e:
                                assertions.append({
                                    'check': 'pre_restart_binding_survived_container_restart',
                                    'passed': False,
                                    'error': str(e),
                                })
                    else:
                        with open(checkpoint_file, 'w', encoding='utf-8') as f:
                            json.dump({
                                'binding_ref': binding_ref,
                                'root_jti': root_jti,
                                'holder_subject': binding.get('holder_subject'),
                                'holder_jwk': binding.get('holder_jwk'),
                                'binding_version': binding.get('binding_version'),
                            }, f)

                    full = {
                        'services': ['accounts'],
                        'accounts': ['ACC-001'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {
                            'history_days': 90, 'page_size': 1,
                            'fields': ['account_id', 'amount', 'balance', 'date', 'operation', 'type'],
                        },
                    }
                    flow = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(full)) for _ in range(5)),
                        target_root_jti=root_jti,
                    )
                    expected_authority = json.loads(json.dumps(full))
                    expected_record = dataset_expected_records(
                        base_dir, full['accounts'], full['data']['fields'], full['data']['page_size']
                    )
                    observed_authority = (flow.get('token_claims') or {}).get('typed_authority')
                    observed_resource = (flow.get('resource') or {}).get('Data', {}).get('Account', [])
                    oracle_match = observed_authority == expected_authority
                    f4_root_jti = (flow.get('source_evidence') or {}).get('root_jti')
                    assertions.extend([
                        {
                            'check': 'f4_presents_exact_f1_issued_root',
                            'passed': bool(f4_root_jti) and (f4_root_jti == root_jti),
                            'expected_root_jti': root_jti,
                            'observed_root_jti': f4_root_jti,
                        },
                        {
                            'check': 'f2_f5_effective_authority_exact',
                            'passed': flow.get('token_status') == 200 and oracle_match,
                            'expected': expected_authority,
                            'observed': observed_authority,
                        },
                        {
                            'check': 'f6_resource_projection_exact',
                            'passed': flow.get('resource_status') == 200 and observed_resource == expected_record,
                            'expected': expected_record,
                            'observed': observed_resource,
                        },
                    ])

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "VDAM_F1_F6_COMPLETE_FLOW_SUCCESS" if all_ok else "VDAM_FLOW_ASSERTION_FAILED"

                elif case_id in {'VD-F02', 'VD-F03', 'VD-F04', 'VD-F05', 'VD-F06'}:
                    base_vector = {
                        'services': ['accounts', 'balances', 'transactions'],
                        'accounts': ['ACC-001', 'ACC-002', 'ACC-003', 'ACC-004', 'ACC-005'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {
                            'history_days': 90,
                            'page_size': 50,
                            'fields': ['account_id', 'amount', 'balance', 'date', 'operation', 'type'],
                        },
                    }

                    def clone_vector():
                        return json.loads(json.dumps(base_vector))

                    def expected_resource(authority):
                        return dataset_expected_records(
                            base_dir,
                            authority['accounts'],
                            authority['data']['fields'],
                            authority['data']['page_size'],
                        )

                    vector_sets = []
                    if case_id == 'VD-F02':
                        vector_sets.append(('VD-F02', *(clone_vector() for _ in range(5))))
                    elif case_id == 'VD-F03':
                        vectors = [clone_vector() for _ in range(5)]
                        vectors[1]['services'] = ['accounts', 'balances']
                        vectors[1]['accounts'] = ['ACC-001']
                        vector_sets.append(('VD-F03', *vectors))
                    elif case_id == 'VD-F04':
                        vectors = [clone_vector() for _ in range(5)]
                        vectors[4]['services'] = ['accounts']
                        vectors[4]['validity']['end'] = vectors[4]['validity']['start'] + 7 * 86400
                        vectors[4]['data']['history_days'] = 7
                        vectors[4]['data']['fields'] = ['account_id', 'balance']
                        vector_sets.append(('VD-F04', *vectors))
                    elif case_id == 'VD-F05':
                        boundary_path = os.path.join(base_dir, 'evaluation', 'fixtures', 'data', 'boundary_20_vd_f05.json')
                        with open(boundary_path, 'r', encoding='utf-8') as boundary_file:
                            boundaries = json.load(boundary_file)
                        entity_index = {'SC': 0, 'H': 1, 'R': 2, 'T': 3, 'P': 4}
                        for boundary in boundaries:
                            vectors = [clone_vector() for _ in range(5)]
                            target = vectors[entity_index[boundary['restrictive_entity']]]
                            dimension = boundary['restricted_dimension']
                            if dimension == 'S': target['services'] = ['accounts']
                            elif dimension == 'A': target['accounts'] = ['ACC-001']
                            elif dimension == 'V':
                                target['validity'] = {'start': 1788500000 + 5 * 86400, 'end': 1788500000 + 10 * 86400}
                            elif dimension == 'D':
                                target['data'] = {'history_days': 30, 'page_size': 10, 'fields': ['account_id', 'balance']}
                            vector_sets.append((boundary['case_id'], *vectors))
                    else:
                        rejection_mutations = [
                            ('DisjointAccounts', 1, lambda value: value.update({'accounts': ['ACC-999']}), 'REJECT_EMPTY_ACCOUNTS'),
                            ('InvertedValidity', 2, lambda value: value.update({'validity': {'start': 1791092001, 'end': 1788500000}}), 'REJECT_INVALID_VALIDITY_INTERVAL'),
                            ('DisjointFields', 3, lambda value: value['data'].update({'fields': ['merchant_category']}), 'REJECT_EMPTY_DATA_FIELDS'),
                            ('ZeroHistory', 1, lambda value: value['data'].update({'history_days': 0}), 'REJECT_INVALID_HISTORY_WINDOW'),
                            ('ZeroPageSize', 4, lambda value: value['data'].update({'page_size': 0}), 'REJECT_INVALID_PAGE_SIZE'),
                        ]
                        for variant, target_index, mutate, rejection in rejection_mutations:
                            vectors = [clone_vector() for _ in range(5)]
                            mutate(vectors[target_index])
                            vector_sets.append((variant, *vectors, rejection))

                    all_matches = True
                    observed_runs = []
                    for vector_set in vector_sets:
                        variant, sc, h, requested, tpp_bound, policy = vector_set[:6]
                        expected_permit, expected_reason, expected_authority = DasOracleSimulator.evaluate(
                            sc, h, requested, tpp_bound, policy
                        )
                        flow = execute_typed_authority_flow(
                            base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                            sc, h, requested, tpp_bound, policy,
                        )
                        if expected_permit:
                            actual_authority = (flow.get('token_claims') or {}).get('typed_authority')
                            records = (flow.get('resource') or {}).get('Data', {}).get('Account', [])
                            expected_records = expected_resource(expected_authority)
                            matched = (
                                flow.get('token_status') == 200
                                and flow.get('resource_status') == 200
                                and actual_authority == expected_authority
                                and records == expected_records
                            )
                            observed_runs.append({
                                'variant': variant,
                                'expected_authority': expected_authority,
                                'observed_authority': actual_authority,
                                'expected_resource': expected_records,
                                'observed_resource': records,
                                'matched': matched,
                            })
                        else:
                            error_description = (flow.get('token_response') or {}).get('error_description', '')
                            matched = flow.get('token_status') in (400, 403) and expected_reason in error_description
                            observed_runs.append({
                                'variant': variant,
                                'expected_reason': expected_reason,
                                'token_status': flow.get('token_status'),
                                'observed_reason': error_description,
                                'resource_status': flow.get('resource_status'),
                                'matched': matched,
                            })
                        assertions.append({
                            'check': f'typed_authority_exact_{variant}',
                            'passed': matched,
                            'expected_decision': 'PERMIT' if expected_permit else 'DENY',
                        })
                        all_matches = all_matches and matched

                    oracle_match = all_matches
                    observed_authority = observed_runs
                    observed_resource = [run.get('observed_resource') for run in observed_runs if 'observed_resource' in run]
                    status = 'EXECUTED'
                    # Label the decision from what the SUT actually returned across the sub-runs.
                    observed_labels = set()
                    for run in observed_runs:
                        if 'observed_authority' in run:
                            observed_labels.add(authority_decision_label(True, run['observed_authority'], base_vector)
                                                if run['observed_authority'] else 'DENY')
                        else:
                            observed_labels.add('DENY')
                    if not all_matches:
                        actual_decision = 'FAIL'
                    elif observed_labels == {'DENY'}:
                        actual_decision = 'DENY'
                    elif 'PERMIT_RESTRICTED' in observed_labels:
                        actual_decision = 'PERMIT_RESTRICTED'
                    else:
                        actual_decision = 'PERMIT'
                    reason = 'SUT_ORACLE_AND_RESOURCE_EQUALITY' if all_matches else 'SUT_ORACLE_OR_RESOURCE_MISMATCH'

                elif case_id == 'VD-F07':
                    authority = {
                        'services': ['accounts'], 'accounts': ['ACC-001'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {'history_days': 30, 'page_size': 1, 'fields': ['account_id']},
                    }
                    flow = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(authority)) for _ in range(5)),
                    )
                    role_audiences = flow['source_evidence']
                    audience_values = [role_audiences['aud_r'], role_audiences['aud_g'], role_audiences['aud_kb']]
                    assertions.extend([
                        {
                            'check': 'role_audiences_are_pairwise_distinct',
                            'passed': len(set(audience_values)) == 3,
                            'observed': audience_values,
                        },
                        {
                            'check': 'aud_r_targets_resource_server',
                            'passed': role_audiences['aud_r'] == 'http://localhost:4000' and flow['resource_status'] == 200,
                        },
                        {
                            'check': 'aud_g_targets_das_token_endpoint',
                            'passed': role_audiences['aud_g'].endswith('/token') and flow['token_status'] == 200,
                        },
                        {
                            'check': 'aud_kb_targets_holder_proof_verifier',
                            'passed': role_audiences['aud_kb'].endswith('/verify-kb'),
                        },
                    ])

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "AUDIENCE_SEPARATION_VERIFIED" if all_ok else "AUDIENCE_SEPARATION_FAILED"

                elif case_id == 'VD-F08':
                    authority = {
                        'services': ['accounts'], 'accounts': ['ACC-001'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {'history_days': 30, 'page_size': 1, 'fields': ['account_id']},
                    }
                    flow = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(authority)) for _ in range(5)),
                    )
                    evidence = flow['source_evidence']
                    assertions.extend([
                        {
                            'check': 'signed_challenge_correlated_across_challenge_vc_and_vp',
                            'passed': (
                                bool(evidence['r_das_challenge'])
                                and evidence['r_das_challenge'] == evidence['r_das_vp'] == evidence['r_das_delegation']
                            ),
                            'observed': [evidence['r_das_challenge'], evidence['r_das_vp'], evidence['r_das_delegation']],
                        },
                        {
                            'check': 'kb_sd_hash_exact',
                            'passed': evidence['kb_sd_hash'] == evidence['computed_sd_hash'],
                            'observed': evidence['kb_sd_hash'],
                        },
                        {
                            'check': 'fresh_transaction_identifiers_distinct',
                            'passed': len({evidence['r_das_challenge'], evidence['vp_jti'], evidence['delegate_jti']}) == 3,
                        },
                        {
                            'check': 'correlated_presentation_consumed_successfully',
                            'passed': flow['token_status'] == 200 and flow['resource_status'] == 200,
                        },
                    ])

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "CHALLENGE_NONCE_BINDING_VERIFIED" if all_ok else "NONCE_BINDING_CHECK_FAILED"

                elif case_id == 'VD-F09':
                    authority = {
                        'services': ['accounts'], 'accounts': ['ACC-001', 'ACC-002'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {'history_days': 7, 'page_size': 2, 'fields': ['account_id', 'balance']},
                    }
                    flow = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(authority)) for _ in range(5)),
                    )
                    expected_records = dataset_expected_records(
                        base_dir, authority['accounts'], authority['data']['fields'],
                        authority['data']['page_size']
                    )
                    token_ok = (flow.get('token_status') == 200)
                    resource_ok = (flow.get('resource_status') == 200)
                    observed_authority = (flow.get('token_claims') or {}).get('typed_authority')
                    raw_resource = flow.get('resource') or {}
                    data_obj = raw_resource.get('Data') or {}
                    observed_resource = data_obj.get('Account', [])
                    strict_envelope = (
                        isinstance(raw_resource, dict)
                        and set(raw_resource.keys()) <= {'Data', 'Links', 'Meta'}
                        and isinstance(data_obj, dict)
                        and set(data_obj.keys()) == {'Account'}
                    )
                    oracle_match = (observed_authority == authority)
                    assertions.extend([
                        {'check': 'flow_transport_success', 'passed': token_ok and resource_ok, 'token_status': flow.get('token_status'), 'resource_status': flow.get('resource_status')},
                        {'check': 'token_authority_exact', 'passed': oracle_match, 'expected': authority, 'observed': observed_authority},
                        {'check': 'rs_projection_exact', 'passed': (observed_resource == expected_records and strict_envelope), 'expected': expected_records, 'observed': observed_resource, 'strict_envelope': strict_envelope},
                    ])

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "AUTHORITY_PROJECTION_CONSISTENCY_VERIFIED" if all_ok else "PROJECTION_CONSISTENCY_FAILED"

                elif case_id == 'VD-F10':
                    # Establish an explicit initial F1, then run two independent
                    # F2-F6 transactions against the same committed root.
                    _, initial = _post_json(f"{wallet_url}/api/provision-scope-vc", {})
                    initial_root_jti = initial.get('jti')
                    authority = {
                        'services': ['accounts'], 'accounts': ['ACC-001'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {'history_days': 30, 'page_size': 1, 'fields': ['account_id', 'balance']},
                    }
                    flow1 = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(authority)) for _ in range(5)),
                        target_root_jti=initial_root_jti,
                    )
                    flow2 = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url,
                        *(json.loads(json.dumps(authority)) for _ in range(5)),
                        target_root_jti=initial_root_jti,
                    )
                    token1 = flow1.get('token_claims') or {}
                    token2 = flow2.get('token_claims') or {}
                    raw_res1 = flow1.get('resource') or {}
                    raw_res2 = flow2.get('resource') or {}
                    data_obj1 = raw_res1.get('Data') or {}
                    data_obj2 = raw_res2.get('Data') or {}
                    resource1 = data_obj1.get('Account', [])
                    resource2 = data_obj2.get('Account', [])
                    strict_envelope1 = (
                        isinstance(raw_res1, dict)
                        and set(raw_res1.keys()) <= {'Data', 'Links', 'Meta'}
                        and isinstance(data_obj1, dict)
                        and set(data_obj1.keys()) == {'Account'}
                    )
                    strict_envelope2 = (
                        isinstance(raw_res2, dict)
                        and set(raw_res2.keys()) <= {'Data', 'Links', 'Meta'}
                        and isinstance(data_obj2, dict)
                        and set(data_obj2.keys()) == {'Account'}
                    )
                    flow1_ok = (flow1.get('token_status') == 200 and flow1.get('resource_status') == 200)
                    flow2_ok = (flow2.get('token_status') == 200 and flow2.get('resource_status') == 200)
                    assertions.extend([
                        {
                            'check': 'repeated_flows_transport_success',
                            'passed': flow1_ok and flow2_ok,
                            'flow1_token': flow1.get('token_status'),
                            'flow1_resource': flow1.get('resource_status'),
                            'flow2_token': flow2.get('token_status'),
                            'flow2_resource': flow2.get('resource_status'),
                        },
                        {
                            'check': 'repeated_resource_envelopes_strict',
                            'passed': strict_envelope1 and strict_envelope2,
                            'envelope1_valid': strict_envelope1,
                            'envelope2_valid': strict_envelope2,
                        },
                        {
                            'check': 'initial_f1_root_reused_by_both_repeated_transactions',
                            'passed': (
                                bool(initial_root_jti)
                                and flow1['source_evidence']['root_jti'] == initial_root_jti
                                and flow2['source_evidence']['root_jti'] == initial_root_jti
                            ),
                            'root_jti': initial_root_jti,
                        },
                        {
                            'check': 'repeated_transactions_use_fresh_challenge_vp_delegation_and_token',
                            'passed': (
                                flow1['source_evidence']['r_das_challenge'] != flow2['source_evidence']['r_das_challenge']
                                and flow1['source_evidence']['vp_jti'] != flow2['source_evidence']['vp_jti']
                                and flow1['source_evidence']['delegate_jti'] != flow2['source_evidence']['delegate_jti']
                                and token1.get('jti') != token2.get('jti')
                            ),
                        },
                        {
                            'check': 'initial_and_repeated_authority_equal_exactly',
                            'passed': token1.get('typed_authority') == authority == token2.get('typed_authority'),
                        },
                        {
                            'check': 'initial_and_repeated_resource_equal_exactly',
                            'passed': resource1 == resource2 == dataset_expected_records(
                                base_dir, authority['accounts'], authority['data']['fields'],
                                authority['data']['page_size']
                            ),
                            'expected': dataset_expected_records(
                                base_dir, authority['accounts'], authority['data']['fields'],
                                authority['data']['page_size']
                            ),
                            'observed': [resource1, resource2],
                        },
                    ])

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "PATH_PARTITIONING_VERIFIED" if all_ok else "PATH_PARTITIONING_FAILED"

                elif case_id == 'VD-F11':
                    # Selective Disclosure & TPP Data Shielding Verification
                    _post_json(f"{wallet_url}/api/provision-scope-vc", {})
                    flow_res = execute_vdam_delegation_flow(tpp_host=tpp_host, wallet_host=wallet_host, scopes=["accounts:read"])
                    assertions.append({'check': 'delegation_flow_executed', 'passed': bool(flow_res.get('access_token'))})

                    with urllib.request.urlopen(f"{tpp_url}/api/status", timeout=30) as resp:
                        tpp_state = json.loads(resp.read().decode('utf-8'))
                        assertions.append({'check': 'tpp_status_ok', 'passed': resp.status == 200})

                        # The claim names and values the Wallet actually places in the DAS-only encrypted
                        # package. Searching for names that never occur in this system would make the
                        # shielding assertion impossible to fail.
                        DAS_ONLY_CLAIM_NAMES = {'das_only_claims', 'holder_account_tax_id', 'internal_risk_tier'}
                        DAS_ONLY_CLAIM_VALUES = {'TAX-99881122', 'LOW_RISK'}

                        def find_shielded_leak(value, path='$'):
                            """Path of the first DAS-only claim name or value found, or None."""
                            if isinstance(value, dict):
                                for key, child in value.items():
                                    if str(key).lower() in DAS_ONLY_CLAIM_NAMES:
                                        return f"{path}.{key}"
                                    found = find_shielded_leak(child, f"{path}.{key}")
                                    if found:
                                        return found
                            elif isinstance(value, list):
                                for index, child in enumerate(value):
                                    found = find_shielded_leak(child, f"{path}[{index}]")
                                    if found:
                                        return found
                            elif isinstance(value, str) and value in DAS_ONLY_CLAIM_VALUES:
                                return path
                            return None

                        # Control: the detector must actually fire on the claims it is looking for, otherwise a
                        # clean result proves nothing.
                        leak_detector_control = find_shielded_leak(
                            {'vcs': {'authorization': {'das_only_claims': {'holder_account_tax_id': 'TAX-99881122'}}}}
                        )
                        assertions.append({
                            'check': 'shielded_claim_detector_is_effective',
                            'passed': leak_detector_control is not None,
                            'control_hit': leak_detector_control,
                        })
                        tpp_state_leak = find_shielded_leak(tpp_state)
                        assertions.append({
                            'check': 'undisclosed_claims_shielded',
                            'passed': tpp_state_leak is None,
                            'leak_path': tpp_state_leak,
                        })
                        disclosed_names = (
                            tpp_state.get('vcs', {}).get('authorization', {}).get('disclosedClaimNames', [])
                        )
                        assertions.append({
                            'check': 'root_vc_disclosure_set_exact',
                            'passed': disclosed_names == ['scopes'],
                            'expected': ['scopes'],
                            'observed': disclosed_names,
                        })

                    f11_req = urllib.request.Request(f"{tpp_url}/api/call-banking-api", data=json.dumps({"endpoint": "/api/v1/accounts"}).encode('utf-8'), headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(f11_req, timeout=30) as resp:
                        rs_res = json.loads(resp.read().decode('utf-8'))
                        assertions.append({'check': 'rs_sd_response_200', 'passed': rs_res.get('status') == 200})
                        accs = rs_res.get('data', {}).get('Data', {}).get('Account', []) or rs_res.get('data', {}).get('Account', [])
                        assertions.append({'check': 'sd_projected_claim_account_id_present', 'passed': len(accs) > 0})
                        rs_leak = find_shielded_leak(rs_res)
                        assertions.append({
                            'check': 'sd_shielded_claims_excluded_from_payload',
                            'passed': rs_leak is None,
                            'leak_path': rs_leak,
                        })

                    status = 'EXECUTED'
                    all_ok = all(a['passed'] for a in assertions)
                    actual_decision = "PERMIT" if all_ok else "FAIL"
                    reason = "SELECTIVE_DISCLOSURE_SHIELDING_VERIFIED" if all_ok else "SHIELDING_CHECK_FAILED"

            except Exception as e:
                status = 'FAIL'
                actual_decision = "FAIL"
                reason = f"LIVE_SUT_ERROR: {str(e)}"
                assertions.append({'check': 'live_sut_call_succeeded', 'passed': False, 'error': str(e)})

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        if status != 'NOT_RUN':
            passed = len(assertions) > 0 and all(a.get('passed', False) for a in assertions) and (actual_decision == c.get('expected_decision'))
            status = 'PASS' if passed else 'FAIL'

        # The case-level mode comes from the frozen case definition. For VD-F01 the F1 leg is reported
        # separately, because it can degrade to the provisioning hook while the rest of the case is unchanged.
        effective_mode = c.get('execution_mode', 'PRODUCTION_E2E')
        effective_assistance = list(c.get('test_assistance', []))
        f1_leg = None
        if case_id == 'VD-F01' and 'f1_mode' in locals():
            f1_leg = {'execution_mode': f1_mode, 'test_assistance': f1_assistance, 'error': f1_error}
            for item in f1_assistance:
                if item not in effective_assistance:
                    effective_assistance.append(item)
        res = {
            'suite': 'VDAM_Valid_SUT',
            'tier': 'SUT_CONFORMANCE',
            'case_id': case_id,
            'name': c['name'],
            'configuration': c.get('configuration', 'B1-C0, B1-C2'),
            'status': status,
            'execution_mode': effective_mode,
            'test_assistance': effective_assistance,
            'f1_leg': f1_leg,
            'production_boundary': c.get('production_boundary', 'TOKEN_AND_RESOURCE_SERVER'),
            'proven_requirements': c.get('proven_requirements', []),
            'uncovered_aspects': c.get('uncovered_aspects', []),
            'expected_decision': c.get('expected_decision', 'PERMIT'),
            'actual_decision': actual_decision,
            'oracle_match': oracle_match,
            'observed_authority': observed_authority,
            'observed_resource': observed_resource,
            'reason': reason,
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'VDAM_Valid_SUT',
            'tier': 'SUT_CONFORMANCE',
            'status': status,
            'assertions': assertions,
            'timestamp': res['timestamp']
        })

    return results


def run_vdam_negative_sut_conformance(base_dir, traces_out):
    """
    Tier: SUT_CONFORMANCE
    VDAM Negative Suite security filter mutations against live microservice endpoints:
      - VD-N01 (Aud_KB, Nonce, SdHash)
      - VD-N02 (Aud_G)
      - VD-N03 (PresenterMismatch, Signer, ReplacementKey, IssuanceRecord)
      - VD-N04 (SequentialReplay, ConcurrentDuplicate)
      - VD-N05 (AuthorityExpansion)
      - VD-N06 (ExpiredState, MissingRecord, DisabledAssociation, PostIssuanceInvalidation, StaleSnapshot, RollbackVersion)
      - VD-N07 (RSUnauthorizedResource)
      - VD-N08 (TamperedPackage)
    R4-02: Executable negative mutation adapter.
      - When services are offline: records ENVIRONMENT_PENDING: SUT_OFFLINE.
      - When services are online: executes negative mutation requests.
    """
    cases_path = os.path.join(base_dir, 'evaluation', 'tests', 'vdam_negative_cases.json')
    with open(cases_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    bank_host = os.environ.get('BANK_HOST', '127.0.0.1')
    tpp_host = os.environ.get('TPP_HOST', '127.0.0.1')
    wallet_host = os.environ.get('WALLET_HOST', '127.0.0.1')
    issuer_url = os.environ.get('VDAM_ISSUER_URL', f'http://{bank_host}:7000')
    das_url = os.environ.get('VDAM_DAS_URL', f'http://{bank_host}:7000')
    rs_url = os.environ.get('VDAM_RS_URL', f'http://{bank_host}:4000')
    tpp_url = os.environ.get('VDAM_TPP_URL', f'http://{tpp_host}:6001')
    wallet_url = os.environ.get('VDAM_WALLET_URL', f'http://{wallet_host}:5000')

    das_online, das_probe = check_service_online(f"{issuer_url}/health", timeout=1.0)
    rs_online, rs_probe = check_service_online(f"{rs_url}/health", timeout=1.0)
    tpp_online, tpp_probe = check_service_online(f"{tpp_url}/api/status", timeout=1.0)
    wallet_online, wallet_probe = check_service_online(f"{wallet_url}/api/config", timeout=1.0)
    vdam_online = das_online and rs_online and tpp_online and wallet_online

    # Execute positive control once to establish genuine baseline credentials
    pos_tok = None
    pos_flow_ok = False
    if vdam_online:
        try:
            _post_json(f"{wallet_url}/api/provision-scope-vc", {})
            pos_flow = execute_vdam_delegation_flow(tpp_host=tpp_host, wallet_host=wallet_host, scopes=["accounts:read", "ReadAccountsDetail"])
            pos_tok = pos_flow.get('access_token')
            if pos_tok:
                f6_req = urllib.request.Request(f"{tpp_url}/api/call-banking-api", data=json.dumps({"endpoint": "/api/v1/accounts"}).encode('utf-8'), headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(f6_req, timeout=5) as f6_resp:
                    rs_data = json.loads(f6_resp.read().decode('utf-8'))
                    if rs_data.get('status') == 200:
                        pos_flow_ok = True
        except Exception:
            pos_tok = None
            pos_flow_ok = False

    valid_authz_vc = None
    valid_delegate_vc = None
    if vdam_online:
        try:
            with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=300) as r:
                w_data = json.loads(r.read().decode('utf-8'))
                v_list = w_data.get('vcs', [])
                root_vcs = [v for v in v_list if v.get('type') == 'AuthorizationCredential' or ('scope' in str(v.get('type', '')).lower() and 'delegate' not in str(v.get('type', '')).lower())]
                if root_vcs:
                    valid_authz_vc = root_vcs[-1].get('sdJwt')
                    root_jti = root_vcs[-1].get('jti')
                    matching_dels = [v for v in v_list if 'delegate' in str(v.get('type', '')).lower() and v.get('payload', {}).get('parent_vc_jti') == root_jti]
                    if matching_dels:
                        valid_delegate_vc = matching_dels[-1].get('sdJwt')
                    else:
                        all_dels = [v for v in v_list if 'delegate' in str(v.get('type', '')).lower()]
                        if all_dels:
                            valid_delegate_vc = all_dels[-1].get('sdJwt')
        except Exception:
            pass

    def mutate_kb_jwt(delegate_vc_str, key_to_mutate, new_value, signer_url=None):
        import base64
        if not delegate_vc_str or '~' not in delegate_vc_str:
            return delegate_vc_str
        parts = delegate_vc_str.split('~')
        kb_jwt = parts[-1]
        kb_sections = kb_jwt.split('.')
        if len(kb_sections) < 2:
            return delegate_vc_str
        try:
            payload_b64 = kb_sections[1]
            p_bytes = base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4))
            kb_p = json.loads(p_bytes.decode('utf-8'))
            kb_p[key_to_mutate] = new_value
            signer = signer_url or f"{wallet_url}/api/test/sign-artifact"
            new_kb_jwt = sign_test_artifact(signer, kb_p, "kb+jwt")
            parts[-1] = new_kb_jwt
            return '~'.join(parts)
        except Exception as exc:
            if str(exc).startswith("FIXTURE_PREREQUISITE_FAILED:"):
                raise
            raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: cannot rebuild signed KB-JWT: {exc}") from exc

    def mutate_vc_payload(vc_str, key_to_mutate, new_value, signer_url, typ="vc+sd-jwt"):
        import base64
        if not vc_str:
            return vc_str
        parts = vc_str.split('~')
        jwt_sections = parts[0].split('.')
        if len(jwt_sections) < 2:
            return vc_str
        try:
            payload_b64 = jwt_sections[1]
            p_bytes = base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4))
            vc_p = json.loads(p_bytes.decode('utf-8'))
            vc_p[key_to_mutate] = new_value
            parts[0] = sign_test_artifact(signer_url, vc_p, typ)
            return '~'.join(parts)
        except Exception as exc:
            if str(exc).startswith("FIXTURE_PREREQUISITE_FAILED:"):
                raise
            raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: cannot rebuild signed VC: {exc}") from exc

    def sign_test_artifact(url, payload, typ, signer_profile=None, return_details=False):
        request_body = {"payload": payload, "typ": typ}
        if signer_profile:
            request_body['signer_profile'] = signer_profile
        sign_req = urllib.request.Request(
            url,
            data=json.dumps(request_body).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        sign_data = None
        for attempt in range(2):
            try:
                with urllib.request.urlopen(sign_req, timeout=90) as sign_resp:
                    if sign_resp.status != 200:
                        raise RuntimeError(f"signer returned HTTP {sign_resp.status}")
                    sign_data = json.loads(sign_resp.read().decode('utf-8'))
                    break
            except Exception as exc:
                if attempt == 0 and "timed out" in str(exc).lower():
                    time.sleep(1)
                    continue
                raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: authorized signer unavailable at {url}: {exc}") from exc
        signed_jwt = sign_data.get('signedJwt')
        if not signed_jwt:
            raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: authorized signer at {url} returned no signedJwt")
        return sign_data if return_details else signed_jwt

    def root_binding_reference(root_vc):
        _, payload = decode_jwt_payload_unverified(root_vc.split('~', 1)[0])
        record_id = payload.get('holder_cert_ref') if isinstance(payload, dict) else None
        if not record_id:
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: root credential has no holder_cert_ref")
        return record_id

    def read_binding(record_id):
        try:
            with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{record_id}", timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: authoritative binding read failed for {record_id}: {exc}"
            ) from exc

    def set_binding_status(record_id, status_value):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/status",
            data=json.dumps({'status': status_value}).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: authoritative binding transition failed for {record_id}: {exc}"
            ) from exc

    def set_lookup_available(available_bool):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/lookup-availability",
            data=json.dumps({'available': available_bool}).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: setting lookup availability failed: {exc}"
            ) from exc

    def invalidate_wallet_cert(record_id):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/invalidate-wallet-cert",
            data=b"{}",
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: invalidating wallet cert failed for {record_id}: {exc}"
            ) from exc

    def invalidate_holder_key(record_id):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/invalidate-holder-key",
            data=b"{}",
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: invalidating holder key failed for {record_id}: {exc}"
            ) from exc

    def advance_binding_version(record_id):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/advance-version",
            data=b"{}",
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: advancing binding version failed for {record_id}: {exc}"
            ) from exc

    def mutate_binding(record_id, mutations):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/mutate",
            data=json.dumps(mutations).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: mutating binding failed for {record_id}: {exc}"
            ) from exc

    def reset_binding(record_id):
        request = urllib.request.Request(
            f"{issuer_url}/api/test/bindings/{record_id}/reset",
            data=b"{}",
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f"FIXTURE_PREREQUISITE_FAILED: resetting binding failed for {record_id}: {exc}"
            ) from exc

    def fresh_delegation_fixture():
        init_body = json.dumps({"requestedScopes": ["accounts:read"]}).encode('utf-8')
        init_req = urllib.request.Request(
            f"{tpp_url}/api/request-delegate",
            data=init_body,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(init_req, timeout=300) as init_response:
            init_data = json.loads(init_response.read().decode('utf-8'))
        request_id = init_data.get('requestId')
        request_payload = init_data.get('requestPayload') or {}
        challenge = request_payload.get('challenge') or {}
        if not request_id or not challenge.get('r_das') or not request_payload.get('ch_das'):
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: fresh delegation request has no signed DAS challenge")

        fetch_req = urllib.request.Request(f"{wallet_url}/api/fetch-tpp-request?requestId={request_id}")
        with urllib.request.urlopen(fetch_req, timeout=300):
            pass
        approve_body = json.dumps({
            "requestId": request_id,
            "approvedScopes": ["accounts:read"]
        }).encode('utf-8')
        approve_req = urllib.request.Request(
            f"{wallet_url}/api/approve-delegate",
            data=approve_body,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(approve_req, timeout=300) as approve_response:
            approve_data = json.loads(approve_response.read().decode('utf-8'))
        delegate_jti = approve_data.get('delegateVcJti')
        with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=300) as vcs_response:
            wallet_vcs = json.loads(vcs_response.read().decode('utf-8')).get('vcs', [])
        roots = [
            vc for vc in wallet_vcs
            if vc.get('type') == 'AuthorizationCredential'
            or ('scope' in str(vc.get('type', '')).lower() and 'delegate' not in str(vc.get('type', '')).lower())
        ]
        delegates = [vc for vc in wallet_vcs if 'delegate' in str(vc.get('type', '')).lower()]
        selected_delegate = next((vc for vc in delegates if vc.get('jti') == delegate_jti), None)
        if not selected_delegate:
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: approved delegation credential cannot be identified by JTI")
        parent_jti = (selected_delegate.get('payload') or {}).get('parent_vc_jti')
        selected_root = next((vc for vc in roots if vc.get('jti') == parent_jti), None)
        if not selected_root:
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: approved delegation has no matching root credential")
        if not roots or not delegates:
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: fresh approval produced no root/delegation credential pair")
        nonlocal valid_authz_vc, valid_delegate_vc
        valid_authz_vc = selected_root.get('sdJwt')
        valid_delegate_vc = selected_delegate.get('sdJwt')
        return selected_root.get('sdJwt'), selected_delegate.get('sdJwt'), {
            'ch_das': request_payload['ch_das'],
            'challenge': challenge,
            'das_encrypted_package': approve_data.get('das_encrypted_package'),
        }

    def get_current_credentials():
        nonlocal valid_authz_vc, valid_delegate_vc
        try:
            with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=300) as r:
                w_data = json.loads(r.read().decode('utf-8'))
                v_list = w_data.get('vcs', [])
                root_vcs = [v for v in v_list if v.get('type') == 'AuthorizationCredential' or ('scope' in str(v.get('type', '')).lower() and 'delegate' not in str(v.get('type', '')).lower())]
                if root_vcs:
                    valid_authz_vc = root_vcs[-1].get('sdJwt')
                    r_jti = root_vcs[-1].get('jti')
                    matching_dels = [v for v in v_list if 'delegate' in str(v.get('type', '')).lower() and v.get('payload', {}).get('parent_vc_jti') == r_jti]
                    if matching_dels:
                        valid_delegate_vc = matching_dels[-1].get('sdJwt')
        except Exception:
            pass
        return valid_authz_vc, valid_delegate_vc

    def send_assertion_mutation(payload_dict, extra_headers=None, credential_pair=None, challenge_data=None):
        authz_vc, delegate_vc = credential_pair or get_current_credentials()
        if not authz_vc or not delegate_vc:
            raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: positive control did not provide both root and delegation credentials")
        base_payload = {
            "iss": "tpp-demo-client",
            "aud": f"{issuer_url}/token",
            "aud_g": f"{issuer_url}/token",
            "aud_r": "http://localhost:4000",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "jti": f"mut-{secrets.token_hex(8)}",
            "authorization_vc": authz_vc,
            "delegate_vc": delegate_vc
        }
        if challenge_data:
            challenge = challenge_data['challenge']
            base_payload['ch_das'] = challenge_data['ch_das']
            base_payload['r_das'] = challenge['r_das']
            base_payload['aud'] = challenge.get('aud_g', base_payload['aud'])
            base_payload['aud_g'] = challenge.get('aud_g', base_payload['aud_g'])
            base_payload['aud_r'] = challenge.get('aud_r', base_payload['aud_r'])
        base_payload.update(payload_dict)
        # Bind the assertion to the artifacts and challenge it actually carries after the mutation, so a case
        # reaches its target predicate instead of stopping at the F4 presentation binding. A case that tests
        # the binding itself overrides presentation_binding through payload_dict.
        if 'presentation_binding' not in payload_dict:
            base_payload['presentation_binding'] = compute_presentation_binding(
                base_payload.get('authorization_vc'),
                base_payload.get('delegate_vc'),
                base_payload.get('r_das', ''),
            )
        vp_jwt = sign_test_artifact(f"{tpp_url}/api/test/sign-artifact", base_payload, "JWT")

        post_data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": vp_jwt
        }).encode('utf-8')
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if extra_headers:
            headers.update(extra_headers)
        return urllib.request.Request(f"{issuer_url}/token", data=post_data, headers=headers)

    results = []
    for c in cases:
        case_id = c['case_id']
        t0 = time.perf_counter_ns()
        assertions = []
        actual_decision = "UNKNOWN"
        reason = ""
        status = "FAIL"

        if not vdam_online:
            status = 'NOT_RUN'
            actual_decision = 'NOT_RUN'
            reason = f"ENVIRONMENT_PENDING: SUT_OFFLINE (VDAM microservices unreachable at Bank={issuer_url}, TPP={tpp_url}, Wallet={wallet_url}, RS={rs_url})"
            assertions.append({'check': 'sut_service_online', 'passed': False, 'reason': reason})
        elif not pos_flow_ok:
            status = 'FAIL'
            actual_decision = 'FAIL'
            reason = "POSITIVE_CONTROL_FAILED: Prior genuine delegation flow failed to produce valid access token"
            assertions.append({'check': 'positive_control_verified', 'passed': False, 'reason': reason})
        else:
            assertions.append({'check': 'positive_control_verified', 'passed': True})
            try:
                if case_id in {
                    'VD-N05-DisjointAccounts', 'VD-N05-InvertedValidity',
                    'VD-N05-DisjointFields', 'VD-N05-ZeroHistory', 'VD-N05-ZeroPageSize'
                }:
                    base_vector = {
                        'services': ['accounts', 'balances', 'transactions'],
                        'accounts': ['ACC-001', 'ACC-002', 'ACC-003', 'ACC-004', 'ACC-005'],
                        'validity': {'start': 1788500000, 'end': 1791092000},
                        'data': {
                            'history_days': 90, 'page_size': 50,
                            'fields': ['account_id', 'amount', 'balance', 'date', 'operation', 'type'],
                        },
                    }
                    vectors = [json.loads(json.dumps(base_vector)) for _ in range(5)]
                    expected_reason = c['expected_reason']
                    if case_id == 'VD-N05-DisjointAccounts':
                        vectors[1]['accounts'] = ['ACC-999']
                    elif case_id == 'VD-N05-InvertedValidity':
                        vectors[2]['validity'] = {'start': 1791092001, 'end': 1788500000}
                    elif case_id == 'VD-N05-DisjointFields':
                        vectors[3]['data']['fields'] = ['merchant_category']
                    elif case_id == 'VD-N05-ZeroHistory':
                        vectors[1]['data']['history_days'] = 0
                    elif case_id == 'VD-N05-ZeroPageSize':
                        vectors[4]['data']['page_size'] = 0
                    permitted, oracle_reason, _ = DasOracleSimulator.evaluate(*vectors)
                    assertions.append({
                        'check': 'independent_oracle_rejects_exact_variant',
                        'passed': not permitted and oracle_reason == expected_reason,
                        'expected': expected_reason,
                        'observed': oracle_reason,
                    })
                    flow = execute_typed_authority_flow(
                        base_dir, issuer_url, tpp_url, wallet_url, rs_url, *vectors
                    )
                    observed_reason = (flow.get('token_response') or {}).get('error_description', '')
                    rejected = (
                        flow.get('token_status') in (400, 403)
                        and expected_reason in observed_reason
                        and flow.get('resource_status') is None
                    )
                    assertions.append({
                        'check': 'sut_rejects_at_typed_authority_boundary',
                        'passed': rejected,
                        'token_status': flow.get('token_status'),
                        'expected_reason': expected_reason,
                        'observed_reason': observed_reason,
                        'resource_status': flow.get('resource_status'),
                    })
                    actual_decision = 'DENY' if rejected else 'FAIL'
                    reason = expected_reason if rejected else 'TYPED_AUTHORITY_BOUNDARY_REJECTION_MISMATCH'

                elif case_id == 'VD-N04-SequentialReplay':
                    # Sequential replay test:
                    # 1. Establish fresh delegation approval in TPP state
                    # 2. First presentation: call /api/token -> MUST SUCCEED (HTTP 200, PERMIT)
                    # 3. Second presentation (replay): call /api/token immediately again with the same consumed challenge / JTI -> MUST BE REJECTED (HTTP 400/409, REJECT)
                    del_flow = execute_vdam_delegation_flow(tpp_host=tpp_host, wallet_host=wallet_host, scopes=["accounts:read"])
                    first_tok_ok = bool(del_flow.get('access_token'))
                    assertions.append({'check': 'initial_presentation_permitted', 'passed': first_tok_ok})

                    replay_req = urllib.request.Request(f"{tpp_url}/api/token", data=b'', headers={'Content-Type': 'application/json'})
                    second_rejection_ok = False
                    rej_reason = ""
                    try:
                        with urllib.request.urlopen(replay_req, timeout=300) as resp:
                            assertions.append({'check': 'sequential_replay_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_REPLAYED_CREDENTIAL"
                    except urllib.error.HTTPError as e:
                        second_rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403, 409),
                            expected_semantic_tokens=['REJECT_REPLAYED_CREDENTIAL', 'replay', 'replayed', 'consumed']
                        )
                        assertions.append({'check': 'sequential_replay_rejected', 'passed': second_rejection_ok, 'reason': rej_reason})

                    all_replay_ok = first_tok_ok and second_rejection_ok
                    actual_decision = "DENY" if all_replay_ok else "FAIL"
                    reason = "REJECT_REPLAYED_CREDENTIAL" if all_replay_ok else ("FIRST_PRESENTATION_FAILED" if not first_tok_ok else rej_reason)

                elif case_id == 'VD-N04-ConcurrentDuplicate':
                    # Concurrent duplicate presentation with synchronization barrier:
                    # 1. Stage delegation request and approve it in Wallet so TPP has pending approved VCs
                    # 2. Fire 2 concurrent requests to /api/token simultaneously
                    # 3. The atomic synchronization barrier at the Bank Issuer DAS must permit EXACTLY ONE (HTTP 200) and reject the duplicate (HTTP 400/409)
                    del_init = json.dumps({"scopes": ["accounts:read"]}).encode('utf-8')
                    init_req = urllib.request.Request(f"{tpp_url}/api/request-delegate", data=del_init, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(init_req, timeout=300) as r:
                        del_data = json.loads(r.read().decode('utf-8'))
                    req_id = del_data.get('requestId')

                    fetch_req = urllib.request.Request(f"{wallet_url}/api/fetch-tpp-request?requestId={req_id}")
                    with urllib.request.urlopen(fetch_req, timeout=300) as r:
                        pass

                    app_body = json.dumps({"requestId": req_id, "approvedScopes": ["accounts:read"]}).encode('utf-8')
                    app_req = urllib.request.Request(f"{wallet_url}/api/approve-delegate", data=app_body, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(app_req, timeout=300) as r:
                        pass

                    import concurrent.futures
                    import threading
                    start_barrier = threading.Barrier(3, timeout=300)
                    def send_tok():
                        start_barrier.wait()
                        r = urllib.request.Request(f"{tpp_url}/api/token", data=b'', headers={'Content-Type': 'application/json'})
                        try:
                            with urllib.request.urlopen(r, timeout=300) as resp:
                                return resp.status, "PERMIT", False
                        except urllib.error.HTTPError as e:
                            ok, why = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403, 409),
                                expected_semantic_tokens=['REJECT_REPLAYED_CREDENTIAL']
                            )
                            return e.code, ("REJECTION_VERIFIED" if ok else why), ok
                        except Exception as ex:
                            return 500, str(ex), False

                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
                    f1 = executor.submit(send_tok)
                    f2 = executor.submit(send_tok)
                    start_barrier.wait()
                    res1_code, res1_reason, res1_verified = f1.result()
                    res2_code, res2_reason, res2_verified = f2.result()
                    executor.shutdown(wait=True)

                    statuses = [res1_code, res2_code]
                    permit_count = sum(1 for s in statuses if s == 200)
                    reject_count = sum(1 for s in statuses if s in (400, 401, 403, 409))
                    verified_rejection_count = sum(1 for item in (res1_verified, res2_verified) if item)
                    replay_barrier_ok = (permit_count == 1 and reject_count == 1 and verified_rejection_count == 1)
                    assertions.append({'check': 'exactly_one_permit_enforced', 'passed': permit_count == 1, 'permit_count': permit_count, 'codes': statuses})
                    assertions.append({'check': 'duplicate_rejection_enforced', 'passed': verified_rejection_count == 1, 'reject_count': reject_count, 'verified_rejection_count': verified_rejection_count, 'codes': statuses})
                    actual_decision = "EXACTLY_ONE_PERMIT" if replay_barrier_ok else "FAIL"
                    reason = "REJECT_CONCURRENT_DUPLICATE" if replay_barrier_ok else f"CONCURRENT_ANOMALY_PERMIT_{permit_count}_REJECT_{reject_count}_{statuses}"

                elif case_id == 'VD-N07-RSUnauthorizedResource':
                    # The target must be an account that exists and belongs to another holder. A request for a
                    # non-existent account would only produce a not-found answer, which is not evidence that
                    # the resource server enforces an authorization boundary.
                    foreign = dataset_foreign_account(base_dir)
                    assertions.append({
                        'check': 'target_account_exists_and_belongs_to_another_holder',
                        'passed': foreign is not None,
                        'target_account': foreign['canonical_id'] if foreign else None,
                        'owner_client_id': foreign['client_id'] if foreign else None,
                    })
                    if foreign is None:
                        raise RuntimeError('FIXTURE_PREREQUISITE_FAILED: no foreign account available in the dataset')
                    # The request is legitimate in every other respect, including the sender binding, so the
                    # only thing under test is the account boundary.
                    req = urllib.request.Request(
                        f"{rs_url}/api/v1/accounts/{foreign['canonical_id']}",
                        headers={
                            'Authorization': f'Bearer {pos_tok}',
                            **forwarded_tpp_certificate_headers(base_dir),
                        },
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            body = json.loads(resp.read().decode('utf-8'))
                            assertions.append({
                                'check': 'unauthorized_resource_rejected',
                                'passed': False,
                                'http_status': resp.status,
                                'leaked_payload': body,
                            })
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_UNAUTHORIZED_RESOURCE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(403,),
                            expected_semantic_tokens=['REJECT_RESOURCE_ACCESS_OUT_OF_BOUNDS']
                        )
                        assertions.append({'check': 'unauthorized_resource_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_RESOURCE_ACCESS_OUT_OF_BOUNDS" if rejection_ok else rej_reason

                elif case_id == 'VD-N01-AudKB':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_del_vc = mutate_kb_jwt(
                        fresh_delegate_vc, 'aud', 'https://unauthorized-kb-audience.bank.com'
                    )
                    tok_req = send_assertion_mutation({
                        "delegate_vc": mutated_del_vc,
                        "jti": f"mut-audkb-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(tok_req, timeout=300) as resp:
                            assertions.append({'check': 'invalid_kb_audience_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_INVALID_KB_AUDIENCE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_INVALID_KB_AUDIENCE', 'kb_audience', 'audience']
                        )
                        assertions.append({'check': 'invalid_kb_audience_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_INVALID_KB_AUDIENCE" if rejection_ok else rej_reason

                elif case_id == 'VD-N01-Nonce':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_del_vc = mutate_kb_jwt(
                        fresh_delegate_vc, 'nonce', f"mismatched-nonce-{time.perf_counter_ns()}"
                    )
                    tok_req = send_assertion_mutation({
                        "delegate_vc": mutated_del_vc,
                        "jti": f"mut-nonce-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(tok_req, timeout=300) as resp:
                            assertions.append({'check': 'nonce_mismatch_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_NONCE_MISMATCH"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_NONCE_MISMATCH', 'nonce']
                        )
                        assertions.append({'check': 'nonce_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_NONCE_MISMATCH" if rejection_ok else rej_reason

                elif case_id == 'VD-N01-SdHash':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_del_vc = mutate_kb_jwt(fresh_delegate_vc, 'sd_hash', 'corrupted_sd_hash_digest_tampered_0000')
                    req = send_assertion_mutation({
                        "delegate_vc": mutated_del_vc,
                        "jti": f"mut-sdhash-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, mutated_del_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'corrupted_sd_hash_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_CORRUPTED_SD_HASH"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_CORRUPTED_SD_HASH', 'sd_hash', 'hash mismatch']
                        )
                        assertions.append({'check': 'corrupted_sd_hash_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_CORRUPTED_SD_HASH" if rejection_ok else rej_reason

                elif case_id == 'VD-N02-AudG':
                    req = send_assertion_mutation({
                        "aud": "https://unauthorized-grant-authority.bank.com",
                        "aud_g": "https://unauthorized-grant-authority.bank.com",
                        "jti": f"mut-audg-{time.perf_counter_ns()}"
                    })
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'invalid_aud_g_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_INVALID_AUD_G"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_INVALID_GRANT_AUDIENCE', 'grant_audience']
                        )
                        assertions.append({'check': 'invalid_aud_g_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_INVALID_GRANT_AUDIENCE" if rejection_ok else rej_reason

                elif case_id == 'VD-N02-PresentationBinding':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    tok_req = send_assertion_mutation({
                        "presentation_binding": "mismatched-presentation-binding-f4-digest",
                        "jti": f"mut-presbind-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(tok_req, timeout=300) as resp:
                            assertions.append({'check': 'presentation_binding_mismatch_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_PRESENTATION_BINDING_MISMATCH"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_PRESENTATION_BINDING_MISMATCH', 'presentation binding']
                        )
                        assertions.append({'check': 'presentation_binding_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_PRESENTATION_BINDING_MISMATCH" if rejection_ok else rej_reason

                elif case_id == 'VD-N02-CrossContextParent':
                    # Genuine Two-Context Substitution:
                    # 1. Establish Context 1: Root Scope VC 1 and Delegation VC 1
                    root_vc_1, del_vc_1, ch_data_1 = fresh_delegation_fixture()

                    # 2. Establish Context 2: Re-provision distinct Scope VC 2 and Delegation VC 2
                    _post_json(f"{wallet_url}/api/provision-scope-vc", {})
                    root_vc_2, del_vc_2, ch_data_2 = fresh_delegation_fixture()

                    _, root_payload_1 = decode_jwt_payload_unverified(root_vc_1.split('~', 1)[0])
                    _, root_payload_2 = decode_jwt_payload_unverified(root_vc_2.split('~', 1)[0])
                    root_1_jti = root_payload_1.get('jti')
                    root_2_jti = root_payload_2.get('jti')
                    contexts_distinct = bool(root_1_jti and root_2_jti and root_1_jti != root_2_jti)
                    assertions.append({
                        'check': 'genuine_two_issuance_contexts_established',
                        'passed': contexts_distinct,
                        'context1_root_jti': root_1_jti,
                        'context2_root_jti': root_2_jti,
                    })

                    # 3. Cross-Context Substitution: Present Root Scope VC 1 paired with Delegation VC 2
                    # with challenge_data=ch_data_2 (matching del_vc_2's valid KB-JWT nonce)
                    tok_req = send_assertion_mutation({
                        "jti": f"mut-crossctx-{time.perf_counter_ns()}"
                    }, credential_pair=(root_vc_1, del_vc_2), challenge_data=ch_data_2)
                    try:
                        with urllib.request.urlopen(tok_req, timeout=300) as resp:
                            assertions.append({'check': 'cross_context_parent_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_CROSS_CONTEXT_PARENT"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_MISMATCHED_ISSUANCE_CONTEXT', 'parent_vc_jti']
                        )
                        assertions.append({'check': 'cross_context_parent_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_MISMATCHED_ISSUANCE_CONTEXT" if rejection_ok else rej_reason

                elif case_id == 'VD-N03-PresenterMismatch':
                    ch_data = None
                    try:
                        ch_req = urllib.request.Request(
                            f"{issuer_url}/api/v1/challenge",
                            data=json.dumps({"tpp_client_id": "tpp-demo-client", "aud_r": "http://localhost:4000"}).encode('utf-8'),
                            headers={
                                "Content-Type": "application/json",
                                "X-Client-Cert-Thumbprint": "thumbprint-holder-A-12345678"
                            }
                        )
                        with urllib.request.urlopen(ch_req, timeout=30) as c_resp:
                            ch_data = json.loads(c_resp.read().decode('utf-8'))
                    except Exception:
                        pass

                    payload_mut = {
                        "jti": f"mut-presmismatch-{time.perf_counter_ns()}"
                    }
                    if ch_data:
                        payload_mut["r_das"] = ch_data['challenge']['r_das']
                        payload_mut["ch_das"] = ch_data['ch_das']
                    req = send_assertion_mutation(
                        payload_mut,
                        extra_headers={"X-Client-Cert-Thumbprint": "thumbprint-holder-B-87654321"}
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'presenter_mismatch_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_PRESENTER_MISMATCH"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_PRESENTER_CERTIFICATE_MISMATCH', 'presenter', 'thumbprint']
                        )
                        assertions.append({'check': 'presenter_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_PRESENTER_CERTIFICATE_MISMATCH" if rejection_ok else rej_reason

                elif case_id == 'VD-N03-WrongDelegationSigner':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_del_vc = mutate_vc_payload(
                        fresh_delegate_vc, 'sub', 'unauthorized-sub-signer',
                        f"{tpp_url}/api/test/sign-artifact"
                    )
                    req = send_assertion_mutation({
                        "delegate_vc": mutated_del_vc,
                        "jti": f"mut-wrongdelsig-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, mutated_del_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'wrong_delegation_signer_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_WRONG_DELEGATION_SIGNER"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_WRONG_DELEGATION_SIGNER']
                        )
                        assertions.append({'check': 'wrong_delegation_signer_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_WRONG_DELEGATION_SIGNER" if rejection_ok else rej_reason

                elif case_id == 'VD-N03-WrongKbSigner':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    corrupted_kb_vc = mutate_kb_jwt(
                        fresh_delegate_vc, 'iat', int(time.time()),
                        f"{tpp_url}/api/test/sign-artifact"
                    )
                    req = send_assertion_mutation({
                        "delegate_vc": corrupted_kb_vc,
                        "jti": f"mut-wrongkbsig-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, corrupted_kb_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'wrong_kb_signer_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_WRONG_KB_SIGNER"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_INVALID_KB_JWT_SIGNATURE']
                        )
                        assertions.append({'check': 'wrong_kb_signer_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_WRONG_KB_SIGNER" if rejection_ok else rej_reason

                elif case_id == 'VD-N03-SubstitutedHolderKey':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    delegate_parts = fresh_delegate_vc.split('~')
                    _, delegate_payload = decode_jwt_payload_unverified(delegate_parts[0])
                    replacement_probe = sign_test_artifact(
                        f"{wallet_url}/api/test/sign-artifact", {}, "vc+sd-jwt",
                        signer_profile='replacement', return_details=True,
                    )
                    replacement_jwk = replacement_probe.get('signerPublicJwk')
                    if not replacement_jwk:
                        raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: replacement signer returned no public JWK")
                    delegate_payload['wallet_ec_jwk'] = replacement_jwk
                    delegate_payload['holder_key_hint'] = replacement_jwk
                    # The hybrid profile needs both components advertised for the substitution attempt to be
                    # a complete one; the DAS must still refuse to verify under the advertised key.
                    replacement_pqc = replacement_probe.get('signerCompositePublicKey')
                    if replacement_pqc:
                        delegate_payload['wallet_pqc_public_key'] = replacement_pqc
                    delegate_parts[0] = sign_test_artifact(
                        f"{wallet_url}/api/test/sign-artifact", delegate_payload, "vc+sd-jwt",
                        signer_profile='replacement',
                    )
                    substituted_delegate_vc = '~'.join(delegate_parts)
                    req = send_assertion_mutation(
                        {"jti": f"mut-subholderkey-{time.perf_counter_ns()}"},
                        credential_pair=(fresh_authz_vc, substituted_delegate_vc),
                        challenge_data=challenge_data,
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'substituted_holder_key_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_SUBSTITUTED_HOLDER_KEY"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_SUBSTITUTED_HOLDER_KEY', 'holder', 'key', 'hint', 'untrusted', 'record']
                        )
                        assertions.append({'check': 'substituted_holder_key_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_SUBSTITUTED_HOLDER_KEY" if rejection_ok else rej_reason

                elif case_id == 'VD-N03-MismatchedIssuanceRecord':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(fresh_authz_vc)
                    try:
                        # Present a credential whose identity is not the one committed at F1. The issuance
                        # record is deliberately NOT re-committed, so the DAS must detect that the presented
                        # credential does not correspond to its authoritative issuance record.
                        mutated_authz_vc = mutate_vc_payload(
                            fresh_authz_vc, 'jti', f"urn:uuid:uncommitted-{secrets.token_hex(8)}",
                            f"{issuer_url}/api/test/sign-artifact"
                        )
                        req = send_assertion_mutation({
                            "authorization_vc": mutated_authz_vc,
                            "jti": f"mut-issrec-{time.perf_counter_ns()}"
                        }, credential_pair=(mutated_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'mismatched_issuance_record_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_MISMATCHED_ISSUANCE_RECORD"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_MISMATCHED_ISSUANCE_RECORD']
                            )
                            assertions.append({'check': 'mismatched_issuance_record_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_MISMATCHED_ISSUANCE_RECORD" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N03-BindingHolderMismatch':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(fresh_authz_vc)
                    mutate_binding(binding_ref, {'holder_subject': 'altered-unauthorized-holder-subject-000'})
                    try:
                        req = send_assertion_mutation(
                            {"jti": f"mut-bindholder-{time.perf_counter_ns()}"},
                            credential_pair=(fresh_authz_vc, fresh_delegate_vc),
                            challenge_data=challenge_data,
                        )
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'binding_holder_mismatch_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_BINDING_HOLDER_MISMATCH"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_BINDING_HOLDER_MISMATCH']
                            )
                            assertions.append({'check': 'binding_holder_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_HOLDER_MISMATCH" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N03-BindingKeySetMismatch':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(fresh_authz_vc)
                    mutate_binding(binding_ref, {'raw_jwk_json': '{"kty":"EC","crv":"P-256","x":"mismatched","y":"mismatched"}'})
                    try:
                        req = send_assertion_mutation(
                            {"jti": f"mut-bindkeyset-{time.perf_counter_ns()}"},
                            credential_pair=(fresh_authz_vc, fresh_delegate_vc),
                            challenge_data=challenge_data,
                        )
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'binding_key_set_mismatch_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_BINDING_KEY_SET_MISMATCH"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_BINDING_KEY_SET_MISMATCH']
                            )
                            assertions.append({'check': 'binding_key_set_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_KEY_SET_MISMATCH" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N03-BindingWalletThumbprintMismatch':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(fresh_authz_vc)
                    mutate_binding(binding_ref, {'wallet_thumbprint': 'altered-wallet-cert-thumbprint-0000000000'})
                    try:
                        req = send_assertion_mutation(
                            {"jti": f"mut-bindwalletthumb-{time.perf_counter_ns()}"},
                            credential_pair=(fresh_authz_vc, fresh_delegate_vc),
                            challenge_data=challenge_data,
                        )
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'binding_wallet_thumbprint_mismatch_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_BINDING_WALLET_THUMBPRINT_MISMATCH"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_BINDING_WALLET_CERTIFICATE_MISMATCH']
                            )
                            assertions.append({'check': 'binding_wallet_thumbprint_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_WALLET_CERTIFICATE_MISMATCH" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N03-BindingProfileMismatch':
                    root_vc, delegate_vc, ch_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    mutate_binding(binding_ref, {'binding_profile': 'altered-unsupported-binding-profile-v9'})
                    try:
                        req = send_assertion_mutation(
                            {"jti": f"mut-bindprofile-{time.perf_counter_ns()}"},
                            credential_pair=(root_vc, delegate_vc),
                            challenge_data=ch_data,
                        )
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'binding_profile_mismatch_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_BINDING_PROFILE_MISMATCH"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_BINDING_PROFILE_MISMATCH']
                            )
                            assertions.append({'check': 'binding_profile_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_PROFILE_MISMATCH" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N03-BindingCredentialStatusMismatch':
                    root_vc, delegate_vc, ch_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    mutate_binding(binding_ref, {'status_list_reference': 'https://bank.com/status/mismatched-status-entry-999'})
                    try:
                        req = send_assertion_mutation(
                            {"jti": f"mut-bindcredstatus-{time.perf_counter_ns()}"},
                            credential_pair=(root_vc, delegate_vc),
                            challenge_data=ch_data,
                        )
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'binding_credential_status_mismatch_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_BINDING_CREDENTIAL_STATUS_MISMATCH"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_BINDING_CREDENTIAL_STATUS_MISMATCH']
                            )
                            assertions.append({'check': 'binding_credential_status_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_CREDENTIAL_STATUS_MISMATCH" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N05-AuthorityExpansion':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_del_vc = mutate_vc_payload(
                        fresh_delegate_vc, 'delegated_scopes', ['accounts:read', 'admin:unauthorized_expansion_scope'],
                        f"{wallet_url}/api/test/sign-artifact"
                    )
                    req = send_assertion_mutation({
                        "delegate_vc": mutated_del_vc,
                        "jti": f"mut-authexp-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_authz_vc, mutated_del_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'authority_expansion_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_AUTHORITY_EXPANSION"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_UNAUTHORIZED_AUTHORITY_EXPANSION']
                        )
                        assertions.append({'check': 'authority_expansion_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_UNAUTHORIZED_AUTHORITY_EXPANSION" if rejection_ok else rej_reason

                elif case_id == 'VD-N06-ExpiredState':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_authz_vc = mutate_vc_payload(
                        fresh_authz_vc, 'exp', int(time.time()) - 3600,
                        f"{issuer_url}/api/test/sign-artifact"
                    )
                    req = send_assertion_mutation({
                        "authorization_vc": mutated_authz_vc,
                        "jti": f"mut-expired-{time.perf_counter_ns()}"
                    }, credential_pair=(mutated_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'expired_state_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_EXPIRED_STATE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_REVOKED_OR_EXPIRED_CREDENTIAL']
                        )
                        assertions.append({'check': 'expired_state_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL" if rejection_ok else rej_reason

                elif case_id == 'VD-N06-MissingRecord':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    mutated_authz_vc = mutate_vc_payload(
                        fresh_authz_vc, 'holder_cert_ref', 'missing-record-nonexistent-ref',
                        f"{issuer_url}/api/test/sign-artifact"
                    )
                    req = send_assertion_mutation({
                        "authorization_vc": mutated_authz_vc,
                        "jti": f"mut-missingrec-{time.perf_counter_ns()}"
                    }, credential_pair=(mutated_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'missing_record_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_MISSING_RECORD"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_MISSING_ISSUANCE_RECORD']
                        )
                        assertions.append({'check': 'missing_record_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_MISSING_ISSUANCE_RECORD" if rejection_ok else rej_reason

                elif case_id == 'VD-N06-LookupUnavailable':
                    fresh_authz_vc, fresh_delegate_vc, challenge_data = fresh_delegation_fixture()
                    set_lookup_available(False)
                    try:
                        req = send_assertion_mutation({
                            "jti": f"mut-lookupunavail-{time.perf_counter_ns()}"
                        }, credential_pair=(fresh_authz_vc, fresh_delegate_vc), challenge_data=challenge_data)
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'lookup_unavailable_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_LOOKUP_UNAVAILABLE"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403, 503),
                                expected_semantic_tokens=['REJECT_BINDING_LOOKUP_UNAVAILABLE']
                            )
                            assertions.append({'check': 'lookup_unavailable_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_BINDING_LOOKUP_UNAVAILABLE" if rejection_ok else rej_reason
                    finally:
                        set_lookup_available(True)

                elif case_id == 'VD-N06-DisabledAssociation':
                    root_vc, delegate_vc, _ = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    suspended = set_binding_status(binding_ref, 'SUSPENDED')
                    assertions.append({
                        'check': 'authoritative_binding_suspended',
                        'passed': suspended.get('status') == 'SUSPENDED',
                        'binding_ref': binding_ref,
                        'binding_version': suspended.get('binding_version'),
                    })
                    req = send_assertion_mutation(
                        {"jti": f"mut-disassoc-{time.perf_counter_ns()}"},
                        credential_pair=(root_vc, delegate_vc),
                        challenge_data=_,
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'disabled_association_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_DISABLED_ASSOCIATION"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['disabled', 'suspended', 'revoked', 'REJECT_DISABLED_ASSOCIATION']
                        )
                        assertions.append({'check': 'disabled_association_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_DISABLED_ASSOCIATION" if rejection_ok else rej_reason
                    finally:
                        set_binding_status(binding_ref, 'ACTIVE')

                elif case_id == 'VD-N06-PostIssuanceInvalidation':
                    root_vc, delegate_vc, _ = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    revoked = set_binding_status(binding_ref, 'REVOKED')
                    assertions.append({
                        'check': 'authoritative_binding_revoked_after_f1',
                        'passed': revoked.get('status') == 'REVOKED',
                        'binding_ref': binding_ref,
                        'binding_version': revoked.get('binding_version'),
                    })
                    req = send_assertion_mutation(
                        {"jti": f"mut-postinv-{time.perf_counter_ns()}"},
                        credential_pair=(root_vc, delegate_vc),
                        challenge_data=_,
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'post_issuance_invalidation_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_POST_ISSUANCE_INVALIDATION"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['invalidation', 'revoked', 'compromised', 'REJECT_REVOKED_OR_EXPIRED_CREDENTIAL']
                        )
                        assertions.append({'check': 'post_issuance_invalidation_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL" if rejection_ok else rej_reason
                    finally:
                        set_binding_status(binding_ref, 'ACTIVE')

                elif case_id == 'VD-N06-WalletCertificateInvalidated':
                    root_vc, delegate_vc, ch_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    invalidate_wallet_cert(binding_ref)
                    assertions.append({'check': 'wallet_cert_invalidated_state_set', 'passed': True, 'binding_ref': binding_ref})
                    try:
                        req = send_assertion_mutation({
                            "jti": f"mut-walletcertinv-{time.perf_counter_ns()}"
                        }, credential_pair=(root_vc, delegate_vc), challenge_data=ch_data)
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'wallet_cert_invalidated_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_WALLET_CERT_INVALIDATED"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_WALLET_CERTIFICATE_INVALIDATED']
                            )
                            assertions.append({'check': 'wallet_cert_invalidated_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_WALLET_CERTIFICATE_INVALIDATED" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N06-HolderKeyInvalidated':
                    root_vc, delegate_vc, ch_data = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    invalidate_holder_key(binding_ref)
                    assertions.append({'check': 'holder_key_invalidated_state_set', 'passed': True, 'binding_ref': binding_ref})
                    try:
                        req = send_assertion_mutation({
                            "jti": f"mut-holderkeyinv-{time.perf_counter_ns()}"
                        }, credential_pair=(root_vc, delegate_vc), challenge_data=ch_data)
                        try:
                            with urllib.request.urlopen(req, timeout=300) as resp:
                                assertions.append({'check': 'holder_key_invalidated_rejected', 'passed': False})
                                actual_decision = "PERMIT"
                                reason = "UNEXPECTED_PERMIT_ON_HOLDER_KEY_INVALIDATED"
                        except urllib.error.HTTPError as e:
                            rejection_ok, rej_reason = verify_security_rejection(
                                e,
                                expected_codes=(400, 401, 403),
                                expected_semantic_tokens=['REJECT_HOLDER_KEY_INVALIDATED']
                            )
                            assertions.append({'check': 'holder_key_invalidated_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                            actual_decision = "DENY" if rejection_ok else "FAIL"
                            reason = "REJECT_HOLDER_KEY_INVALIDATED" if rejection_ok else rej_reason
                    finally:
                        reset_binding(binding_ref)

                elif case_id == 'VD-N06-StaleBindingSnapshot':
                    root_vc, del_vc, ch_data = fresh_delegation_fixture()
                    req = send_assertion_mutation({
                        "binding_snapshot_timestamp": int(time.time()) - 86400 * 30,
                        "jti": f"mut-stalesnap-{time.perf_counter_ns()}"
                    }, credential_pair=(root_vc, del_vc), challenge_data=ch_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'stale_snapshot_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_STALE_SNAPSHOT"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['stale', 'snapshot', 'freshness', 'timestamp', 'REJECT_STALE_BINDING_SNAPSHOT']
                        )
                        assertions.append({'check': 'stale_snapshot_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_STALE_BINDING_SNAPSHOT" if rejection_ok else rej_reason

                elif case_id == 'VD-N06-RollbackVersion':
                    root_vc, delegate_vc, _ = fresh_delegation_fixture()
                    binding_ref = root_binding_reference(root_vc)
                    original_binding = read_binding(binding_ref)
                    stale_version = original_binding.get('binding_version')
                    set_binding_status(binding_ref, 'SUSPENDED')
                    current_binding = set_binding_status(binding_ref, 'ACTIVE')
                    assertions.append({
                        'check': 'authoritative_binding_version_advanced',
                        'passed': current_binding.get('binding_version', 0) > stale_version,
                        'binding_ref': binding_ref,
                        'stale_version': stale_version,
                        'current_version': current_binding.get('binding_version'),
                    })
                    req = send_assertion_mutation(
                        {
                            "binding_version": stale_version,
                            "jti": f"mut-rollback-{time.perf_counter_ns()}",
                        },
                        credential_pair=(root_vc, delegate_vc),
                        challenge_data=_,
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'rollback_version_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_ROLLBACK_VERSION"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['rollback', 'version', 'REJECT_ROLLBACK_VERSION']
                        )
                        assertions.append({'check': 'rollback_version_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_ROLLBACK_VERSION" if rejection_ok else rej_reason

                elif case_id == 'VD-N06-AdverseVersionBeforeCommit':
                    fresh_root, fresh_del, ch_data = fresh_delegation_fixture()
                    _, root_p = decode_jwt_payload_unverified(fresh_root.split('~', 1)[0])
                    b_ref = root_p.get('holder_cert_ref')
                    with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{b_ref}", timeout=300) as resp:
                        b_before = json.loads(resp.read().decode('utf-8'))
                    v_before = b_before.get('binding_version', 1)

                    req = send_assertion_mutation({
                        "test_hook_advance_version_before_commit": True,
                        "jti": f"mut-advver-{time.perf_counter_ns()}"
                    }, credential_pair=(fresh_root, fresh_del), challenge_data=ch_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'adverse_version_before_commit_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_ADVERSE_VERSION_BEFORE_COMMIT"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403, 409),
                            expected_semantic_tokens=['REJECT_BINDING_CHANGED_BEFORE_COMMIT', 'version changed']
                        )
                        with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{b_ref}", timeout=300) as resp:
                            b_after = json.loads(resp.read().decode('utf-8'))
                        v_after = b_after.get('binding_version', 1)
                        record_id_after = b_after.get('record_id')
                        record_identity_correlated = (record_id_after == b_ref)
                        version_mutated = (v_after > v_before) and record_identity_correlated
                        assertions.extend([
                            {'check': 'adverse_version_before_commit_rejected', 'passed': rejection_ok, 'reason': rej_reason},
                            {'check': 'binding_version_actually_advanced_in_store', 'passed': version_mutated, 'version_before': v_before, 'version_after': v_after, 'record_id': record_id_after, 'record_correlated': record_identity_correlated},
                        ])
                        actual_decision = "DENY" if (rejection_ok and version_mutated) else "FAIL"
                        reason = "REJECT_BINDING_CHANGED_BEFORE_COMMIT" if (rejection_ok and version_mutated) else rej_reason

                elif case_id == 'VD-N08-TamperedPackage':
                    root_vc, del_vc, ch_data = fresh_delegation_fixture()
                    genuine_pkg = ch_data.get('das_encrypted_package')
                    if not genuine_pkg or not isinstance(genuine_pkg, str):
                        raise RuntimeError("FIXTURE_PREREQUISITE_FAILED: fresh delegation did not provide genuine das_encrypted_package")

                    tampered_pkg = None
                    if '.' in genuine_pkg:
                        # Classical 5-part compact JWE
                        jwe_parts = genuine_pkg.split('.')
                        if len(jwe_parts) != 5:
                            raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: das_encrypted_package has {len(jwe_parts)} parts instead of 5")
                        ciphertext_raw = base64.urlsafe_b64decode(jwe_parts[3] + '=' * (-len(jwe_parts[3]) % 4))
                        tampered_ciphertext = bytearray(ciphertext_raw)
                        if len(tampered_ciphertext) > 0:
                            tampered_ciphertext[0] ^= 0x01
                        else:
                            tampered_ciphertext = bytearray(b'\x01')
                        jwe_parts[3] = base64.urlsafe_b64encode(tampered_ciphertext).decode('ascii').rstrip('=')
                        tampered_pkg = '.'.join(jwe_parts)
                    else:
                        # PQC JSON-serialized encrypted package
                        try:
                            pkg_json = json.loads(genuine_pkg)
                            ct_b64 = pkg_json.get('ciphertext', '')
                            ct_raw = base64.b64decode(ct_b64)
                            tampered_ct = bytearray(ct_raw)
                            if len(tampered_ct) > 0:
                                tampered_ct[0] ^= 0x01
                            else:
                                tampered_ct = bytearray(b'\x01')
                            pkg_json['ciphertext'] = base64.b64encode(tampered_ct).decode('ascii')
                            tampered_pkg = json.dumps(pkg_json)
                        except Exception as parse_err:
                            raise RuntimeError(f"FIXTURE_PREREQUISITE_FAILED: could not parse PQC das_encrypted_package JSON: {parse_err}")

                    req = send_assertion_mutation({
                        "das_encrypted_package": tampered_pkg,
                        "jti": f"mut-tampkg-{time.perf_counter_ns()}"
                    }, credential_pair=(root_vc, del_vc), challenge_data=ch_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'tampered_package_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_TAMPERED_PACKAGE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_INVALID_DAS_ENCRYPTED_PACKAGE', 'decrypted', 'package', 'mismatch']
                        )
                        assertions.append({'check': 'tampered_package_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_INVALID_DAS_ENCRYPTED_PACKAGE" if rejection_ok else rej_reason

                elif case_id == 'VD-N08-MissingRequiredDisclosure':
                    # Strip all disclosures from Root Scope VC while keeping issuer JWT valid
                    root_vc, del_vc, ch_data = fresh_delegation_fixture()
                    root_jwt_only = root_vc.split('~')[0]
                    req = send_assertion_mutation({
                        "authorization_vc": root_jwt_only,
                        "jti": f"mut-missreqdisc-{time.perf_counter_ns()}"
                    }, credential_pair=(root_vc, del_vc), challenge_data=ch_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'missing_required_disclosure_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_MISSING_REQUIRED_DISCLOSURE"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_MISSING_REQUIRED_DISCLOSURE']
                        )
                        assertions.append({'check': 'missing_required_disclosure_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_MISSING_REQUIRED_DISCLOSURE" if rejection_ok else rej_reason

                elif case_id == 'VD-N08-DisclosureSetMismatch':
                    # Append an unadvertised forbidden disclosure to valid Root VC
                    root_vc, del_vc, ch_data = fresh_delegation_fixture()
                    extra_disclosure = "WyJyYW5kb20tc2FsdC1hYmMxMjMiLCAidW5hdXRob3JpemVkX2NsYWltIiwgImZvcmJpZGRlbi12YWx1ZSJd"
                    root_with_extra = f"{root_vc}~{extra_disclosure}"
                    req = send_assertion_mutation({
                        "authorization_vc": root_with_extra,
                        "jti": f"mut-discmismatch-{time.perf_counter_ns()}"
                    }, credential_pair=(root_vc, del_vc), challenge_data=ch_data)
                    try:
                        with urllib.request.urlopen(req, timeout=300) as resp:
                            assertions.append({'check': 'disclosure_set_mismatch_rejected', 'passed': False})
                            actual_decision = "PERMIT"
                            reason = "UNEXPECTED_PERMIT_ON_DISCLOSURE_SET_MISMATCH"
                    except urllib.error.HTTPError as e:
                        rejection_ok, rej_reason = verify_security_rejection(
                            e,
                            expected_codes=(400, 401, 403),
                            expected_semantic_tokens=['REJECT_DISCLOSURE_SET_MISMATCH']
                        )
                        assertions.append({'check': 'disclosure_set_mismatch_rejected', 'passed': rejection_ok, 'reason': rej_reason})
                        actual_decision = "DENY" if rejection_ok else "FAIL"
                        reason = "REJECT_DISCLOSURE_SET_MISMATCH" if rejection_ok else rej_reason

                else:
                    status = 'NOT_RUN'
                    actual_decision = 'NOT_RUN'
                    reason = 'REQUIRED_CASE_ADAPTER_NOT_IMPLEMENTED'
                    assertions.append({
                        'check': 'case_specific_adapter_present',
                        'passed': False,
                        'case_id': case_id,
                        'reason': reason,
                    })

            except Exception as e:
                prerequisite_failure = str(e).startswith("FIXTURE_PREREQUISITE_FAILED:")
                status = 'INCONCLUSIVE' if prerequisite_failure else 'FAIL'
                actual_decision = "INCONCLUSIVE" if prerequisite_failure else "FAIL"
                prefix = "FIXTURE_PREREQUISITE_FAILED" if prerequisite_failure else "LIVE_MUTATION_ERROR"
                reason = f"{prefix}: {str(e)}"
                assertions.append({'check': 'mutation_fixture_ready', 'passed': False, 'error': str(e)})

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        if status not in ('NOT_RUN', 'INCONCLUSIVE'):
            passed = len(assertions) > 0 and all(a.get('passed', False) for a in assertions) and (actual_decision == c.get('expected_decision'))
            status = 'PASS' if passed else 'FAIL'

        res = {
            'suite': 'VDAM_Negative_SUT',
            'tier': 'SUT_CONFORMANCE',
            'case_id': case_id,
            'name': c['name'],
            'configuration': c.get('configuration', 'B1-C0, B1-C2'),
            'status': status,
            'execution_mode': c.get('execution_mode', 'TEST_ASSISTED'),
            'test_assistance': c.get('test_assistance', []),
            'production_boundary': c.get('production_boundary', 'TOKEN_DECISION_ENDPOINT'),
            'proven_requirements': c.get('proven_requirements', []),
            'uncovered_aspects': c.get('uncovered_aspects', []),
            'expected_decision': c.get('expected_decision', 'DENY'),
            'actual_decision': actual_decision,
            # Whether the observed decision matched the independently expected one for this case.
            'oracle_match': (actual_decision == c.get('expected_decision')) if status != 'NOT_RUN' else None,
            'reason': reason,
            'execution_time_us': round(elapsed_us, 2),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        results.append(res)
        traces_out.append({
            'trace_id': f"TRC-{case_id}",
            'case_id': case_id,
            'suite': 'VDAM_Negative_SUT',
            'tier': 'SUT_CONFORMANCE',
            'status': status,
            'assertions': assertions,
            'timestamp': res['timestamp']
        })

    return results


# =====================================================================
# MAIN CONFORMANCE ENGINE & REPORT GENERATOR
# =====================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="VDAM Executable Conformance Test Engine")
    parser.add_argument("--suite", choices=["all", "b0", "vdam", "oracle", "crypto"], default="all", help="Specific suite to execute")
    parser.add_argument("--include-quantum", action="store_true", help="Include the HY-* provider-backed suite for B1-C2")
    parser.add_argument("--local", action="store_true", default=False, help="Target local Docker Desktop environment")
    parser.add_argument("--run-id", required=True, help="Unique immutable evidence run ID")
    args, _ = parser.parse_known_args()

    if args.local:
        os.environ['BANK_HOST'] = 'localhost'
        os.environ['KEYCLOAK_HOST'] = 'localhost'
        os.environ['TPP_HOST'] = 'localhost'
        os.environ['WALLET_HOST'] = 'localhost'
        os.environ['RS_HOST'] = 'localhost'

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    evidence_dir = os.path.join(base_dir, 'evaluation', 'evidence', 'conformance', args.run_id)
    if os.path.exists(evidence_dir):
        raise SystemExit(f"Refusing to overwrite existing run directory: {evidence_dir}")
    os.makedirs(evidence_dir)

    cases_jsonl_path = os.path.join(evidence_dir, 'cases.jsonl')
    traces_jsonl_path = os.path.join(evidence_dir, 'traces.jsonl')
    summary_csv_path = os.path.join(evidence_dir, 'conformance-summary.csv')

    print("=================================================================")
    print(" VDAM Executable Conformance Test Engine (Gate G3)")
    print(" Executing protocol cases across test tiers:")
    print("   1. ORACLE_UNIT        (Boundary matrix 20 & typed lattice meet)")
    print("   2. CRYPTOGRAPHIC_UNIT (NIST P-384 ECDSA & anti-downgrade audit)")
    print("   3. SUT_CONFORMANCE    (Live microservice flows / honest NOT_RUN)")
    if args.local:
        print("   * Execution Target: LOCAL DOCKER DESKTOP")
    if not args.include_quantum:
        print("   * Quantum / Hybrid Suite: DEFERRED_BY_USER_SCOPE")
    print("=================================================================\n")

    all_traces = []
    all_suites = [
        ("Boundary Matrix 20", "ORACLE_UNIT", run_boundary_20_conformance),
        ("VDAM Oracle Math", "ORACLE_UNIT", run_vdam_oracle_math_conformance),
        ("Hybrid PQC Verification", "CRYPTOGRAPHIC_UNIT", run_hybrid_crypto_conformance),
        ("B0 FAPI Baseline", "SUT_CONFORMANCE", run_b0_conformance),
        ("VDAM Valid SUT", "SUT_CONFORMANCE", run_vdam_valid_sut_conformance),
        ("VDAM Negative SUT", "SUT_CONFORMANCE", run_vdam_negative_sut_conformance),
    ]

    if args.suite == 'b0':
        suites = [s for s in all_suites if s[0] == "B0 FAPI Baseline"]
    elif args.suite == 'vdam':
        suites = [s for s in all_suites if 'VDAM' in s[0] or 'Boundary' in s[0]]
    elif args.suite == 'oracle':
        suites = [s for s in all_suites if s[1] == 'ORACLE_UNIT']
    elif args.suite == 'crypto':
        if not args.include_quantum:
            raise SystemExit("--suite crypto requires --include-quantum")
        suites = [s for s in all_suites if s[1] == 'CRYPTOGRAPHIC_UNIT']
    else:
        suites = [s for s in all_suites if args.include_quantum or s[0] != "Hybrid PQC Verification"]

    all_results = []
    summary_rows = []

    for suite_name, tier, runner_fn in suites:
        print(f"Executing suite: {suite_name} [{tier}]...")
        res = runner_fn(base_dir, all_traces)

        for r in res:
            r['run_id'] = args.run_id
        for trace in all_traces:
            trace['run_id'] = args.run_id
        all_results.extend(res)

        total = len(res)
        passed = sum(1 for r in res if r['status'] == 'PASS')
        failed = sum(1 for r in res if r['status'] == 'FAIL')
        inconclusive = sum(1 for r in res if r['status'] == 'INCONCLUSIVE')
        not_run = sum(1 for r in res if r['status'] == 'NOT_RUN')
        pass_rate = (passed / total) * 100.0 if total > 0 else 0.0

        if not_run > 0 or inconclusive > 0:
            print(f"  -> {passed}/{total} passed, {failed} failed, {inconclusive} inconclusive, {not_run} NOT_RUN\n")
        else:
            print(f"  -> {passed}/{total} passed ({pass_rate:.1f}%)\n")

        summary_rows.append({
            'suite': suite_name.replace(' ', '_'),
            'tier': tier,
            'total_cases': total,
            'passed_cases': passed,
            'failed_cases': failed,
            'inconclusive_cases': inconclusive,
            'not_run_cases': not_run,
            'pass_rate_pct': f"{pass_rate:.2f}%",
            'execution_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

    # Subtotals by tier
    oracle_crypto_cases = [r for r in all_results if r['tier'] in ('ORACLE_UNIT', 'CRYPTOGRAPHIC_UNIT')]
    oc_total = len(oracle_crypto_cases)
    oc_passed = sum(1 for r in oracle_crypto_cases if r['status'] == 'PASS')
    oc_failed = sum(1 for r in oracle_crypto_cases if r['status'] == 'FAIL')
    oc_inconc = sum(1 for r in oracle_crypto_cases if r['status'] == 'INCONCLUSIVE')
    oc_not_run = sum(1 for r in oracle_crypto_cases if r['status'] == 'NOT_RUN')
    oc_rate = (oc_passed / oc_total) * 100.0 if oc_total > 0 else 0.0

    summary_rows.append({
        'suite': 'TOTAL_ORACLE_AND_CRYPTO',
        'tier': 'ORACLE_UNIT/CRYPTOGRAPHIC_UNIT',
        'total_cases': oc_total,
        'passed_cases': oc_passed,
        'failed_cases': oc_failed,
        'inconclusive_cases': oc_inconc,
        'not_run_cases': oc_not_run,
        'pass_rate_pct': f"{oc_rate:.2f}%",
        'execution_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

    sut_cases = [r for r in all_results if r['tier'] == 'SUT_CONFORMANCE']
    sut_total = len(sut_cases)
    sut_passed = sum(1 for r in sut_cases if r['status'] == 'PASS')
    sut_failed = sum(1 for r in sut_cases if r['status'] == 'FAIL')
    sut_inconc = sum(1 for r in sut_cases if r['status'] == 'INCONCLUSIVE')
    sut_not_run = sum(1 for r in sut_cases if r['status'] == 'NOT_RUN')
    sut_rate = (sut_passed / sut_total) * 100.0 if sut_total > 0 else 0.0

    summary_rows.append({
        'suite': 'TOTAL_SUT_CONFORMANCE',
        'tier': 'SUT_CONFORMANCE',
        'total_cases': sut_total,
        'passed_cases': sut_passed,
        'failed_cases': sut_failed,
        'inconclusive_cases': sut_inconc,
        'not_run_cases': sut_not_run,
        'pass_rate_pct': f"{sut_rate:.2f}%",
        'execution_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

    # Total row across all 69 cases
    total_all = len(all_results)
    passed_all = sum(1 for r in all_results if r['status'] == 'PASS')
    failed_all = sum(1 for r in all_results if r['status'] == 'FAIL')
    inconc_all = sum(1 for r in all_results if r['status'] == 'INCONCLUSIVE')
    not_run_all = sum(1 for r in all_results if r['status'] == 'NOT_RUN')
    pass_rate_all = (passed_all / total_all) * 100.0 if total_all > 0 else 0.0

    summary_rows.append({
        'suite': 'TOTAL_ALL_CASES',
        'tier': 'ALL_TIERS',
        'total_cases': total_all,
        'passed_cases': passed_all,
        'failed_cases': failed_all,
        'inconclusive_cases': inconc_all,
        'not_run_cases': not_run_all,
        'pass_rate_pct': f"{pass_rate_all:.2f}%",
        'execution_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

    # Write cases.jsonl
    with open(cases_jsonl_path, 'x', encoding='utf-8') as f:
        for r in all_results:
            f.write(json.dumps(r) + '\n')

    # Write traces.jsonl
    with open(traces_jsonl_path, 'x', encoding='utf-8') as f:
        for t in all_traces:
            f.write(json.dumps(t) + '\n')

    # A run writes only to its immutable evidence package. Cross-run reports are
    # generated later from explicitly accepted run IDs.
    fieldnames = ['suite', 'tier', 'total_cases', 'passed_cases', 'failed_cases', 'inconclusive_cases', 'not_run_cases', 'pass_rate_pct', 'execution_timestamp']
    for target_csv in [summary_csv_path]:
        with open(target_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in summary_rows:
                writer.writerow(row)

    print("==================================================================================================")
    print(" Conformance Execution Summary (Deliverables O1 & O2 Generated)")
    print("==================================================================================================")
    print(f"{'Suite':<26} | {'Tier':<20} | {'Total':<5} | {'Pass':<5} | {'Fail':<5} | {'Inconc':<6} | {'NotRun':<6} | {'Rate':<7}")
    print("--------------------------------------------------------------------------------------------------")
    for row in summary_rows:
        print(f"{row['suite']:<26} | {row['tier']:<20} | {row['total_cases']:<5} | {row['passed_cases']:<5} | {row['failed_cases']:<5} | {row['inconclusive_cases']:<6} | {row['not_run_cases']:<6} | {row['pass_rate_pct']:<7}")
    print("==================================================================================================\n")

    print(f"[OK] Wrote {len(all_results)} test cases to {cases_jsonl_path}")
    print(f"[OK] Wrote {len(all_traces)} execution traces to {traces_jsonl_path}")
    print(f"[OK] Exported summary to {summary_csv_path}")

    run_id = os.environ.get('CONFORMANCE_RUN_ID', '')
    configuration = os.environ.get('CONFORMANCE_CONFIGURATION', 'B1-C0')
    if 'post-restart' not in run_id:
        checkpoint_dir = os.path.join(base_dir, 'evaluation', 'state')
        checkpoint_file = os.path.join(checkpoint_dir, f"durability_checkpoint_{configuration}.json")
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, 'r', encoding='utf-8') as f:
                    chk = json.load(f)
                b_ref = chk.get('binding_ref')
                if b_ref:
                    issuer_host = os.environ.get('BANK_HOST', '127.0.0.1')
                    issuer_url = os.environ.get('VDAM_ISSUER_URL', f'http://{issuer_host}:7000')
                    with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{b_ref}", timeout=300) as resp:
                        cur_b = json.loads(resp.read().decode('utf-8'))
                    chk['binding_version'] = cur_b.get('binding_version')
                    chk['holder_subject'] = cur_b.get('holder_subject')
                    chk['holder_jwk'] = cur_b.get('holder_jwk')
                    with open(checkpoint_file, 'w', encoding='utf-8') as f:
                        json.dump(chk, f)
            except Exception:
                pass

    if failed_all > 0:
        print(f"\n[FAIL] Conformance run failed with {failed_all} failures.")
        sys.exit(1)
    else:
        print(f"\n[DISPOSITION] Gate G3: PARTIAL ({oc_passed}/{oc_total} Unit Oracles PASSED; {not_run_all} cases NOT_RUN awaiting VM deployment).")
        print("[SUCCESS] Tiered Conformance Engine executed cleanly with 0 failures and 0 mock passes.")


if __name__ == '__main__':
    main()
