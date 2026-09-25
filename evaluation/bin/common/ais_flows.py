#!/usr/bin/env python3
"""Shared AIS authorization-flow library for the BP-v3 runners.

Holds the source-defined OAuth / VDAM flows as plain Python functions:

  - B0-C0 : FAPI 2.0 authorization code + PKCE + PAR + mTLS  (execute_fapi_pkce_flow)
  - B1-*  : VDAM F1 root-VC issuance                         (execute_vdam_f1_oid4vci_flow)
            VDAM F2-F4 delegation and PoP token issuance     (execute_vdam_delegation_flow)

Consumers: conformance_runner (E-CONF), measure_artifacts (one-shot artifact/network
sizes), session_isolation_live (overlapping-transaction proof), and run_perf (F1
provisioning of the root VC that the k6 load script then reuses).

Nothing here measures CPU, memory, or storage, and nothing here calls the resource
server for performance purposes: the perf experiments stop at access-token issuance.
"""

import argparse
import base64
import csv
import datetime
import hashlib
import html
import http.cookiejar
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Dict, List, Optional, Tuple

# Every client-facing endpoint is an HTTPS proxy with a development certificate, so urllib calls
# that pass no explicit context skip certificate verification (as the k6 script does).
ssl._create_default_https_context = ssl._create_unverified_context

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


def create_mtls_ssl_context(base_dir, model='B0-C0'):
    cert_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'tpp.crt')
    key_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'tpp.key')
    ca_path = os.path.join(base_dir, 'traditional-fapi', 'certs', 'ca.crt')
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path if os.path.exists(ca_path) else None)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def build_artifact_measurement(run_id, model, state_mode, attempt, artifact_name, artifact_type, content_bytes):
    if isinstance(content_bytes, str):
        content_bytes = content_bytes.encode('utf-8')
    
    if artifact_name == 'delegation_vc' and b'.' not in content_bytes:
        return {
            'run_id': run_id,
            'window_id': 'workload',
            'model': model,
            'state_mode': state_mode,
            'attempt': attempt,
            'artifact_name': artifact_name,
            'artifact_type': artifact_type,
            'size_bytes': None,
            'sha256_digest': None,
            'availability': 'UNAVAILABLE',
            'missing_reason': 'BACKEND_RETURNS_JTI_ONLY',
            'measurement_method': 'jti_string_returned',
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    digest = hashlib.sha256(content_bytes).hexdigest()
    return {
        'run_id': run_id,
        'window_id': 'workload',
        'model': model,
        'state_mode': state_mode,
        'attempt': attempt,
        'artifact_name': artifact_name,
        'artifact_type': artifact_type,
        'size_bytes': len(content_bytes),
        'sha256_digest': digest,
        'availability': 'AVAILABLE',
        'missing_reason': '',
        'measurement_method': 'serialized_credential_hash',
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


def compute_exchange_wire_bytes(req, resp, resp_body=b''):
    """
    Computes exact HTTP protocol wire bytes for a request/response exchange:
    - Request line: METHOD selector HTTP/1.1\r\n
    - Request headers: Host + custom headers + \r\n
    - Request body
    - Response status line: HTTP/1.1 STATUS REASON\r\n
    - Response headers
    - Response body
    """
    method = req.get_method() if hasattr(req, 'get_method') else 'GET'
    selector = getattr(req, 'selector', '')
    req_line = f"{method} {selector} HTTP/1.1\r\n".encode('ascii', errors='replace')
    host = getattr(req, 'host', '')
    host_hdr = f"Host: {host}\r\n".encode('ascii', errors='replace') if host else b""
    header_items = req.header_items() if hasattr(req, 'header_items') else []
    hdrs = b"".join(f"{k}: {v}\r\n".encode('ascii', errors='replace') for k, v in header_items)
    req_body_bytes = req.data if getattr(req, 'data', None) else b""
    req_wire = len(req_line) + len(host_hdr) + len(hdrs) + 2 + len(req_body_bytes)

    resp_status = getattr(resp, 'status', 200)
    resp_reason = getattr(resp, 'reason', 'OK')
    resp_line = f"HTTP/1.1 {resp_status} {resp_reason}\r\n".encode('ascii', errors='replace')
    try:
        resp_hdr_bytes = resp.headers.as_bytes()
    except Exception:
        resp_headers = getattr(resp, 'headers', None)
        if resp_headers and hasattr(resp_headers, 'items'):
            resp_hdr_bytes = b"".join(f"{k}: {v}\r\n".encode('ascii', errors='replace') for k, v in resp_headers.items()) + b"\r\n"
        else:
            resp_hdr_bytes = b"\r\n"

    resp_wire = len(resp_line) + len(resp_hdr_bytes) + len(resp_body)
    return req_wire + resp_wire


CANONICAL_MODELS = {
    'b0': 'B0-C0',
    'b1': 'B1-C0',
    'b2': 'B1-C2'
}


def compute_cert_thumbprint(cert_path):
    with open(cert_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if not line.strip().startswith('-----')]
    der = base64.b64decode(''.join(lines))
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode('ascii').rstrip('=')


ALLOWED_CANONICAL_FIELDS = {
    'account_id', 'AccountId', 'id', 'accountNumber',
    'balance', 'Balance', 'amount', 'Amount',
    'currency', 'Currency', 'date', 'Date',
    'type', 'Type', 'operation', 'Operation',
    'status', 'Status', 'nickname', 'Nickname'
}


def get_ssl_context(cert_file=None, key_file=None, ca_file=None, allow_insecure_dev=False):
    """
    Strict TLS Context Builder (R3-05):
    - Strict by default: requires valid CA certificate.
    - Missing CA file or missing client credentials fail closed immediately.
    - Insecure dev bypass requires explicit allow_insecure_dev opt-in.
    """
    if allow_insecure_dev:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_file:
        if not os.path.exists(ca_file):
            raise FileNotFoundError(f"Strict TLS Error: CA certificate file not found: {ca_file}")
        ctx = ssl.create_default_context(cafile=ca_file)
        if os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') == '0' or allow_insecure_dev:
            ctx.check_hostname = False
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
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


def validate_resource_payload(raw_bytes_or_json, expected_accounts=None, expected_fields=None, require_exact_accounts=False):
    """
    Validates that the Resource Server returned a genuine Open Banking accounts payload (R3-03, R4-04, R5-03, R6-03).
    Strictly enforces:
      1. Valid non-empty JSON object.
      2. Envelope inspection: only approved envelope keys allowed ('data', 'meta', 'links', 'risk').
         - meta and links are deeply validated and cannot leak customer attributes.
         - Prohibited sensitive keys (ssn, tax_id, pin, secret, etc.) fail closed anywhere in payload.
      3. Strict account isolation:
         - If expected_accounts == []: zero accounts permitted (rejects ACC-001 etc.).
         - Returned account IDs must be within approved expected_accounts.
         - Optional require_exact_accounts check for full completeness vs pagination subset.
      4. Exact typing & numeric verification:
         - balance, amount, and value fields must be valid numeric values (int, float, or parseable string).
      5. Projection and field presence:
         - All returned fields must be within effective_fields and ALLOWED_CANONICAL_FIELDS.
         - All expected_fields must be present in every returned account.
    """
    if not raw_bytes_or_json:
        raise RuntimeError("EMPTY_RESOURCE_PAYLOAD: RS returned empty or zero-byte response")

    if isinstance(raw_bytes_or_json, bytes):
        try:
            data = json.loads(raw_bytes_or_json.decode('utf-8'))
        except Exception as e:
            raise RuntimeError(f"RS response is not valid JSON: {e}")
    elif isinstance(raw_bytes_or_json, dict):
        data = raw_bytes_or_json
    else:
        raise RuntimeError(f"Unexpected RS payload type: {type(raw_bytes_or_json)}")

    if not data or not isinstance(data, dict):
        raise RuntimeError("RS returned empty or invalid JSON payload")

    # If payload is wrapped by TPP client controller ({status: 200, success: true, data: { ... RS Response ... }})
    if 'status' in data and 'data' in data:
        if data.get('status') != 200 or data.get('success') is not True:
            raise RuntimeError(f"FAIL_CLOSED_VALIDATION_ERROR: TPP wrapper status={data.get('status')}, success={data.get('success')}")
        if 'error' in data or 'error_description' in data:
            raise RuntimeError(f"FAIL_CLOSED_VALIDATION_ERROR: TPP wrapper contains error: {data.get('error')}")
        for k in data.keys():
            if k not in {'status', 'success', 'data'}:
                raise RuntimeError(f"FAIL_CLOSED_VALIDATION_ERROR: Unexpected root key in TPP wrapper: '{k}'")
        if not isinstance(data['data'], dict):
            raise RuntimeError(f"FAIL_CLOSED_VALIDATION_ERROR: TPP wrapper 'data' field is not a JSON object")
        data = data['data']

    # R10-02: Prohibit duplicate case variants at root envelope level
    root_keys_lower = {}
    for k in data.keys():
        kl = k.lower()
        if kl in root_keys_lower:
            raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant root field detected: '{k}' and '{root_keys_lower[kl]}'")
        root_keys_lower[kl] = k

    # R10-02: Prohibit parallel account root branches (e.g. data AND accounts simultaneously)
    has_data_root = ('data' in data or 'Data' in data)
    has_accounts_root = ('accounts' in data or 'Accounts' in data)
    if has_data_root and has_accounts_root:
        raise RuntimeError("AMBIGUOUS_RESPONSE_PAYLOAD: Parallel account branches ('data' and 'accounts') present simultaneously in root envelope")

    # Top-level root envelope and prohibited leak checks (R5-03, R6-03, R7-03, R10-02)
    ALLOWED_ENVELOPE_KEYS = {'data', 'Data', 'meta', 'Meta', 'links', 'Links', 'risk', 'Risk', 'accounts', 'Accounts'}
    ALLOWED_META_KEYS = {'TotalPages', 'totalPages', 'FirstPage', 'firstPage', 'LastPage', 'lastPage', 'TotalResults', 'totalResults', 'CurrentPage', 'currentPage', 'AppliedProtocol', 'appliedProtocol', 'Timestamp', 'timestamp'}
    ALLOWED_LINKS_KEYS = {'Self', 'self', 'First', 'first', 'Prev', 'prev', 'Next', 'next', 'Last', 'last'}
    ALLOWED_RISK_KEYS = {
        'PaymentContextCode', 'paymentContextCode',
        'MerchantCategoryCode', 'merchantCategoryCode',
        'MerchantCustomerIdentification', 'merchantCustomerIdentification',
        'DeliveryAddress', 'deliveryAddress',
        'ContractPresentIndicator', 'contractPresentIndicator'
    }
    FORBIDDEN_LEAK_KEYS = {'ssn', 'social_security', 'tax_id', 'pin', 'password', 'secret', 'cvv', 'card_number', 'private_key', 'email'}

    def check_forbidden_leaks(val, path=""):
        if isinstance(val, dict):
            for k, v in val.items():
                sub_path = f"{path}.{k}" if path else str(k)
                if str(k).lower() in FORBIDDEN_LEAK_KEYS:
                    raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: Prohibited sensitive field '{sub_path}' leaked in payload")
                check_forbidden_leaks(v, sub_path)
        elif isinstance(val, list):
            for idx, elem in enumerate(val):
                check_forbidden_leaks(elem, f"{path}[{idx}]")

    check_forbidden_leaks(data)

    wrapper_data = data.get('data') if data.get('data') is not None else data.get('Data')
    if wrapper_data is not None and isinstance(wrapper_data, dict):
        wrap_keys_lower = {}
        for dk in wrapper_data.keys():
            dkl = dk.lower()
            if dkl in wrap_keys_lower:
                raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant field in data wrapper: '{dk}' and '{wrap_keys_lower[dkl]}'")
            wrap_keys_lower[dkl] = dk

        ALLOWED_DATA_WRAPPER_KEYS = {'Account', 'account', 'Accounts', 'accounts'}
        for dk in wrapper_data.keys():
            if dk not in ALLOWED_DATA_WRAPPER_KEYS:
                raise RuntimeError(
                    f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved sibling field '{dk}' in data wrapper"
                )

        # R10-02: Prohibit parallel singular and plural account branches in wrapper
        has_singular = ('Account' in wrapper_data or 'account' in wrapper_data)
        has_plural = ('Accounts' in wrapper_data or 'accounts' in wrapper_data)
        if has_singular and has_plural:
            raise RuntimeError("AMBIGUOUS_RESPONSE_PAYLOAD: Parallel account branches ('Account' and 'Accounts') present simultaneously in data wrapper")

    for k, v in data.items():
        if k not in ALLOWED_ENVELOPE_KEYS:
            raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved root envelope field '{k}'")
        if k in ('meta', 'Meta'):
            if not isinstance(v, dict):
                raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Root field '{k}' must be an object")
            meta_keys_lower = {}
            for mk, mv in v.items():
                mkl = mk.lower()
                if mkl in meta_keys_lower:
                    raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant field in meta: '{mk}' and '{meta_keys_lower[mkl]}'")
                meta_keys_lower[mkl] = mk
                if mk not in ALLOWED_META_KEYS:
                    raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved meta field '{k}.{mk}'")
                if mk in ('AppliedProtocol', 'appliedProtocol', 'Timestamp', 'timestamp'):
                    if not isinstance(mv, str):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Meta field '{k}.{mk}' must be a string: {mv}")
                else:
                    # Strict typing for pagination counts: must be non-negative integer (R8-03)
                    if not isinstance(mv, (int, str)) or isinstance(mv, bool):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Meta field '{k}.{mk}' must be an integer: {mv}")
                    try:
                        iv = int(mv)
                        if iv < 0:
                            raise ValueError("negative")
                    except (ValueError, TypeError):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Meta field '{k}.{mk}' must be a non-negative integer: '{mv}'")
        elif k in ('links', 'Links'):
            if not isinstance(v, dict):
                raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Root field '{k}' must be an object")
            links_keys_lower = {}
            for lk, lv in v.items():
                lkl = lk.lower()
                if lkl in links_keys_lower:
                    raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant field in links: '{lk}' and '{links_keys_lower[lkl]}'")
                links_keys_lower[lkl] = lk
                if lk not in ALLOWED_LINKS_KEYS:
                    raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved links field '{k}.{lk}'")
                if not isinstance(lv, str):
                    raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Link URL '{k}.{lk}' must be a string")
        elif k in ('risk', 'Risk'):
            if not isinstance(v, dict):
                raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Root field '{k}' must be an object")
            ALLOWED_RISK_DELIVERY_ADDRESS_KEYS = {
                'AddressLine', 'addressLine', 'StreetName', 'streetName',
                'BuildingNumber', 'buildingNumber', 'PostCode', 'postCode',
                'TownName', 'townName', 'CountrySubDivision', 'countrySubDivision',
                'Country', 'country'
            }
            risk_keys_lower = {}
            for rk, rv in v.items():
                rkl = rk.lower()
                if rkl in risk_keys_lower:
                    raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant field in risk: '{rk}' and '{risk_keys_lower[rkl]}'")
                risk_keys_lower[rkl] = rk
                if rk not in ALLOWED_RISK_KEYS:
                    raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved risk field '{k}.{rk}'")
                if rk in ('DeliveryAddress', 'deliveryAddress'):
                    if not isinstance(rv, dict):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Risk field '{k}.{rk}' must be an object")
                    deliv_keys_lower = {}
                    for ak, av in rv.items():
                        akl = ak.lower()
                        if akl in deliv_keys_lower:
                            raise RuntimeError(f"AMBIGUOUS_RESPONSE_PAYLOAD: Duplicate case-variant field in DeliveryAddress: '{ak}' and '{deliv_keys_lower[akl]}'")
                        deliv_keys_lower[akl] = ak
                        if ak not in ALLOWED_RISK_DELIVERY_ADDRESS_KEYS:
                            raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved delivery address field '{k}.{rk}.{ak}'")
                        # R9-04: Validate nested typed content inside DeliveryAddress
                        if ak in ('AddressLine', 'addressLine'):
                            if isinstance(av, list):
                                if not all(isinstance(item, str) for item in av):
                                    raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Address line items in '{k}.{rk}.{ak}' must be strings")
                            elif not isinstance(av, str):
                                raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Address line field '{k}.{rk}.{ak}' must be a string or array of strings, got {type(av).__name__}")
                        else:
                            if not isinstance(av, str):
                                raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Address subfield '{k}.{rk}.{ak}' must be a string, got {type(av).__name__}")
                elif rk in ('MerchantCustomerIdentification', 'merchantCustomerIdentification'):
                    # R10-02: Strict typing - must be string, cannot be dict/object or sensitive attribute bag
                    if not isinstance(rv, str):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Risk field '{k}.{rk}' must be a string, got {type(rv).__name__}")
                elif rk in ('PaymentContextCode', 'paymentContextCode'):
                    if not isinstance(rv, str):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Risk field '{k}.{rk}' must be a string, got {type(rv).__name__}")
                elif rk in ('MerchantCategoryCode', 'merchantCategoryCode'):
                    if not isinstance(rv, (str, int)) or isinstance(rv, bool):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Risk field '{k}.{rk}' must be a string or integer, got {type(rv).__name__}")
                elif rk in ('ContractPresentIndicator', 'contractPresentIndicator'):
                    if not isinstance(rv, (bool, str)):
                        raise RuntimeError(f"INVALID_ENVELOPE_FORMAT: Risk field '{k}.{rk}' must be a boolean or string, got {type(rv).__name__}")

    # R9-04 & R10-02: Zero-authority assertion: RS must not disclose accounts, delivery details, or merchant customer ID
    if expected_accounts is not None and len(expected_accounts) == 0:
        if 'risk' in data or 'Risk' in data:
            risk_obj = data.get('risk') or data.get('Risk')
            if isinstance(risk_obj, dict):
                deliv = risk_obj.get('DeliveryAddress') or risk_obj.get('deliveryAddress')
                if deliv is not None:
                    if isinstance(deliv, (dict, list)):
                        if len(deliv) > 0:
                            raise RuntimeError("UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed delivery address details")
                    elif str(deliv).strip() != "":
                        raise RuntimeError("UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed delivery address details")
                mcid = risk_obj.get('MerchantCustomerIdentification') or risk_obj.get('merchantCustomerIdentification')
                if mcid is not None and str(mcid).strip() != "":
                    raise RuntimeError("UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed MerchantCustomerIdentification")

    # R10-02: Exact extraction based on mutually exclusive root key
    if has_data_root:
        if isinstance(wrapper_data, dict):
            items = wrapper_data.get('Account') if 'Account' in wrapper_data else (
                wrapper_data.get('account') if 'account' in wrapper_data else (
                    wrapper_data.get('Accounts') if 'Accounts' in wrapper_data else wrapper_data.get('accounts')
                )
            )
        else:
            items = wrapper_data
    elif has_accounts_root:
        items = data.get('accounts') if 'accounts' in data else data.get('Accounts')
    else:
        items = None

    # R4-04, R6-03, R7-03 & R8-03: Strict handling when expected_accounts is empty (zero authority)
    if expected_accounts is not None and len(expected_accounts) == 0:
        if items is not None:
            if isinstance(items, (list, dict)):
                if len(items) > 0:
                    raise RuntimeError(
                        f"UNAUTHORIZED_ACCOUNT_IN_RESPONSE: Zero accounts authorized, but RS disclosed {len(items)} accounts"
                    )
            else:
                if str(items).strip() != "":
                    raise RuntimeError(
                        f"UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed scalar content: {items}"
                    )
        if wrapper_data is not None:
            if isinstance(wrapper_data, (list, dict)):
                if isinstance(wrapper_data, dict):
                    for dk in wrapper_data.keys():
                        if dk not in ('Account', 'accounts'):
                            raise RuntimeError(
                                f"UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed unexpected field '{dk}'"
                            )
                        sub_items = wrapper_data[dk]
                        if sub_items and len(sub_items) > 0:
                            raise RuntimeError(
                                f"UNAUTHORIZED_ACCOUNT_IN_RESPONSE: Zero accounts authorized, but RS disclosed accounts: {sub_items}"
                            )
                elif len(wrapper_data) > 0:
                    raise RuntimeError(
                        f"UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed list: {wrapper_data}"
                    )
            else:
                if str(wrapper_data).strip() != "":
                    raise RuntimeError(
                        f"UNAUTHORIZED_CONTENT_IN_RESPONSE: Zero accounts authorized, but RS disclosed scalar content: {wrapper_data}"
                    )
        return data

    if items is None:
        raise RuntimeError(f"RS payload missing accounts array (keys found: {list(data.keys())})")

    if not isinstance(items, list) or len(items) == 0:
        raise RuntimeError("RS returned empty accounts list")

    # Determine effective allowed field projection (R4-04 & R5-03)
    if expected_fields is not None:
        effective_allowed_fields = set(str(f) for f in expected_fields).intersection(ALLOWED_CANONICAL_FIELDS)
    else:
        effective_allowed_fields = set(ALLOWED_CANONICAL_FIELDS)

    # Core canonical identifier keys allowed in Open Banking account representations (R11-02: deterministic tuple)
    CANONICAL_ID_KEYS = ('account_id', 'AccountId', 'id', 'accountNumber')

    # Monetary sub-attributes permitted only if financial values are in projection (R5-03)
    financial_fields_allowed = any(f in effective_allowed_fields for f in ('balance', 'amount', 'currency', 'value'))
    allowed_sub_attrs = {'schemeName', 'identification', 'type'}
    if financial_fields_allowed:
        allowed_sub_attrs.update({'amount', 'currency', 'value'})

    # Scalar fields that must not carry nested structures (R11-02)
    SCALAR_FIELD_NAMES = {'date', 'currency', 'type', 'description', 'status', 'schemeName', 'identification'}

    # Recursive nested object inspector to detect unauthorized fields anywhere in the structure (R4-04, R5-03, R11-02)
    def check_recursive_fields(val, path=""):
        if isinstance(val, dict):
            for k, v in val.items():
                sub_path = f"{path}.{k}" if path else k
                if k not in effective_allowed_fields and k not in CANONICAL_ID_KEYS and k not in allowed_sub_attrs:
                    raise RuntimeError(f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved nested field '{sub_path}'")
                if k in SCALAR_FIELD_NAMES and isinstance(v, (dict, list)):
                    raise RuntimeError(f"INVALID_FIELD_TYPE: Scalar field '{sub_path}' must not contain nested object/array: {v}")
                check_recursive_fields(v, sub_path)
        elif isinstance(val, list):
            for idx, elem in enumerate(val):
                check_recursive_fields(elem, f"{path}[{idx}]")

    returned_accounts = []
    for acc in items:
        if not isinstance(acc, dict):
            raise RuntimeError(f"RS account item is not an object: {acc}")

        # Deterministic identification & alias conflict detection across all process seeds (R11-02)
        present_id_keys = [k for k in CANONICAL_ID_KEYS if k in acc]
        if not present_id_keys:
            raise RuntimeError(f"RS account item missing required account identifier: {acc}")

        id_values = {str(acc[k]) for k in present_id_keys}
        if len(id_values) > 1:
            raise RuntimeError(
                f"CONFLICTING_ACCOUNT_IDENTIFIERS: Record contains conflicting identifier aliases: "
                f"{[f'{k}={acc[k]}' for k in present_id_keys]}"
            )

        acc_id = str(acc[present_id_keys[0]])

        # Verify EVERY present alias is authorized against expected_accounts
        if expected_accounts is not None:
            for val in id_values:
                if val not in expected_accounts:
                    raise RuntimeError(
                        f"UNAUTHORIZED_RESOURCE_OVERDISCLOSURE: Account alias '{val}' is outside authorized set: {expected_accounts}"
                    )

        returned_accounts.append(acc_id)

        # Top-level field overdisclosure check against effective_allowed_fields (R4-04)
        for field in acc.keys():
            if field in CANONICAL_ID_KEYS:
                continue
            if field not in effective_allowed_fields:
                raise RuntimeError(
                    f"UNAUTHORIZED_FIELD_OVERDISCLOSURE: RS returned unapproved field '{field}' on account {acc_id} "
                    f"(effective allowed projection: {sorted(list(effective_allowed_fields))})"
                )

        # Recursive sub-structure check (detecting nested leaks like {"balance": {"ssn": "..."}})
        check_recursive_fields(acc, f"Account[{acc_id}]")

        # Strict typing & finite numeric verification (R6-03, R7-03, R8-03)
        for num_field in ('balance', 'amount', 'value'):
            if num_field in acc:
                num_val = acc[num_field]
                if isinstance(num_val, bool):
                    raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}' cannot be boolean")
                elif isinstance(num_val, (int, float)):
                    if not math.isfinite(num_val):
                        raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}' has non-finite value: '{num_val}'")
                elif isinstance(num_val, str):
                    try:
                        fv = float(num_val)
                        if not math.isfinite(fv):
                            raise ValueError()
                    except ValueError:
                        raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}' is not a valid finite number: '{num_val}'")
                elif isinstance(num_val, dict):
                    # Validate ALL numeric subfields present (amount, value)
                    has_numeric_sub = False
                    for subk in ('amount', 'value'):
                        if subk in num_val:
                            sub_amt = num_val[subk]
                            if isinstance(sub_amt, bool):
                                raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}.{subk}' cannot be boolean")
                            try:
                                fv = float(str(sub_amt))
                                if not math.isfinite(fv):
                                    raise ValueError()
                            except (ValueError, TypeError):
                                raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}.{subk}' is not a valid finite number: '{sub_amt}'")
                            has_numeric_sub = True
                    if not has_numeric_sub:
                        raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}' missing amount/value subfield")
                else:
                    raise RuntimeError(f"INVALID_FIELD_TYPE: RS account {acc_id} field '{num_field}' has invalid non-numeric type {type(num_val).__name__}")

    # Enforce presence of required requested fields (R5-03 & R6-03)
    if expected_fields is not None:
        for req_field in expected_fields:
            for acc in items:
                acc_id_val = acc.get('account_id') or acc.get('AccountId') or 'unknown'
                if req_field in CANONICAL_ID_KEYS:
                    if not any(k in acc for k in CANONICAL_ID_KEYS):
                        raise RuntimeError(f"MISSING_REQUIRED_FIELD: RS account {acc_id_val} missing requested field '{req_field}'")
                else:
                    if req_field not in acc:
                        raise RuntimeError(f"MISSING_REQUIRED_FIELD: RS account {acc_id_val} missing requested field '{req_field}'")

    # Enforce duplicate account detection (R7-03)
    if len(returned_accounts) != len(set(returned_accounts)):
        raise RuntimeError(
            f"DUPLICATE_ACCOUNT_IN_RESPONSE: RS returned duplicate account records in response: {returned_accounts}"
        )

    # Enforce authorized accounts matching (R3-03, R4-04 & R5-03)
    if expected_accounts is not None:
        expected_set = set(str(a) for a in expected_accounts)
        for r_acc in returned_accounts:
            if r_acc not in expected_set:
                raise RuntimeError(
                    f"UNAUTHORIZED_ACCOUNT_IN_RESPONSE: RS returned unauthorized account '{r_acc}', "
                    f"expected subset of {sorted(list(expected_set))}"
                )
        if require_exact_accounts and set(returned_accounts) != expected_set:
            raise RuntimeError(
                f"ACCOUNT_SET_COMPLETENESS_MISMATCH: Expected exact accounts {sorted(list(expected_set))}, "
                f"but got {sorted(returned_accounts)}"
            )

    return data


def load_workload_fixture(base_dir, workload):
    """Loads deterministic workload fixture parameters (accounts, permissions, window, pageSize)."""
    fixture_filename = f"workload_{workload.lower()}.json"
    fixture_path = os.path.join(base_dir, 'evaluation', 'fixtures', 'data', fixture_filename)
    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Fixture file not found: {fixture_path}. Regenerate the fixtures with evaluation/fixtures/FixtureGenerator.java first.")
    with open(fixture_path, 'r', encoding='utf-8') as f:
        return json.load(f)



def generate_pkce_pair():
    """Generates RFC 7636 PKCE code_verifier and code_challenge (S256)."""
    verifier_bytes = secrets.token_bytes(32)
    verifier = base64.urlsafe_b64encode(verifier_bytes).decode('ascii').rstrip('=')
    challenge_bytes = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')
    return verifier, challenge


def decode_jwt_payload_unverified(jwt_str):
    """Decodes JWT payload claims without cryptographic verification for inspection."""
    try:
        parts = jwt_str.split('.')
        if len(parts) < 2:
            return {}, {}
        header_raw = parts[0] + '=' * (-len(parts[0]) % 4)
        payload_raw = parts[1] + '=' * (-len(parts[1]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw.encode('ascii')).decode('utf-8'))
        payload = json.loads(base64.urlsafe_b64decode(payload_raw.encode('ascii')).decode('utf-8'))
        return header, payload
    except Exception:
        return {}, {}


class RedirectCaptureHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that intercepts redirection to the OAuth callback URL,
    preventing an unhandled network error if the callback listener is absent,
    while allowing intermediate redirects (e.g. login actions) to proceed.
    Also rewrites internal localhost references to keycloak_host when running across nodes.
    """
    def __init__(self, callback_prefix, keycloak_host=None):
        super().__init__()
        self.callback_prefix = callback_prefix
        self.keycloak_host = keycloak_host
        self.captured_redirect = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.keycloak_host:
            parsed = urllib.parse.urlparse(newurl)
            if parsed.hostname and parsed.hostname != self.keycloak_host and 'realms/traditional-fapi' in newurl:
                newurl = parsed._replace(netloc=f"{self.keycloak_host}:{parsed.port or 8443}").geturl()
        if newurl.startswith(self.callback_prefix) or ('code=' in newurl and 'state=' in newurl):
            self.captured_redirect = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        loc = headers.get('Location')
        if loc and self.keycloak_host:
            parsed = urllib.parse.urlparse(loc)
            if parsed.hostname and parsed.hostname != self.keycloak_host and 'realms/traditional-fapi' in loc:
                loc = parsed._replace(netloc=f"{self.keycloak_host}:{parsed.port or 8443}").geturl()
        if loc and (loc.startswith(self.callback_prefix) or ('code=' in loc and 'state=' in loc)):
            self.captured_redirect = loc
            return fp
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302


class AllowSecureCookiesPolicy(http.cookiejar.DefaultCookiePolicy):
    """Permits Secure cookies across localhost/local docker benchmark endpoints."""
    def return_ok_secure(self, cookie, req):
        return True


def compute_http_timeouts(deadline_mono: Optional[float] = None, phase_read_max: float = 10.0) -> Tuple[float, float]:
    """
    Computes fine-grained timeout semantics:
      connect_timeout = min(3.0, remaining)
      phase_read_timeout = min(phase_read_max, remaining)
      absolute E2E deadline checked before each HTTP operation.
    """
    if deadline_mono is not None:
        remaining = deadline_mono - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("E2E_TIMEOUT: Absolute transaction deadline exceeded")
        connect_timeout = min(3.0, remaining)
        read_timeout = min(phase_read_max, remaining)
        return connect_timeout, read_timeout
    return 3.0, phase_read_max


def execute_fapi_pkce_flow(
    keycloak_host,
    tpp_host,
    bank_host,
    mtls_ctx,
    scope='openid accounts:read ReadAccountsDetail',
    authorization_details=None,
    username='testuser',
    password='password',
    client_id='tpp-client',
    client_secret='tpp-client-secret-key-12345',
    timeout=10
):
    """
    Executes a genuine, compliant FAPI 2.0 Authorization Code flow with PKCE (S256),
    Pushed Authorization Requests (PAR, RFC 9126), and mTLS client authentication (RFC 8705).
    Fail-closed policy: Raises RuntimeError on any failure (no permissive fallbacks).
    """
    code_verifier, code_challenge = generate_pkce_pair()
    state = f"fapi-state-{secrets.token_hex(8)}"
    nonce = f"fapi-nonce-{secrets.token_hex(8)}"
    redirect_uri = f"https://{tpp_host}:4443/callback"

    # Step 1: PAR (Pushed Authorization Request)
    par_url = f"https://{keycloak_host}:8443/realms/traditional-fapi/protocol/openid-connect/ext/par/request"
    par_params = {
        'response_type': 'code',
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }
    if authorization_details:
        par_params['authorization_details'] = (
            authorization_details if isinstance(authorization_details, str)
            else json.dumps(authorization_details)
        )
    par_body = urllib.parse.urlencode(par_params).encode('utf-8')

    t0_par = time.perf_counter_ns()
    par_req = urllib.request.Request(
        par_url,
        data=par_body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    with urllib.request.urlopen(par_req, context=mtls_ctx, timeout=timeout) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"PAR request failed with HTTP {resp.status}")
        par_raw = resp.read()
        par_res = json.loads(par_raw.decode('utf-8'))
        request_uri = par_res.get('request_uri')
        if not request_uri:
            raise RuntimeError(f"PAR response missing request_uri: {par_res}")
        par_wire = compute_exchange_wire_bytes(par_req, resp, par_raw)
    t1_par = time.perf_counter_ns()
    par_ms = (t1_par - t0_par) / 1_000_000.0

    # Step 2: Headless User Authentication & Consent (Obtaining Authorization Code)
    t0_auth = time.perf_counter_ns()
    cookie_jar = http.cookiejar.CookieJar()
    redirect_handler = RedirectCaptureHandler(redirect_uri, keycloak_host=keycloak_host)
    https_handler = urllib.request.HTTPSHandler(context=mtls_ctx)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        redirect_handler,
        https_handler
    )

    auth_req_url = (
        f"https://{keycloak_host}:8443/realms/traditional-fapi/protocol/openid-connect/auth?"
        f"client_id={urllib.parse.quote(client_id)}&request_uri={urllib.parse.quote(request_uri)}"
    )
    auth_req = urllib.request.Request(
        auth_req_url,
        headers={'User-Agent': 'VDAM-Conformance-Engine/1.0'}
    )
    auth_resp = opener.open(auth_req, timeout=timeout)
    captured_code = None

    # Check if immediate redirect to callback occurred (e.g. existing SSO session)
    loc = redirect_handler.captured_redirect or auth_resp.headers.get('Location')
    if loc and 'code=' in loc:
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        captured_code = query_params.get('code', [None])[0]
        auth_wire = compute_exchange_wire_bytes(auth_req, auth_resp, b'')
    else:
        page_html = auth_resp.read().decode('utf-8', errors='replace')
        auth_wire = compute_exchange_wire_bytes(auth_req, auth_resp, page_html.encode('utf-8'))

        action_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', page_html, re.IGNORECASE)
        if not action_match:
            raise RuntimeError(f"Keycloak auth page did not contain a login form: {page_html[:300]}")

        action_url = html.unescape(action_match.group(1))
        action_url = urllib.parse.urljoin(auth_req_url, action_url)
        parsed_action = urllib.parse.urlparse(action_url)
        if parsed_action.hostname and parsed_action.hostname != keycloak_host and 'realms/traditional-fapi' in action_url:
            action_url = parsed_action._replace(netloc=f"{keycloak_host}:{parsed_action.port or 8443}").geturl()

        login_body = urllib.parse.urlencode({
            'username': username,
            'password': password,
            'credentialId': ''
        }).encode('utf-8')

        login_req = urllib.request.Request(
            action_url,
            data=login_body,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'VDAM-Conformance-Engine/1.0'
            }
        )
        login_resp = opener.open(login_req, timeout=timeout)

        loc = redirect_handler.captured_redirect or login_resp.headers.get('Location')
        if loc and 'code=' in loc:
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
            captured_code = query_params.get('code', [None])[0]
            auth_wire += compute_exchange_wire_bytes(login_req, login_resp, b'')
        else:
            # Check for consent screen
            post_login_html = login_resp.read().decode('utf-8', errors='replace')
            auth_wire += compute_exchange_wire_bytes(login_req, login_resp, post_login_html.encode('utf-8'))

            consent_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', post_login_html, re.IGNORECASE)
            if consent_match:
                raw_consent_action = html.unescape(consent_match.group(1))
                joined_consent = urllib.parse.urljoin(action_url, raw_consent_action)
                parsed_consent = urllib.parse.urlparse(joined_consent)
                if parsed_consent.hostname and parsed_consent.hostname != keycloak_host and 'realms/traditional-fapi' in joined_consent:
                    consent_url = parsed_consent._replace(netloc=f"{keycloak_host}:{parsed_consent.port or 8443}").geturl()
                else:
                    consent_url = joined_consent

                consent_data = {'accept': 'Yes'}
                hidden_code = re.search(r'<input\s+[^>]*name=["\']code["\']\s+[^>]*value=["\']([^"\']+)["\']', post_login_html, re.IGNORECASE)
                if not hidden_code:
                    hidden_code = re.search(r'<input\s+[^>]*value=["\']([^"\']+)["\']\s+[^>]*name=["\']code["\']', post_login_html, re.IGNORECASE)
                if hidden_code:
                    consent_data['code'] = hidden_code.group(1)

                consent_body = urllib.parse.urlencode(consent_data).encode('utf-8')
                consent_req = urllib.request.Request(
                    consent_url,
                    data=consent_body,
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'VDAM-Conformance-Engine/1.0'
                    }
                )
                consent_resp = opener.open(consent_req, timeout=timeout)
                auth_wire += compute_exchange_wire_bytes(consent_req, consent_resp, b'')
                loc = redirect_handler.captured_redirect or consent_resp.headers.get('Location')
                if loc and 'code=' in loc:
                    query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                    captured_code = query_params.get('code', [None])[0]
                else:
                    raise RuntimeError(f"Consent submission did not redirect to callback. Loc: {loc}")
            else:
                raise RuntimeError(f"Expected redirect with code or consent screen after login, got: {post_login_html[:300]}")

    if not captured_code:
        raise RuntimeError("Failed to extract authorization code from Keycloak login redirect.")

    t1_auth = time.perf_counter_ns()
    auth_ms = (t1_auth - t0_auth) / 1_000_000.0

    # Step 3: Token Exchange with PKCE (grant_type=authorization_code & code_verifier)
    t0_token = time.perf_counter_ns()
    token_url = f"https://{keycloak_host}:8443/realms/traditional-fapi/protocol/openid-connect/token"
    token_params = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'client_secret': client_secret,
        'code': captured_code,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
    }
    token_body = urllib.parse.urlencode(token_params).encode('utf-8')
    token_req = urllib.request.Request(
        token_url,
        data=token_body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    with urllib.request.urlopen(token_req, context=mtls_ctx, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Token endpoint returned HTTP {resp.status}")
        token_raw = resp.read()
        token_res = json.loads(token_raw.decode('utf-8'))
        access_token = token_res.get('access_token')
        if not access_token:
            raise RuntimeError(f"Token response missing access_token: {token_res}")
        token_wire = compute_exchange_wire_bytes(token_req, resp, token_raw)
    t1_token = time.perf_counter_ns()
    token_ms = (t1_token - t0_token) / 1_000_000.0

    return {
        'access_token': access_token,
        'token_response': token_res,
        'auth_code': captured_code,
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'request_uri': request_uri,
        'state': state,
        'nonce': nonce,
        'par_ms': par_ms,
        'par_wire': par_wire,
        'auth_ms': auth_ms,
        'auth_wire': auth_wire,
        'token_ms': token_ms,
        'token_wire': token_wire
    }


def execute_vdam_f1_oid4vci_flow(
    wallet_url='https://localhost:3443',
    keycloak_host='localhost',
    username='testuser',
    password='password',
    timeout=15,
    issuer_url=None
):
    """
    Executes a genuine Phase F1 (OID4VCI Scope VC Acquisition) flow:
      1. POST /api/receive-offer to Wallet
      2. POST /api/start-auth to Wallet (Wallet pushes PAR to Keycloak, creates PKCE verifier)
      3. Headless Keycloak authentication (submitting credentials to Keycloak login form)
      4. Invoking Wallet callback at /callback?code=...&state=...
      5. Wallet exchanges authorization code for Keycloak token, signs openid4vci-proof+jwt,
         requests Scope VC at Bank Issuer /credential, and stores it in wallet storage.
    """
    t0_e2e = time.perf_counter_ns()

    # Step 0: Record pre-existing Scope VCs before starting F1
    with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=timeout) as pre_vcs_resp:
        pre_vcs_data = json.loads(pre_vcs_resp.read().decode('utf-8')).get('vcs', [])
    before_root_jtis = {
        v.get('jti') for v in pre_vcs_data
        if v.get('type') in ('AuthorizationCredential', 'ScopeCredential')
        or ('scope' in str(v.get('type', '')).lower() and 'delegate' not in str(v.get('type', '')).lower())
    }

    # Step 1: POST /api/receive-offer
    t0 = time.perf_counter_ns()
    offer_req = urllib.request.Request(
        f"{wallet_url}/api/receive-offer",
        data=b"{}",
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(offer_req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Wallet receive-offer failed with HTTP {resp.status}")
        raw = resp.read()
        offer_res = json.loads(raw.decode('utf-8'))
        session_id = offer_res.get('sessionId')
        if not session_id:
            raise RuntimeError(f"Wallet receive-offer missing sessionId: {offer_res}")
        wire_offer = compute_exchange_wire_bytes(offer_req, resp, raw)
    t1 = time.perf_counter_ns()
    offer_ms = (t1 - t0) / 1_000_000.0

    # Step 2: POST /api/start-auth
    t0 = time.perf_counter_ns()
    start_auth_req = urllib.request.Request(
        f"{wallet_url}/api/start-auth",
        data=json.dumps({'sessionId': session_id}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(start_auth_req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Wallet start-auth failed with HTTP {resp.status}")
        raw = resp.read()
        start_auth_res = json.loads(raw.decode('utf-8'))
        auth_url = start_auth_res.get('authUrl')
        if not auth_url:
            raise RuntimeError(f"Wallet start-auth missing authUrl: {start_auth_res}")
        wire_start_auth = compute_exchange_wire_bytes(start_auth_req, resp, raw)
    t1 = time.perf_counter_ns()
    start_auth_ms = (t1 - t0) / 1_000_000.0

    # Step 3: Headless Keycloak Login
    t0 = time.perf_counter_ns()
    cookie_jar = http.cookiejar.CookieJar(AllowSecureCookiesPolicy())
    redirect_uri = f"{wallet_url}/callback"
    redirect_handler = RedirectCaptureHandler(redirect_uri, keycloak_host=keycloak_host)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        redirect_handler
    )

    auth_req = urllib.request.Request(
        auth_url,
        headers={'User-Agent': 'VDAM-Conformance-Engine/1.0'}
    )
    auth_resp = opener.open(auth_req, timeout=timeout)
    loc = redirect_handler.captured_redirect or auth_resp.headers.get('Location')
    captured_code = None
    captured_state = None
    wire_kc = 0

    if loc and 'code=' in loc:
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        captured_code = query_params.get('code', [None])[0]
        captured_state = query_params.get('state', [None])[0]
        wire_kc += compute_exchange_wire_bytes(auth_req, auth_resp, b'')
    else:
        page_html = auth_resp.read().decode('utf-8', errors='replace')
        wire_kc += compute_exchange_wire_bytes(auth_req, auth_resp, page_html.encode('utf-8'))

        action_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', page_html, re.IGNORECASE)
        if not action_match:
            raise RuntimeError(f"Keycloak auth page did not contain a login form: {page_html[:300]}")

        action_url = html.unescape(action_match.group(1))
        action_url = urllib.parse.urljoin(auth_url, action_url)
        parsed_action = urllib.parse.urlparse(action_url)
        if parsed_action.hostname and parsed_action.hostname != keycloak_host and 'realms/fapi-demo' in action_url:
            action_url = parsed_action._replace(netloc=f"{keycloak_host}:{parsed_action.port or 8080}").geturl()

        login_body = urllib.parse.urlencode({
            'username': username,
            'password': password,
            'credentialId': ''
        }).encode('utf-8')

        login_req = urllib.request.Request(
            action_url,
            data=login_body,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'VDAM-Conformance-Engine/1.0'
            }
        )
        login_resp = opener.open(login_req, timeout=timeout)
        loc = redirect_handler.captured_redirect or login_resp.headers.get('Location')
        if loc and 'code=' in loc:
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
            captured_code = query_params.get('code', [None])[0]
            captured_state = query_params.get('state', [None])[0]
            wire_kc += compute_exchange_wire_bytes(login_req, login_resp, b'')
        else:
            post_login_html = login_resp.read().decode('utf-8', errors='replace')
            wire_kc += compute_exchange_wire_bytes(login_req, login_resp, post_login_html.encode('utf-8'))
            consent_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', post_login_html, re.IGNORECASE)
            if consent_match:
                raw_consent_action = html.unescape(consent_match.group(1))
                joined_consent = urllib.parse.urljoin(action_url, raw_consent_action)
                consent_data = {'accept': 'Yes'}
                hidden_code = re.search(r'<input\s+[^>]*name=["\']code["\']\s+[^>]*value=["\']([^"\']+)["\']', post_login_html, re.IGNORECASE)
                if hidden_code:
                    consent_data['code'] = hidden_code.group(1)
                consent_req = urllib.request.Request(
                    joined_consent,
                    data=urllib.parse.urlencode(consent_data).encode('utf-8'),
                    headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'VDAM-Conformance-Engine/1.0'}
                )
                consent_resp = opener.open(consent_req, timeout=timeout)
                wire_kc += compute_exchange_wire_bytes(consent_req, consent_resp, b'')
                loc = redirect_handler.captured_redirect or consent_resp.headers.get('Location')
                if loc and 'code=' in loc:
                    query_params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                    captured_code = query_params.get('code', [None])[0]
                    captured_state = query_params.get('state', [None])[0]

    if not captured_code:
        raise RuntimeError("Failed to capture Keycloak authorization code during OID4VCI flow")

    t1 = time.perf_counter_ns()
    kc_auth_ms = (t1 - t0) / 1_000_000.0

    # Step 4: Invoke Wallet Callback
    t0 = time.perf_counter_ns()
    cb_url = f"{wallet_url}/callback?code={urllib.parse.quote(captured_code)}&state={urllib.parse.quote(captured_state or '')}"
    cb_req = urllib.request.Request(cb_url)
    try:
        with urllib.request.urlopen(cb_req, timeout=timeout) as cb_resp:
            wire_cb = compute_exchange_wire_bytes(cb_req, cb_resp, cb_resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (301, 302):
            wire_cb = 0
        else:
            raise RuntimeError(f"Wallet callback failed with HTTP {e.code}")
    t1 = time.perf_counter_ns()
    cb_ms = (t1 - t0) / 1_000_000.0

    # Step 5: Verify newly issued VC in Wallet (Strictly NO fallback to pre-existing credentials)
    with urllib.request.urlopen(f"{wallet_url}/api/vcs", timeout=timeout) as vcs_resp:
        vcs_data = json.loads(vcs_resp.read().decode('utf-8')).get('vcs', [])
    root_vcs = [
        v for v in vcs_data
        if v.get('type') in ('AuthorizationCredential', 'ScopeCredential')
        or ('scope' in str(v.get('type', '')).lower() and 'delegate' not in str(v.get('type', '')).lower())
    ]
    fresh_root_vcs = [v for v in root_vcs if v.get('jti') and v.get('jti') not in before_root_jtis]
    if not fresh_root_vcs:
        raise RuntimeError(
            f"F1_STALE_CREDENTIAL_ERROR: No fresh Scope VC issued during OID4VCI flow. "
            f"Pre-existing JTIs: {sorted(list(before_root_jtis))}. "
            f"Found {len(root_vcs)} total Scope VCs, 0 fresh."
        )

    latest_vc = fresh_root_vcs[-1]
    sd_jwt_str = latest_vc.get('sdJwt') or ''
    if not sd_jwt_str:
        raise RuntimeError(f"F1_EMPTY_CREDENTIAL_ERROR: Fresh Scope VC '{latest_vc.get('jti')}' missing sdJwt payload")

    # Correlate and verify committed issuance binding record at Bank Issuer
    effective_issuer_url = issuer_url or os.environ.get('VDAM_ISSUER_URL', 'https://localhost:9443')
    _, root_payload = decode_jwt_payload_unverified(sd_jwt_str.split('~', 1)[0])
    binding_ref = root_payload.get('holder_cert_ref')
    if binding_ref:
        binding_check_url = f"{effective_issuer_url}/api/test/bindings/{binding_ref}"
        try:
            with urllib.request.urlopen(binding_check_url, timeout=timeout) as b_resp:
                if b_resp.status == 200:
                    b_data = json.loads(b_resp.read().decode('utf-8'))
                    if b_data.get('record_id') != binding_ref or b_data.get('status') != 'ACTIVE':
                        raise RuntimeError(f"F1_BINDING_STATUS_ERROR: Binding record {binding_ref} status is {b_data.get('status')}, expected ACTIVE")
        except urllib.error.HTTPError as b_err:
            # If 403 or 404 under normal non-conformance profile, binding verification endpoint is disabled by profile
            if b_err.code not in (403, 404):
                raise RuntimeError(f"F1_BINDING_COMMIT_ERROR: Failed to verify issuance binding record at {binding_check_url}: HTTP {b_err.code}")
        except Exception as b_exc:
            # Network connection issues to issuer
            pass

    t_end_e2e = time.perf_counter_ns()
    total_e2e_ms = (t_end_e2e - t0_e2e) / 1_000_000.0

    return {
        'status': 'SUCCESS',
        'jti': latest_vc.get('jti'),
        'credential': latest_vc.get('sdJwt'),
        'offer_ms': offer_ms,
        'start_auth_ms': start_auth_ms,
        'kc_auth_ms': kc_auth_ms,
        'cb_ms': cb_ms,
        'total_e2e_ms': total_e2e_ms,
        'total_wire_bytes': wire_offer + wire_start_auth + wire_kc + wire_cb,
        'step_ms': {'offer': offer_ms, 'start_auth': start_auth_ms, 'keycloak_login': kc_auth_ms, 'callback': cb_ms},
        'step_wire': {'offer': wire_offer, 'start_auth': wire_start_auth, 'keycloak_login': wire_kc, 'callback': wire_cb},
    }


def execute_vdam_delegation_flow(tpp_host='localhost', wallet_host='localhost', scopes=None, authz_vc_jti=None):
    """
    Executes fresh Phases F2, F3, F4 on every iteration (Rule 8):
      - Phase F2: TPP generates challenge request (/api/request-delegate)
      - Phase F3: Wallet fetches and signs delegation VC (/api/approve-delegate) with challenge nonce
      - Phase F4: TPP exchanges delegation bundle for fresh PoP access token (/api/token)
    """
    if scopes is None:
        scopes = ["accounts:read", "ReadAccountsDetail", "ReadAccountsBasic", "ReadBalances", "ReadTransactionsDetail", "ReadTransactionsBasic", "ReadDirectDebits"]

    tpp_url = os.environ.get('VDAM_TPP_URL') or f"https://{tpp_host}:4443"
    wallet_url = os.environ.get('VDAM_WALLET_URL') or f"https://{wallet_host}:3443"
    t0 = time.perf_counter_ns()
    total_wire = 0

    # 1. TPP Request delegate (Phase F2)
    # The TPP reads "requestedScopes"; a differently named field is ignored and the TPP then
    # falls back to a Bank policy lookup on every request.
    req_body = json.dumps({"requestedScopes": scopes}).encode('utf-8')
    req = urllib.request.Request(f"{tpp_url}/api/request-delegate", data=req_body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            raise RuntimeError(f"TPP request-delegate failed with HTTP {resp.status}")
        raw_del = resp.read()
        delegate_data = json.loads(raw_del.decode('utf-8'))
        wire_request_delegate = compute_exchange_wire_bytes(req, resp, raw_del)
        total_wire += wire_request_delegate
    request_id = delegate_data.get("requestId")
    if not request_id:
        raise RuntimeError(f"TPP request-delegate returned missing requestId: {delegate_data}")

    # 2. Wallet fetch
    fetch_url = f"{wallet_url}/api/fetch-tpp-request?requestId={request_id}"
    req = urllib.request.Request(fetch_url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Wallet fetch-tpp-request failed with HTTP {resp.status}")
        raw_fetch = resp.read()
        wire_fetch_request = compute_exchange_wire_bytes(req, resp, raw_fetch)
        total_wire += wire_fetch_request

    # 3. Wallet approve delegate (Phase F3)
    approve_dict = {
        "requestId": request_id,
        "approvedScopes": scopes
    }
    if authz_vc_jti:
        approve_dict["authzVcJti"] = authz_vc_jti
    approve_body = json.dumps(approve_dict).encode('utf-8')
    req = urllib.request.Request(f"{wallet_url}/api/approve-delegate", data=approve_body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Wallet approve-delegate failed with HTTP {resp.status}")
        raw_app = resp.read()
        app_data = json.loads(raw_app.decode('utf-8'))
        wire_approve_delegate = compute_exchange_wire_bytes(req, resp, raw_app)
        total_wire += wire_approve_delegate

    # 4. TPP token exchange (Phase F4)
    # requestId selects this transaction's state in the TPP; without it the TPP would use whichever
    # request was created last, which is wrong as soon as two transactions overlap.
    token_body = json.dumps({"requestId": request_id}).encode('utf-8')
    req = urllib.request.Request(f"{tpp_url}/api/token", data=token_body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            raise RuntimeError(f"TPP token exchange failed with HTTP {resp.status}")
        raw_tok = resp.read()
        tok_data = json.loads(raw_tok.decode('utf-8'))
        wire_token = compute_exchange_wire_bytes(req, resp, raw_tok)
        total_wire += wire_token
    access_token = tok_data.get('access_token') or tok_data.get('token')
    if not access_token:
        raise RuntimeError(f"TPP token exchange failed: missing access_token in {tok_data}")

    t1 = time.perf_counter_ns()
    auth_ms = (t1 - t0) / 1_000_000.0
    return {
        'access_token': access_token,
        'auth_ms': auth_ms,
        'auth_wire': total_wire,
        'step_wire': {
            'request_delegate': wire_request_delegate,
            'fetch_request': wire_fetch_request,
            'approve_delegate': wire_approve_delegate,
            'token': wire_token,
        },
        'request_id': request_id,
        'delegate_vc_jti': app_data.get('delegateVcJti')
    }


def ensure_tpp_session(tpp_host='localhost', wallet_host='localhost'):
    """
    Preflight check to verify TPP and Wallet communication can successfully negotiate a delegation token.
    """
    execute_vdam_delegation_flow(tpp_host, wallet_host)
    return True


# ---------------------------------------------------------------------------
# Auth-only entry points used by the perf runners.
# Every function here stops at access-token issuance; none touches the resource server.
# ---------------------------------------------------------------------------

B0_ALLOWED_SCOPES = {
    'openid', 'accounts:read', 'transfers:read', 'transfers:write',
    'ReadAccountsDetail', 'ReadAccountsBasic', 'ReadBalances',
    'ReadTransactionsDetail', 'ReadTransactionsBasic', 'CreateDomesticPayment',
    'ReadDirectDebits'
}

B0_CLIENT_ID = 'tpp-client'
B0_CLIENT_SECRET = 'tpp-client-secret-key-12345'
B0_USERNAME = 'testuser'
B0_PASSWORD = 'password'


def perf_hosts():
    """Resolves the role hosts exactly as the flows do, from the environment."""
    bank_host = os.environ.get('BANK_HOST', 'localhost')
    return {
        'bank_host': bank_host,
        'keycloak_host': os.environ.get('KEYCLOAK_HOST', bank_host),
        'tpp_host': os.environ.get('TPP_HOST', 'localhost'),
        'wallet_host': os.environ.get('WALLET_HOST', 'localhost'),
        'issuer_url': os.environ.get('VDAM_ISSUER_URL', f'https://{bank_host}:9443'),
        'tpp_url': os.environ.get('VDAM_TPP_URL') or f"https://{os.environ.get('TPP_HOST', 'localhost')}:4443",
        'wallet_url': os.environ.get('VDAM_WALLET_URL') or f"https://{os.environ.get('WALLET_HOST', 'localhost')}:3443",
        'b0_tpp_url': os.environ.get('B0_TPP_URL') or f"https://{os.environ.get('TPP_HOST', 'localhost')}:4443",
    }


def b0_auth_params(base_dir, workload):
    """PAR scope and RAR authorization_details for B0, derived from the workload fixture."""
    fixture = load_workload_fixture(base_dir, workload)
    bank_host = perf_hosts()['bank_host']
    perms = " ".join(p for p in fixture.get('permissions', ['ReadAccountsDetail']) if p in B0_ALLOWED_SCOPES)
    return {
        'scope': f"openid accounts:read {perms} rs-audience".strip(),
        'authorization_details': [{
            'type': 'account_information',
            'actions': ['read'],
            'locations': [f"https://{bank_host}:8443/api/v1/accounts"],
            'datatypes': fixture.get('data_fields', ['accounts', 'balances']),
        }],
    }


def vdam_auth_scopes(base_dir, workload):
    """Scopes requested in the VDAM delegation, derived from the workload fixture."""
    fixture = load_workload_fixture(base_dir, workload)
    scopes = list(fixture.get('permissions', ['ReadAccountsBasic', 'ReadAccountsDetail']))
    if 'accounts:read' not in scopes:
        scopes.append('accounts:read')
    return scopes


def _browser_login_for_code(auth_url, keycloak_host, callback_prefix, username, password, timeout, context):
    """Plays the user's browser at Keycloak: open the authorization page, log in, accept consent.

    Returns (authorization_code, wire_bytes). No client certificate is presented: a browser has none.
    """
    cookie_jar = http.cookiejar.CookieJar()
    redirect_handler = RedirectCaptureHandler(callback_prefix, keycloak_host=keycloak_host)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        redirect_handler,
        urllib.request.HTTPSHandler(context=context),
    )

    def code_from(location):
        if location and 'code=' in location:
            return urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('code', [None])[0]
        return None

    def pin_host(url):
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname and parsed.hostname != keycloak_host and 'realms/traditional-fapi' in url:
            return parsed._replace(netloc=f"{keycloak_host}:{parsed.port or 8443}").geturl()
        return url

    def form_action(page, base_url):
        match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', page, re.IGNORECASE)
        if not match:
            return None
        return pin_host(urllib.parse.urljoin(base_url, html.unescape(match.group(1))))

    ua = {'User-Agent': 'VDAM-Perf-Client/1.0'}
    auth_url = pin_host(auth_url)
    auth_req = urllib.request.Request(auth_url, headers=ua)
    auth_resp = opener.open(auth_req, timeout=timeout)
    code = code_from(redirect_handler.captured_redirect or auth_resp.headers.get('Location'))
    if code:
        return code, compute_exchange_wire_bytes(auth_req, auth_resp, b'')

    page = auth_resp.read().decode('utf-8', errors='replace')
    wire = compute_exchange_wire_bytes(auth_req, auth_resp, page.encode('utf-8'))
    login_url = form_action(page, auth_url)
    if not login_url:
        raise RuntimeError(f"Keycloak auth page did not contain a login form: {page[:300]}")

    login_req = urllib.request.Request(
        login_url,
        data=urllib.parse.urlencode({'username': username, 'password': password, 'credentialId': ''}).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded', **ua},
    )
    login_resp = opener.open(login_req, timeout=timeout)
    code = code_from(redirect_handler.captured_redirect or login_resp.headers.get('Location'))
    if code:
        return code, wire + compute_exchange_wire_bytes(login_req, login_resp, b'')

    post_login = login_resp.read().decode('utf-8', errors='replace')
    wire += compute_exchange_wire_bytes(login_req, login_resp, post_login.encode('utf-8'))
    consent_url = form_action(post_login, login_url)
    if not consent_url:
        raise RuntimeError(f"Expected a redirect with a code or a consent screen after login, got: {post_login[:300]}")
    consent_data = {'accept': 'Yes'}
    hidden = (
        re.search(r'<input\s+[^>]*name=["\']code["\']\s+[^>]*value=["\']([^"\']+)["\']', post_login, re.IGNORECASE)
        or re.search(r'<input\s+[^>]*value=["\']([^"\']+)["\']\s+[^>]*name=["\']code["\']', post_login, re.IGNORECASE)
    )
    if hidden:
        consent_data['code'] = hidden.group(1)
    consent_req = urllib.request.Request(
        consent_url,
        data=urllib.parse.urlencode(consent_data).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded', **ua},
    )
    consent_resp = opener.open(consent_req, timeout=timeout)
    wire += compute_exchange_wire_bytes(consent_req, consent_resp, b'')
    code = code_from(redirect_handler.captured_redirect or consent_resp.headers.get('Location'))
    if not code:
        raise RuntimeError("Consent submission did not redirect to the callback with a code")
    return code, wire


def execute_b0_via_tpp(tpp_url, keycloak_host, tpp_host, scope, username=B0_USERNAME, password=B0_PASSWORD, timeout=10):
    """One B0 authorization driven the way a user's browser drives it.

    The client only calls the TPP backend and Keycloak's login page. The TPP itself performs the
    PAR request and the mTLS token exchange, so those hops are real server-side hops.
      1. POST TPP /api/auth/initiate         (TPP -> Keycloak PAR over mTLS)
      2. browser -> Keycloak authorize/login/consent -> authorization code
      3. POST TPP /api/auth/token-exchange   (TPP -> Keycloak token over mTLS)
    """
    context = ssl._create_unverified_context()  # dev certificates; the browser step presents no client cert
    json_headers = {'Content-Type': 'application/json'}

    t0 = time.perf_counter_ns()
    init_req = urllib.request.Request(
        f"{tpp_url}/api/auth/initiate", data=json.dumps({'scope': scope}).encode('utf-8'), headers=json_headers)
    with urllib.request.urlopen(init_req, context=context, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"TPP initiate failed with HTTP {resp.status}")
        init_raw = resp.read()
        init = json.loads(init_raw.decode('utf-8'))
        par_wire = compute_exchange_wire_bytes(init_req, resp, init_raw)
    par_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    redirect_url, state = init.get('redirectUrl'), init.get('state')
    if not init.get('usedPar') or not redirect_url or not state:
        raise RuntimeError(f"TPP did not complete PAR (usedPar={init.get('usedPar')})")
    request_uri = urllib.parse.parse_qs(urllib.parse.urlparse(redirect_url).query).get('request_uri', [None])[0]

    t1 = time.perf_counter_ns()
    code, auth_wire = _browser_login_for_code(
        redirect_url, keycloak_host, f"https://{tpp_host}:4443/callback", username, password, timeout, context)
    auth_ms = (time.perf_counter_ns() - t1) / 1_000_000.0

    t2 = time.perf_counter_ns()
    tok_req = urllib.request.Request(
        f"{tpp_url}/api/auth/token-exchange",
        data=json.dumps({'code': code, 'state': state}).encode('utf-8'), headers=json_headers)
    with urllib.request.urlopen(tok_req, context=context, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"TPP token exchange failed with HTTP {resp.status}")
        tok_raw = resp.read()
        tok = json.loads(tok_raw.decode('utf-8'))
        token_wire = compute_exchange_wire_bytes(tok_req, resp, tok_raw)
    token_ms = (time.perf_counter_ns() - t2) / 1_000_000.0
    access_token = (tok.get('tokens') or {}).get('access_token')
    if not access_token:
        raise RuntimeError("TPP token exchange response has no access_token")

    return {
        'access_token': access_token,
        'auth_code': code,
        'request_uri': request_uri,
        'state': state,
        'pkce_challenge': init.get('pkceChallenge'),
        'par_ms': par_ms, 'par_wire': par_wire,
        'auth_ms': auth_ms, 'auth_wire': auth_wire,
        'token_ms': token_ms, 'token_wire': token_wire,
    }


def run_b0_auth(base_dir, workload):
    """One B0 authorization as a browser would drive it (PAR and token exchange happen in the TPP)."""
    hosts = perf_hosts()
    params = b0_auth_params(base_dir, workload)
    return execute_b0_via_tpp(
        tpp_url=hosts['b0_tpp_url'],
        keycloak_host=hosts['keycloak_host'],
        tpp_host=hosts['tpp_host'],
        scope=params['scope'],
    )


def run_vdam_auth(base_dir, workload, authz_vc_jti=None):
    """One VDAM authorization (F2-F4). Same code path for B1-C0 and B1-C2."""
    hosts = perf_hosts()
    return execute_vdam_delegation_flow(
        tpp_host=hosts['tpp_host'],
        wallet_host=hosts['wallet_host'],
        scopes=vdam_auth_scopes(base_dir, workload),
        authz_vc_jti=authz_vc_jti,
    )


def provision_root_vc(timeout=15):
    """Runs F1 once and returns the root (Scope) VC that later F2-F4 authorizations reuse.

    Returns {'jti', 'credential', 'digest', 'f1_ms', 'f1_wire'}. Raises if F1 issued nothing.
    """
    hosts = perf_hosts()
    res = execute_vdam_f1_oid4vci_flow(
        wallet_url=hosts['wallet_url'],
        keycloak_host=hosts['keycloak_host'],
        username=B0_USERNAME,
        password=B0_PASSWORD,
        timeout=timeout,
        issuer_url=hosts['issuer_url'],
    )
    credential = res.get('credential')
    jti = res.get('jti')
    if not credential or not jti:
        raise RuntimeError("F1 root VC provisioning returned no credential or jti")
    return {
        'jti': jti,
        'credential': credential,
        'digest': hashlib.sha256(credential.encode('utf-8')).hexdigest(),
        'f1_ms': res.get('total_e2e_ms', 0),
        'f1_wire': res.get('total_wire_bytes', 0),
        'f1_step_ms': res.get('step_ms', {}),
        'f1_step_wire': res.get('step_wire', {}),
    }


def fetch_delegate_artifacts(wallet_url, request_id, timeout=10):
    """Reads the serialized credentials of an approved delegation from the Wallet.

    Uses the Wallet's existing GET /api/delegate-vcs/{requestId} endpoint, the same one the TPP reads
    to obtain the delegation, so no protocol behavior is added. Call it after the measured F2-F4 flow:
    it is a read-only lookup that must stay outside the latency and wire-byte accounting.

    Returns the parsed JSON body. Its `delegate_vc` is the serialized Delegation VC, `authorization_vc`
    the root-VC presentation, and `das_encrypted_package` the encrypted DAS package when present.
    """
    context = ssl._create_unverified_context()  # development certificates
    url = f"{wallet_url}/api/delegate-vcs/{urllib.parse.quote(str(request_id), safe='')}"
    with urllib.request.urlopen(urllib.request.Request(url), context=context, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Wallet delegate-vcs lookup failed with HTTP {resp.status}")
        return json.loads(resp.read().decode('utf-8'))
