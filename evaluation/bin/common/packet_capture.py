#!/usr/bin/env python3
"""Local-only diagnostic raw packet capture of the TPP<->Bank gateway hop.

Scope (local-diagnostic only; see docs/EVALUATION_PROTOCOL.md section 4.3 and decision DEC-022):
  * LOCAL Docker execution only (environment == "local"). Not used against the VM.
  * Captures on the TPP gateway and Bank gateway containers' own network interface, via a throwaway
    sidecar container attached to the target's network namespace
    (`docker run --network container:<target> ... tcpdump ...`). No host-level access, no SSH, no
    change to the containers under test.
  * Reports real on-the-wire byte totals (TCP/IP + TLS ciphertext, since every hop is TLS/mTLS) and a
    packet count. It does not decrypt TLS and never reads application payload; this is a size metric,
    not a content metric. See measure_artifacts.py's `tpp_vp_assertion`/`par_request_object` entries for
    why this hop was previously entirely unmeasured (built server-to-server, never returned to the
    client-facing boundary).
  * The captured .pcap stays local (evaluation/evidence/ is gitignored) for manual inspection;
    only its byte/packet totals and SHA-256 go into the manifest, never its content.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

CAPTURE_IMAGE = "nicolaka/netshoot"

# Container names of the TPP and Bank gateway/ingress role, per model, for LOCAL docker-compose only.
# These are the nginx proxies that actually originate/terminate the TPP<->Bank mTLS hop; the model's own
# app container (tpp-fapi, classical_tpp_java, pqc_tpp_java) calls out through its gateway.
LOCAL_GATEWAY_CONTAINERS = {
    "B0-C0": {"tpp": "fapi_tpp_gateway", "bank": "fapi_bank_gateway"},
    "B1-C0": {"tpp": "classical_tpp_gateway", "bank": "classical_tls_server_proxy"},
    "B1-C2": {"tpp": "pqc_tpp_gateway", "bank": "pqc_oqs_server_proxy"},
}

# The magic number is 0xa1b2c3d4 (microsecond) / 0xa1b23c4d (nanosecond). These sets are the bytes AS
# THEY APPEAR ON DISK: a little-endian-written file stores 0xa1b2c3d4 byte-reversed (d4 c3 b2 a1), so
# that on-disk sequence means "read everything else as little-endian" (and vice versa for big-endian).
_PCAP_MAGIC_LE = {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}
_PCAP_MAGIC_BE = {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}


class CaptureError(RuntimeError):
    pass


def container_running(name: str) -> bool:
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True, check=False,
    )
    return out.returncode == 0 and out.stdout.strip() == "true"


def start_capture(target_container: str, out_dir: Path, label: str) -> dict:
    """Starts a detached tcpdump sidecar sharing `target_container`'s network namespace."""
    if not container_running(target_container):
        raise CaptureError(f"capture target container is not running: {target_container}")
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_name = f"{label}.pcap"
    sidecar_name = f"pcap-{label}-{uuid.uuid4().hex[:8]}"
    cmd = [
        "docker", "run", "-d", "--rm", "--name", sidecar_name,
        "--network", f"container:{target_container}",
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "-v", f"{out_dir.resolve().as_posix()}:/capture",
        CAPTURE_IMAGE, "tcpdump", "-i", "any", "-s", "0", "-w", f"/capture/{pcap_name}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise CaptureError(f"failed to start capture sidecar for {target_container}: {result.stderr.strip()}")
    time.sleep(1.0)  # let tcpdump attach to the interface before the measured traffic starts
    return {"sidecar_name": sidecar_name, "pcap_path": out_dir / pcap_name, "target_container": target_container}


def stop_capture(capture: dict, drain_seconds: float = 1.0) -> Path:
    """Stops the sidecar (tcpdump flushes its pcap on exit) and returns the pcap path."""
    time.sleep(drain_seconds)  # let in-flight packets land before the capture stops
    subprocess.run(["docker", "stop", "-t", "3", capture["sidecar_name"]], capture_output=True, check=False)
    time.sleep(0.5)
    return capture["pcap_path"]


def pcap_summary(pcap_path: Path) -> dict:
    """Pure-format pcap parse: packet count and real on-wire byte total (orig_len per record). Never
    reads or returns payload content."""
    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        return {"packets": 0, "total_bytes": 0, "sha256": None}
    data = pcap_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) < 24:
        return {"packets": 0, "total_bytes": 0, "sha256": digest}
    magic = data[:4]
    if magic in _PCAP_MAGIC_LE:
        endian = "<"
    elif magic in _PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise CaptureError(f"unrecognized pcap magic in {pcap_path}: {magic!r}")
    offset = 24
    packets = 0
    total = 0
    n = len(data)
    while offset + 16 <= n:
        _, _, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16 + incl_len
        packets += 1
        total += orig_len
    return {"packets": packets, "total_bytes": total, "sha256": digest}


def capture_pair(tpp_container: str, bank_container: str, out_dir: Path, label: str) -> dict:
    """Starts capture on both the TPP and Bank gateway containers; returns the two capture handles."""
    return {
        "tpp": start_capture(tpp_container, out_dir, f"{label}-tpp"),
        "bank": start_capture(bank_container, out_dir, f"{label}-bank"),
    }


def stop_pair(captures: dict, drain_seconds: float = 1.0) -> dict:
    """Stops both captures and returns {'tpp': {...summary...}, 'bank': {...summary...}}."""
    result = {}
    for side, capture in captures.items():
        pcap_path = stop_capture(capture, drain_seconds=drain_seconds)
        summary = pcap_summary(pcap_path)
        summary["pcap_path"] = str(pcap_path)
        result[side] = summary
    return result
