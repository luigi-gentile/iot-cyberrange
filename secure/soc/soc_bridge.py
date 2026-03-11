#!/usr/bin/env python3
"""
soc_bridge.py — Suricata eve.json → InfluxDB bridge with correlation engine

Reads Suricata alerts from eve.json in real-time and writes two InfluxDB
measurements:
  - suricata_alert  : one data point per Suricata alert (IDS events)
  - soc_event       : one data point per correlated multi-stage attack

Correlation rules (5-minute sliding window):
  ATTACK_CHAIN    — S4 Brute Force + S5 Lateral Movement  (CRITICAL)
  MULTI_VECTOR    — S3 DoS + S4 Brute Force               (HIGH)
  RECON_TO_ACTION — S5 Lateral Movement + S2/S6           (CRITICAL)

MITRE ATT&CK for ICS:
  Multi-stage correlation maps to T0891 (Hardcoded Credentials) chained
  with T0843 (Program Download) / T0856 (Spoof Reporting Message).
"""

import json
import os
import time
from collections import deque
from datetime import datetime, timezone

import requests

# ── Configuration ────────────────────────────────────────────────────────────
EVE_LOG      = os.getenv("EVE_LOG",        "/var/log/suricata/eve.json")
INFLUXDB_URL = os.getenv("INFLUXDB_URL",   "http://172.22.0.30:8086")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG",   "iot-cyberrange")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "sensors")
INFLUXDB_TOKEN  = os.getenv("INFLUXDB_TOKEN",  "secure-admin-token-abc123xyz987")

POLL_INTERVAL      = 0.5   # seconds between readline() attempts
FILE_WAIT_INTERVAL = 2.0   # seconds to wait when eve.json does not exist yet
CORRELATION_WINDOW = 300   # seconds — sliding window for correlation rules

# ── SID → Scenario mapping ───────────────────────────────────────────────────
SID_TO_SCENARIO = {
    1000001: "S1",
    1000002: "S2",
    1000003: "S3",
    1000004: "S3",
    1000005: "S4",
    1000006: "S5",
    1000007: "S5",
    1000008: "S5",
    1000009: "S5",
    1000010: "S6",
}

# ── InfluxDB helpers ──────────────────────────────────────────────────────────

_WRITE_URL = (
    f"{INFLUXDB_URL}/api/v2/write"
    f"?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=ns"
)
_HEADERS = {
    "Authorization": f"Token {INFLUXDB_TOKEN}",
    "Content-Type":  "text/plain; charset=utf-8",
}


def _escape_tag(value: str) -> str:
    """Escape special characters in InfluxDB line-protocol tag values."""
    return value.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def _escape_field_str(value: str) -> str:
    """Escape a string field value (wrap in quotes, escape inner quotes)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_line(line: str) -> bool:
    """POST a single line-protocol line to InfluxDB. Returns True on success."""
    try:
        r = requests.post(_WRITE_URL, headers=_HEADERS, data=line.encode(), timeout=5)
        return r.status_code == 204
    except requests.RequestException:
        return False


def write_alert(ts_ns: int, scenario: str, sid: int, src_ip: str, signature: str) -> bool:
    """Write one suricata_alert data point."""
    line = (
        f"suricata_alert,"
        f"scenario={_escape_tag(scenario)},"
        f"sid={sid},"
        f"src_ip={_escape_tag(src_ip)},"
        f"signature={_escape_tag(signature)} "
        f"count=1i "
        f"{ts_ns}"
    )
    return write_line(line)


def write_soc_event(ts_ns: int, event_type: str, severity: str,
                    scenarios: str, description: str) -> bool:
    """Write one soc_event data point (correlation result)."""
    line = (
        f"soc_event,"
        f"type={_escape_tag(event_type)},"
        f"severity={_escape_tag(severity)},"
        f"scenarios={_escape_tag(scenarios)} "
        f"count=1i,"
        f"description={_escape_field_str(description)} "
        f"{ts_ns}"
    )
    return write_line(line)


# ── Correlation engine ────────────────────────────────────────────────────────

# alert_history: each entry = {"ts": float (epoch), "scenario": str}
alert_history: deque = deque(maxlen=200)

# Track last emission time per correlation type to avoid duplicates
_last_emitted: dict[str, float] = {}


def _recent_scenarios() -> set:
    """Return the set of scenarios seen in the last CORRELATION_WINDOW seconds."""
    cutoff = time.time() - CORRELATION_WINDOW
    return {e["scenario"] for e in alert_history if e["ts"] >= cutoff}


def _emit_if_new(event_type: str, severity: str, scenarios: str,
                 description: str) -> None:
    """Emit a soc_event only if this type was not emitted in the last window."""
    now = time.time()
    last = _last_emitted.get(event_type, 0.0)
    if now - last < CORRELATION_WINDOW:
        return  # already emitted within this window, skip
    _last_emitted[event_type] = now
    ts_ns = int(now * 1e9)
    ok = write_soc_event(ts_ns, event_type, severity, scenarios, description)
    status = "OK" if ok else "ERR"
    print(
        f"[SOC] [{status}] CORRELATION {event_type} ({severity}) — {scenarios}",
        flush=True,
    )


def check_correlations() -> None:
    """Evaluate all correlation rules against recent alert history."""
    seen = _recent_scenarios()

    # Rule 1 — ATTACK_CHAIN (CRITICAL): Brute Force → Lateral Movement
    if "S4" in seen and "S5" in seen:
        _emit_if_new(
            "ATTACK_CHAIN", "CRITICAL", "S4+S5",
            "Brute Force followed by Lateral Movement — credential attack chain detected",
        )

    # Rule 2 — MULTI_VECTOR (HIGH): DoS + Brute Force
    if "S3" in seen and "S4" in seen:
        _emit_if_new(
            "MULTI_VECTOR", "HIGH", "S3+S4",
            "DoS distraction combined with Brute Force — multi-vector attack pattern",
        )

    # Rule 3 — RECON_TO_ACTION (CRITICAL): Lateral Movement → Injection / Replay
    if "S5" in seen and ("S2" in seen or "S6" in seen):
        involved = "+".join(sorted({"S5"} | (seen & {"S2", "S6"})))
        _emit_if_new(
            "RECON_TO_ACTION", "CRITICAL", involved,
            "Lateral Movement followed by data manipulation — recon-to-action chain",
        )


# ── Alert processing ──────────────────────────────────────────────────────────

def process_alert(event: dict) -> None:
    """Parse a Suricata alert event and write it to InfluxDB."""
    try:
        alert  = event.get("alert", {})
        sid    = alert.get("signature_id", 0)
        sig    = alert.get("signature", "unknown")
        src_ip = event.get("src_ip", "0.0.0.0")

        scenario = SID_TO_SCENARIO.get(sid, f"SID{sid}")

        # Parse timestamp from eve.json (ISO 8601 with offset)
        ts_str = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            ts_ns = int(dt.timestamp() * 1e9)
        except (ValueError, OSError):
            ts_ns = int(time.time() * 1e9)

        ok = write_alert(ts_ns, scenario, sid, src_ip, sig)
        status = "OK" if ok else "ERR"
        print(
            f"[ALERT] [{status}] {scenario} | SID {sid} | {src_ip} | {sig}",
            flush=True,
        )

        # Update history and check correlations
        alert_history.append({"ts": ts_ns / 1e9, "scenario": scenario})
        check_correlations()

    except Exception as exc:
        print(f"[WARN] Failed to process alert: {exc}", flush=True)


# ── File tail loop ────────────────────────────────────────────────────────────

def tail_eve_log() -> None:
    """
    Continuously tail eve.json and process new alert lines.

    On startup: seek to end of file to skip historical events.
    On file truncation/rotation: reset to beginning.
    """
    # Wait for eve.json to appear
    while not os.path.exists(EVE_LOG):
        print(f"[*] Waiting for {EVE_LOG} ...", flush=True)
        time.sleep(FILE_WAIT_INTERVAL)

    print(f"[+] Found {EVE_LOG} — seeking to end", flush=True)
    f = open(EVE_LOG, "r")
    f.seek(0, 2)  # seek to end: only process NEW events
    last_size = f.tell()

    processed = 0
    print("[+] SOC bridge active — monitoring for Suricata alerts", flush=True)

    while True:
        line = f.readline()

        if not line:
            # No new data — check for file rotation/truncation
            try:
                current_size = os.path.getsize(EVE_LOG)
                if current_size < last_size:
                    print("[*] eve.json truncated — resetting position", flush=True)
                    f.close()
                    f = open(EVE_LOG, "r")
                    last_size = 0
                else:
                    last_size = current_size
            except OSError:
                pass
            time.sleep(POLL_INTERVAL)
            continue

        last_size = f.tell()
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") == "alert":
            process_alert(event)
            processed += 1


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60, flush=True)
    print("  IoT Cyberrange — SOC Bridge", flush=True)
    print(f"  InfluxDB : {INFLUXDB_URL}", flush=True)
    print(f"  Bucket   : {INFLUXDB_BUCKET}", flush=True)
    print(f"  eve.json : {EVE_LOG}", flush=True)
    print("=" * 60, flush=True)

    # Verify InfluxDB connectivity
    try:
        r = requests.get(
            f"{INFLUXDB_URL}/health",
            headers={"Authorization": f"Token {INFLUXDB_TOKEN}"},
            timeout=5,
        )
        if r.status_code == 200:
            print("[+] InfluxDB reachable", flush=True)
        else:
            print(f"[!] InfluxDB health check returned {r.status_code}", flush=True)
    except requests.RequestException as e:
        print(f"[!] InfluxDB not reachable yet: {e} — will retry on writes", flush=True)

    tail_eve_log()
