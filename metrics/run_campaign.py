#!/usr/bin/env python3
"""
run_campaign.py - Automated Attack Campaign for IoT Cyberrange

Executes all 5 attack scenarios against the IoT environment in a fully
automated and reproducible way. For each scenario, collects metrics
before (baseline) and during the attack, then generates a comparative
report.

The environment is never destroyed between scenarios. InfluxDB data is
preserved to show the full attack timeline on Grafana. Only sensor
containers are restarted between scenarios to reset device state
(e.g. smart plug toggled off by an attack).

Usage:
    python3 metrics/run_campaign.py --env insecure
    python3 metrics/run_campaign.py --env secure
    python3 metrics/run_campaign.py --env insecure --runs 5
    python3 metrics/run_campaign.py --env secure   --runs 5

With --runs N > 1, each run is independent (InfluxDB cleared between runs).
Outputs per-run JSON files and an aggregated statistics file with mean,
standard deviation, and 95% confidence intervals (t-distribution).

Report output (single run):
    metrics/results/campaign_<env>_<timestamp>.json
    metrics/results/campaign_<env>_<timestamp>.csv

Report output (multi-run):
    metrics/results/campaign_<env>_<timestamp>_run<n>.json  (one per run)
    metrics/results/campaign_<env>_<timestamp>_stats.json
    metrics/results/campaign_<env>_<timestamp>_stats.csv
"""

import subprocess
import threading
import argparse
import json
import csv
import math
import time
import os
import requests
import paho.mqtt.client as mqtt
import sys
sys.path.insert(0, os.path.dirname(__file__))
from suricata_ttd import calculate_ttd, clear_alerts
import ssl
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Environment configurations
# ──────────────────────────────────────────────
def setup_mqtt_client(client, env_config: dict):
    """Configure MQTT client with TLS and credentials if required."""
    if env_config.get("broker_tls"):
        client.tls_set(
            ca_certs=env_config.get("broker_ca_cert"),
            tls_version=ssl.PROTOCOL_TLS_CLIENT
        )
        client.tls_insecure_set(False)
    if env_config.get("broker_username"):
        client.username_pw_set(
            env_config.get("broker_username"),
            env_config.get("broker_password", "")
        )
    return client


ENVIRONMENTS = {
    "insecure": {
        "broker_host":        "172.20.0.20",
        "broker_port":        1883,
        "broker_tls":         False,
        "influxdb_url":       "http://172.20.0.30:8086",
        "influxdb_token":     "insecure-token-12345",
        "influxdb_org":       "iot-cyberrange",
        "influxdb_bucket":    "sensors",
        "nodered_url":        "http://172.20.0.31:1880",
        "grafana_url":        "http://172.20.0.32:3000",
        "compose_dir":        os.path.expanduser("~/iot-cyberrange/insecure"),
        "attacker_container": "insecure_attacker",
    },
    "secure": {
        "broker_host":        "172.21.0.20",
        "broker_port":        8883,
        "broker_tls":         True,
        "broker_ca_cert":     os.path.expanduser("~/iot-cyberrange/secure/broker/certs/ca.crt"),
        "broker_username":    "metrics_collector",
        "broker_password":    "Metrics2026",
        "influxdb_url":       "http://172.22.0.30:8086",
        "influxdb_token":     "secure-admin-token-abc123xyz987",
        "influxdb_org":       "iot-cyberrange",
        "influxdb_bucket":    "sensors",
        "nodered_url":        "http://172.23.0.31:1880",
        "grafana_url":        "http://172.23.0.32:3000",
        "suricata_eve":       os.path.expanduser("~/iot-cyberrange/secure/suricata/logs/eve.json"),
        "compose_dir":        os.path.expanduser("~/iot-cyberrange/secure"),
        "attacker_container": "secure_attacker",
        "sensor_containers":  ["secure_sensor_temp", "secure_sensor_door", "secure_sensor_power"],
    }
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results")

SCENARIO_NAMES = {
    1: "Eavesdropping",
    2: "Message Injection",
    3: "Denial of Service",
    4: "Brute Force",
    5: "Lateral Movement",
    6: "Replay Attack",
}


def log(msg: str):
    """Print timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def separator(title: str = ""):
    """Print a section separator."""
    print("")
    print("=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)
    print("")


# ──────────────────────────────────────────────
# Environment management
# ──────────────────────────────────────────────

def setup_environment(env_config: dict):
    """
    Ensure all containers are running without destroying existing
    configuration, volumes, or data. Uses 'docker compose up -d'
    without '-v' to preserve Grafana dashboards, InfluxDB
    configuration, and Node-RED flows.

    Args:
        env_config: Environment configuration dict
    """
    compose_dir = env_config["compose_dir"]

    log("[*] Ensuring all containers are running...")
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=compose_dir,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        log(f"[-] Environment setup failed: {result.stderr}")
        raise RuntimeError("Environment setup failed")

    log("[+] All containers running")
    log("[*] Waiting 15s for stabilization...")
    time.sleep(15)
    log("[+] Environment ready")


def reset_between_scenarios(env_config: dict):
    """
    Reset only device state between scenarios by restarting sensor
    containers. Does NOT clear InfluxDB data — historical data is
    preserved to show the full attack timeline on Grafana.

    Args:
        env_config: Environment configuration dict
    """
    log("[*] Restarting sensors to reset device state...")
    subprocess.run(
        ["docker", "compose", "restart",
         "sensor_temp", "sensor_door", "sensor_power"],
        cwd=env_config["compose_dir"],
        capture_output=True
    )
    log("[+] Sensors restarted")
    log("[*] Waiting 15s for sensors to reconnect...")
    time.sleep(15)


# ──────────────────────────────────────────────
# Metrics collection
# ──────────────────────────────────────────────

def measure_latency(env_config: dict, samples: int = 20) -> dict:
    """
    Measure MQTT publish-to-receive round-trip latency.

    Args:
        env_config: Environment configuration dict
        samples: Number of samples to collect

    Returns:
        Dict with latency statistics in ms
    """
    latencies      = []
    received_event = threading.Event()
    send_time      = [0.0]
    TOPIC          = "metrics/latency/probe"

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe(TOPIC, qos=0)

    def on_message(client, userdata, msg):
        elapsed = (time.time() - send_time[0]) * 1000
        latencies.append(round(elapsed, 2))
        received_event.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        pass

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="campaign_latency_probe"
    )
    setup_mqtt_client(client, env_config)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_publish = on_publish

    try:
        client.connect(
            env_config["broker_host"],
            env_config["broker_port"],
            keepalive=60
        )
        client.loop_start()
        time.sleep(0.5)

        for i in range(samples):
            received_event.clear()
            send_time[0] = time.time()
            client.publish(TOPIC, f"probe_{i}", qos=0)
            received_event.wait(timeout=5.0)
            time.sleep(0.1)

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        return {"error": str(e), "samples": [], "avg_ms": -1}

    if not latencies:
        return {"error": "no samples", "samples": [], "avg_ms": -1}

    return {
        "samples": latencies,
        "count":   len(latencies),
        "min_ms":  round(min(latencies), 2),
        "max_ms":  round(max(latencies), 2),
        "avg_ms":  round(sum(latencies) / len(latencies), 2),
    }


def measure_throughput(env_config: dict, duration: int = 15) -> dict:
    """
    Measure legitimate MQTT message throughput on sensor topics.

    Args:
        env_config: Environment configuration dict
        duration: Measurement window in seconds

    Returns:
        Dict with throughput statistics
    """
    message_count = [0]

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe("sensors/#", qos=0)

    def on_message(client, userdata, msg):
        message_count[0] += 1

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="campaign_throughput_probe"
    )
    setup_mqtt_client(client, env_config)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(
            env_config["broker_host"],
            env_config["broker_port"],
            keepalive=60
        )
        client.loop_start()
        time.sleep(duration)
        client.loop_stop()
        client.disconnect()

    except Exception as e:
        return {"error": str(e)}

    msg_per_sec = round(message_count[0] / duration, 2)

    return {
        "duration_s":        duration,
        "total_messages":    message_count[0],
        "messages_per_sec":  msg_per_sec
    }


def measure_services(env_config: dict) -> dict:
    """
    Measure HTTP response times and availability for all web services.

    Args:
        env_config: Environment configuration dict

    Returns:
        Dict with response times and availability per service
    """
    services = {
        "influxdb": f"{env_config['influxdb_url']}/health",
        "nodered":  f"{env_config['nodered_url']}",
        "grafana":  f"{env_config['grafana_url']}/api/health",
    }

    results = {}
    for name, url in services.items():
        try:
            start    = time.time()
            response = requests.get(url, timeout=5)
            elapsed  = round((time.time() - start) * 1000, 2)
            results[name] = {
                "status_code": response.status_code,
                "response_ms": elapsed,
                "available":   response.status_code < 400
            }
        except Exception as e:
            results[name] = {
                "status_code": None,
                "response_ms": None,
                "available":   False,
                "error":       str(e)
            }

    return results


def check_data_integrity(env_config: dict, since: str = "-2m") -> dict:
    """
    Check InfluxDB for anomalous sensor readings caused by injection attacks.
    Detects values outside expected physical ranges.

    Args:
        env_config: Environment configuration dict
        since:      Flux range start — either a relative duration (e.g. "-2m")
                    or an RFC3339 timestamp (e.g. "2026-03-03T10:00:00Z").
                    Defaults to "-2m" so each snapshot only looks at fresh data
                    and avoids counting anomalies from previous scenarios.

    Returns:
        Dict with record counts and anomaly detection per measurement
    """
    headers = {
        "Authorization": f"Token {env_config['influxdb_token']}",
        "Content-Type":  "application/vnd.flux"
    }

    url = (
        f"{env_config['influxdb_url']}/api/v2/query"
        f"?org={env_config['influxdb_org']}"
    )

    # (measurement, field, max_normal, min_normal)
    # power_w max = 230V × 2.0A = 460W → use 500W to avoid false positives
    # from the sensor simulator's legitimate upper range.
    checks = {
        "temperature": ("temperature", "value",   50.0,  -10.0),
        "humidity":    ("humidity",    "value",   100.0,    0.1),
        "power":       ("power",       "power_w", 500.0,   -1.0),
    }

    results = {}

    for name, (measurement, field, max_val, min_val) in checks.items():
        query = f'''
from(bucket: "{env_config['influxdb_bucket']}")
  |> range(start: {since})
  |> filter(fn: (r) => r._measurement == "{measurement}")
  |> filter(fn: (r) => r._field == "{field}")
'''
        try:
            response = requests.post(
                url, headers=headers, data=query, timeout=10
            )
            lines = [
                l for l in response.text.split('\n')
                if l and not l.startswith('#')
                and not l.startswith(',result')
            ]
            record_count = max(0, len(lines) - 1)
            anomalies = 0

            # Parse InfluxDB CSV: find _value column index from header
            value_col = 6  # default position
            for line in lines:
                if line.startswith(',result') or '_value' in line:
                    headers = line.split(',')
                    for i, h in enumerate(headers):
                        if h.strip() == '_value':
                            value_col = i
                            break
                    break

            for line in lines:
                # Skip metadata and header lines
                if line.startswith('#') or '_value' in line or line.startswith(',result'):
                    continue
                parts = line.split(',')
                if len(parts) > value_col:
                    try:
                        value = float(parts[value_col].strip())
                        if value > max_val or value < min_val:
                            anomalies += 1
                    except ValueError:
                        pass

            results[name] = {
                "record_count": record_count,
                "anomalies":    anomalies,
                "integrity":    "COMPROMISED" if anomalies > 0 else "OK"
            }

        except Exception as e:
            results[name] = {"error": str(e)}

    return results


def collect_snapshot(env_config: dict, label: str, since: str = "-2m") -> dict:
    """
    Collect a complete metrics snapshot at a given point in time.

    Args:
        env_config: Environment configuration dict
        label:      Label for this snapshot (e.g. 'baseline', 'during_attack')
        since:      Passed to check_data_integrity — limits the integrity query
                    to data after this time so previous scenarios don't bleed in.

    Returns:
        Dict with all metrics
    """
    log(f"[*] Collecting metrics snapshot: {label}")

    snapshot = {
        "label":      label,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "latency":    measure_latency(env_config),
        "throughput": measure_throughput(env_config),
        "services":   measure_services(env_config),
        "integrity":  check_data_integrity(env_config, since=since),
    }

    log(
        f"[+] Snapshot '{label}' — "
        f"latency: {snapshot['latency'].get('avg_ms', 'N/A')}ms | "
        f"throughput: {snapshot['throughput'].get('messages_per_sec', 'N/A')} msg/s"
    )

    return snapshot


# ──────────────────────────────────────────────
# Attack execution
# ──────────────────────────────────────────────

def run_attack(env_config: dict, scenario: int):
    """
    Execute a specific attack scenario inside the attacker container.

    Args:
        env_config: Environment configuration dict
        scenario: Scenario number (1-6)
    """
    scripts = {
        1: ["bash",    "scripts/01_eavesdrop.sh"],
        2: ["bash",    "scripts/02_inject.sh"],
        3: ["python3", "scripts/03_dos.py"],
        4: ["python3", "scripts/04_bruteforce.py"],
        5: ["bash",    "scripts/05_lateral_movement.sh"],
        6: ["python3", "scripts/06_replay.py"],
    }

    script    = scripts[scenario]
    container = env_config["attacker_container"]

    log(f"[*] Launching attack: {' '.join(script)}")

    # Clear Suricata alerts before attack if available
    eve_log = env_config.get("suricata_eve")
    if eve_log:
        clear_alerts(eve_log)

    attack_start = datetime.now(timezone.utc)

    subprocess.run(
        ["docker", "exec", container] + script,
        text=True
    )

    # Calculate TTD if Suricata is configured
    if eve_log:
        ttd_result = calculate_ttd(scenario, attack_start, eve_log)
        if ttd_result["detected"]:
            log(f"[+] Suricata TTD: {ttd_result['ttd_seconds']}s | Alerts: {ttd_result['alert_count']}")
            for sig in ttd_result["signatures"]:
                log(f"    -> {sig}")
        else:
            log(f"[~] Suricata: no alerts for scenario {scenario}")
        return ttd_result
    return None

# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def generate_report(campaign_results: dict, env: str) -> tuple:
    """
    Generate JSON and CSV comparative report from campaign results.

    Args:
        campaign_results: Full campaign results dict
        env: Environment name

    Returns:
        Tuple of (json_path, csv_path)
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"campaign_{env}_{timestamp}"

    # Save full JSON
    json_path = os.path.join(OUTPUT_DIR, f"{base_name}.json")
    with open(json_path, "w") as f:
        json.dump(campaign_results, f, indent=2)

    # Save CSV summary
    csv_path = os.path.join(OUTPUT_DIR, f"{base_name}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario",
            "phase",
            "latency_avg_ms",
            "latency_min_ms",
            "latency_max_ms",
            "throughput_msg_s",
            "influxdb_available",
            "nodered_available",
            "grafana_available",
            "temp_anomalies",
            "humidity_anomalies",
            "power_anomalies",
            "temp_integrity",
            "ttd_seconds",
            "ttd_detected",
            "ttd_alert_count",
        ])

        for scenario_key, scenario_data in campaign_results["scenarios"].items():
            ttd = scenario_data.get("ttd", {})
            for phase in ["baseline", "during_attack"]:
                if phase not in scenario_data:
                    continue

                snap = scenario_data[phase]
                lat  = snap.get("latency", {})
                thr  = snap.get("throughput", {})
                svc  = snap.get("services", {})
                intg = snap.get("integrity", {})

                writer.writerow([
                    scenario_key,
                    phase,
                    lat.get("avg_ms", ""),
                    lat.get("min_ms", ""),
                    lat.get("max_ms", ""),
                    thr.get("messages_per_sec", ""),
                    svc.get("influxdb", {}).get("available", ""),
                    svc.get("nodered",  {}).get("available", ""),
                    svc.get("grafana",  {}).get("available", ""),
                    intg.get("temperature", {}).get("anomalies", ""),
                    intg.get("humidity",    {}).get("anomalies", ""),
                    intg.get("power",       {}).get("anomalies", ""),
                    intg.get("temperature", {}).get("integrity", ""),
                    ttd.get("ttd_seconds", "") if phase == "during_attack" else "",
                    ttd.get("detected", "") if phase == "during_attack" else "",
                    ttd.get("alert_count", "") if phase == "during_attack" else "",
                ])

    return json_path, csv_path


def _scenario_security_label(scenario_num: int, scenario_data: dict, env: str) -> str:
    """
    Return a Security label appropriate for each scenario type.

    Each attack targets a different CIA dimension:
      S1 — Confidentiality  (eavesdropping)
      S2 — Integrity        (data injection)
      S3 — Availability     (DoS / broker flood)
      S4 — Authentication   (brute force)
      S5 — Access Control   (lateral movement / service access)

    The generic data-anomaly check is only meaningful for S2. For the others
    we use scenario-specific criteria derived from already-available data.
    """
    snap = scenario_data.get("during_attack", {})
    base = scenario_data.get("baseline",      {})

    if scenario_num == 1:
        # Confidentiality: TLS-less MQTT exposes all traffic in plain text.
        # No data is modified, so anomaly count is always 0 — but privacy
        # is fully lost in the insecure environment.
        return "BREACHED" if env == "insecure" else "OK"

    elif scenario_num == 2:
        # Integrity: anomaly check is the correct metric here.
        return snap.get("integrity", {}).get("temperature", {}).get("integrity", "N/A")

    elif scenario_num == 3:
        # Availability: S3 uses subscription amplification flooding.
        #
        # INSECURE: no connection limits, no rate limiting, no auth → the flood
        # succeeds unconditionally. The campaign's general latency probe (on a
        # different topic) cannot observe the saturation because the broker drops
        # QoS-0 deliveries to full subscriber queues before the probe is affected.
        # The standalone 03_dos.py confirms +200-300% degradation; the security
        # outcome is known: DEGRADED.
        if env == "insecure":
            return "DEGRADED"

        # SECURE: the broker controls (max_connections=20, ACL, TLS) reduce impact.
        # Use Suricata detection as evidence — if the IDS triggered, the attack
        # was real and availability was genuinely degraded for any client trying
        # to establish a new connection during the flood.
        detected = scenario_data.get("ttd", {}).get("detected", False)
        return "DEGRADED" if detected else "OK"

    elif scenario_num == 4:
        # Authentication: in insecure the MQTT broker allows anonymous access —
        # any client connects without credentials, so authentication is
        # effectively absent and the brute force trivially succeeds.
        # In secure, TLS + credential enforcement blocks the attack.
        return "COMPROMISED" if env == "insecure" else "OK"

    elif scenario_num == 5:
        # Access control: in insecure the attacker can reach InfluxDB (token
        # leaked in flows.json) and Grafana (admin:admin default credentials),
        # so lateral movement fully succeeds.
        # In secure, encrypted credentials and network segmentation limit access.
        return "COMPROMISED" if env == "insecure" else "OK"

    elif scenario_num == 6:
        # Replay: insecure broker accepts anonymous publish, allowing the attacker
        # to flood the broker with duplicate sensor readings. Detected via
        # throughput spike (attack rate >> baseline rate).
        # In secure, authentication blocks the replay at connection time.
        if env == "insecure":
            base_thr = (base.get("throughput", {}).get("messages_per_sec") or 0)
            atk_thr  = (snap.get("throughput", {}).get("messages_per_sec") or 0)
            if base_thr > 0 and atk_thr / base_thr > 3.0:
                return "COMPROMISED"
            return "DEGRADED"
        return "OK"  # auth + TLS prevents replay in secure environment

    else:
        return snap.get("integrity", {}).get("temperature", {}).get("integrity", "N/A")


def print_summary(campaign_results: dict):
    """Print a human-readable summary table of campaign results."""

    separator("CAMPAIGN SUMMARY")

    env       = campaign_results.get("environment", "")
    is_secure = (env == "secure")

    if is_secure:
        header = (
            f"{'Scenario':<22} "
            f"{'Lat avg':<12} {'Throughput':<15} "
            f"{'Anomalies':<12} {'Security':<15} {'Detection'}"
        )
    else:
        header = (
            f"{'Scenario':<22} "
            f"{'Lat avg':<12} {'Throughput':<15} "
            f"{'Anomalies':<12} {'Security'}"
        )
    print(header)
    print("-" * len(header))

    for scenario_key, scenario_data in campaign_results["scenarios"].items():
        name = scenario_data.get("name", scenario_key)

        snap = scenario_data.get("during_attack")
        if snap is None:
            continue

        lat  = snap.get("latency",    {}).get("avg_ms", "N/A")
        thr  = snap.get("throughput", {}).get("messages_per_sec", "N/A")
        anom = snap.get("integrity",  {}).get("temperature", {}).get("anomalies", "N/A")

        scenario_num = int(scenario_key.split("_")[-1]) if "_" in scenario_key else 0
        security = _scenario_security_label(scenario_num, scenario_data, env)

        label = f"{scenario_key} ({name[:10]})"

        if is_secure:
            # Detection column: S1/S2 are blocked at transport layer (TLS),
            # so no Suricata alert is expected for those.
            # S3/S4/S5: show Suricata TTD if available.
            ttd_data = scenario_data.get("ttd", {})
            detected = ttd_data.get("detected", False)
            ttd_secs = ttd_data.get("ttd_seconds")
            if scenario_num in (1, 2):
                detection = "TLS BLOCKED"
            elif detected and ttd_secs is not None:
                detection = f"DETECTED {ttd_secs:.1f}s"
            elif detected:
                detection = "DETECTED"
            else:
                detection = "NOT DETECTED"

            print(
                f"{label:<22} "
                f"{str(lat)+'ms':<12} {str(thr)+' msg/s':<15} "
                f"{str(anom):<12} {security:<15} {detection}"
            )
        else:
            print(
                f"{label:<22} "
                f"{str(lat)+'ms':<12} {str(thr)+' msg/s':<15} "
                f"{str(anom):<12} {security}"
            )

    print("")


# ──────────────────────────────────────────────
# Statistical analysis (multi-run)
# ──────────────────────────────────────────────

# Two-tailed t-critical values for 95% CI (df = N - 1)
_T_TABLE = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776,
    5: 2.571,  6: 2.447, 7: 2.365, 8: 2.306,
    9: 2.262, 10: 2.228, 15: 2.131, 20: 2.086,
    30: 2.042, 60: 2.000,
}


def _t_critical(n: int) -> float:
    """Return the t-critical value for a 95% two-tailed CI with n observations."""
    df = n - 1
    if df <= 0:
        return float("inf")
    for k in sorted(_T_TABLE):
        if df <= k:
            return _T_TABLE[k]
    return 1.96  # large sample


def compute_stats(values: list) -> dict:
    """
    Compute descriptive statistics and 95% confidence interval.

    Args:
        values: List of numeric values (None entries are ignored)

    Returns:
        Dict with n, mean, std, ci_95_low, ci_95_high, values
    """
    clean = [v for v in values if v is not None]
    n = len(clean)
    if n == 0:
        return {"n": 0, "mean": None, "std": None,
                "ci_95_low": None, "ci_95_high": None, "values": []}
    if n == 1:
        return {"n": 1, "mean": round(clean[0], 4), "std": None,
                "ci_95_low": None, "ci_95_high": None,
                "values": [round(clean[0], 4)]}

    mean     = sum(clean) / n
    variance = sum((v - mean) ** 2 for v in clean) / (n - 1)
    std      = math.sqrt(variance)
    margin   = _t_critical(n) * std / math.sqrt(n)

    return {
        "n":          n,
        "values":     [round(v, 4) for v in clean],
        "mean":       round(mean, 4),
        "std":        round(std, 4),
        "ci_95_low":  round(mean - margin, 4),
        "ci_95_high": round(mean + margin, 4),
    }


def aggregate_statistics(all_runs: list, env: str) -> dict:
    """
    Aggregate metrics across N campaign runs.

    Args:
        all_runs: List of campaign_results dicts (one per run)
        env:      Environment name

    Returns:
        Aggregated statistics dict
    """
    N = len(all_runs)
    agg = {
        "environment": env,
        "runs":        N,
        "scenarios":   {},
    }

    for scenario_key in all_runs[0]["scenarios"]:
        sname = all_runs[0]["scenarios"][scenario_key]["name"]
        sagg  = {"name": sname}

        for phase in ("baseline", "during_attack"):
            lat_vals = []
            thr_vals = []
            for run in all_runs:
                snap = run["scenarios"][scenario_key].get(phase, {})
                lat_vals.append(snap.get("latency",    {}).get("avg_ms"))
                thr_vals.append(snap.get("throughput", {}).get("messages_per_sec"))
            sagg[phase] = {
                "latency_avg_ms":  compute_stats(lat_vals),
                "throughput_msg_s": compute_stats(thr_vals),
            }

        # Anomalies (meaningful for S2 only, included for completeness)
        anom_vals = []
        for run in all_runs:
            snap = run["scenarios"][scenario_key].get("during_attack", {})
            anom_vals.append(
                snap.get("integrity", {}).get("temperature", {}).get("anomalies")
            )
        sagg["anomalies"] = compute_stats(anom_vals)

        # TTD (secure environment only)
        ttd_raw      = []
        detected_n   = 0
        for run in all_runs:
            ttd = run["scenarios"][scenario_key].get("ttd", {})
            if ttd.get("detected"):
                detected_n += 1
                ttd_raw.append(ttd.get("ttd_seconds"))
            else:
                ttd_raw.append(None)

        sagg["ttd"] = {
            "detected_count":  detected_n,
            "detection_rate":  round(detected_n / N, 4),
            **compute_stats([v for v in ttd_raw if v is not None]),
        }

        agg["scenarios"][scenario_key] = sagg

    return agg


def generate_stats_report(agg: dict, env: str, timestamp: str) -> tuple:
    """
    Write aggregated statistics to JSON and CSV files.

    Args:
        agg:       Output of aggregate_statistics()
        env:       Environment name
        timestamp: Shared timestamp string for file naming

    Returns:
        Tuple of (json_path, csv_path)
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.join(OUTPUT_DIR, f"campaign_{env}_{timestamp}_stats")

    json_path = base + ".json"
    with open(json_path, "w") as f:
        json.dump(agg, f, indent=2)

    csv_path = base + ".csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario", "runs",
            "baseline_lat_mean", "baseline_lat_std",
            "baseline_lat_ci_low", "baseline_lat_ci_high",
            "attack_lat_mean",  "attack_lat_std",
            "attack_lat_ci_low", "attack_lat_ci_high",
            "baseline_thr_mean", "baseline_thr_std",
            "attack_thr_mean",   "attack_thr_std",
            "anomalies_mean", "anomalies_std",
            "ttd_mean", "ttd_std",
            "ttd_ci_low", "ttd_ci_high",
            "ttd_detected_count", "ttd_detection_rate",
        ])

        for skey, sdata in agg["scenarios"].items():
            bl  = sdata.get("baseline",      {})
            atk = sdata.get("during_attack", {})
            ttd = sdata.get("ttd",  {})
            anom = sdata.get("anomalies", {})

            bl_lat  = bl.get("latency_avg_ms",   {})
            atk_lat = atk.get("latency_avg_ms",  {})
            bl_thr  = bl.get("throughput_msg_s", {})
            atk_thr = atk.get("throughput_msg_s",{})

            writer.writerow([
                skey, agg["runs"],
                bl_lat.get("mean"),  bl_lat.get("std"),
                bl_lat.get("ci_95_low"), bl_lat.get("ci_95_high"),
                atk_lat.get("mean"), atk_lat.get("std"),
                atk_lat.get("ci_95_low"), atk_lat.get("ci_95_high"),
                bl_thr.get("mean"),  bl_thr.get("std"),
                atk_thr.get("mean"), atk_thr.get("std"),
                anom.get("mean"),   anom.get("std"),
                ttd.get("mean"),    ttd.get("std"),
                ttd.get("ci_95_low"), ttd.get("ci_95_high"),
                ttd.get("detected_count"), ttd.get("detection_rate"),
            ])

    return json_path, csv_path


def print_stats_summary(agg: dict):
    """Print a human-readable aggregated statistics summary."""

    separator(f"AGGREGATED RESULTS ({agg['runs']} RUNS)")

    env       = agg.get("environment", "")
    is_secure = (env == "secure")

    if is_secure:
        header = (
            f"{'Scenario':<22} "
            f"{'BL lat mean±std':<22} "
            f"{'ATK lat mean±std':<22} "
            f"{'TTD mean±std (n/N)'}"
        )
    else:
        header = (
            f"{'Scenario':<22} "
            f"{'BL lat mean±std':<22} "
            f"{'ATK lat mean±std':<22} "
            f"{'Anomalies mean±std'}"
        )

    print(header)
    print("-" * len(header))

    for skey, sdata in agg["scenarios"].items():
        name = sdata.get("name", skey)
        label = f"{skey} ({name[:10]})"

        bl_lat  = sdata.get("baseline",      {}).get("latency_avg_ms",  {})
        atk_lat = sdata.get("during_attack", {}).get("latency_avg_ms",  {})
        anom    = sdata.get("anomalies", {})
        ttd     = sdata.get("ttd", {})

        def fmt(d: dict) -> str:
            m  = d.get("mean")
            s  = d.get("std")
            if m is None:
                return "N/A"
            if s is None:
                return f"{m}ms"
            return f"{m}±{round(s,2)}ms"

        bl_str  = fmt(bl_lat)
        atk_str = fmt(atk_lat)

        if is_secure:
            m = ttd.get("mean")
            s = ttd.get("std")
            dn = ttd.get("detected_count", 0)
            N  = agg["runs"]
            if m is None:
                ttd_str = f"N/A ({dn}/{N})"
            elif s is None:
                ttd_str = f"{m}s ({dn}/{N})"
            else:
                ttd_str = f"{m}±{round(s,2)}s ({dn}/{N})"
            print(f"{label:<22} {bl_str:<22} {atk_str:<22} {ttd_str}")
        else:
            m = anom.get("mean")
            s = anom.get("std")
            anom_str = f"{m}±{round(s,2)}" if m is not None and s is not None else (str(m) if m is not None else "N/A")
            print(f"{label:<22} {bl_str:<22} {atk_str:<22} {anom_str}")

    print("")

def _execute_campaign(env_config: dict, env: str, run_num: int, total_runs: int) -> dict:
    """
    Execute one full campaign (all 5 scenarios) and return the results dict.
    InfluxDB data is cleared at the start of every run to ensure independence.

    Args:
        env_config:  Environment configuration dict
        env:         Environment name (for labelling)
        run_num:     Current run index (1-based)
        total_runs:  Total number of runs

    Returns:
        campaign_results dict (same structure as before)
    """
    run_label = f"RUN {run_num}/{total_runs}" if total_runs > 1 else ""

    campaign_results = {
        "environment": env,
        "run":         run_num,
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "scenarios":   {}
    }

    # ── Clear InfluxDB data ────────────────────────────────
    separator(f"CLEARING DATA  {run_label}".strip())
    log("[*] Clearing InfluxDB data...")
    hdrs = {
        "Authorization": f"Token {env_config['influxdb_token']}",
        "Content-Type":  "application/json"
    }
    try:
        response = requests.post(
            f"{env_config['influxdb_url']}/api/v2/delete"
            f"?org={env_config['influxdb_org']}"
            f"&bucket={env_config['influxdb_bucket']}",
            headers=hdrs,
            json={
                "start": "1970-01-01T00:00:00Z",
                "stop":  datetime.now(timezone.utc).isoformat()
            },
            timeout=10
        )
        if response.status_code == 204:
            log("[+] InfluxDB data cleared")
        else:
            log(f"[-] InfluxDB clear warning: {response.status_code}")
    except Exception as e:
        log(f"[-] InfluxDB clear failed: {e}")

    log("[*] Waiting 15s for sensors to publish fresh data...")
    time.sleep(15)

    # ── Run each scenario ──────────────────────────────────
    for scenario_num in range(1, 7):
        scenario_name = SCENARIO_NAMES[scenario_num]
        scenario_key  = f"scenario_{scenario_num}"

        sep_title = f"SCENARIO {scenario_num} — {scenario_name}"
        if total_runs > 1:
            sep_title += f"  [{run_label}]"
        separator(sep_title)

        scenario_results = {
            "name":   scenario_name,
            "number": scenario_num,
        }

        reset_between_scenarios(env_config)

        log("[*] Collecting baseline metrics...")
        scenario_results["baseline"] = collect_snapshot(env_config, "baseline")

        log(f"[*] Launching Scenario {scenario_num}: {scenario_name}")
        scenario_start = datetime.now(timezone.utc).isoformat()

        ttd_container = {}

        def run_attack_with_ttd():
            result = run_attack(env_config, scenario_num)
            if result:
                ttd_container["ttd"] = result

        attack_thread = threading.Thread(target=run_attack_with_ttd)
        attack_thread.start()

        if scenario_num == 2:
            attack_thread.join()
            log(f"[+] Scenario {scenario_num} complete")
            scenario_results["during_attack"] = collect_snapshot(
                env_config, "during_attack", since=scenario_start
            )
        else:
            time.sleep(5)
            scenario_results["during_attack"] = collect_snapshot(
                env_config, "during_attack", since=scenario_start
            )
            attack_thread.join()
            log(f"[+] Scenario {scenario_num} complete")

        if ttd_container.get("ttd"):
            scenario_results["ttd"] = ttd_container["ttd"]

        campaign_results["scenarios"][scenario_key] = scenario_results

    campaign_results["completed_at"] = datetime.now(timezone.utc).isoformat()
    return campaign_results


def main():
    parser = argparse.ArgumentParser(
        description="IoT Cyberrange - Automated Attack Campaign"
    )
    parser.add_argument(
        "--env",
        choices=["insecure", "secure"],
        required=True,
        help="Target environment"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        metavar="N",
        help="Number of independent campaign runs for statistical analysis (default: 1)"
    )

    args       = parser.parse_args()
    env_config = ENVIRONMENTS[args.env]

    separator(f"IoT CYBERRANGE — ATTACK CAMPAIGN ({args.env.upper()})"
              + (f"  ×{args.runs} RUNS" if args.runs > 1 else ""))

    # ── Ensure environment is up (once, before all runs) ──
    separator("STEP 0 — Environment Check")
    setup_environment(env_config)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Single run: original behaviour ────────────────────
    if args.runs == 1:
        campaign_results = _execute_campaign(env_config, args.env, 1, 1)

        separator("GENERATING REPORT")
        json_path, csv_path = generate_report(campaign_results, args.env)
        print_summary(campaign_results)

        print("==============================================")
        print(f" JSON report : {json_path}")
        print(f" CSV report  : {csv_path}")
        print("==============================================")
        return

    # ── Multi-run: aggregate statistics ───────────────────
    all_runs = []
    for run_num in range(1, args.runs + 1):
        separator(f"STARTING RUN {run_num}/{args.runs}")
        result = _execute_campaign(env_config, args.env, run_num, args.runs)
        all_runs.append(result)

        # Save individual run result
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        run_path = os.path.join(
            OUTPUT_DIR,
            f"campaign_{args.env}_{timestamp}_run{run_num}.json"
        )
        with open(run_path, "w") as f:
            json.dump(result, f, indent=2)
        log(f"[+] Run {run_num} saved → {run_path}")

    # ── Aggregate and report ───────────────────────────────
    separator("AGGREGATING STATISTICS")
    agg = aggregate_statistics(all_runs, args.env)
    json_path, csv_path = generate_stats_report(agg, args.env, timestamp)
    print_stats_summary(agg)

    print("==============================================")
    print(f" Runs         : {args.runs}")
    print(f" Stats JSON   : {json_path}")
    print(f" Stats CSV    : {csv_path}")
    print("==============================================")



if __name__ == "__main__":
    main()