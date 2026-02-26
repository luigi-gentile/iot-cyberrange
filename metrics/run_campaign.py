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

Report output:
    metrics/results/campaign_<env>_<timestamp>.json
    metrics/results/campaign_<env>_<timestamp>.csv
"""

import subprocess
import threading
import argparse
import json
import csv
import time
import os
import requests
import paho.mqtt.client as mqtt
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Environment configurations
# ──────────────────────────────────────────────
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
        "influxdb_url":       "http://172.22.0.30:8086",
        "influxdb_token":     "secure-token-abcdef",
        "influxdb_org":       "iot-cyberrange",
        "influxdb_bucket":    "sensors",
        "nodered_url":        "http://172.22.0.31:1880",
        "grafana_url":        "http://172.23.0.32:3000",
        "compose_dir":        os.path.expanduser("~/iot-cyberrange/secure"),
        "attacker_container": "secure_attacker",
    }
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results")

SCENARIO_NAMES = {
    1: "Eavesdropping",
    2: "Message Injection",
    3: "Denial of Service",
    4: "Brute Force",
    5: "Lateral Movement",
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


def check_data_integrity(env_config: dict) -> dict:
    """
    Check InfluxDB for anomalous sensor readings caused by injection attacks.
    Detects values outside expected physical ranges in the last 10 minutes.

    Args:
        env_config: Environment configuration dict

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
    checks = {
        "temperature": ("temperature", "value",   50.0,  -10.0),
        "humidity":    ("humidity",    "value",   100.0,    0.1),
        "power":       ("power",       "power_w", 400.0,   -1.0),
    }

    results = {}

    for name, (measurement, field, max_val, min_val) in checks.items():
        query = f'''
from(bucket: "{env_config['influxdb_bucket']}")
  |> range(start: -1h)
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


def collect_snapshot(env_config: dict, label: str) -> dict:
    """
    Collect a complete metrics snapshot at a given point in time.

    Args:
        env_config: Environment configuration dict
        label: Label for this snapshot (e.g. 'baseline', 'during_attack')

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
        "integrity":  check_data_integrity(env_config),
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
        scenario: Scenario number (1-5)
    """
    scripts = {
        1: ["bash", "scripts/01_eavesdrop.sh"],
        2: ["bash", "scripts/02_inject.sh"],
        3: ["python3", "scripts/03_dos.py"],
        4: ["python3", "scripts/04_bruteforce.py"],
        5: ["bash", "scripts/05_lateral_movement.sh"],
    }

    script    = scripts[scenario]
    container = env_config["attacker_container"]

    log(f"[*] Launching attack: {' '.join(script)}")

    subprocess.run(
        ["docker", "exec", container] + script,
        text=True
    )


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
        ])

        for scenario_key, scenario_data in campaign_results["scenarios"].items():
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
                ])

    return json_path, csv_path


def print_summary(campaign_results: dict):
    """Print a human-readable summary table of campaign results."""

    separator("CAMPAIGN SUMMARY")

    header = (
        f"{'Scenario':<22} {'Phase':<20} "
        f"{'Lat avg':<12} {'Throughput':<15} "
        f"{'Anomalies':<12} {'Integrity'}"
    )
    print(header)
    print("-" * len(header))

    for scenario_key, scenario_data in campaign_results["scenarios"].items():
        name = scenario_data.get("name", scenario_key)
        for phase in ["baseline", "during_attack"]:
            if phase not in scenario_data:
                continue

            snap = scenario_data[phase]
            lat  = snap.get("latency",    {}).get("avg_ms", "N/A")
            thr  = snap.get("throughput", {}).get("messages_per_sec", "N/A")
            anom = snap.get("integrity",  {}).get("temperature", {}).get("anomalies", "N/A")
            intg = snap.get("integrity",  {}).get("temperature", {}).get("integrity", "N/A")

            label = f"{scenario_key} ({name[:10]})"
            print(
                f"{label:<22} {phase:<20} "
                f"{str(lat)+'ms':<12} {str(thr)+' msg/s':<15} "
                f"{str(anom):<12} {intg}"
            )

    print("")


# ──────────────────────────────────────────────
# Main campaign orchestrator
# ──────────────────────────────────────────────

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

    args       = parser.parse_args()
    env_config = ENVIRONMENTS[args.env]

    campaign_results = {
        "environment": args.env,
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "scenarios":   {}
    }

    separator(f"IoT CYBERRANGE — ATTACK CAMPAIGN ({args.env.upper()})")

    # ── Step 0: Ensure environment is up ──────────────────────
    separator("STEP 0 — Environment Check")
    setup_environment(env_config)

    # ── Clear old data before starting campaign ───────────────
    separator("CLEARING OLD DATA")
    log("[*] Clearing InfluxDB data from previous runs...")
    headers = {
        "Authorization": f"Token {env_config['influxdb_token']}",
        "Content-Type":  "application/json"
    }
    try:
        response = requests.post(
            f"{env_config['influxdb_url']}/api/v2/delete"
            f"?org={env_config['influxdb_org']}"
            f"&bucket={env_config['influxdb_bucket']}",
            headers=headers,
            json={
                "start": "1970-01-01T00:00:00Z",
                "stop":  datetime.now(timezone.utc).isoformat()
            },
            timeout=10
        )
        if response.status_code == 204:
            log("[+] InfluxDB data cleared successfully")
        else:
            log(f"[-] InfluxDB clear warning: {response.status_code}")
    except Exception as e:
        log(f"[-] InfluxDB clear failed: {e}")
    log("[*] Waiting 15s for sensors to publish fresh data...")
    time.sleep(15)

    # ── Run each scenario ──────────────────────────────────────
    for scenario_num in range(1, 6):
        scenario_name = SCENARIO_NAMES[scenario_num]
        scenario_key  = f"scenario_{scenario_num}"

        separator(f"SCENARIO {scenario_num} — {scenario_name}")

        scenario_results = {
            "name":   scenario_name,
            "number": scenario_num,
        }

        # Reset only device state between scenarios
        reset_between_scenarios(env_config)

        # Collect baseline before attack
        log("[*] Collecting baseline metrics...")
        scenario_results["baseline"] = collect_snapshot(env_config, "baseline")

        # Launch attack in background thread
        log(f"[*] Launching Scenario {scenario_num}: {scenario_name}")
        attack_thread = threading.Thread(
            target=run_attack,
            args=(env_config, scenario_num)
        )
        attack_thread.start()

        # Scenario 2 (injection): wait for attack to complete before measuring
        # so forged data is already in InfluxDB when we check integrity
        # All other scenarios: measure during attack
        if scenario_num == 2:
            attack_thread.join()
            log(f"[+] Scenario {scenario_num} complete")
            scenario_results["during_attack"] = collect_snapshot(
                env_config, "during_attack"
            )
        else:
            time.sleep(5)
            scenario_results["during_attack"] = collect_snapshot(
                env_config, "during_attack"
            )
            attack_thread.join()
            log(f"[+] Scenario {scenario_num} complete")

        campaign_results["scenarios"][scenario_key] = scenario_results

    # ── Generate report ────────────────────────────────────────
    separator("GENERATING REPORT")

    campaign_results["completed_at"] = datetime.now(timezone.utc).isoformat()
    json_path, csv_path = generate_report(campaign_results, args.env)
    print_summary(campaign_results)

    print("==============================================")
    print(f" JSON report : {json_path}")
    print(f" CSV report  : {csv_path}")
    print("==============================================")


if __name__ == "__main__":
    main()