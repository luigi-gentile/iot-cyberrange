#!/usr/bin/env python3
"""
collect_metrics.py - Automated Metrics Collection for IoT Cyberrange

Collects quantitative metrics from the IoT infrastructure to enable
systematic comparison between the insecure and secure environments.

Metrics collected:
    - MQTT broker statistics (via $SYS topic tree)
    - Message latency (publish-to-receive round trip)
    - Message throughput (messages per second)
    - Broker connection count
    - InfluxDB data integrity (record count and value ranges)
    - Service availability (HTTP response times)

Usage:
    python3 collect_metrics.py --env insecure --mode baseline
    python3 collect_metrics.py --env insecure --mode attack --scenario 3
    python3 collect_metrics.py --env secure --mode baseline
"""

import paho.mqtt.client as mqtt
import argparse
import json
import csv
import time
import threading
import requests
import os
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Environment configurations
# ──────────────────────────────────────────────
ENVIRONMENTS = {
    "insecure": {
        "broker_host":    "172.20.0.20",
        "broker_port":    1883,
        "broker_tls":     False,
        "influxdb_url":   "http://172.20.0.30:8086",
        "influxdb_token": "insecure-token-12345",
        "influxdb_org":   "iot-cyberrange",
        "influxdb_bucket":"sensors",
        "nodered_url":    "http://172.20.0.31:1880",
        "grafana_url":    "http://172.20.0.32:3000",
    },
    "secure": {
        "broker_host":    "172.21.0.20",
        "broker_port":    8883,
        "broker_tls":     True,
        "influxdb_url":   "http://172.22.0.30:8086",
        "influxdb_token": "secure-token-abcdef",
        "influxdb_org":   "iot-cyberrange",
        "influxdb_bucket":"sensors",
        "nodered_url":    "http://172.22.0.31:1880",
        "grafana_url":    "http://172.23.0.32:3000",
    }
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results")


def log(msg: str):
    """Print timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ──────────────────────────────────────────────
# Metric 1: MQTT Latency
# ──────────────────────────────────────────────

def measure_mqtt_latency(env_config: dict, samples: int = 20) -> dict:
    """
    Measure MQTT publish-to-receive round-trip latency.

    Publishes a timestamped message and measures time until
    the same message is received back via subscription.

    Args:
        env_config: Environment configuration dict
        samples: Number of latency samples to collect

    Returns:
        Dict with min, max, avg, and all latency samples in ms
    """
    log(f"[*] Measuring MQTT latency ({samples} samples)...")

    latencies = []
    received_event = threading.Event()
    send_time = [0.0]

    LATENCY_TOPIC = "metrics/latency/probe"

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe(LATENCY_TOPIC, qos=0)

    def on_message(client, userdata, msg):
        elapsed = (time.time() - send_time[0]) * 1000
        latencies.append(round(elapsed, 2))
        received_event.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        pass

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="metrics_latency_probe"
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
        time.sleep(0.5)  # wait for connection

        for i in range(samples):
            received_event.clear()
            send_time[0] = time.time()
            client.publish(LATENCY_TOPIC, f"probe_{i}", qos=0)
            received_event.wait(timeout=5.0)
            time.sleep(0.2)

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        log(f"[-] Latency measurement failed: {e}")
        return {"error": str(e), "samples": []}

    if not latencies:
        return {"error": "no samples collected", "samples": []}

    return {
        "samples":    latencies,
        "count":      len(latencies),
        "min_ms":     round(min(latencies), 2),
        "max_ms":     round(max(latencies), 2),
        "avg_ms":     round(sum(latencies) / len(latencies), 2),
    }


# ──────────────────────────────────────────────
# Metric 2: MQTT Throughput
# ──────────────────────────────────────────────

def measure_mqtt_throughput(env_config: dict, duration: int = 10) -> dict:
    """
    Measure MQTT message throughput in messages per second.

    Subscribes to all sensor topics and counts messages received
    over a fixed time window.

    Args:
        env_config: Environment configuration dict
        duration: Measurement window in seconds

    Returns:
        Dict with total messages and messages per second
    """
    log(f"[*] Measuring MQTT throughput ({duration}s window)...")

    message_count = [0]

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe("#", qos=0)

    def on_message(client, userdata, msg):
        message_count[0] += 1

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="metrics_throughput_probe"
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
        log(f"[-] Throughput measurement failed: {e}")
        return {"error": str(e)}

    msg_per_sec = round(message_count[0] / duration, 2)
    log(f"[+] Throughput: {message_count[0]} messages in {duration}s ({msg_per_sec} msg/s)")

    return {
        "duration_s":      duration,
        "total_messages":  message_count[0],
        "messages_per_sec": msg_per_sec
    }


# ──────────────────────────────────────────────
# Metric 3: Broker Statistics
# ──────────────────────────────────────────────

def collect_broker_stats(env_config: dict) -> dict:
    """
    Collect broker statistics from the $SYS topic tree.

    Args:
        env_config: Environment configuration dict

    Returns:
        Dict with broker statistics
    """
    log("[*] Collecting broker statistics from $SYS topic tree...")

    stats = {}
    done_event = threading.Event()

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe("$SYS/#", qos=0)

    def on_message(client, userdata, msg):
        key = msg.topic.replace("$SYS/broker/", "").replace("/", "_")
        try:
            stats[key] = float(msg.payload.decode())
        except ValueError:
            stats[key] = msg.payload.decode()

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="metrics_sys_probe"
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
        time.sleep(3)  # collect for 3 seconds
        client.loop_stop()
        client.disconnect()

    except Exception as e:
        log(f"[-] Broker stats collection failed: {e}")
        return {"error": str(e)}

    log(f"[+] Collected {len(stats)} broker statistics")
    return stats


# ──────────────────────────────────────────────
# Metric 4: Service Availability
# ──────────────────────────────────────────────

def measure_service_availability(env_config: dict) -> dict:
    """
    Measure HTTP response times for all web services.

    Args:
        env_config: Environment configuration dict

    Returns:
        Dict with response times and status codes for each service
    """
    log("[*] Measuring service availability and response times...")

    services = {
        "influxdb": f"{env_config['influxdb_url']}/health",
        "nodered":  f"{env_config['nodered_url']}",
        "grafana":  f"{env_config['grafana_url']}/api/health",
    }

    results = {}

    for service, url in services.items():
        try:
            start = time.time()
            response = requests.get(url, timeout=5)
            elapsed_ms = round((time.time() - start) * 1000, 2)
            results[service] = {
                "status_code":   response.status_code,
                "response_ms":   elapsed_ms,
                "available":     response.status_code < 400
            }
            log(f"[+] {service}: HTTP {response.status_code} in {elapsed_ms}ms")
        except Exception as e:
            results[service] = {
                "status_code":  None,
                "response_ms":  None,
                "available":    False,
                "error":        str(e)
            }
            log(f"[-] {service}: unreachable — {e}")

    return results


# ──────────────────────────────────────────────
# Metric 5: InfluxDB Data Integrity
# ──────────────────────────────────────────────

def check_data_integrity(env_config: dict) -> dict:
    """
    Check InfluxDB data integrity by analyzing recent sensor readings.

    Detects anomalous values that may indicate injection attacks
    (e.g. temperature of 99.99°C or humidity of 0%).

    Args:
        env_config: Environment configuration dict

    Returns:
        Dict with record counts and anomaly detection results
    """
    log("[*] Checking InfluxDB data integrity...")

    headers = {
        "Authorization": f"Token {env_config['influxdb_token']}",
        "Content-Type":  "application/vnd.flux"
    }

    url = f"{env_config['influxdb_url']}/api/v2/query?org={env_config['influxdb_org']}"

    results = {}

    # Check temperature readings
    temp_query = f'''
from(bucket: "{env_config['influxdb_bucket']}")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "temperature")
  |> filter(fn: (r) => r._field == "value")
'''

    try:
        response = requests.post(url, headers=headers, data=temp_query, timeout=10)
        lines = [l for l in response.text.split('\n') if l and not l.startswith('#')]
        record_count = max(0, len(lines) - 1)

        # Detect anomalous temperature values (>50°C or <-10°C)
        anomalies = 0
        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) > 5:
                try:
                    value = float(parts[-1].strip())
                    if value > 50.0 or value < -10.0:
                        anomalies += 1
                except ValueError:
                    pass

        results["temperature"] = {
            "record_count": record_count,
            "anomalies":    anomalies,
            "integrity":    "COMPROMISED" if anomalies > 0 else "OK"
        }
        log(f"[+] Temperature: {record_count} records, {anomalies} anomalies detected")

    except Exception as e:
        results["temperature"] = {"error": str(e)}

    return results


# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def save_results(metrics: dict, env: str, mode: str, scenario: int = None):
    """
    Save collected metrics to JSON and CSV files.

    Args:
        metrics: Collected metrics dict
        env: Environment name (insecure/secure)
        mode: Collection mode (baseline/attack)
        scenario: Attack scenario number if mode is attack
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_str = f"_scenario{scenario}" if scenario else ""
    base_name = f"{env}_{mode}{scenario_str}_{timestamp}"

    # Save JSON
    json_file = os.path.join(OUTPUT_DIR, f"{base_name}.json")
    with open(json_file, "w") as f:
        json.dump(metrics, f, indent=2)
    log(f"[+] JSON results saved to {json_file}")

    # Save CSV summary
    csv_file = os.path.join(OUTPUT_DIR, f"{base_name}.csv")
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value", "unit"])

        # Latency
        if "latency" in metrics and "avg_ms" in metrics["latency"]:
            lat = metrics["latency"]
            writer.writerow(["latency_min",  lat["min_ms"], "ms"])
            writer.writerow(["latency_max",  lat["max_ms"], "ms"])
            writer.writerow(["latency_avg",  lat["avg_ms"], "ms"])

        # Throughput
        if "throughput" in metrics and "messages_per_sec" in metrics["throughput"]:
            thr = metrics["throughput"]
            writer.writerow(["throughput_msg_per_sec", thr["messages_per_sec"], "msg/s"])
            writer.writerow(["throughput_total",       thr["total_messages"],   "messages"])

        # Services
        if "services" in metrics:
            for svc, data in metrics["services"].items():
                if "response_ms" in data and data["response_ms"]:
                    writer.writerow([f"{svc}_response_ms", data["response_ms"], "ms"])
                writer.writerow([f"{svc}_available", data.get("available", False), "bool"])

        # Data integrity
        if "data_integrity" in metrics:
            for measurement, data in metrics["data_integrity"].items():
                if "record_count" in data:
                    writer.writerow([f"{measurement}_records",   data["record_count"], "count"])
                    writer.writerow([f"{measurement}_anomalies", data["anomalies"],    "count"])
                    writer.writerow([f"{measurement}_integrity", data["integrity"],    "status"])

    log(f"[+] CSV results saved to {csv_file}")
    return json_file, csv_file


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IoT Cyberrange Metrics Collector"
    )
    parser.add_argument(
        "--env",
        choices=["insecure", "secure"],
        required=True,
        help="Target environment"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "attack"],
        required=True,
        help="Collection mode"
    )
    parser.add_argument(
        "--scenario",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Attack scenario number (required if mode=attack)"
    )

    args = parser.parse_args()
    env_config = ENVIRONMENTS[args.env]

    print("==============================================")
    print(" IoT Cyberrange - Metrics Collector")
    print("==============================================")
    print(f" Environment : {args.env}")
    print(f" Mode        : {args.mode}")
    if args.scenario:
        print(f" Scenario    : {args.scenario}")
    print(f" Broker      : {env_config['broker_host']}:{env_config['broker_port']}")
    print("==============================================")
    print("")

    metrics = {
        "environment": args.env,
        "mode":        args.mode,
        "scenario":    args.scenario,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "broker":      f"{env_config['broker_host']}:{env_config['broker_port']}"
    }

    # Collect all metrics
    metrics["latency"]        = measure_mqtt_latency(env_config)
    metrics["throughput"]     = measure_mqtt_throughput(env_config)
    metrics["broker_stats"]   = collect_broker_stats(env_config)
    metrics["services"]       = measure_service_availability(env_config)
    metrics["data_integrity"] = check_data_integrity(env_config)

    # Save results
    json_file, csv_file = save_results(
        metrics, args.env, args.mode, args.scenario
    )

    print("")
    print("==============================================")
    print(" Collection Complete")
    print("==============================================")
    if "latency" in metrics and "avg_ms" in metrics["latency"]:
        print(f" Latency avg     : {metrics['latency']['avg_ms']}ms")
    if "throughput" in metrics and "messages_per_sec" in metrics["throughput"]:
        print(f" Throughput      : {metrics['throughput']['messages_per_sec']} msg/s")
    print(f" JSON output     : {json_file}")
    print(f" CSV output      : {csv_file}")
    print("==============================================")


if __name__ == "__main__":
    main()