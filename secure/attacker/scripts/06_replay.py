#!/usr/bin/env python3
"""
06_replay.py - MQTT Replay Attack (Secure Environment)

Attempts to replicate the insecure replay attack against a TLS-secured
broker that enforces certificate validation and credential authentication.

The attacker possesses the public CA certificate (obtained via network
reconnaissance), but has no valid username/password for the broker. Each
connection attempt performs a full TLS handshake and then receives a
CONNACK with return code 5 (Not Authorised / Bad Credentials).

Attack flow:
  Stage 1 — Anonymous connection attempt (fails: allow_anonymous=false).
  Stage 2 — Six common credential pairs attempted in rapid succession.
  Result  — 0 messages captured, 0 messages replayed; attack BLOCKED.

Detection:
  Rapid TLS connection bursts trigger Suricata SID 1000010, generating
  an alert even though no data was compromised.

MITRE ATT&CK for ICS:
  Tactic   : Impair Process Control (TA0106)
  Technique: T0856 — Spoof Reporting Message (attempt blocked at auth layer)
"""

import os
import ssl
import sys
import time
import threading
import paho.mqtt.client as mqtt

BROKER  = os.getenv("BROKER_HOST", "172.21.0.20")
PORT    = int(os.getenv("BROKER_PORT", "8883"))
CA_CERT = "/attacker/ca.crt"

# Credential candidates — attacker has no valid account
CREDS = [
    (None,      None),
    ("admin",   "admin"),
    ("guest",   "guest"),
    ("sensor",  "sensor"),
    ("iot",     "iot"),
    ("mqtt",    "mqtt"),
]


def _try_connect(client_id: str, user: str | None, pwd: str | None) -> bool:
    """
    Attempt a single authenticated connection.
    Returns True only if the broker sends CONNACK rc=0 (Success).
    Uses on_connect callback to detect auth failures that paho v2 does
    not surface as exceptions (rc != 0 → CONNACK refused).
    """
    auth_result = [None]   # None = not yet known, True = accepted, False = refused
    event = threading.Event()

    def on_connect(client, userdata, flags, reason_code, properties):
        # reason_code is a ReasonCode object in paho v2
        auth_result[0] = not reason_code.is_failure
        event.set()

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    c.tls_set(ca_certs=CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    c.tls_insecure_set(False)
    if user is not None:
        c.username_pw_set(user, pwd)
    c.on_connect = on_connect

    try:
        c.connect(BROKER, PORT, keepalive=10)
        c.loop_start()
        event.wait(timeout=3.0)   # wait for CONNACK
        c.loop_stop()
        c.disconnect()
    except Exception:
        return False

    return auth_result[0] is True


print(f"[*] Target : {BROKER}:{PORT}  (TLS, authentication enforced)")
print(f"[*] Trying {len(CREDS)} credential combination(s)...\n")

connected = False

for i, (user, pwd) in enumerate(CREDS, 1):
    label = f"{user}:{pwd}" if user else "anonymous"
    if _try_connect(f"replay_attempt_{i}", user, pwd):
        print(f"[?] Attempt {i:02d} ({label}) — accepted (unexpected!)")
        connected = True
        break
    else:
        print(f"[-] Attempt {i:02d} ({label}) — refused (Not Authorised)")

    time.sleep(0.3)   # small gap between bursts — triggers Suricata SID 1000010

print()

if connected:
    print("[!] Unexpected: connection succeeded — check broker ACL configuration")
    sys.exit(1)

print(f"[!] All {len(CREDS)} credential attempts refused by the broker")
print("[+] Replay attack BLOCKED — broker requires valid MQTT authentication")
print("[+] TLS encryption also prevents passive capture of sensor payloads")
print("[i] Suricata should have logged the rapid connection burst (SID 1000010)")
