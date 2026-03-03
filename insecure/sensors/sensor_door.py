"""
sensor_door.py - Door/Window Contact Sensor Simulator

Simulates a reed-switch IoT sensor that publishes door open/close events
to an MQTT broker. Events are triggered randomly to simulate real usage,
with a persistent state machine (open/closed).

Vulnerabilities (intentional):
    - Hardcoded credentials in source code
    - Credentials exposed in MQTT payload
    - No TLS encryption
    - No certificate validation
    - Device fingerprint exposed in every message
"""

import paho.mqtt.client as mqtt
import time
import random
import json
import os
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Device configuration (hardcoded - intentionally vulnerable)
# ──────────────────────────────────────────────
DEVICE_ID       = os.getenv("DEVICE_ID", "sensor_door_01")
FIRMWARE_VER    = "2.1.0"
HARDCODED_USER  = "root"
HARDCODED_PASS  = "password"

# ──────────────────────────────────────────────
# Broker configuration
# ──────────────────────────────────────────────
BROKER_HOST      = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 1883))
CHECK_INTERVAL   = int(os.getenv("CHECK_INTERVAL", 3))   # seconds between state checks
# Probability of the door OPENING per check (when closed).
# 2% per 3 s ≈ ~1 opening every 2-3 minutes — realistic for a monitored entrance.
OPEN_PROBABILITY  = float(os.getenv("OPEN_PROBABILITY", 0.02))
# Probability of the door CLOSING per check (when open, after MIN_OPEN_SECS).
CLOSE_PROBABILITY = float(os.getenv("CLOSE_PROBABILITY", 0.15))
# Minimum seconds the door stays open before it can auto-close.
MIN_OPEN_SECS     = float(os.getenv("MIN_OPEN_SECS", 20.0))

# ──────────────────────────────────────────────
# Door state — time-aware to enforce realistic open/close durations
# ──────────────────────────────────────────────
_last_change = 0.0   # monotonic timestamp of last state change

# ──────────────────────────────────────────────
# MQTT topics
# ──────────────────────────────────────────────
TOPIC_STATE     = f"sensors/{DEVICE_ID}/state"
TOPIC_EVENT     = f"sensors/{DEVICE_ID}/event"
TOPIC_STATUS    = f"status/{DEVICE_ID}/heartbeat"


def build_state_payload(state: str, event_triggered: bool) -> str:
    """
    Build a JSON payload representing the current door state.

    Intentional vulnerability: credentials and device fingerprint
    are included in every message payload.

    Args:
        state: Current door state ('open' or 'closed')
        event_triggered: Whether this publish was triggered by a state change

    Returns:
        JSON string payload
    """
    payload = {
        "device_id":       DEVICE_ID,
        "firmware":        FIRMWARE_VER,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "state":           state,
        "event_triggered": event_triggered,
        # Intentional vulnerability: credentials exposed in payload
        "credentials":     f"{HARDCODED_USER}:{HARDCODED_PASS}",
        # Intentional vulnerability: device fingerprint exposed
        "mac_address":     "B8:27:EB:12:34:56"
    }
    return json.dumps(payload)


def build_event_payload(previous_state: str, new_state: str) -> str:
    """
    Build a JSON payload for a door state change event.

    Args:
        previous_state: State before the change
        new_state: State after the change

    Returns:
        JSON string payload
    """
    payload = {
        "device_id":      DEVICE_ID,
        "firmware":       FIRMWARE_VER,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "event":          "state_change",
        "previous_state": previous_state,
        "new_state":      new_state,
        "credentials":    f"{HARDCODED_USER}:{HARDCODED_PASS}"
    }
    return json.dumps(payload)


def build_heartbeat_payload(state: str) -> str:
    """
    Build a heartbeat payload with current device status.

    Args:
        state: Current door state

    Returns:
        JSON string with device status
    """
    payload = {
        "device_id":   DEVICE_ID,
        "firmware":    FIRMWARE_VER,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "status":      "online",
        "uptime_s":    int(time.monotonic()),
        "last_state":  state
    }
    return json.dumps(payload)


def on_connect(client, userdata, flags, reason_code, properties):
    """Callback fired when the client connects to the broker."""
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected to broker at {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[{DEVICE_ID}] Connection failed with code {reason_code}")


def on_publish(client, userdata, mid, reason_code, properties):
    """Callback fired when a message is successfully published."""
    print(f"[{DEVICE_ID}] Message published (mid={mid})")


def main():
    """
    Main loop: simulate door state machine and publish events.

    The sensor maintains a persistent state (open/closed) and randomly
    triggers state changes to simulate real door activity.
    No authentication is enforced — intentionally vulnerable.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)

    # Intentional vulnerability: no TLS, no certificate validation
    client.on_connect = on_connect
    client.on_publish = on_publish

    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    time.sleep(1)

    # Initial door state
    current_state = "closed"
    global _last_change
    _last_change = time.monotonic()
    print(f"[{DEVICE_ID}] Initial state: {current_state}")

    try:
        while True:
            elapsed = time.monotonic() - _last_change
            # Determine transition probability based on current state and elapsed time:
            #   closed → open : low base probability (realistic opening rate)
            #   open   → closed: only after the door has been open long enough
            if current_state == "closed":
                should_change = random.random() < OPEN_PROBABILITY
            else:
                # Door must stay open at least MIN_OPEN_SECS before auto-closing
                should_change = elapsed >= MIN_OPEN_SECS and random.random() < CLOSE_PROBABILITY

            if should_change:
                previous_state = current_state
                current_state  = "open" if current_state == "closed" else "closed"
                _last_change   = time.monotonic()

                # Publish state change event
                client.publish(
                    TOPIC_EVENT,
                    build_event_payload(previous_state, current_state),
                    qos=1  # QoS 1 for events — at least once delivery
                )
                print(f"[{DEVICE_ID}] Event: {previous_state} → {current_state}")

            # Always publish current state
            client.publish(
                TOPIC_STATE,
                build_state_payload(current_state, False),
                qos=0
            )
            print(f"[{DEVICE_ID}] State: {current_state} → {TOPIC_STATE}")

            # Publish heartbeat
            client.publish(TOPIC_STATUS, build_heartbeat_payload(current_state), qos=0)
            print(f"[{DEVICE_ID}] Heartbeat sent → {TOPIC_STATUS}")

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print(f"[{DEVICE_ID}] Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()