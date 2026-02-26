"""
sensor_power.py - Smart Plug / Power Consumption Sensor Simulator

Simulates a smart plug IoT device that monitors and publishes real-time
power consumption data to an MQTT broker. Also accepts remote commands
to toggle the plug on/off, simulating actuator functionality.

Vulnerabilities (intentional):
    - Hardcoded credentials in source code
    - Credentials exposed in MQTT payload
    - No TLS encryption
    - Accepts remote commands with no authentication check
    - Command injection possible via unvalidated MQTT payload
    - Device model and firmware exposed in every message
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
DEVICE_ID       = os.getenv("DEVICE_ID", "sensor_power_01")
FIRMWARE_VER    = "3.0.1"
DEVICE_MODEL    = "SmartPlug-X200"
HARDCODED_USER  = "user"
HARDCODED_PASS  = "1234"

# ──────────────────────────────────────────────
# Broker configuration
# ──────────────────────────────────────────────
BROKER_HOST      = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 1883))
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 4))  # seconds

# ──────────────────────────────────────────────
# MQTT topics
# ──────────────────────────────────────────────
TOPIC_POWER     = f"sensors/{DEVICE_ID}/power"
TOPIC_STATUS    = f"status/{DEVICE_ID}/heartbeat"
TOPIC_COMMAND   = f"commands/{DEVICE_ID}/set"    # subscribes to this topic for remote control


# ──────────────────────────────────────────────
# Device state
# ──────────────────────────────────────────────
device_state = {
    "plug_on": True,   # whether the smart plug is currently on
    "uptime":  0
}


def build_power_payload(watts: float, voltage: float, current: float) -> str:
    """
    Build a JSON payload for a power consumption reading.

    Intentional vulnerability: credentials, device model and firmware
    are exposed in every message, allowing attacker reconnaissance.

    Args:
        watts: Current power consumption in watts
        voltage: Current voltage in volts
        current: Current amperage in amperes

    Returns:
        JSON string payload
    """
    payload = {
        "device_id":    DEVICE_ID,
        "device_model": DEVICE_MODEL,
        "firmware":     FIRMWARE_VER,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "plug_on":      device_state["plug_on"],
        "power_w":      watts,
        "voltage_v":    voltage,
        "current_a":    current,
        # Intentional vulnerability: credentials exposed in payload
        "credentials":  f"{HARDCODED_USER}:{HARDCODED_PASS}"
    }
    return json.dumps(payload)


def build_heartbeat_payload() -> str:
    """
    Build a heartbeat payload with current device status.

    Returns:
        JSON string with device status
    """
    payload = {
        "device_id":    DEVICE_ID,
        "device_model": DEVICE_MODEL,
        "firmware":     FIRMWARE_VER,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "status":       "online",
        "plug_on":      device_state["plug_on"],
        "uptime_s":     int(time.monotonic())
    }
    return json.dumps(payload)


def on_connect(client, userdata, flags, reason_code, properties):
    """
    Callback fired when the client connects to the broker.
    Subscribes to the command topic to enable remote control.
    """
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected to broker at {BROKER_HOST}:{BROKER_PORT}")
        # Subscribe to command topic — intentional vulnerability: no auth check
        client.subscribe(TOPIC_COMMAND, qos=1)
        print(f"[{DEVICE_ID}] Subscribed to command topic: {TOPIC_COMMAND}")
    else:
        print(f"[{DEVICE_ID}] Connection failed with code {reason_code}")


def on_message(client, userdata, msg):
    """
    Callback fired when a command message is received.

    Intentional vulnerability: accepts any command from any client
    with no authentication or authorization check. An attacker can
    turn the plug on/off by simply publishing to the command topic.

    Expected payload: {"command": "on"} or {"command": "off"}
    """
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        command = payload.get("command", "").lower()

        print(f"[{DEVICE_ID}] Command received: {command}")

        if command == "on":
            device_state["plug_on"] = True
            print(f"[{DEVICE_ID}] Plug turned ON via remote command")
        elif command == "off":
            device_state["plug_on"] = False
            print(f"[{DEVICE_ID}] Plug turned OFF via remote command")
        else:
            # Intentional vulnerability: unrecognized command is logged but not rejected
            print(f"[{DEVICE_ID}] Unknown command received: {command}")

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[{DEVICE_ID}] Failed to parse command payload: {e}")


def on_publish(client, userdata, mid, reason_code, properties):
    """Callback fired when a message is successfully published."""
    print(f"[{DEVICE_ID}] Message published (mid={mid})")


def simulate_power_reading() -> tuple:
    """
    Simulate realistic power consumption readings.

    When plug is on: simulates a device consuming between 50W and 300W.
    When plug is off: returns zero values.

    Returns:
        Tuple of (watts, voltage, current)
    """
    if not device_state["plug_on"]:
        return 0.0, 0.0, 0.0

    voltage = round(random.uniform(219.0, 231.0), 2)   # EU standard ~230V
    watts   = round(random.uniform(50.0, 300.0), 2)
    current = round(watts / voltage, 3)

    return watts, voltage, current


def main():
    """
    Main loop: connect to broker, listen for commands, and publish
    power consumption readings indefinitely.
    No authentication is enforced — intentionally vulnerable.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)

    # Intentional vulnerability: no TLS, no certificate validation
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_publish = on_publish

    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    time.sleep(1)

    try:
        while True:
            watts, voltage, current = simulate_power_reading()

            # Publish power reading
            client.publish(
                TOPIC_POWER,
                build_power_payload(watts, voltage, current),
                qos=0
            )
            print(f"[{DEVICE_ID}] Power: {watts}W, {voltage}V, {current}A → {TOPIC_POWER}")

            # Publish heartbeat
            client.publish(TOPIC_STATUS, build_heartbeat_payload(), qos=0)
            print(f"[{DEVICE_ID}] Heartbeat sent → {TOPIC_STATUS}")

            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"[{DEVICE_ID}] Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()