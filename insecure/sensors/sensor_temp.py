"""
sensor_temp.py - Temperature and Humidity Sensor Simulator

Simulates a DHT22-like IoT sensor that periodically publishes temperature
and humidity readings to an MQTT broker.

Vulnerabilities (intentional):
    - Hardcoded credentials in source code
    - Credentials exposed in MQTT payload
    - No TLS encryption
    - No certificate validation
    - Anonymous connection fallback
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
DEVICE_ID       = os.getenv("DEVICE_ID", "sensor_temp_01")
FIRMWARE_VER    = "1.0.2"
HARDCODED_USER  = "admin"
HARDCODED_PASS  = "admin123"

# ──────────────────────────────────────────────
# Broker configuration
# ──────────────────────────────────────────────
BROKER_HOST     = os.getenv("BROKER_HOST", "172.20.0.20")
BROKER_PORT     = int(os.getenv("BROKER_PORT", 1883))
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 5))  # seconds

# ──────────────────────────────────────────────
# MQTT topics
# ──────────────────────────────────────────────
TOPIC_TEMPERATURE   = f"sensors/{DEVICE_ID}/temperature"
TOPIC_HUMIDITY      = f"sensors/{DEVICE_ID}/humidity"
TOPIC_STATUS        = f"status/{DEVICE_ID}/heartbeat"


def build_payload(sensor_type: str, value: float, unit: str) -> str:
    """
    Build a JSON payload for a sensor reading.

    Intentional vulnerability: credentials are included in the payload,
    simulating real-world IoT devices that expose sensitive data in messages.

    Args:
        sensor_type: Type of reading (e.g. 'temperature', 'humidity')
        value: Sensor reading value
        unit: Unit of measurement

    Returns:
        JSON string payload
    """
    payload = {
        "device_id":   DEVICE_ID,
        "firmware":    FIRMWARE_VER,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "type":        sensor_type,
        "value":       value,
        "unit":        unit,
        # Intentional vulnerability: credentials exposed in payload
        "credentials": f"{HARDCODED_USER}:{HARDCODED_PASS}"
    }
    return json.dumps(payload)


def build_heartbeat_payload() -> str:
    """
    Build a heartbeat/status payload published periodically.

    Returns:
        JSON string with device status
    """
    payload = {
        "device_id": DEVICE_ID,
        "firmware":  FIRMWARE_VER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    "online",
        "uptime_s":  int(time.monotonic())
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
    Main loop: connect to broker and publish sensor readings indefinitely.
    No authentication is enforced — intentionally vulnerable.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)

    # Intentional vulnerability: no TLS, no certificate validation
    client.on_connect = on_connect
    client.on_publish = on_publish

    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    # Wait for connection to establish
    time.sleep(1)

    try:
        while True:
            # Simulate realistic sensor readings with slight noise
            temperature = round(random.uniform(18.0, 35.0), 2)
            humidity    = round(random.uniform(30.0, 90.0), 2)

            # Publish temperature reading
            client.publish(
                TOPIC_TEMPERATURE,
                build_payload("temperature", temperature, "celsius"),
                qos=0
            )
            print(f"[{DEVICE_ID}] Temperature: {temperature}°C → {TOPIC_TEMPERATURE}")

            # Publish humidity reading
            client.publish(
                TOPIC_HUMIDITY,
                build_payload("humidity", humidity, "%"),
                qos=0
            )
            print(f"[{DEVICE_ID}] Humidity: {humidity}% → {TOPIC_HUMIDITY}")

            # Publish heartbeat every cycle
            client.publish(TOPIC_STATUS, build_heartbeat_payload(), qos=0)
            print(f"[{DEVICE_ID}] Heartbeat sent → {TOPIC_STATUS}")

            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"[{DEVICE_ID}] Shutting down...")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()