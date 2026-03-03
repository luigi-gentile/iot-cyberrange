"""
sensor_door.py - Secure Door Sensor Simulator

Security controls applied:
    - TLS 1.2+ with CA certificate validation
    - Credentials via environment variables
    - No credentials in MQTT payload
"""
import paho.mqtt.client as mqtt
import ssl, time, random, json, os
from datetime import datetime, timezone

DEVICE_ID        = os.getenv("DEVICE_ID", "sensor_door_01")
FIRMWARE_VER     = "2.1.0"
BROKER_HOST      = os.getenv("BROKER_HOST", "172.21.0.20")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 8883))
BROKER_USERNAME  = os.getenv("BROKER_USERNAME", "sensor_door_01")
BROKER_PASSWORD  = os.getenv("BROKER_PASSWORD", "")
BROKER_CA_CERT   = os.getenv("BROKER_CA_CERT", "/certs/ca.crt")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 3))

TOPIC_DOOR    = f"sensors/{DEVICE_ID}/door"
TOPIC_STATUS  = f"status/{DEVICE_ID}/heartbeat"
TOPIC_COMMAND = f"commands/{DEVICE_ID}/set"

door_state   = "closed"
_last_change = 0.0   # monotonic timestamp of last door state change

# 2% chance to open per check; closes after ≥20 s with 15% probability per check
OPEN_PROBABILITY  = float(os.getenv("OPEN_PROBABILITY",  0.02))
CLOSE_PROBABILITY = float(os.getenv("CLOSE_PROBABILITY", 0.15))
MIN_OPEN_SECS     = float(os.getenv("MIN_OPEN_SECS",     20.0))

def build_door_payload(state):
    return json.dumps({
        "device_id": DEVICE_ID,
        "firmware":  FIRMWARE_VER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      "door_state",
        "state":     state,
    })

def build_heartbeat():
    return json.dumps({
        "device_id": DEVICE_ID,
        "firmware":  FIRMWARE_VER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    "online",
        "uptime_s":  int(time.monotonic())
    })

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected (TLS)")
        client.subscribe(TOPIC_COMMAND, qos=1)
    else:
        print(f"[{DEVICE_ID}] Connection failed: {reason_code}")

def on_message(client, userdata, msg):
    global door_state
    try:
        cmd = json.loads(msg.payload.decode())
        if cmd.get("action") in ["open", "closed"]:
            door_state = cmd["action"]
            print(f"[{DEVICE_ID}] Command: door -> {door_state}")
    except Exception as e:
        print(f"[{DEVICE_ID}] Invalid command: {e}")

def main():
    global door_state
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)
    client.tls_set(ca_certs=BROKER_CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)
    client.username_pw_set(BROKER_USERNAME, BROKER_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()
    time.sleep(2)
    global _last_change
    _last_change = time.monotonic()
    try:
        while True:
            elapsed = time.monotonic() - _last_change
            if door_state == "closed":
                should_change = random.random() < OPEN_PROBABILITY
            else:
                should_change = elapsed >= MIN_OPEN_SECS and random.random() < CLOSE_PROBABILITY

            if should_change:
                global door_state
                door_state   = "open" if door_state == "closed" else "closed"
                _last_change = time.monotonic()
            client.publish(TOPIC_DOOR, build_door_payload(door_state), qos=1)
            print(f"[{DEVICE_ID}] Door: {door_state}")
            client.publish(TOPIC_STATUS, build_heartbeat(), qos=1)
            time.sleep(PUBLISH_INTERVAL)
    except KeyboardInterrupt:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
