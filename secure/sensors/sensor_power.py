"""
sensor_power.py - Secure Power Meter / Smart Plug Simulator

Security controls applied:
    - TLS 1.2+ with CA certificate validation
    - Credentials via environment variables
    - No credentials in MQTT payload
"""
import paho.mqtt.client as mqtt
import ssl, time, random, json, os
from datetime import datetime, timezone

DEVICE_ID        = os.getenv("DEVICE_ID", "sensor_power_01")
FIRMWARE_VER     = "3.0.1"
BROKER_HOST      = os.getenv("BROKER_HOST", "172.21.0.20")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 8883))
BROKER_USERNAME  = os.getenv("BROKER_USERNAME", "sensor_power_01")
BROKER_PASSWORD  = os.getenv("BROKER_PASSWORD", "")
BROKER_CA_CERT   = os.getenv("BROKER_CA_CERT", "/certs/ca.crt")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 4))

TOPIC_POWER   = f"sensors/{DEVICE_ID}/power"
TOPIC_STATUS  = f"status/{DEVICE_ID}/heartbeat"
TOPIC_COMMAND = f"commands/{DEVICE_ID}/set"

plug_on = True

def build_power_payload():
    if plug_on:
        voltage = round(random.uniform(220.0, 230.0), 2)
        current = round(random.uniform(0.5, 2.0), 3)
        power   = round(voltage * current, 2)
    else:
        voltage = round(random.uniform(220.0, 230.0), 2)
        current = 0.0
        power   = 0.0
    return json.dumps({
        "device_id": DEVICE_ID,
        "firmware":  FIRMWARE_VER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      "power",
        "voltage_v": voltage,
        "current_a": current,
        "power_w":   power,
        "plug_on":   plug_on,
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
    global plug_on
    try:
        cmd = json.loads(msg.payload.decode())
        action = cmd.get("action", "").lower()
        if action == "on":
            plug_on = True
            print(f"[{DEVICE_ID}] Plug turned ON")
        elif action == "off":
            plug_on = False
            print(f"[{DEVICE_ID}] Plug turned OFF")
    except Exception as e:
        print(f"[{DEVICE_ID}] Invalid command: {e}")

def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)
    client.tls_set(ca_certs=BROKER_CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)
    client.username_pw_set(BROKER_USERNAME, BROKER_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()
    time.sleep(2)
    try:
        while True:
            client.publish(TOPIC_POWER, build_power_payload(), qos=1)
            print(f"[{DEVICE_ID}] Power: plug={'ON' if plug_on else 'OFF'}")
            client.publish(TOPIC_STATUS, build_heartbeat(), qos=1)
            time.sleep(PUBLISH_INTERVAL)
    except KeyboardInterrupt:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
