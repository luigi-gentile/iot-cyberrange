"""
sensor_temp.py - Secure Temperature and Humidity Sensor Simulator

Security controls applied:
    - TLS 1.2+ with CA certificate validation
    - Credentials via environment variables (no hardcoding)
    - No credentials in MQTT payload
    - No anonymous connection fallback
"""
import paho.mqtt.client as mqtt
import ssl, time, random, json, os
from datetime import datetime, timezone

DEVICE_ID        = os.getenv("DEVICE_ID", "sensor_temp_01")
FIRMWARE_VER     = "1.0.2"
BROKER_HOST      = os.getenv("BROKER_HOST", "172.21.0.20")
BROKER_PORT      = int(os.getenv("BROKER_PORT", 8883))
BROKER_USERNAME  = os.getenv("BROKER_USERNAME", "sensor_temp_01")
BROKER_PASSWORD  = os.getenv("BROKER_PASSWORD", "")
BROKER_CA_CERT   = os.getenv("BROKER_CA_CERT", "/certs/ca.crt")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", 5))

TOPIC_TEMPERATURE = f"sensors/{DEVICE_ID}/temperature"
TOPIC_HUMIDITY    = f"sensors/{DEVICE_ID}/humidity"
TOPIC_STATUS      = f"status/{DEVICE_ID}/heartbeat"

def build_payload(sensor_type, value, unit):
    return json.dumps({
        "device_id": DEVICE_ID,
        "firmware":  FIRMWARE_VER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      sensor_type,
        "value":     value,
        "unit":      unit,
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
        print(f"[{DEVICE_ID}] Connected to broker at {BROKER_HOST}:{BROKER_PORT} (TLS)")
    else:
        print(f"[{DEVICE_ID}] Connection failed: {reason_code}")

def on_publish(client, userdata, mid, reason_code, properties):
    print(f"[{DEVICE_ID}] Message published (mid={mid})")

def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID, protocol=mqtt.MQTTv311)
    client.tls_set(ca_certs=BROKER_CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)
    client.username_pw_set(BROKER_USERNAME, BROKER_PASSWORD)
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()
    time.sleep(2)
    try:
        while True:
            temperature = round(random.uniform(18.0, 35.0), 2)
            humidity    = round(random.uniform(30.0, 90.0), 2)
            client.publish(TOPIC_TEMPERATURE, build_payload("temperature", temperature, "celsius"), qos=1)
            print(f"[{DEVICE_ID}] Temperature: {temperature}C")
            client.publish(TOPIC_HUMIDITY, build_payload("humidity", humidity, "%"), qos=1)
            print(f"[{DEVICE_ID}] Humidity: {humidity}%")
            client.publish(TOPIC_STATUS, build_heartbeat(), qos=1)
            print(f"[{DEVICE_ID}] Heartbeat sent")
            time.sleep(PUBLISH_INTERVAL)
    except KeyboardInterrupt:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
