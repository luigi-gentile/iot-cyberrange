#!/bin/bash
# SCENARIO 2 - Message Injection (SECURE environment)
# Expected result: FAILS - Auth required, ACL blocks unauthorized publish

BROKER_HOST="${BROKER_HOST:-172.21.0.20}"
BROKER_PORT="${BROKER_PORT:-8883}"
OUTPUT_DIR="/attacker/results"
OUTPUT_FILE="$OUTPUT_DIR/02_inject_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$OUTPUT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUTPUT_FILE"; }

echo "=============================================="
echo " SCENARIO 2 - Message Injection (SECURE)"
echo "=============================================="
echo " Target broker : $BROKER_HOST:$BROKER_PORT"
echo " Expected      : FAIL - Auth + ACL blocks injection"
echo "=============================================="

INJECTED=0
BLOCKED=0

log "[*] Phase 1: Attempting injection without credentials..."
RESULT=$(timeout 5 mosquitto_pub \
    -h "$BROKER_HOST" \
    -p "$BROKER_PORT" \
    -t "sensors/sensor_temp_01/temperature" \
    -m '{"value":99.99,"unit":"celsius","device_id":"attacker"}' 2>&1)

if echo "$RESULT" | grep -q "error\|not authorised\|Connection refused"; then
    log "[+] BLOCKED: Unauthenticated injection rejected"
    BLOCKED=$((BLOCKED + 1))
else
    log "[-] WARNING: Injection may have succeeded"
    INJECTED=$((INJECTED + 1))
fi

log "[*] Phase 2: Attempting injection with wrong credentials..."
RESULT=$(timeout 5 mosquitto_pub \
    -h "$BROKER_HOST" \
    -p "$BROKER_PORT" \
    -u "admin" \
    -P "admin123" \
    -t "sensors/sensor_temp_01/temperature" \
    -m '{"value":99.99,"unit":"celsius","device_id":"attacker"}' 2>&1)

if echo "$RESULT" | grep -q "error\|not authorised\|Connection refused"; then
    log "[+] BLOCKED: Wrong credentials rejected"
    BLOCKED=$((BLOCKED + 1))
else
    log "[-] WARNING: Wrong credentials accepted"
    INJECTED=$((INJECTED + 1))
fi

log "[*] Phase 3: Attempting actuator sabotage without credentials..."
RESULT=$(timeout 5 mosquitto_pub \
    -h "$BROKER_HOST" \
    -p "$BROKER_PORT" \
    -t "commands/sensor_power_01/set" \
    -m '{"action":"off"}' 2>&1)

if echo "$RESULT" | grep -q "error\|not authorised\|Connection refused"; then
    log "[+] BLOCKED: Unauthorized actuator command rejected"
    BLOCKED=$((BLOCKED + 1))
else
    log "[-] WARNING: Actuator command may have succeeded"
    INJECTED=$((INJECTED + 1))
fi

echo ""
echo "=============================================="
echo " ATTACK SUMMARY - Scenario 2 (SECURE)"
echo "=============================================="
echo " Injections blocked : $BLOCKED/3"
echo " Injections success : $INJECTED/3"
echo " Result             : $([ $INJECTED -eq 0 ] && echo 'ATTACK BLOCKED' || echo 'PARTIALLY SUCCESSFUL')"
echo " Output saved to    : $OUTPUT_FILE"
echo "=============================================="
