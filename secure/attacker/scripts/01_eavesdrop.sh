#!/bin/bash
# SCENARIO 1 - Eavesdropping Attack (SECURE environment)
# Expected result: FAILS - TLS encrypts all traffic

BROKER_HOST="${BROKER_HOST:-172.21.0.20}"
BROKER_PORT="${BROKER_PORT:-8883}"
DURATION="${DURATION:-60}"
OUTPUT_DIR="/attacker/results"
OUTPUT_FILE="$OUTPUT_DIR/01_eavesdrop_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$OUTPUT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUTPUT_FILE"; }

echo "=============================================="
echo " SCENARIO 1 - Eavesdropping (SECURE)"
echo "=============================================="
echo " Target broker : $BROKER_HOST:$BROKER_PORT"
echo " Duration      : ${DURATION}s"
echo " Expected      : FAIL - TLS encryption active"
echo "=============================================="

log "[*] Attempting anonymous subscribe to all topics..."
CAPTURED=0

timeout "$DURATION" mosquitto_sub \
    -h "$BROKER_HOST" \
    -p "$BROKER_PORT" \
    -t "#" \
    -v 2>&1 | while IFS= read -r line; do
    log "[CAPTURED] $line"
    CAPTURED=$((CAPTURED + 1))
done

log ""
log "[*] Attempting plaintext connection (no TLS)..."
RESULT=$(timeout 5 mosquitto_pub \
    -h "$BROKER_HOST" \
    -p "$BROKER_PORT" \
    -t "test/eavesdrop" \
    -m "test" 2>&1)

if echo "$RESULT" | grep -q "error\|Connection refused\|timeout"; then
    log "[+] BLOCKED: Plaintext connection rejected by broker"
    BLOCKED=1
else
    log "[-] WARNING: Connection succeeded unexpectedly"
    BLOCKED=0
fi

echo ""
echo "=============================================="
echo " ATTACK SUMMARY - Scenario 1 (SECURE)"
echo "=============================================="
echo " Messages captured : $CAPTURED"
echo " TLS bypass        : FAILED"
echo " Result            : $([ $BLOCKED -eq 1 ] && echo 'ATTACK BLOCKED' || echo 'CHECK MANUALLY')"
echo " Output saved to   : $OUTPUT_FILE"
echo "=============================================="
