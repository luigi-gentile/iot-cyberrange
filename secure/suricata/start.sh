#!/bin/bash
# Trova il bridge della rete iot_devices dinamicamente
NETWORK_ID=$(docker network inspect secure_iot_devices --format '{{.Id}}' | cut -c1-12)
INTERFACE="br-${NETWORK_ID}"

echo "[*] Suricata starting on interface: $INTERFACE"
echo "[*] Verifying interface exists..."
ip link show "$INTERFACE" || { echo "[-] Interface $INTERFACE not found"; exit 1; }

echo "[*] Starting Suricata..."
exec suricata -c /etc/suricata/suricata.yaml \
    -i "$INTERFACE" \
    -l /var/log/suricata \
    --init-errors-fatal
