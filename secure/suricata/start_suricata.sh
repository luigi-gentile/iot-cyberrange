#!/bin/bash
# Dynamically resolve the iot_devices bridge interface and start Suricata
NETWORK_ID=$(docker network inspect secure_iot_devices --format '{{.Id}}' | cut -c1-12)
INTERFACE="br-${NETWORK_ID}"

echo "[*] Starting Suricata on interface: $INTERFACE"
ip link show "$INTERFACE" || { echo "[-] Interface not found"; exit 1; }

docker rm -f secure_suricata 2>/dev/null

docker run -d \
    --name secure_suricata \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    --cap-add SYS_NICE \
    -v ~/iot-cyberrange/secure/suricata/suricata.yaml:/etc/suricata/suricata.yaml \
    -v ~/iot-cyberrange/secure/suricata/rules:/etc/suricata/rules \
    -v ~/iot-cyberrange/secure/suricata/logs:/var/log/suricata \
    jasonish/suricata:latest \
    -c /etc/suricata/suricata.yaml \
    -i "$INTERFACE" \
    --init-errors-fatal

echo "[+] Suricata started"
docker logs secure_suricata --tail 5
