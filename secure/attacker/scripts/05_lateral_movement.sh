#!/bin/bash
# SCENARIO 5 - Lateral Movement (SECURE environment)
# Expected result: FAILS - Network segmentation, auth on all services

BROKER_HOST="${BROKER_HOST:-172.21.0.20}"
SUBNET="${SUBNET:-172.21.0.0/24}"
OUTPUT_DIR="/attacker/results"
OUTPUT_FILE="$OUTPUT_DIR/05_lateral_movement_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$OUTPUT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUTPUT_FILE"; }

# Note: In secure env, attacker is only on iot_devices network (172.21.0.0/24)
# data_pipeline (172.22.0.0/24) is internal and unreachable
NODERED_HOST="172.22.0.31"
INFLUXDB_HOST="172.22.0.30"
GRAFANA_HOST="172.22.0.32"

echo "=============================================="
echo " SCENARIO 5 - Lateral Movement (SECURE)"
echo "=============================================="
echo " Subnet   : $SUBNET"
echo " Expected : FAIL - Network segmentation active"
echo "=============================================="

SERVICES_DISCOVERED=0
SERVICES_ACCESSED=0

log "[*] Phase 1: Network reconnaissance — scanning $SUBNET"
log ""
NMAP_OUT=$(nmap -sn "$SUBNET" --open 2>/dev/null)
SERVICES_DISCOVERED=$(echo "$NMAP_OUT" | grep -c "Host is up")
echo "$NMAP_OUT" | grep -E "Nmap scan|Host is up" | while read -r line; do
    log "[+] $line"
done
log ""
log "[*] Port scan on discovered hosts..."
nmap -p 1883,1880,8086,3000,8883,8884 "$SUBNET" --open 2>/dev/null | tee -a "$OUTPUT_FILE"
log ""

log "[*] Phase 2: MQTT broker enumeration"
log "[*] Attempting anonymous subscribe to \$SYS..."
RESULT=$(timeout 5 mosquitto_sub \
    -h "$BROKER_HOST" \
    -p 8883 \
    -t "\$SYS/#" \
    -v -C 1 2>&1)
if echo "$RESULT" | grep -q "error\|not authorised\|Connection refused"; then
    log "[+] BLOCKED: Anonymous access to broker rejected"
else
    log "[-] WARNING: Broker accessible without credentials"
fi
log ""

log "[*] Phase 3: Attempting Node-RED admin UI access"
log "[*] Target: http://$NODERED_HOST:1880 (data_pipeline network)"
NODERED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    "http://$NODERED_HOST:1880" 2>/dev/null)
if [ "$NODERED_RESPONSE" = "000" ] || [ -z "$NODERED_RESPONSE" ]; then
    log "[+] BLOCKED: Node-RED unreachable (network segmentation)"
else
    log "[-] WARNING: Node-RED accessible (HTTP $NODERED_RESPONSE)"
    SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
fi
log ""

log "[*] Phase 4: Attempting InfluxDB access"
log "[*] Target: http://$INFLUXDB_HOST:8086 (data_pipeline network)"
INFLUX_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    "http://$INFLUXDB_HOST:8086/health" 2>/dev/null)
if [ "$INFLUX_RESPONSE" = "000" ] || [ -z "$INFLUX_RESPONSE" ]; then
    log "[+] BLOCKED: InfluxDB unreachable (network segmentation)"
else
    log "[-] WARNING: InfluxDB accessible (HTTP $INFLUX_RESPONSE)"
    SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
fi
log ""

log "[*] Phase 5: Attempting Grafana access with default credentials"
log "[*] Target: http://$GRAFANA_HOST:3000 (data_pipeline network)"
GRAFANA_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    "http://$GRAFANA_HOST:3000" 2>/dev/null)
if [ "$GRAFANA_RESPONSE" = "000" ] || [ -z "$GRAFANA_RESPONSE" ]; then
    log "[+] BLOCKED: Grafana unreachable (network segmentation)"
else
    GRAFANA_DEFAULT=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 \
        -u "admin:admin" \
        "http://$GRAFANA_HOST:3000/api/org" 2>/dev/null)
    if [ "$GRAFANA_DEFAULT" = "200" ]; then
        log "[-] WARNING: Grafana accessible with default credentials"
        SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
    else
        log "[+] BLOCKED: Default credentials rejected"
    fi
fi
log ""

echo "=============================================="
echo " ATTACK SUMMARY - Scenario 5 (SECURE)"
echo "=============================================="
echo " Hosts discovered  : $SERVICES_DISCOVERED"
echo " Services accessed : $SERVICES_ACCESSED"
echo " Records exfiltrated: 0"
echo " Result            : $([ $SERVICES_ACCESSED -eq 0 ] && echo 'ATTACK BLOCKED' || echo 'PARTIALLY SUCCESSFUL')"
echo " Output saved to   : $OUTPUT_FILE"
echo "=============================================="
