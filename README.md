# IoT Cyber Range

A containerized dual-environment IoT security testbed for quantitative evaluation of attack scenarios and defensive controls.

Developed as part of a Master's thesis in Computer Engineering (Cybersecurity & Cloud).

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Environment Setup](#environment-setup)
  - [Insecure Environment](#insecure-environment)
  - [Secure Environment](#secure-environment)
- [Suricata IDS](#suricata-ids)
- [Running Attack Campaigns](#running-attack-campaigns)
- [Attack Scenarios](#attack-scenarios)
- [MITRE ATT&CK for ICS Mapping](#mitre-attck-for-ics-mapping)
- [Metrics & Results](#metrics--results)
- [Troubleshooting](#troubleshooting)

---

## Overview

The cyber range implements two parallel IoT environments on a single host:

| | Insecure | Secure |
|---|---|---|
| **Transport** | Plaintext MQTT (port 1883) | TLS 1.3 (port 8883) |
| **Authentication** | Anonymous | Username + password |
| **Authorization** | No ACL | Per-user topic ACL |
| **Network** | Flat — 172.20.0.0/24 | Segmented — 3 subnets |
| **IDS** | None | Suricata (TTD measurement) |

Five attack scenarios are executed against both environments by an attacker container, with metrics collected automatically via a campaign orchestrator.

---

## Architecture

```
INSECURE ENVIRONMENT (172.20.0.0/24)
┌─────────────┐    MQTT     ┌──────────────┐    ┌──────────────┐
│ sensor_temp │────────────►│              │    │   InfluxDB   │
│ sensor_door │────────────►│   Mosquitto  │◄───│   Node-RED   │
│sensor_power │────────────►│  (port 1883) │    │   Grafana    │
└─────────────┘             └──────────────┘    └──────────────┘
      ▲                            ▲
      └──────── attacker ──────────┘

SECURE ENVIRONMENT
┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────┐
│   iot_devices            │  │   data_pipeline          │  │   management     │
│   172.21.0.0/24          │  │   172.22.0.0/24          │  │   172.23.0.0/24  │
│                          │  │                          │  │                  │
│ sensor_temp (172.21.0.10)│  │  InfluxDB (172.22.0.30)  │  │  admin access    │
│ sensor_door (172.21.0.11)│  │  Node-RED (172.22.0.31)  │  │                  │
│sensor_power (172.21.0.12)│  │ Grafana  (172.22.0.32)   │  │                  │
│ broker TLS  (172.21.0.20)│  │                          │  │                  │
│ attacker    (172.21.0.99)│  │                          │  │                  │
└──────────────────────────┘  └──────────────────────────┘  └──────────────────┘
          │
    Suricata IDS (host network, monitors br-<network_id>)
```

---

## Prerequisites

- Ubuntu 22.04+ (tested on ARM64 and x86_64)
- Docker Engine 24+
- Docker Compose v2
- Python 3.10+
- 4GB RAM minimum, 8GB recommended
- 10GB free disk space

### Install dependencies

```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Python packages
pip3 install paho-mqtt influxdb-client requests --break-system-packages
```

---

## Repository Structure

```
iot-cyberrange/
├── insecure/
│   ├── docker-compose.yml
│   ├── broker/
│   │   └── mosquitto.conf
│   ├── sensors/
│   │   ├── sensor_temp/
│   │   ├── sensor_door/
│   │   └── sensor_power/
│   ├── nodered/
│   │   └── flows.json
│   └── attacker/
│       ├── Dockerfile
│       └── scripts/
│           ├── 01_eavesdrop.sh
│           ├── 02_inject.sh
│           ├── 03_dos.py
│           ├── 04_bruteforce.py
│           └── 05_lateral_movement.sh
│
├── secure/
│   ├── docker-compose.yml
│   ├── broker/
│   │   ├── mosquitto.conf
│   │   ├── acl
│   │   ├── passwd
│   │   └── certs/
│   │       ├── ca.crt
│   │       ├── ca.key
│   │       ├── server.crt
│   │       └── server.key
│   ├── sensors/
│   │   ├── sensor_temp/
│   │   ├── sensor_door/
│   │   └── sensor_power/
│   ├── nodered/
│   │   └── flows.json
│   ├── attacker/
│   │   ├── Dockerfile
│   │   └── scripts/
│   │       ├── 01_eavesdrop.sh
│   │       ├── 02_inject.sh
│   │       ├── 03_dos.py
│   │       ├── 04_bruteforce.py
│   │       └── 05_lateral_movement.sh
│   └── suricata/
│       ├── suricata.yaml
│       ├── start_suricata.sh
│       ├── rules/
│       │   └── iot-cyberrange.rules
│       └── logs/
│           └── eve.json
│
└── metrics/
    ├── run_campaign.py          # Main campaign orchestrator
    ├── collect_metrics.py       # Metrics snapshot collector
    ├── suricata_ttd.py          # Time to Detection parser
    └── results/                 # Campaign output (JSON + CSV)
```

---

## Quick Start

```bash
# Clone the repository
git clone <repo-url>
cd iot-cyberrange

# Start insecure environment
cd insecure && docker compose up -d
cd ..

# Start secure environment
cd secure && docker compose up -d
cd ..

# Start Suricata IDS (secure environment only)
bash secure/suricata/start_suricata.sh

# Run full campaign on insecure environment
python3 metrics/run_campaign.py --env insecure

# Run full campaign on secure environment
python3 metrics/run_campaign.py --env secure
```

---

## Environment Setup

### Insecure Environment

The insecure environment requires no additional configuration — all services start with default, unauthenticated settings.

```bash
cd insecure
docker compose up -d
```

**Verify all containers are running:**

```bash
docker compose ps
```

Expected output:
```
insecure_broker      Up
insecure_sensor_temp Up
insecure_sensor_door Up
insecure_sensor_power Up
insecure_influxdb    Up
insecure_nodered     Up (healthy)
insecure_grafana     Up
insecure_attacker    Up
```

**Access services (from browser on the host machine):**
- Grafana: `http://<host-ip>:3000` (admin/admin)
- InfluxDB: `http://<host-ip>:8086`
- Node-RED: `http://<host-ip>:1880`

**Access services (from within Docker network):**
- Grafana: http://172.20.0.32:3000 (admin/admin)
- InfluxDB: http://172.20.0.30:8086
- Node-RED: http://172.20.0.31:1880

---

### Secure Environment

#### 1. Generate TLS certificates (first time only)

```bash
cd secure/broker/certs

# Generate CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=IoT-Cyberrange-CA"

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=172.21.0.20"
openssl x509 -req -days 3650 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt

cd ../../..
```

#### 2. Generate MQTT password file (first time only)

```bash
# Create passwd file with all users
docker run --rm -it eclipse-mosquitto mosquitto_passwd -c /tmp/passwd metrics_collector
# Then add remaining users:
docker run --rm -it eclipse-mosquitto mosquitto_passwd /tmp/passwd sensor_temp_01
docker run --rm -it eclipse-mosquitto mosquitto_passwd /tmp/passwd sensor_door_01
docker run --rm -it eclipse-mosquitto mosquitto_passwd /tmp/passwd sensor_power_01
docker run --rm -it eclipse-mosquitto mosquitto_passwd /tmp/passwd nodered

# Or use the pre-configured passwd file already in the repo
```

The pre-configured credentials are:

| User | Password | Role |
|---|---|---|
| `sensor_temp_01` | `TempSensor2026` | Temperature sensor |
| `sensor_door_01` | `DoorSensor2026` | Door sensor |
| `sensor_power_01` | `PowerSensor2026` | Power sensor |
| `nodered` | `NodeRed2026` | Data pipeline |
| `metrics_collector` | `Metrics2026` | Campaign orchestrator |

#### 3. Copy CA certificate to attacker container

The DoS script requires the CA certificate to establish TLS connections for the latency monitor:

```bash
docker cp secure/broker/certs/ca.crt secure_attacker:/attacker/ca.crt
```

> **Note:** This step must be repeated if the attacker container is recreated.

#### 4. Start the environment

```bash
cd secure
docker compose up -d
cd ..
```

**Verify all containers are running:**

```bash
docker compose -f secure/docker-compose.yml ps
```

Expected output:
```
secure_broker        Up
secure_sensor_temp   Up
secure_sensor_door   Up
secure_sensor_power  Up
secure_influxdb      Up
secure_nodered       Up (healthy)
secure_grafana       Up
secure_attacker      Up
```

**Access services** (from management network or via port mapping):
- Grafana: http://172.23.0.32:3000 (admin/admin)
- InfluxDB: http://172.22.0.30:8086
- Node-RED: http://172.23.0.31:1880

---

## Suricata IDS

Suricata is deployed on the **secure environment only** in passive IDS mode. It cannot be included in docker-compose because it requires the dynamically assigned Docker bridge interface name.

### Start Suricata

```bash
bash secure/suricata/start_suricata.sh
```

This script automatically:
1. Discovers the bridge interface for `secure_iot_devices` network
2. Removes any existing `secure_suricata` container
3. Starts Suricata with the correct interface

### Verify Suricata is running

```bash
docker ps | grep suricata
docker logs secure_suricata --tail 20
```

### Check alerts

```bash
python3 metrics/suricata_ttd.py
```

### Custom rules

Rules are located in `secure/suricata/rules/iot-cyberrange.rules`. All rules operate on TCP/TLS metadata only (no payload inspection — TLS 1.3 encrypts all MQTT traffic).

| SID | Scenario | Detection Method |
|---|---|---|
| 1000001 | S1 Eavesdropping | Failed TLS connections > 3 in 10s |
| 1000002 | S2 Injection | Repeated failed connections > 5 in 15s |
| 1000003 | S3 DoS (SYN flood) | TCP SYN > 15 in 3s |
| 1000004 | S3 DoS (conn rate) | Connection rate > 25 in 5s |
| 1000005 | S4 Brute Force | Rapid TLS reconnects > 8 in 20s |
| 1000006 | S5 Port scan | SYN > 20 in 5s on IoT subnet |
| 1000007 | S5 Lateral movement | Cross-subnet access to data_pipeline |
| 1000008 | S5 Node-RED access | TCP to port 1880 from IoT subnet |
| 1000009 | S5 InfluxDB access | TCP to port 8086 from IoT subnet |

---

## Running Attack Campaigns

The campaign orchestrator runs all 6 attack scenarios sequentially, collecting metrics before, during, and after each attack.

### Full campaign

```bash
# Insecure environment
python3 metrics/run_campaign.py --env insecure

# Secure environment (requires Suricata running)
python3 metrics/run_campaign.py --env secure
```

### Single scenario

```bash
python3 metrics/run_campaign.py --env insecure --scenario 3
python3 metrics/run_campaign.py --env secure --scenario 5
```

### Multi-run statistical analysis

Run N independent campaigns and get aggregated statistics (mean, standard deviation, 95% confidence interval via t-distribution):

```bash
# 5 independent runs on insecure environment
python3 metrics/run_campaign.py --env insecure --runs 5

# 5 independent runs on secure environment
python3 metrics/run_campaign.py --env secure --runs 5
```

Each run clears InfluxDB at the start to ensure independence. Outputs:
- `campaign_<env>_<timestamp>_run<n>.json` — raw results for each run
- `campaign_<env>_<timestamp>_stats.json` — aggregated statistics
- `campaign_<env>_<timestamp>_stats.csv` — aggregated statistics (CSV)

Aggregated metrics per scenario:

| Metric | Description |
|---|---|
| `latency_avg_ms` | Mean ± std of MQTT round-trip latency, baseline and under attack |
| `throughput_msg_s` | Mean ± std of message throughput |
| `ttd_mean` / `ttd_std` | Time-to-detect statistics (secure env only) |
| `ttd_detection_rate` | Fraction of runs where Suricata detected the attack |
| `anomalies_mean` | Mean anomalous readings detected (S2 only) |

### Output

Results are saved to `metrics/results/`:
- `campaign_<env>_<timestamp>.json` — full results with all metrics
- `campaign_<env>_<timestamp>.csv` — summary table for analysis

The CSV includes TTD columns for the secure environment:

```
scenario, phase, latency_avg_ms, latency_min_ms, latency_max_ms,
throughput_msg_s, influxdb_available, nodered_available,
grafana_available, temp_anomalies, humidity_anomalies,
power_anomalies, temp_integrity, ttd_seconds, ttd_detected,
ttd_alert_count
```

---

## Attack Scenarios

### S1 — Eavesdropping

Passive MQTT traffic capture via anonymous subscription.

```bash
docker exec insecure_attacker bash scripts/01_eavesdrop.sh
docker exec secure_attacker bash scripts/01_eavesdrop.sh
```

**Insecure result:** Captures plaintext messages including sensor data and credentials.  
**Secure result:** TLS 1.3 encrypts all traffic — 0 messages captured.

---

### S2 — Message Injection

Injects forged sensor readings and unauthorized actuator commands.

```bash
docker exec insecure_attacker bash scripts/02_inject.sh
docker exec secure_attacker bash scripts/02_inject.sh
```

**Insecure result:** 21 messages injected; smart plug actuator sabotaged.  
**Secure result:** Authentication + ACL blocks all injection attempts.

---

### S3 — Denial of Service

Subscription amplification attack: 50 concurrent workers subscribe to all readable topics before flooding, creating an N-fold fanout that saturates the broker's message routing capacity.

```bash
docker exec insecure_attacker python3 scripts/03_dos.py
docker exec secure_attacker python3 scripts/03_dos.py
```

**Insecure result:** All 50 workers connect; +471% latency degradation (0.74ms → 4.23ms); broker routing 500,000 deliveries/s.
**Secure result:** Only 16/50 workers connect (`max_connections=20`); ACL limits topics to `sensors/#` and `metrics/dos/latency`; +98% latency degradation (0.97ms → 1.92ms); attack partially mitigated.

---

### S4 — Brute Force

Dictionary attack on MQTT credentials, followed by credential reuse from S1.

```bash
docker exec insecure_attacker python3 scripts/04_bruteforce.py
docker exec secure_attacker python3 scripts/04_bruteforce.py
```

**Insecure result:** 24/24 credentials matched (anonymous broker accepts all); 3/3 harvested credentials reused.  
**Secure result:** 0/12 credentials found; no credential reuse possible (TLS prevented eavesdropping in S1).

---

### S5 — Lateral Movement

Network reconnaissance followed by attempts to access data pipeline services.

```bash
docker exec insecure_attacker bash scripts/05_lateral_movement.sh
docker exec secure_attacker bash scripts/05_lateral_movement.sh
```

**Insecure result:** 3 services compromised (Node-RED, InfluxDB, Grafana); 908 sensor records exfiltrated.
**Secure result:** Network segmentation blocks all cross-subnet access; 0 services reached.

---

### S6 — Replay Attack

Captures legitimate sensor messages via anonymous subscription, then replays them in rapid bursts to flood the broker with duplicate historical data. Unlike injection (S2), replayed values are always within normal bounds — bypassing threshold-based anomaly detection.

```bash
docker exec insecure_attacker python3 scripts/06_replay.py
docker exec secure_attacker python3 scripts/06_replay.py
```

**Insecure result:** ~10–20× throughput spike; InfluxDB flooded with duplicate sensor readings; data timeline integrity violated.
**Secure result:** All 6 authentication attempts refused (anonymous + common credentials); 0 messages captured or replayed; Suricata detects rapid connection burst.

---

## MITRE ATT&CK for ICS Mapping

Each attack scenario is mapped to the [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) framework (v15), which provides a standardised taxonomy of adversarial techniques targeting Industrial Control Systems and cyber-physical environments.

| Scenario | Attack Vector | Tactic | Technique | Secure Countermeasure | IDS Rule |
|---|---|---|---|---|---|
| **S1** — Eavesdropping | Passive MQTT traffic capture; anonymous subscription to `sensors/#` | Collection (TA0100) | [T0842 — Network Sniffing](https://attack.mitre.org/techniques/T0842/) | TLS 1.2 encrypts all traffic; 0 messages readable | Preventive (no post-fact detection) |
| **S2** — Message Injection | Forged sensor readings published to `sensors/#`; unauthorized actuator commands on `commands/#` | Impair Process Control (TA0106) | [T0856 — Spoof Reporting Message](https://attack.mitre.org/techniques/T0856/) | MQTT authentication + per-user ACL blocks unauthenticated publish | SID 1000002 (repeated failed connections) |
| **S3** — Denial of Service | Subscription amplification flood: 50 concurrent workers saturate broker routing capacity | Inhibit Response Function (TA0107) | [T0814 — Denial of Service](https://attack.mitre.org/techniques/T0814/) | `max_connections=20` + `max_inflight_messages=10` caps attack surface | SID 1000003 (SYN flood), SID 1000004 (connection rate) |
| **S4** — Brute Force | Dictionary attack on MQTT credentials; credential reuse from S1 harvested data | Initial Access (TA0108) | [T0859 — Valid Accounts](https://attack.mitre.org/techniques/T0859/) | Strong per-device credentials; anonymous access disabled; TLS prevents S1 harvest | SID 1000005 (rapid reconnects) |
| **S5** — Lateral Movement | Port scan of IoT subnet; pivot to data pipeline services (Node-RED :1880, InfluxDB :8086, Grafana :3001) | Lateral Movement (TA0109) | [T0886 — Remote Services](https://attack.mitre.org/techniques/T0886/) | Three isolated subnets (`internal: true`); no cross-subnet routing | SID 1000006 (port scan), SID 1000007–1000009 (cross-subnet access) |
| **S6** — Replay Attack | Captured sensor messages republished in bulk to flood broker with duplicate historical data | Impair Process Control (TA0106) | [T0856 — Spoof Reporting Message](https://attack.mitre.org/techniques/T0856/) | Authentication blocks anonymous replay; TLS prevents passive payload capture | SID 1000010 (rapid connection burst) |

### Detection vs. Prevention

Not all techniques are detectable after the fact — some are blocked at the architectural level before Suricata can observe them:

| Scenario | Security Posture | TTD |
|---|---|---|
| S1 — Eavesdropping | **Preventive** — TLS makes captured traffic unreadable | N/A |
| S2 — Message Injection | **Preventive** — broker rejects unauthenticated publish | N/A |
| S3 — Denial of Service | **Detective + Mitigative** — rate limiting reduces blast radius; IDS alerts on flood | Measured (seconds) |
| S4 — Brute Force | **Detective** — IDS detects rapid reconnect pattern; credentials not compromised | Measured (seconds) |
| S5 — Lateral Movement | **Preventive + Detective** — segmentation blocks pivot; IDS alerts on scan and cross-subnet probe | Measured (seconds) |
| S6 — Replay Attack | **Preventive + Detective** — authentication blocks anonymous replay; IDS detects connection burst | Measured (seconds) |

### Compliance Reference

This mapping supports alignment with the following standards:

- **IEC 62443-3-3** (System Security Requirements): SR 3.1 (Communication Integrity), SR 3.4 (Software and Information Integrity), SR 5.1 (Network Segmentation)
- **NIST SP 800-82r3** (Guide to OT Security): network segmentation, encryption in transit, least-privilege access control
- **ENISA IoT Security Guidelines** (2023): device authentication, transport security, network monitoring

---

## Metrics & Results

### Collected metrics per scenario

- **Latency:** MQTT round-trip avg/min/max (ms)
- **Throughput:** Messages per second
- **Service availability:** InfluxDB, Node-RED, Grafana reachability
- **Data integrity:** Anomaly detection on temperature/humidity/power readings
- **TTD (secure only):** Time from attack start to first Suricata alert (seconds)

### Summary of results

| Scenario | Insecure | Secure | TTD |
|---|---|---|---|
| S1 Eavesdropping | ~133 msgs captured | 0 msgs captured | Not detected (preventive control) |
| S2 Injection | 21 msgs injected | 0 msgs injected | Not detected (preventive control) |
| S3 DoS | +471% latency (50/50 workers) | +98% latency (16/50 workers) | 10.1s |
| S4 Brute Force | 24/24 credentials | 0/12 credentials | 7.2s |
| S5 Lateral Movement | 3 services breached, 908 records | 0 services reached | 5.0s |

---

## Troubleshooting

### Containers not starting

```bash
# Check logs
docker compose -f insecure/docker-compose.yml logs <service>
docker compose -f secure/docker-compose.yml logs <service>

# Recreate specific container
docker compose -f secure/docker-compose.yml up -d --force-recreate broker
```

### Suricata not detecting alerts

```bash
# Verify interface
NETWORK_ID=$(docker network inspect secure_iot_devices --format '{{.Id}}' | cut -c1-12)
echo "Interface: br-${NETWORK_ID}"
ip link show "br-${NETWORK_ID}"

# Check Suricata logs
docker logs secure_suricata 2>&1 | grep -i "rule\|error\|load"

# Check rules loaded
docker logs secure_suricata 2>&1 | grep "signatures processed"

# Restart Suricata
bash secure/suricata/start_suricata.sh
```

### Node-RED not writing to InfluxDB

```bash
# Check Node-RED logs
docker logs insecure_nodered 2>&1 | grep -v "probe\|Unexpected" | tail -20

# Verify MQTT topic subscription
curl -s http://172.20.0.31:1880/flows | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n.get('type') == 'mqtt in':
        print('Topic:', n.get('topic'))
"
# Should be: sensors/#
# If it shows #, fix with:
FLOWS=$(curl -s http://172.20.0.31:1880/flows)
FIXED=$(echo "$FLOWS" | python3 -c "
import sys, json
f = json.load(sys.stdin)
for n in f:
    if n.get('type') == 'mqtt in' and n.get('topic') == '#':
        n['topic'] = 'sensors/#'
print(json.dumps(f))
")
curl -s -X POST http://172.20.0.31:1880/flows \
    -H "Content-Type: application/json" \
    -H "Node-RED-Deployment-Type: full" \
    -d "$FIXED"
```

### CA certificate missing in attacker container

```bash
# Secure DoS requires ca.crt
docker cp secure/broker/certs/ca.crt secure_attacker:/attacker/ca.crt
```

### InfluxDB token error

```bash
# Insecure token
grep INFLUXDB_INIT_ADMIN_TOKEN insecure/docker-compose.yml

# Secure token
grep INFLUXDB_INIT_ADMIN_TOKEN secure/docker-compose.yml
```

### Network interface changed after reboot

Docker bridge interface names are dynamic. After a host reboot, re-run:

```bash
bash secure/suricata/start_suricata.sh
```

---

## Notes

- All containers run on a single host — network latency values are lower than real IoT deployments but comparisons between insecure and secure remain valid.
- Suricata S1/S2 non-detection is expected: the broker rejects those attacks so quickly that connection count never reaches the detection threshold. This is a positive result — preventive controls make detection unnecessary.
- The DoS script uses a dedicated latency monitor thread separate from the flood clients to obtain accurate broker responsiveness metrics.