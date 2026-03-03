# ──────────────────────────────────────────────────────────────────────────────
# Dockerfile - IoT Attacker Container
#
# Builds a specialized attack container for IoT/MQTT security testing.
# Contains all tools and scripts needed to demonstrate the attack scenarios
# described in the thesis.
#
# Installed tools:
#   - mosquitto-clients: MQTT publish/subscribe CLI tools
#   - nmap: Network scanner for reconnaissance
#   - tcpdump: Packet capture and traffic analysis
#   - hping3: Packet crafting for DoS attacks
#   - python3 + paho-mqtt: MQTT attack scripting
#   - curl: HTTP requests to backend services
#   - iputils-ping: Network connectivity testing
# ──────────────────────────────────────────────────────────────────────────────

FROM kalilinux/kali-rolling:latest

WORKDIR /attacker

# Update package list and install attack tools
RUN apt-get update && apt-get install -y \
    mosquitto-clients \
    nmap \
    tcpdump \
    hping3 \
    python3 \
    python3-pip \
    curl \
    iputils-ping \
    net-tools \
    iproute2 \
    && pip3 install paho-mqtt --break-system-packages \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy all attack scripts into the container
COPY scripts/ ./scripts/
RUN chmod +x ./scripts/*.sh

# Default command: show available attack scripts
CMD ["/bin/bash", "-c", "echo '=== IoT Cyberrange - Attacker Container ===' && echo '' && echo 'Available attack scripts:' && ls -la scripts/ && echo '' && echo 'Run: bash scripts/<script_name>' && tail -f /dev/null"]