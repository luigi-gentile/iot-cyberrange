# Suricata IDS

Suricata is not included in docker-compose because it requires the dynamically
assigned bridge interface name of the Docker network. To start it, run:

    bash ~/iot-cyberrange/secure/suricata/start_suricata.sh

Or manually:

    NETWORK_ID=$(docker network inspect secure_iot_devices --format '{{.Id}}' | cut -c1-12)
    docker run -d --name secure_suricata --network host \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_NICE \
        -v ~/iot-cyberrange/secure/suricata/suricata.yaml:/etc/suricata/suricata.yaml \
        -v ~/iot-cyberrange/secure/suricata/rules:/etc/suricata/rules \
        -v ~/iot-cyberrange/secure/suricata/logs:/var/log/suricata \
        jasonish/suricata:latest \
        -c /etc/suricata/suricata.yaml -i br-$NETWORK_ID --init-errors-fatal
