#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# entrypoint.sh - Sensor Container Entrypoint
#
# Selects and launches the correct sensor script based on the SENSOR_SCRIPT
# environment variable. This allows a single Docker image to simulate
# multiple sensor types without rebuilding.
#
# Usage:
#   SENSOR_SCRIPT=sensor_temp.py docker run sensor-image
# ──────────────────────────────────────────────────────────────────────────────

if [ -z "$SENSOR_SCRIPT" ]; then
    echo "[entrypoint] ERROR: SENSOR_SCRIPT environment variable is not set."
    echo "[entrypoint] Available scripts: sensor_temp.py, sensor_door.py, sensor_power.py"
    exit 1
fi

if [ ! -f "/app/$SENSOR_SCRIPT" ]; then
    echo "[entrypoint] ERROR: Script '$SENSOR_SCRIPT' not found in /app/"
    exit 1
fi

echo "[entrypoint] Starting sensor: $SENSOR_SCRIPT"
exec python "/app/$SENSOR_SCRIPT"