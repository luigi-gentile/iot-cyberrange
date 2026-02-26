# ──────────────────────────────────────────────────────────────────────────────
# Dockerfile - IoT Sensor Simulator
#
# Builds a lightweight Python container that simulates a vulnerable IoT sensor.
# The specific sensor script is selected at runtime via the SENSOR_SCRIPT
# environment variable, allowing a single image to run all sensor types.
#
# Intentional vulnerabilities:
#   - Runs as root (no USER directive)
#   - No resource limits enforced at image level
#   - Sensitive environment variables not masked
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

WORKDIR /app

# Install required Python dependencies
RUN pip install --no-cache-dir paho-mqtt

# Copy all sensor scripts into the container
COPY sensor_temp.py .
COPY sensor_door.py .
COPY sensor_power.py .

# Entrypoint script that selects the correct sensor at runtime
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]