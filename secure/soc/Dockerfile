FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.31.0

COPY soc_bridge.py .

# Unbuffered output — logs are visible in docker logs
ENV PYTHONUNBUFFERED=1

CMD ["python3", "soc_bridge.py"]
