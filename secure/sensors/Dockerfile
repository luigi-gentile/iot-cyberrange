FROM python:3.11-slim
WORKDIR /app
RUN pip install paho-mqtt
COPY sensor_temp.py sensor_door.py sensor_power.py entrypoint.sh ./
RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
