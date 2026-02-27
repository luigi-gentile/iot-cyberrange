#!/bin/bash
case "$SENSOR_TYPE" in
  temp)  exec python3 -u sensor_temp.py  ;;
  door)  exec python3 -u sensor_door.py  ;;
  power) exec python3 -u sensor_power.py ;;
  *) echo "Unknown SENSOR_TYPE: $SENSOR_TYPE"; exit 1 ;;
esac
