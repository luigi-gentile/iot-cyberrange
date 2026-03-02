#!/usr/bin/env python3
"""
suricata_ttd.py - Time to Detection parser for Suricata alerts

Reads eve.json and calculates TTD for each attack scenario
by comparing alert timestamp with attack start time.
"""
import json
import os
from datetime import datetime, timezone

EVE_LOG = os.path.expanduser("~/iot-cyberrange/secure/suricata/logs/eve.json")

SCENARIO_KEYWORDS = {
    1: ["S1", "eavesdropping", "Eavesdrop"],
    2: ["S2", "injection", "Injection"],
    3: ["S3", "flood", "DoS"],
    4: ["S4", "brute", "Brute"],
    5: ["S5", "lateral", "scan", "Lateral"],
}

def read_alerts(eve_log: str = EVE_LOG) -> list:
    """Read all alerts from eve.json."""
    alerts = []
    try:
        with open(eve_log, 'r') as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e.get('event_type') == 'alert':
                        alerts.append(e)
                except:
                    pass
    except FileNotFoundError:
        pass
    return alerts

def get_alerts_for_scenario(scenario: int, after: datetime, eve_log: str = EVE_LOG) -> list:
    """Get alerts for a specific scenario after a given timestamp."""
    keywords = SCENARIO_KEYWORDS.get(scenario, [])
    alerts = read_alerts(eve_log)
    matching = []
    for a in alerts:
        try:
            ts = datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00'))
            if ts < after:
                continue
            sig = a['alert']['signature']
            if any(k in sig for k in keywords):
                matching.append(a)
        except:
            pass
    return matching

def calculate_ttd(scenario: int, attack_start: datetime, eve_log: str = EVE_LOG) -> dict:
    """
    Calculate Time to Detection for a scenario.
    
    Args:
        scenario: Scenario number (1-5)
        attack_start: datetime when attack started
        eve_log: path to eve.json
    
    Returns:
        Dict with TTD in seconds and alert details
    """
    alerts = get_alerts_for_scenario(scenario, attack_start, eve_log)
    
    if not alerts:
        return {
            "detected": False,
            "ttd_seconds": None,
            "alert_count": 0,
            "first_alert": None,
            "signatures": []
        }
    
    # First alert timestamp
    first_ts = None
    for a in alerts:
        try:
            ts = datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00'))
            if first_ts is None or ts < first_ts:
                first_ts = ts
        except:
            pass
    
    ttd = (first_ts - attack_start).total_seconds() if first_ts else None
    
    return {
        "detected": True,
        "ttd_seconds": round(ttd, 3) if ttd else None,
        "alert_count": len(alerts),
        "first_alert": first_ts.isoformat() if first_ts else None,
        "signatures": list(set(a['alert']['signature'] for a in alerts))
    }

def clear_alerts(eve_log: str = EVE_LOG):
    """Clear the eve.json log file."""
    try:
        with open(eve_log, 'w') as f:
            pass
    except:
        pass

if __name__ == "__main__":
    alerts = read_alerts()
    print(f"Total alerts in log: {len(alerts)}")
    for a in alerts:
        print(f"  [{a['timestamp']}] {a['alert']['signature']}")
