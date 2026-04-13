import requests
from .config import CAPEC_URL

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def fetch_mitre_objects(offset=0, limit=5):
    print(f"    [MITRE] Fetching items {offset} to {offset+limit}...")
    try:
        resp = requests.get(MITRE_URL, timeout=90)
        data = resp.json()
        objects = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
        return {"objects": objects[offset : offset + limit]}
    except Exception as e:
        print(f"    [!] MITRE Error: {e}")
        return {"objects": []}

def fetch_capec_objects(offset=0, limit=5):
    print(f"    [CAPEC] Fetching items {offset} to {offset+limit}...")
    try:
        resp = requests.get(CAPEC_URL, timeout=30)
        data = resp.json()
        objects = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
        return {"objects": objects[offset : offset + limit]}
    except Exception as e:
        print(f"    [!] CAPEC Error: {e}")
        return {"objects": []}
    