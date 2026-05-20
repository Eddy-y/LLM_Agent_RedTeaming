import json
import boto3
import requests
from pathlib import Path
from tenacity import retry, wait_exponential, stop_after_attempt
from .config import CAPEC_URL, get_settings


MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def _get_cached_universal(url: str, filename: str) -> dict:
    settings = get_settings()
    s3 = boto3.client('s3') if settings.s3_cache_bucket else None
    
    # 1. Try S3 if in serverless environment
    if s3:
        try:
            obj = s3.get_object(Bucket=settings.s3_cache_bucket, Key=f"universal_cache/{filename}")
            return json.loads(obj['Body'].read().decode('utf-8'))
        except Exception:
            pass # Fallback to download
            
    # 2. Try Local Filesystem
    cache_path = Path(settings.data_dir) / "universal_cache" / filename
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    print(f"    [Cache Miss] Downloading {filename}...")
    resp = requests.get(url, timeout=90)
    resp.raise_for_status()
    data = resp.json()
    
    # Save back to caches
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    if s3:
        s3.put_object(Bucket=settings.s3_cache_bucket, Key=f"universal_cache/{filename}", Body=json.dumps(data))
        
    return data

@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
def fetch_mitre_objects(offset=0, limit=5):
    try:
        data = _get_cached_universal(MITRE_URL, "mitre.json")
        objects = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
        return {"objects": objects[offset : offset + limit]}
    except Exception:
        return {"objects": []}

@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
def fetch_capec_objects(offset=0, limit=5):
    try:
        data = _get_cached_universal(CAPEC_URL, "capec.json")
        objects = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
        return {"objects": objects[offset : offset + limit]}
    except Exception:
        return {"objects": []}