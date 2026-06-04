import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip() or default

@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("data")
    packages: tuple[str, ...] = ("numpy", "flask", "pandas", "requests", "django", "pytest")
    github_token: str | None = _env("GITHUB_TOKEN")
    nvd_api_key: str | None = _env("NVD_API_KEY")
    aws_profile_name: str | None = _env("AWS_PROFILE_NAME")
    bedrock_model_id: str = _env("BEDROCK_MODEL_ID", "meta.llama3-8b-instruct-v1:0")
    s3_cache_bucket: str | None = _env("S3_CACHE_BUCKET")
    http_timeout_seconds: int = 30
    user_agent: str = "cs-poc-data-pipeline/1.0"
    sqs_queue_url: str | None = _env("SQS_QUEUE_URL")
    aws_region: str = _env("AWS_REGION", "us-east-1")

def get_settings() -> Settings:
    return Settings()