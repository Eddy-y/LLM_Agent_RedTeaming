Setup

1) Create venv
python3 -m venv .venv
source .venv/bin/activate

2) Install deps
pip install -r requirements.txt

3) Set env vars
export GITHUB_TOKEN="your token"
Optional
export NVD_API_KEY="your key"

4) Run
python -m src.run_pipeline

Outputs

Raw files saved under:
data/raw/<run_id>/<package>/<source>.json

SQLite db:
data/pipeline.sqlite

Tables:
fetch_log
extracted_items
