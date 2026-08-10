"""Find regions of CSV with highest concentration of Python exploits."""

import csv
from pathlib import Path

csv_path = Path("data/exploitdb_cache/files_exploits.csv")

print("Scanning CSV for Python exploit density...\n")

# Check different regions
regions = [
    (0, 1000),
    (5000, 6000),
    (10000, 11000),
    (15000, 16000),
    (20000, 21000),
    (25000, 26000),
    (30000, 31000),
    (35000, 36000),
    (40000, 41000),
    (45000, 46000)
]

results = []

with csv_path.open('r', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)

    for start, end in regions:
        python_count = 0

        # Reset file pointer
        f.seek(0)
        next(reader)  # Skip header

        for idx, row in enumerate(reader):
            if idx < start:
                continue
            if idx >= end:
                break

            if row.get('file', '').endswith('.py'):
                python_count += 1

        results.append((start, end, python_count))
        print(f"Rows {start:5d}-{end:5d}: {python_count:3d} Python exploits ({python_count/10:.1f}%)")

# Find best region
best = max(results, key=lambda x: x[2])
print(f"\nBest region: Rows {best[0]}-{best[1]} with {best[2]} Python exploits")
print(f"\nRecommendation: Use offset {best[0]} with batch size 1000")
