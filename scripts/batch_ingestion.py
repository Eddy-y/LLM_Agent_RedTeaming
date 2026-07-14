"""
batch_ingestion.py

Runs the ingestion pipeline multiple times to accumulate historical data.
Monitors progress and provides detailed statistics.

Usage: python batch_ingestion.py --runs 50
"""

import sys
sys.path.insert(0, '.')

import argparse
import time
from datetime import datetime
from src.db import get_db_connection, release_db_connection

def get_record_counts():
    """Get current record counts by source."""
    conn = get_db_connection()
    if not conn:
        return {}

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, COUNT(*)
                FROM threat_intelligence_records
                GROUP BY source
                ORDER BY source
            """)
            return {row[0]: row[1] for row in cur.fetchall()}
    except Exception as e:
        print(f"    [WARN] Could not fetch record counts: {e}")
        return {}
    finally:
        release_db_connection(conn)

def get_pagination_state():
    """Get current pagination offsets."""
    conn = get_db_connection()
    if not conn:
        return []

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, package_name, offset_value
                FROM pipeline_state
                ORDER BY source, package_name
            """)
            return cur.fetchall()
    except Exception as e:
        print(f"    [WARN] Could not fetch pagination state: {e}")
        return []
    finally:
        release_db_connection(conn)

def get_embedding_stats():
    """Get embedding population statistics."""
    conn = get_db_connection()
    if not conn:
        return {}

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source,
                       COUNT(*) as total,
                       COUNT(embedding) as with_embedding
                FROM threat_intelligence_records
                GROUP BY source
            """)
            return {row[0]: {'total': row[1], 'with_embedding': row[2]} for row in cur.fetchall()}
    except Exception as e:
        print(f"    [WARN] Could not fetch embedding stats: {e}")
        return {}
    finally:
        release_db_connection(conn)

def print_progress_header(run_num, total_runs):
    """Print a nice header for each run."""
    print("\n" + "=" * 70)
    print(f"RUN {run_num}/{total_runs} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

def print_progress_summary(run_num, total_runs, start_time):
    """Print summary statistics after each run."""
    print("\n" + "-" * 70)
    print(f"PROGRESS SUMMARY - Run {run_num}/{total_runs}")
    print("-" * 70)

    # Record counts
    counts = get_record_counts()
    if counts:
        print("\nRecord Counts by Source:")
        for source, count in sorted(counts.items()):
            print(f"  {source:20} | {count:>6} records")
        print(f"  {'TOTAL':20} | {sum(counts.values()):>6} records")

    # Pagination state
    state = get_pagination_state()
    if state:
        print("\nPagination State:")
        for source, package, offset in state:
            print(f"  {source:20} | {package:15} | offset={offset}")

    # Embedding statistics
    embedding_stats = get_embedding_stats()
    if embedding_stats:
        print("\nEmbedding Population:")
        total_records = sum(s['total'] for s in embedding_stats.values())
        total_with_embedding = sum(s['with_embedding'] for s in embedding_stats.values())
        coverage = (total_with_embedding / total_records * 100) if total_records > 0 else 0

        for source, stats in sorted(embedding_stats.items()):
            pct = (stats['with_embedding'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {source:20} | {stats['with_embedding']}/{stats['total']} ({pct:.1f}%)")
        print(f"  {'TOTAL':20} | {total_with_embedding}/{total_records} ({coverage:.1f}%)")

    # Time statistics
    elapsed = time.time() - start_time
    avg_per_run = elapsed / run_num if run_num > 0 else 0
    remaining_runs = total_runs - run_num
    estimated_remaining = avg_per_run * remaining_runs

    print(f"\nTime Statistics:")
    print(f"  Elapsed: {int(elapsed)}s ({elapsed/60:.1f} min)")
    print(f"  Avg per run: {avg_per_run:.1f}s")
    if remaining_runs > 0:
        print(f"  Estimated remaining: {int(estimated_remaining)}s ({estimated_remaining/60:.1f} min)")

    print("-" * 70)

def run_batch_ingestion(num_runs: int, pause_seconds: int = 10):
    """Run the ingestion pipeline multiple times."""
    print("\n" + "=" * 70)
    print("BATCH INGESTION STARTED")
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Total runs: {num_runs}")
    print(f"  Pause between runs: {pause_seconds}s")
    print(f"  Estimated duration: {(num_runs * 20 + (num_runs - 1) * pause_seconds) / 60:.1f} min")
    print("\n" + "=" * 70)

    # Import after setting up sys.path
    from scripts.ingest_to_sqs import run_pipeline

    start_time = time.time()
    successful_runs = 0
    failed_runs = 0

    for i in range(1, num_runs + 1):
        print_progress_header(i, num_runs)

        try:
            # Run the ingestion pipeline
            run_id = run_pipeline()
            successful_runs += 1
            print(f"\n[SUCCESS] Run {i} completed. run_id = {run_id}")

        except KeyboardInterrupt:
            print("\n\n[INTERRUPTED] Batch ingestion interrupted by user.")
            print(f"\nCompleted {successful_runs}/{num_runs} runs before interruption.")
            break

        except Exception as e:
            failed_runs += 1
            print(f"\n[ERROR] Run {i} failed: {e}")
            print("Continuing to next run...")

        # Print summary after each run
        print_progress_summary(i, num_runs, start_time)

        # Pause between runs (except after the last run)
        if i < num_runs:
            print(f"\nPausing {pause_seconds} seconds before next run...")
            time.sleep(pause_seconds)

    # Final summary
    total_elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print("BATCH INGESTION COMPLETE")
    print("=" * 70)
    print(f"\nFinal Statistics:")
    print(f"  Successful runs: {successful_runs}/{num_runs}")
    print(f"  Failed runs: {failed_runs}/{num_runs}")
    print(f"  Total time: {int(total_elapsed)}s ({total_elapsed/60:.1f} min)")

    # Final record counts
    counts = get_record_counts()
    if counts:
        print(f"\nFinal Record Counts:")
        for source, count in sorted(counts.items()):
            print(f"  {source:20} | {count:>6} records")
        print(f"  {'TOTAL':20} | {sum(counts.values()):>6} records")

    # Final pagination state
    state = get_pagination_state()
    if state:
        print(f"\nFinal Pagination State:")
        for source, package, offset in state:
            print(f"  {source:20} | {package:15} | offset={offset}")

    print("\n" + "=" * 70)
    print("\n[NEXT STEP] Verify Neo4j population:")
    print("  1. Open Neo4j Browser")
    print("  2. Run: MATCH (n) RETURN labels(n)[0] as NodeType, count(n) ORDER BY count(n) DESC")
    print("  3. Run: MATCH ()-[r]->() RETURN type(r), count(r) ORDER BY count(r) DESC")
    print("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run ingestion pipeline multiple times to accumulate historical data"
    )
    parser.add_argument(
        '--runs',
        type=int,
        default=50,
        help='Number of ingestion runs (default: 50)'
    )
    parser.add_argument(
        '--pause',
        type=int,
        default=10,
        help='Seconds to pause between runs (default: 10)'
    )

    args = parser.parse_args()

    if args.runs < 1:
        print("[ERROR] Number of runs must be at least 1")
        sys.exit(1)

    if args.pause < 0:
        print("[ERROR] Pause duration cannot be negative")
        sys.exit(1)

    try:
        run_batch_ingestion(args.runs, args.pause)
    except Exception as e:
        print(f"\n[FATAL ERROR] Batch ingestion failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
