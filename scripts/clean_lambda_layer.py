#!/usr/bin/env python3
"""
Script to clean up Lambda layer and remove unnecessary packages.
This script removes build tools and documentation to reduce layer size.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def get_directory_size(path):
    """Calculate total size of directory in MB."""
    total = 0
    for entry in Path(path).rglob('*'):
        if entry.is_file():
            total += entry.stat().st_size
    return total / (1024 * 1024)  # Convert to MB


def remove_pattern(base_path, pattern, description):
    """Remove files/directories matching pattern."""
    removed_count = 0
    for item in Path(base_path).rglob(pattern):
        try:
            if item.is_file():
                item.unlink()
                removed_count += 1
            elif item.is_dir():
                shutil.rmtree(item)
                removed_count += 1
        except Exception as e:
            print(f"  Warning: Could not remove {item}: {e}")
    if removed_count > 0:
        print(f"  Removed {removed_count} {description}")


def main():
    print("=" * 60)
    print("Lambda Layer Cleanup Script")
    print("=" * 60)

    # Navigate to cti_dependencies (now one level up from scripts/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    deps_dir = project_root / "cti_dependencies"
    python_dir = deps_dir / "python"

    if not deps_dir.exists():
        print(f"Error: {deps_dir} not found!")
        sys.exit(1)

    print(f"\nWorking directory: {deps_dir}")

    # Check initial size
    if python_dir.exists():
        initial_size = get_directory_size(python_dir)
        print(f"Initial size: {initial_size:.2f} MB")

    # Step 1: Remove old python directory
    print("\n[1/5] Removing old dependencies...")
    if python_dir.exists():
        shutil.rmtree(python_dir)
        print("  Removed old python/ directory")
    python_dir.mkdir(exist_ok=True)

    # Step 2: Install dependencies
    print("\n[2/5] Installing runtime dependencies...")
    # Try minimal first, fallback to lambda
    requirements_file = deps_dir / "requirements.txt"
    if not requirements_file.exists():
        requirements_file = deps_dir / "requirements-lambda.txt"

    if not requirements_file.exists():
        print(f"Error: {requirements_file} not found!")
        sys.exit(1)

    # Install with platform-specific targeting for Linux Lambda environment
    install_cmd = [
        sys.executable, "-m", "pip", "install",
        "--target", str(python_dir),
        "--platform", "manylinux2014_x86_64",
        "--implementation", "cp",
        "--python-version", "3.13",
        "--only-binary=:all:",
        "--upgrade",
        "-r", str(requirements_file)
    ]

    try:
        result = subprocess.run(
            install_cmd,
            check=True,
            capture_output=True,
            text=True
        )
        print("  Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"  Error installing dependencies: {e}")
        print(f"  STDOUT: {e.stdout}")
        print(f"  STDERR: {e.stderr}")
        print("\n  Trying alternative installation method...")

        # Fallback: install without platform targeting (for local testing)
        install_cmd_simple = [
            sys.executable, "-m", "pip", "install",
            "--target", str(python_dir),
            "--upgrade",
            "-r", str(requirements_file)
        ]

        try:
            subprocess.run(install_cmd_simple, check=True)
            print("  Dependencies installed with fallback method")
        except subprocess.CalledProcessError as e2:
            print(f"  Error: {e2}")
            sys.exit(1)

    # Step 3: Remove unnecessary runtime packages
    print("\n[3/5] Removing unnecessary packages...")

    # Large packages not needed at runtime
    unnecessary_packages = [
        "setuptools*",
        "pip*",
        "wheel*",
        "_distutils_hack*",
        "pkg_resources",
    ]

    for pattern in unnecessary_packages:
        for item in python_dir.glob(pattern):
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                    print(f"  Removed {item.name}/")
                elif item.is_file():
                    item.unlink()
                    print(f"  Removed {item.name}")
            except Exception as e:
                print(f"  Warning: Could not remove {item}: {e}")

    # Step 4: Remove test files and documentation
    print("\n[4/5] Removing test files and documentation...")

    remove_pattern(python_dir, "tests", "test directories")
    remove_pattern(python_dir, "test", "test directories")
    remove_pattern(python_dir, "__pycache__", "__pycache__ directories")
    remove_pattern(python_dir, "*.pyc", ".pyc files")
    remove_pattern(python_dir, "*.pyo", ".pyo files")

    # Remove documentation files
    remove_pattern(python_dir, "*.md", "markdown files")
    remove_pattern(python_dir, "*.rst", "reStructuredText files")
    remove_pattern(python_dir, "LICENSE*", "license files")
    remove_pattern(python_dir, "NOTICE*", "notice files")
    remove_pattern(python_dir, "docs", "documentation directories")
    remove_pattern(python_dir, "examples", "example directories")
    remove_pattern(python_dir, "example", "example directories")

    # Step 5: Clean up dist-info RECORD files
    print("\n[5/5] Cleaning up distribution metadata...")
    remove_pattern(python_dir, "*.dist-info/RECORD", "RECORD files")

    # Final size check
    final_size = get_directory_size(python_dir)
    print("\n" + "=" * 60)
    print(f"Final size: {final_size:.2f} MB")

    if python_dir.exists() and initial_size:
        savings = initial_size - final_size
        savings_pct = (savings / initial_size) * 100
        print(f"Space saved: {savings:.2f} MB ({savings_pct:.1f}%)")

    # Check if we're under AWS Lambda layer limits
    if final_size > 250:
        print("\n[!] WARNING: Layer size exceeds 250 MB unzipped limit!")
        print("   Consider removing more dependencies or splitting the layer.")
    elif final_size > 200:
        print("\n[!] WARNING: Layer size is close to 250 MB limit.")
    else:
        print("\n[OK] Layer size is within AWS Lambda limits.")

    print("=" * 60)
    print("Cleanup complete!")
    print("\nNext steps:")
    print("  1. Run: sam build --use-container")
    print("  2. Run: sam deploy --profile eddy_tamusa_dev")
    print("=" * 60)


if __name__ == "__main__":
    main()
