import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone


def calculate_hash(file_path):
    """Return the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_directory(directory):
    """Calculate SHA-256 hashes for files in a directory."""
    directory = Path(directory)
    results = {}

    if not directory.is_dir():
        raise ValueError(f"Not a valid directory: {directory}")

    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            relative_path = str(file_path.relative_to(directory))
            results[relative_path] = calculate_hash(file_path)

    return results


def save_baseline(directory, baseline_path="baseline.json"):
    """Save the current file hashes as a baseline."""
    hashes = scan_directory(directory)

    baseline = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "directory": str(Path(directory).resolve()),
        "files": hashes,
    }

    Path(baseline_path).write_text(
        json.dumps(baseline, indent=2) + "\n",
        encoding="utf-8",
    )

    return baseline


def check_integrity(directory, baseline_path="baseline.json"):
    """Compare current files against the saved baseline."""
    baseline_file = Path(baseline_path)

    if not baseline_file.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {baseline_file}. Create one first."
        )

    baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
    expected = baseline["files"]
    current = scan_directory(directory)

    changes = []

    for file_path in sorted(expected.keys() - current.keys()):
        changes.append({
            "file": file_path,
            "status": "DELETED",
        })

    for file_path in sorted(current.keys() - expected.keys()):
        changes.append({
            "file": file_path,
            "status": "ADDED",
        })

    for file_path in sorted(expected.keys() & current.keys()):
        if expected[file_path] != current[file_path]:
            changes.append({
                "file": file_path,
                "status": "MODIFIED",
            })

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "directory": str(Path(directory).resolve()),
        "total_files": len(current),
        "changes_detected": len(changes),
        "changes": changes,
    }


def main():
    print("File Integrity Monitoring Tool")
    print("1. Create or replace baseline")
    print("2. Check file integrity")

    choice = input("Choose an option (1 or 2): ").strip()
    directory = input("Directory to monitor: ").strip()

    if choice == "1":
        save_baseline(directory)
        print("Baseline saved to baseline.json")

    elif choice == "2":
        report = check_integrity(directory)
        Path("integrity_report.json").write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(report, indent=2))
        print("Report saved to integrity_report.json")

    else:
        print("Invalid choice. Please choose 1 or 2.")


if __name__ == "__main__":
    main()
