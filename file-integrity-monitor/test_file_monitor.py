import json
import tempfile
import unittest
from pathlib import Path

from file_monitor import calculate_hash, save_baseline, check_integrity


class TestFileMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.monitored = self.root / "monitored"
        self.monitored.mkdir()
        self.baseline = self.root / "baseline.json"

    def test_calculate_hash(self):
        sample = self.monitored / "sample.txt"
        sample.write_text("hello", encoding="utf-8")
        first_hash = calculate_hash(sample)
        sample.write_text("changed", encoding="utf-8")
        second_hash = calculate_hash(sample)
        self.assertNotEqual(first_hash, second_hash)
        self.assertEqual(len(first_hash), 64)

    def test_unchanged_files(self):
        (self.monitored / "config.txt").write_text("safe", encoding="utf-8")
        save_baseline(self.monitored, self.baseline)
        report = check_integrity(self.monitored, self.baseline)
        self.assertEqual(report["changes_detected"], 0)

    def test_modified_file(self):
        sample = self.monitored / "config.txt"
        sample.write_text("original", encoding="utf-8")
        save_baseline(self.monitored, self.baseline)
        sample.write_text("modified", encoding="utf-8")
        report = check_integrity(self.monitored, self.baseline)
        self.assertIn(
            {"file": "config.txt", "status": "MODIFIED"},
            report["changes"],
        )

    def test_added_file(self):
        save_baseline(self.monitored, self.baseline)
        (self.monitored / "new.txt").write_text("new", encoding="utf-8")
        report = check_integrity(self.monitored, self.baseline)
        self.assertIn(
            {"file": "new.txt", "status": "ADDED"},
            report["changes"],
        )

    def test_deleted_file(self):
        (self.monitored / "old.txt").write_text("old", encoding="utf-8")
        save_baseline(self.monitored, self.baseline)
        (self.monitored / "old.txt").unlink()
        report = check_integrity(self.monitored, self.baseline)
        self.assertIn(
            {"file": "old.txt", "status": "DELETED"},
            report["changes"],
        )

    def test_invalid_directory(self):
        with self.assertRaises(ValueError):
            save_baseline(self.root / "missing", self.baseline)


if __name__ == "__main__":
    unittest.main()
