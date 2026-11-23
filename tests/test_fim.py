import hashlib
import tempfile
import unittest
from pathlib import Path

from fim import (
    load_baseline,
    save_baseline,
    scan_directory,
    sha256_file,
)


class FileIntegrityMonitorTests(unittest.TestCase):
    def test_sha256_file_matches_standard_hash(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            file_path = Path(temporary_directory) / "sample.txt"
            file_path.write_bytes(b"hello")

            expected_hash = hashlib.sha256(b"hello").hexdigest()

            self.assertEqual(sha256_file(file_path), expected_hash)

    def test_scan_returns_relative_path_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            folder = Path(temporary_directory) / "watched"
            folder.mkdir()

            file_path = folder / "note.txt"
            file_path.write_text("hello", encoding="utf-8")

            expected_hash = hashlib.sha256(b"hello").hexdigest()

            self.assertEqual(
                scan_directory(folder),
                {"note.txt": expected_hash},
            )

    def test_baseline_file_is_excluded_from_scan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            folder = Path(temporary_directory)
            note_path = folder / "note.txt"
            note_path.write_text("hello", encoding="utf-8")

            baseline_path = folder / "baseline.json"
            save_baseline({"old.txt": "0" * 64}, baseline_path)

            results = scan_directory(folder, baseline_path)

            self.assertIn("note.txt", results)
            self.assertNotIn("baseline.json", results)

    def test_baseline_can_be_saved_and_loaded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            baseline_path = Path(temporary_directory) / "baseline.json"
            expected = {"note.txt": "a" * 64}

            save_baseline(expected, baseline_path)

            self.assertEqual(load_baseline(baseline_path), expected)


if __name__ == "__main__":
    unittest.main()