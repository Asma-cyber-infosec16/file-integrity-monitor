"""A small SHA-256 file integrity monitor for authorized local folders."""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


BASELINE_VERSION = 1
CHUNK_SIZE = 1024 * 1024


def sha256_file(file_path: Path) -> str:
    """Return the SHA-256 hash of a file, reading it in small chunks."""
    digest = hashlib.sha256()

    with file_path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def scan_directory(
    directory: Path,
    baseline_path: Optional[Path] = None,
) -> Dict[str, str]:
    """Hash regular files in a folder and return relative paths and hashes."""
    root = directory.expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Folder does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Not a folder: {root}")

    excluded_baseline = (
        baseline_path.expanduser().resolve()
        if baseline_path is not None
        else None
    )

    hashes: Dict[str, str] = {}

    for file_path in sorted(root.rglob("*")):
        # Skip symbolic links and anything that is not a regular file.
        if file_path.is_symlink() or not file_path.is_file():
            continue

        # Do not hash the baseline file itself.
        if (
            excluded_baseline is not None
            and file_path.resolve() == excluded_baseline
        ):
            continue

        relative_path = file_path.relative_to(root).as_posix()
        hashes[relative_path] = sha256_file(file_path)

    return hashes


def save_baseline(files: Dict[str, str], baseline_path: Path) -> None:
    """Save hashes to a JSON baseline file."""
    baseline_file = baseline_path.expanduser()
    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    document = {
        "version": BASELINE_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": dict(sorted(files.items())),
    }

    temporary_file = baseline_file.with_name(
        baseline_file.name + ".tmp"
    )
    temporary_file.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_file.replace(baseline_file)


def load_baseline(baseline_path: Path) -> Dict[str, str]:
    """Read and validate a previously saved baseline."""
    baseline_file = baseline_path.expanduser()

    try:
        document = json.loads(baseline_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Baseline is not valid JSON: {baseline_file}"
        ) from error

    if not isinstance(document, dict):
        raise ValueError("Baseline must contain a JSON object.")

    if document.get("version") != BASELINE_VERSION:
        raise ValueError(
            f"Unsupported baseline version: {document.get('version')!r}"
        )

    files = document.get("files")

    if not isinstance(files, dict):
        raise ValueError("Baseline must contain a 'files' object.")

    validated_files: Dict[str, str] = {}

    for relative_path, file_hash in files.items():
        if not isinstance(relative_path, str) or not isinstance(file_hash, str):
            raise ValueError("Baseline contains an invalid file entry.")

        if len(file_hash) != 64 or any(
            character not in "0123456789abcdef"
            for character in file_hash.lower()
        ):
            raise ValueError(
                f"Baseline contains an invalid SHA-256 hash for "
                f"{relative_path!r}."
            )

        validated_files[relative_path] = file_hash.lower()

    return validated_files


def run_init(args: argparse.Namespace) -> int:
    """Create or replace a baseline."""
    files = scan_directory(args.directory, args.baseline)
    save_baseline(files, args.baseline)

    print(f"Baseline created: {args.baseline}")
    print(f"Files recorded: {len(files)}")
    return 0


def run_check(args: argparse.Namespace) -> int:
    """Compare the current folder with a saved baseline."""
    expected = load_baseline(args.baseline)
    current = scan_directory(args.directory, args.baseline)

    added = sorted(current.keys() - expected.keys())
    removed = sorted(expected.keys() - current.keys())
    modified = sorted(
        path
        for path in current.keys() & expected.keys()
        if current[path] != expected[path]
    )

    print(f"Files checked: {len(current)}")

    if not added and not removed and not modified:
        print("No changes detected.")
        return 0

    for label, paths in (
        ("NEW", added),
        ("MODIFIED", modified),
        ("REMOVED", removed),
    ):
        for path in paths:
            print(f"[{label}] {path}")

    # Exit code 1 means changes were found.
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Record and check SHA-256 hashes for a folder "
            "you own or are authorized to assess."
        )
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, handler in (
        ("init", run_init),
        ("check", run_check),
    ):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument(
            "directory",
            type=Path,
            help="Folder to scan",
        )
        command_parser.add_argument(
            "--baseline",
            type=Path,
            default=Path(".fim/baseline.json"),
            help="Baseline file path; default: .fim/baseline.json",
        )
        command_parser.set_defaults(handler=handler)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.handler(args)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())