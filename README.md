# File Integrity Monitor

A small Python CLI tool that uses SHA-256 hashes to detect changes in files
inside a folder.

## Features

- Creates a JSON baseline of file hashes
- Detects new, modified, and removed files
- Reads files in chunks
- Uses only the Python standard library
- Includes unit tests

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Quick start

Create a baseline:

```bash
python fim.py init demo_files
