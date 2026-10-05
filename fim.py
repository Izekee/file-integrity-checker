#!/usr/bin/env python3
"""
fim.py - A simple File Integrity Monitor.

Usage:
    python fim.py baseline <folder>    Record a SHA-256 fingerprint of every file
    python fim.py check <folder>       Compare the folder against the saved baseline

Only use this on files and folders you own.
"""

import argparse
import fnmatch
import hashlib
import json
import logging
import os
import sys
from datetime import datetime

CHUNK_SIZE = 8192  # read files in 8 KB pieces so huge files don't fill memory
DEFAULT_BASELINE = "baseline.json"
DEFAULT_EXCLUDES = [".git", "__pycache__", ".DS_Store", "*.pyc", "fim.log"]

# ANSI colors (turned off automatically if output isn't a terminal)
USE_COLOR = sys.stdout.isatty()
RED = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
GRAY = "\033[90m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""


# ---------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------

def hash_file(path):
    """Return the SHA-256 hash of a file, reading it in chunks."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha.update(chunk)
    return sha.hexdigest()


def is_excluded(name, excludes):
    """True if a file/folder name matches any exclusion pattern."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in excludes)


def scan_folder(folder, excludes, skip_files=()):
    """
    Walk a folder and return (files, errors).

    files  -> {relative_path: {"sha256": ..., "size": ...}}
    errors -> [(relative_path, reason), ...] for files we couldn't read
    """
    files = {}
    errors = []
    skip = {os.path.abspath(p) for p in skip_files}

    for root, dirs, filenames in os.walk(folder):
        # Editing dirs in place stops os.walk from entering excluded folders
        dirs[:] = [d for d in dirs if not is_excluded(d, excludes)]

        for name in filenames:
            if is_excluded(name, excludes):
                continue
            full_path = os.path.join(root, name)
            if os.path.abspath(full_path) in skip:
                continue

            rel_path = os.path.relpath(full_path, folder)
            try:
                files[rel_path] = {
                    "sha256": hash_file(full_path),
                    "size": os.path.getsize(full_path),
                }
            except (PermissionError, FileNotFoundError, OSError) as err:
                # File may be locked, unreadable, or deleted mid-scan
                errors.append((rel_path, str(err)))

    return files, errors


def compare(baseline_files, current_files):
    """Compare two scans and sort differences into three groups."""
    modified = sorted(
        p for p in baseline_files
        if p in current_files
        and baseline_files[p]["sha256"] != current_files[p]["sha256"]
    )
    deleted = sorted(p for p in baseline_files if p not in current_files)
    new = sorted(p for p in current_files if p not in baseline_files)
    return {"modified": modified, "deleted": deleted, "new": new}


# ---------------------------------------------------------------
# Baseline saving / loading
# ---------------------------------------------------------------

def save_baseline(baseline_path, folder, files):
    data = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "folder": os.path.abspath(folder),
        "files": files,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_baseline(baseline_path):
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------
# Commands
# ---------------------------------------------------------------

def cmd_baseline(args):
    excludes = DEFAULT_EXCLUDES + (args.exclude or [])
    files, errors = scan_folder(args.folder, excludes, skip_files=[args.baseline])

    save_baseline(args.baseline, args.folder, files)

    print(f"{GREEN}Baseline created:{RESET} {len(files)} files hashed -> {args.baseline}")
    for rel_path, reason in errors:
        print(f"{YELLOW}Skipped{RESET} {rel_path} ({reason})")

    # Hash of the baseline itself. Store this somewhere safe (not in the same
    # folder) so you can later prove the baseline wasn't tampered with.
    baseline_hash = hash_file(args.baseline)
    print(f"\nBaseline file SHA-256: {baseline_hash}")
    print("Write this down somewhere safe. Use it with --expected-hash when checking.")

    logging.info("BASELINE created for %s (%d files)", args.folder, len(files))


def cmd_check(args):
    if not os.path.exists(args.baseline):
        print(f"{RED}No baseline found at {args.baseline}.{RESET} "
              f"Run 'python fim.py baseline {args.folder}' first.")
        return 2

    # Optional: make sure the baseline itself hasn't been altered
    if args.expected_hash:
        actual = hash_file(args.baseline)
        if actual != args.expected_hash:
            print(f"{RED}WARNING: baseline file has been modified!{RESET}")
            print(f"  expected: {args.expected_hash}")
            print(f"  actual:   {actual}")
            logging.warning("Baseline file hash mismatch")
            return 2
        print(f"{GREEN}Baseline file integrity verified.{RESET}")

    baseline = load_baseline(args.baseline)
    excludes = DEFAULT_EXCLUDES + (args.exclude or [])
    current, errors = scan_folder(args.folder, excludes, skip_files=[args.baseline])

    changes = compare(baseline["files"], current)
    total = sum(len(v) for v in changes.values())

    print(f"\nBaseline from: {baseline['created']}")
    print(f"Files checked: {len(current)}\n")

    for path in changes["modified"]:
        print(f"{RED}MODIFIED{RESET}  {path}")
        logging.warning("MODIFIED %s", path)
    for path in changes["new"]:
        print(f"{YELLOW}NEW{RESET}       {path}")
        logging.warning("NEW %s", path)
    for path in changes["deleted"]:
        print(f"{GRAY}DELETED{RESET}   {path}")
        logging.warning("DELETED %s", path)
    for rel_path, reason in errors:
        print(f"{YELLOW}SKIPPED{RESET}   {rel_path} ({reason})")

    if total == 0:
        print(f"{GREEN}No changes detected. All files match the baseline.{RESET}")
        logging.info("CHECK clean for %s", args.folder)
        return 0

    print(f"\n{total} change(s) detected: "
          f"{len(changes['modified'])} modified, "
          f"{len(changes['new'])} new, "
          f"{len(changes['deleted'])} deleted")
    return 1  # non-zero exit code lets other tools/scripts react to changes


# ---------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple file integrity monitor using SHA-256 hashes."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("baseline", "record the current state of a folder"),
        ("check", "compare a folder against its saved baseline"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("folder", help="folder to scan")
        p.add_argument("--baseline", default=DEFAULT_BASELINE,
                       help=f"baseline file path (default: {DEFAULT_BASELINE})")
        p.add_argument("--exclude", nargs="*",
                       help="extra names/patterns to ignore, e.g. --exclude logs '*.tmp'")
        if name == "check":
            p.add_argument("--expected-hash",
                           help="SHA-256 of the baseline file, to detect baseline tampering")
    return parser


def main():
    args = build_parser().parse_args()

    if not os.path.isdir(args.folder):
        print(f"{RED}Error:{RESET} '{args.folder}' is not a folder.")
        return 2

    logging.basicConfig(
        filename="fim.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.command == "baseline":
        cmd_baseline(args)
        return 0
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())