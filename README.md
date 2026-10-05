# File Integrity Checker

A command-line tool that detects whether files in a folder have been modified,
added, or deleted, by comparing SHA-256 fingerprints against a saved baseline.

> Only use this on files and folders you own.

## How it works

1. **Baseline:** the tool walks through a folder and computes a SHA-256 hash
   (a unique fingerprint) of every file, then saves them to `baseline.json`.
2. **Check:** later, it hashes everything again and compares with the baseline.
3. **Report:** any difference is reported as MODIFIED, NEW, or DELETED.

Changing even one character in a file produces a completely different hash,
so tampering is easy to spot.

## Usage

```
python fim.py baseline demo
python fim.py check demo
```

Options:
- `--exclude logs "*.tmp"` ignore files or folders by name/pattern
- `--baseline other.json` use a different baseline file
- `--expected-hash <sha256>` verify the baseline file itself wasn't tampered with

## Demo

<!-- TODO: add a screenshot of `check` output after you modify, delete, and add a file -->

## Why SHA-256?

 used SHA-256 because it's collision-resistant, meaning it's not practically possible to create two different files with the same hash. Older algorithms like MD5 and SHA-1 have known collision attacks, so an attacker could in theory modify a file without changing its hash. SHA-256 is slower, but for an integrity checker, trustworthy results matter more than speed.

## What I learned

Building this taught me how file integrity monitoring works at a basic level and why tools like Tripwire exist. The biggest lesson was that the baseline file is itself a target: if an attacker can modify it, the tool becomes useless, so I added an option to verify its hash. I also practiced structuring a Python project with a CLI, error handling, and automated tests.

## Limitations

- It only detects changes after they happen; it can't prevent them.
- It can't tell whether a change was legitimate or malicious.
- It runs manually, whereas real tools (Tripwire, AIDE) monitor continuously.
- If an attacker can edit your files, they might also edit `baseline.json`.
  The `--expected-hash` option helps, but the hash must be stored somewhere safe.

## Possible improvements

- Run on a schedule (cron / Task Scheduler)
- Email or Slack alerts
- Real-time monitoring with `watchdog`