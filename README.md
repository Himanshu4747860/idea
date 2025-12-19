
# Website Trust Parameter Scanner (MVP v1)

This is an internal demo system for passively scanning predefined websites and collecting trust parameters. It stores results in SQLite and runs via GitHub Actions.

## Purpose
- Scans 6 fixed demo websites.
- Collects 10 passive parameters.
- Stores in SQLite.
- Runs scheduled or manually via GitHub Actions.
- Generates demo data (not reports).

## Setup
1. Clone this repo.
2. Ensure Python 3.11.
3. Install dependencies: `pip install -r requirements.txt`.
4. Run locally: `python scanner/run_scan.py`.
5. Push to GitHub for Actions.

## Security Note
This is a passive trust signal collector, not a vulnerability scanner. All checks are non-intrusive.
=======
# idea
>>>>>>> 9c3b35dae3267a4d1c9394d42838c0a0ac6edde2
