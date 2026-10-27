#!/usr/bin/env python3
"""Entry point: python scripts/nfaudit.py scan <path>. Standard library only (Python 3.9+)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nfaudit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
