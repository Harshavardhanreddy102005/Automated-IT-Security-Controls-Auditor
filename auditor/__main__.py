"""Module execution entry point for `python -m auditor`."""

import sys
from auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())
