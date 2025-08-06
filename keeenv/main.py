#!/usr/bin/env python3
"""
Main entry point for keeenv - Populate environment variables from Keepass
"""

# Verbosity flags are parsed/configured inside core._create_argument_parser()/main.
# This CLI wrapper is responsible for exit codes.
import sys
from .core import main as keeenv_main
from .exceptions import ConfigError, KeePassError, ValidationError, SecurityError


def main() -> None:
    """Main entry point for keeenv."""
    try:
        keeenv_main()
    except (ConfigError, KeePassError, ValidationError, SecurityError):
        # Known failure modes: exit with 1 (single nonzero code policy)
        sys.exit(1)
    except Exception:
        # Unexpected failure: also exit with 1
        sys.exit(1)


if __name__ == "__main__":
    main()
