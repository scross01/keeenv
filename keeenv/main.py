#!/usr/bin/env python3
"""
Main entry point for keeenv - Populate environment variables from Keepass
"""

from .core import main as keeenv_main


def main():
    """Main entry point for keeenv."""
    keeenv_main()


if __name__ == "__main__":
    main()
