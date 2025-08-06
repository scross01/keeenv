"""
keeenv - Populate environment variables from Keepass

A command line tool similar in principle to dotenv to populate environment
variables from a local configuration file, but works with an encrypted
Keepass database to dynamically fetch sensitive data rather than manually
placing passwords and api keys in plain text on the local file system.
"""

__version__ = "0.1.0"
__author__ = "Stephen Cross"
__email__ = "stephen@example.com"

from .core import main

__all__ = ["main"]
