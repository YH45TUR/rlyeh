"""
R'lyeh Honeypot – honeypots package.

Exports:
    SSHHoneypot  – TCP-level SSH emulation honeypot
    WebHoneypot  – Flask-based web application honeypot
"""

from .ssh_honeypot import SSHHoneypot
from .web_honeypot import WebHoneypot

__all__ = ["SSHHoneypot", "WebHoneypot"]
__version__ = "1.1.0"
