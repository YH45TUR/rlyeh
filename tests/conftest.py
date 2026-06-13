"""
Shared pytest fixtures for R'lyeh honeypot tests.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.honeypots.web_honeypot import WebHoneypot
from src.honeypots.ssh_honeypot import SSHHoneypot


@pytest.fixture
def web_honeypot(tmp_path):
    """WebHoneypot instance writing logs to a temporary directory."""
    hp = WebHoneypot(log_dir=str(tmp_path))
    hp.app.config["TESTING"] = True
    return hp


@pytest.fixture
def web_client(web_honeypot):
    """Flask test client for the web honeypot."""
    with web_honeypot.app.test_client() as client:
        yield client


@pytest.fixture
def ssh_honeypot(tmp_path):
    """SSHHoneypot instance writing logs to a temporary directory."""
    return SSHHoneypot(log_dir=str(tmp_path))
