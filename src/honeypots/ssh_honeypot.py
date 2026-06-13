#!/usr/bin/env python3
"""
R'lyeh Honeypot – SSH Honeypot Module
Based on Cowrie architecture principles but simplified for easy deployment.

Changes vs original:
- Session IDs now use uuid4 (MD5 was collision-prone and non-random).
- Max-connections semaphore (50) prevents thread exhaustion DoS.
- Server socket stored on self so stop() closes it cleanly.
- Auth logic comment clarified; incorrect-creds path always sends denial.
"""

import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Maximum simultaneous client threads.  Tune via env var RLYEH_SSH_MAX_CONN.
_DEFAULT_MAX_CONN = int(os.getenv("RLYEH_SSH_MAX_CONN", "50"))


class SSHHoneypot:
    """
    SSH Honeypot that emulates a vulnerable SSH server.

    Accepts TCP connections on *port*, sends a realistic SSH banner, then
    runs a simple text-based fake authentication + interactive shell.
    All sessions are persisted to *log_dir* as newline-delimited JSON.

    Note: This is a *banner/protocol-stub* honeypot.  It does NOT implement
    the full SSH binary protocol (no Paramiko), so automated scanners that
    complete the key-exchange will close the connection immediately.  That is
    intentional: it still captures source IPs, timing, and basic banner grabs
    while avoiding the complexity and resource cost of a full SSH stack.

    Args:
        host: Bind address. Default ``'0.0.0.0'``.
        port: Listen port. Default ``2222``.
        log_dir: Directory where JSONL session logs are written.
        max_connections: Max simultaneous client threads.
    """

    # Credentials that the honeypot will "accept" (on the 3rd attempt only).
    FAKE_ACCOUNTS: Dict[str, list] = {
        "root": ["password", "admin", "123456", "root", "toor"],
        "admin": ["admin", "password", "123456"],
        "user": ["user", "password", "123456"],
        "test": ["test", "password", "123456"],
    }

    # Fake shell responses keyed by command string.
    COMMAND_RESPONSES: Dict[str, str] = {
        "whoami": "root\r\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
        "pwd": "/root\r\n",
        "ls": "Desktop  Documents  Downloads  Music  Pictures  Videos\r\n",
        "ls -la": (
            "total 32\r\n"
            "drwx------  5 root root 4096 Jan 10 12:00 .\r\n"
            "drwxr-xr-x 18 root root 4096 Jan 10 11:00 ..\r\n"
            "-rw-------  1 root root  220 Jan 10 10:00 .bash_logout\r\n"
            "-rw-------  1 root root 3771 Jan 10 10:00 .bashrc\r\n"
            "-rw-------  1 root root  807 Jan 10 10:00 .profile\r\n"
        ),
        "uname -a": (
            "Linux web-server 4.15.0-123-generic "
            "#126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 GNU/Linux\r\n"
        ),
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\r\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
            "mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false\r\n"
        ),
        "cat /etc/shadow": "root:$6$xyz123abc:18295:0:99999:7:::\r\n",
        "ifconfig": (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
            "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\r\n"
        ),
        "ps aux": (
            "USER       PID %CPU %MEM COMMAND\r\n"
            "root         1  0.0  0.3 /sbin/init\r\n"
            "root       500  0.0  0.2 sshd: root@pts/0\r\n"
            "root       501  0.0  0.1 -bash\r\n"
        ),
        "netstat -tulpn": (
            "Proto Local Address  State    PID/Program\r\n"
            "tcp   0.0.0.0:22    LISTEN   500/sshd\r\n"
            "tcp   0.0.0.0:80    LISTEN   800/apache2\r\n"
            "tcp   0.0.0.0:3306  LISTEN   900/mysqld\r\n"
        ),
    }

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        log_dir: str = "/var/log/rlyeh",
        max_connections: int = _DEFAULT_MAX_CONN,
    ) -> None:
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.sessions: Dict[str, dict] = {}
        self.active = False
        self._server_sock: Optional[socket.socket] = None
        self._semaphore = threading.Semaphore(max_connections)

        os.makedirs(log_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the SSH honeypot server (blocking)."""
        self.active = True

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)

        logger.info("\U0001f3ad SSH Honeypot listening on %s:%d", self.host, self.port)

        while self.active:
            try:
                client_sock, address = self._server_sock.accept()
            except OSError:
                # Socket was closed by stop()
                break
            except Exception as exc:
                logger.error("Error accepting connection: %s", exc)
                continue

            # Gate concurrent threads to avoid resource exhaustion.
            if not self._semaphore.acquire(blocking=False):
                logger.warning("Max connections reached, dropping %s", address[0])
                client_sock.close()
                continue

            t = threading.Thread(
                target=self._handle_client_guarded,
                args=(client_sock, address),
                daemon=True,
            )
            t.start()

    def stop(self) -> None:
        """Stop the honeypot and close the server socket."""
        self.active = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        logger.info("\U0001f6d1 SSH Honeypot stopped")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_client_guarded(
        self, client_sock: socket.socket, address: tuple
    ) -> None:
        """Wrapper that always releases the semaphore after handling."""
        try:
            self._handle_client(client_sock, address)
        finally:
            self._semaphore.release()

    def _handle_client(self, client_sock: socket.socket, address: tuple) -> None:
        """Handle a single SSH connection attempt."""
        # FIX: use uuid4 instead of MD5 for non-predictable session IDs.
        session_id = uuid.uuid4().hex[:12]
        client_ip, client_port = address[0], address[1]

        logger.info(
            "\U0001f50c New SSH connection from %s:%d (Session: %s)",
            client_ip,
            client_port,
            session_id,
        )

        session_data: dict = {
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "SSH",
            "honeypot": "rlyeh-ssh",
            "credentials_attempted": [],
            "commands_executed": [],
            "files_downloaded": [],
            "session_duration": 0.0,
            "success": False,
        }
        self.sessions[session_id] = session_data

        try:
            client_sock.send(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")

            raw_banner = client_sock.recv(1024)
            session_data["client_banner"] = raw_banner.decode("utf-8", errors="ignore").strip()

            start_time = time.time()

            if self._simulate_auth(client_sock, session_data):
                session_data["success"] = True
                logger.info("\u2705 Successful auth in session %s", session_id)
                self._simulate_shell(client_sock, session_data)
            else:
                logger.info("\u274c Failed auth in session %s", session_id)
                client_sock.send(b"Permission denied (publickey,password).\r\n")

            session_data["session_duration"] = time.time() - start_time

        except Exception as exc:
            logger.error("Error handling client %s: %s", session_id, exc)
        finally:
            client_sock.close()
            self._save_session(session_data)

    def _simulate_auth(
        self, client_sock: socket.socket, session_data: dict
    ) -> bool:
        """
        Simulate SSH password authentication.

        Strategy: always reject the first two attempts regardless of
        credentials (mirrors real brute-force behaviour); accept on the
        third attempt only if the credentials match a fake account.
        This maximises the number of credential pairs captured.
        """
        max_attempts = 3
        welcome = (
            b"\r\nWelcome to Ubuntu 18.04.5 LTS "
            b"(GNU/Linux 4.15.0-123-generic x86_64)\r\n\r\n"
        )
        client_sock.send(welcome)

        for attempt in range(max_attempts):
            client_sock.send(b"login as: ")
            try:
                username = (
                    client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                )
                if not username:
                    continue

                client_sock.send(
                    f"{username}@192.168.1.100's password: ".encode()
                )
                password = (
                    client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                )
            except Exception as exc:
                logger.error("Auth recv error: %s", exc)
                return False

            session_data["credentials_attempted"].append(
                {
                    "username": username,
                    "password": password,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "attempt": attempt + 1,
                }
            )
            logger.info("\U0001f510 Auth attempt %d: %s:***", attempt + 1, username)

            creds_valid = username in self.FAKE_ACCOUNTS and password in self.FAKE_ACCOUNTS.get(
                username, []
            )

            # FIX: always send denial on non-final attempts; send it on final
            # wrong-creds attempt too (original left that path silent).
            if attempt < max_attempts - 1:
                client_sock.send(b"\r\nPermission denied, please try again.\r\n")
            elif creds_valid:
                return True
            else:
                client_sock.send(b"\r\nPermission denied, please try again.\r\n")

        return False

    def _simulate_shell(
        self, client_sock: socket.socket, session_data: dict
    ) -> None:
        """Simulate an interactive shell for authenticated attackers."""
        motd = (
            b"\r\nWelcome to Ubuntu 18.04.5 LTS"
            b" (GNU/Linux 4.15.0-123-generic x86_64)\r\n"
            b"\r\nLast login: Mon Jan 10 10:00:00 2026 from 10.0.0.5\r\n\r\n"
        )
        client_sock.send(motd)
        prompt = b"root@web-server:~# "

        while True:
            client_sock.send(prompt)
            try:
                raw = client_sock.recv(4096)
                if not raw:
                    break
                command = raw.decode("utf-8", errors="ignore").strip()
                if not command:
                    continue
            except Exception as exc:
                logger.error("Shell recv error: %s", exc)
                break

            session_data["commands_executed"].append(
                {
                    "command": command,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            logger.info("\U0001f4bb Command executed: %s", command)

            response = self._generate_command_response(command)
            client_sock.send(response.encode())

            if command.lower() in ("exit", "logout", "quit"):
                break

    def _generate_command_response(self, command: str) -> str:
        """Return a fake shell response for *command*."""
        cmd_lower = command.lower().strip()

        # wget / curl -> simulate malware download and record it
        if "wget" in cmd_lower or "curl" in cmd_lower:
            parts = command.split()
            url = next((p for p in parts if p.startswith("http")), "unknown")
            logger.warning("\u2b07\ufe0f  Download attempt: %s", url)
            return (
                f"Connecting to {url}... connected.\r\n"
                "HTTP request sent, awaiting response... 200 OK\r\n"
                "Saving to: 'payload.sh'\r\n\r\n"
                "payload.sh 100%[====>] 12.06K --.-KB/s in 0.1s\r\n\r\n"
            )

        return self.COMMAND_RESPONSES.get(
            cmd_lower, f"-bash: {command}: command not found\r\n"
        )

    def _save_session(self, session_data: dict) -> None:
        """Append *session_data* to the daily JSONL log file."""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_file = os.path.join(self.log_dir, f"ssh_honeypot_{date_str}.jsonl")
        try:
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(session_data) + "\n")
            logger.info("\U0001f4be Session saved: %s", session_data["session_id"])
        except OSError as exc:
            logger.error("Failed to save session %s: %s", session_data["session_id"], exc)


if __name__ == "__main__":
    honeypot = SSHHoneypot()
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()
