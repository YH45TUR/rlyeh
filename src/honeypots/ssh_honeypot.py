#!/usr/bin/env python3
"""
R'lyeh Honeypot - SSH Honeypot Module
Based on Cowrie architecture principles but simplified for easy deployment
"""

import socket
import threading
import json
import time
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSHHoneypot:
    """
    SSH Honeypot that emulates a vulnerable SSH server.
    Records all connection attempts, credentials tried, and commands executed.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 2222, 
                 log_dir: str = '/var/log/rlyeh'):
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.sessions: Dict[str, dict] = {}
        self.active = False
        
        # Common credentials attackers try
        self.fake_accounts = {
            'root': ['password', 'admin', '123456', 'root', 'toor'],
            'admin': ['admin', 'password', '123456'],
            'user': ['user', 'password', '123456'],
            'test': ['test', 'password', '123456'],
        }
        
        os.makedirs(log_dir, exist_ok=True)
        
    def start(self):
        """Start the SSH honeypot server"""
        self.active = True
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        logger.info(f"🎭 SSH Honeypot listening on {self.host}:{self.port}")
        
        while self.active:
            try:
                client_sock, address = sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_sock: socket.socket, address: tuple):
        """Handle a single SSH connection attempt"""
        session_id = hashlib.md5(
            f"{address[0]}:{address[1]}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        client_ip = address[0]
        client_port = address[1]
        
        logger.info(f"🔌 New SSH connection from {client_ip}:{client_port} (Session: {session_id})")
        
        # Record session start
        session_data = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'source_ip': client_ip,
            'source_port': client_port,
            'protocol': 'SSH',
            'honeypot': 'rlyeh-ssh',
            'credentials_attempted': [],
            'commands_executed': [],
            'files_downloaded': [],
            'session_duration': 0,
            'success': False,
        }
        
        self.sessions[session_id] = session_data
        
        try:
            # Send SSH banner
            banner = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"
            client_sock.send(banner)
            
            # Receive client banner
            client_banner = client_sock.recv(1024)
            session_data['client_banner'] = client_banner.decode('utf-8', errors='ignore').strip()
            
            start_time = time.time()
            
            # Simulate authentication phase
            auth_success = self._simulate_auth(client_sock, session_data)
            
            if auth_success:
                session_data['success'] = True
                logger.info(f"✅ Successful auth in session {session_id}")
                
                # Simulate shell
                self._simulate_shell(client_sock, session_data)
            else:
                logger.info(f"❌ Failed auth in session {session_id}")
                
                # Send authentication failure
                fail_msg = b"Permission denied, please try again.\r\n"
                client_sock.send(fail_msg)
            
            session_data['session_duration'] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Error handling client {session_id}: {e}")
        finally:
            client_sock.close()
            self._save_session(session_data)
    
    def _simulate_auth(self, client_sock: socket.socket, session_data: dict) -> bool:
        """
        Simulate SSH authentication.
        Always fails first 2 attempts, succeeds on 3rd if common credentials.
        """
        attempts = 0
        max_attempts = 3
        
        # Welcome message
        welcome = b"\r\nWelcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)\r\n\r\n"
        client_sock.send(welcome)
        
        while attempts < max_attempts:
            # Request username
            user_prompt = b"login as: "
            client_sock.send(user_prompt)
            
            try:
                username_data = client_sock.recv(1024)
                username = username_data.decode('utf-8', errors='ignore').strip()
                
                if not username:
                    continue
                
                # Request password
                pass_prompt = f"{username}@192.168.1.100's password: ".encode()
                client_sock.send(pass_prompt)
                
                password_data = client_sock.recv(1024)
                password = password_data.decode('utf-8', errors='ignore').strip()
                
                # Record attempt
                session_data['credentials_attempted'].append({
                    'username': username,
                    'password': password,
                    'timestamp': datetime.now().isoformat(),
                    'attempt': attempts + 1,
                })
                
                logger.info(f"🔐 Auth attempt {attempts + 1}: {username}:{password}")
                
                # Check if common credentials
                if (username in self.fake_accounts and 
                    password in self.fake_accounts.get(username, [])):
                    
                    if attempts == 2:  # Succeed on 3rd attempt with correct creds
                        return True
                
                # Send failure message
                if attempts < max_attempts - 1:
                    fail_msg = b"\r\nPermission denied, please try again.\r\n"
                    client_sock.send(fail_msg)
                
                attempts += 1
                
            except Exception as e:
                logger.error(f"Auth error: {e}")
                return False
        
        return False
    
    def _simulate_shell(self, client_sock: socket.socket, session_data: dict):
        """Simulate a shell for authenticated attackers"""
        # Send motd
        motd = b"""\r\nWelcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 10 12:34:56 UTC 2026

  System load:  0.08              Processes:           89
  Usage of /:   45.2% of 9.78GB   Users logged in:     1
  Memory usage: 23%               IP address for eth0: 192.168.1.100
  Swap usage:   0%

Last login: Mon Jan 10 10:00:00 2026 from 10.0.0.5
\r\n"""
        client_sock.send(motd)
        
        # Fake prompt
        prompt = b"root@web-server:~# "
        
        while True:
            client_sock.send(prompt)
            
            try:
                cmd_data = client_sock.recv(4096)
                if not cmd_data:
                    break
                
                command = cmd_data.decode('utf-8', errors='ignore').strip()
                
                if not command:
                    continue
                
                # Record command
                session_data['commands_executed'].append({
                    'command': command,
                    'timestamp': datetime.now().isoformat(),
                })
                
                logger.info(f"💻 Command executed: {command}")
                
                # Simulate command response
                response = self._generate_command_response(command)
                client_sock.send(response.encode())
                
                if command.lower() in ['exit', 'logout', 'quit']:
                    break
                    
            except Exception as e:
                logger.error(f"Shell error: {e}")
                break
    
    def _generate_command_response(self, command: str) -> str:
        """Generate fake responses to common commands"""
        cmd_lower = command.lower()
        
        responses = {
            'whoami': 'root\r\n',
            'id': 'uid=0(root) gid=0(root) groups=0(root)\r\n',
            'pwd': '/root\r\n',
            'ls': 'Desktop  Documents  Downloads  Music  Pictures  Videos\r\n',
            'ls -la': """total 32
drwx------  5 root root 4096 Jan 10 12:00 .
drwxr-xr-x 18 root root 4096 Jan 10 11:00 ..
-rw-------  1 root root  220 Jan 10 10:00 .bash_logout
-rw-------  1 root root 3771 Jan 10 10:00 .bashrc
drwx------  3 root root 4096 Jan 10 11:00 .cache
drwx------  3 root root 4096 Jan 10 11:00 .config
-rw-------  1 root root  807 Jan 10 10:00 .profile\r\n""",
            'uname -a': 'Linux web-server 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\r\n',
            'cat /etc/passwd': """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false\r\n""",
            'cat /etc/shadow': 'root:$6$xyz123abc:18295:0:99999:7:::\r\n',
            'ifconfig': """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1234:5678:abcd:ef00  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\r\n""",
            'ps aux': """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.3  21532  7640 ?        Ss   Jan10   0:01 /sbin/init
root       500  0.0  0.2  21340  5800 ?        Ss   Jan10   0:00 sshd: root@pts/0
root       501  0.0  0.1   4628  1800 pts/0    S+   12:00   0:00 -bash\r\n""",
            'netstat -tulpn': """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      500/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      800/apache2
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      900/mysqld\r\n""",
        }
        
        # Check for wget/curl (malware download attempt)
        if 'wget' in cmd_lower or 'curl' in cmd_lower:
            return f"Connecting to evil.com|1.2.3.4|:80... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 12345 (12K) [application/octet-stream]\r\nSaving to: 'malware.sh'\r\n\r\nmalware.sh 100%[=======>] 12.06K --.-KB/s    in 0.1s\r\n\r\n2026-01-10 12:34:56 (125 KB/s) - 'malware.sh' saved [12345/12345]\r\n"
        
        return responses.get(cmd_lower, f"-bash: {command}: command not found\r\n")
    
    def _save_session(self, session_data: dict):
        """Save session data to log file"""
        timestamp = datetime.now().strftime('%Y%m%d')
        log_file = os.path.join(self.log_dir, f'ssh_honeypot_{timestamp}.jsonl')
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(session_data) + '\n')
        
        logger.info(f"💾 Session saved: {session_data['session_id']}")
    
    def stop(self):
        """Stop the honeypot"""
        self.active = False
        logger.info("🛑 SSH Honeypot stopped")


if __name__ == '__main__':
    honeypot = SSHHoneypot()
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()
