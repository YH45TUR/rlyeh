#!/usr/bin/env python3
"""
R'lyeh Honeypot - Web Honeypot Module
Simulates vulnerable web applications to attract and log attacks
"""

from flask import Flask, request, jsonify, render_template_string
import logging
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebHoneypot:
    """
    Web honeypot simulating vulnerable WordPress and API endpoints.
    Records all requests, payloads, and attack attempts.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8080,
                 log_dir: str = '/var/log/rlyeh'):
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.attacks: List[dict] = []
        self.app = Flask(__name__)
        
        # Disable Flask default logging
        self.app.logger.disabled = True
        log = logging.getLogger('werkzeug')
        log.disabled = True
        
        os.makedirs(log_dir, exist_ok=True)
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup fake vulnerable routes"""
        
        # Fake WordPress homepage
        @self.app.route('/')
        def wordpress_home():
            self._log_attack('wordpress_home', request)
            return render_template_string(self._get_wordpress_template())
        
        # Fake WordPress login
        @self.app.route('/wp-login.php')
        def wordpress_login():
            self._log_attack('wordpress_login', request)
            
            if request.method == 'POST':
                username = request.form.get('log', '')
                password = request.form.get('pwd', '')
                
                logger.warning(f"🎣 WordPress login attempt: {username}:{password}")
                
                # Always fail with realistic WordPress error
                return render_template_string(self._get_login_error_template())
            
            return render_template_string(self._get_login_template())
        
        # Fake WordPress admin
        @self.app.route('/wp-admin/')
        def wordpress_admin():
            self._log_attack('wordpress_admin_access', request)
            
            # Return fake "not logged in" page
            return """
            <!DOCTYPE html>
            <html><head><title>WordPress > Error</title></head>
            <body class="login wp-core-ui" style="text-align:center; padding-top:100px;">
            <p>You must log in to access the admin area.</p>
            <p><a href="/wp-login.php">Log in</a></p>
            </body></html>
            """, 403
        
        # Fake phpMyAdmin
        @self.app.route('/phpmyadmin/')
        @self.app.route('/phpMyAdmin/')
        @self.app.route('/pma/')
        def phpmyadmin():
            self._log_attack('phpmyadmin_access', request)
            return render_template_string(self._get_phpmyadmin_template())
        
        # Fake API admin endpoint (common IDOR vulnerability)
        @self.app.route('/api/admin')
        def api_admin():
            self._log_attack('api_admin_access', request)
            return jsonify({
                "status": "error",
                "message": "Unauthorized",
                "code": 401
            }), 401
        
        # Fake API users endpoint (IDOR test)
        @self.app.route('/api/users/<id>')
        def api_user(id):
            self._log_attack('api_user_access', request, extra={'user_id': id})
            
            # Simulate user data exposure (intentional fake vulnerability)
            fake_users = {
                '1': {'id': 1, 'username': 'admin', 'email': 'admin@company.com'},
                '2': {'id': 2, 'username': 'john', 'email': 'john@company.com'},
                '999': {'id': 999, 'username': 'backup_admin', 'email': 'backup@company.com', 'password_hash': '5f4dcc3b5aa765d61d8327deb882cf99'}
            }
            
            if id in fake_users:
                return jsonify(fake_users[id])
            
            return jsonify({"error": "User not found"}), 404
        
        # Fake API execute endpoint (RCE honeypot)
        @self.app.route('/api/execute', methods=['POST'])
        def api_execute():
            self._log_attack('api_rce_attempt', request)
            
            command = request.form.get('cmd') or request.json.get('cmd', '')
            
            logger.critical(f"⚠️ RCE attempt: {command}")
            
            # Simulate command execution (fake response)
            fake_response = f"$ {command}\n"
            
            if 'whoami' in command:
                fake_response += "www-data\n"
            elif 'id' in command:
                fake_response += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            elif 'ls' in command or 'dir' in command:
                fake_response += "config.php\n.htaccess\nwp-content\nwp-admin\n"
            elif 'cat' in command or 'type' in command:
                fake_response += "fake file content here\n"
            elif 'wget' in command or 'curl' in command:
                fake_response += "Connecting... downloaded payload.sh\n"
            else:
                fake_response += f"{command}: command not found\n"
            
            return jsonify({
                "status": "success",
                "output": fake_response,
                "execution_time": "0.023s"
            })
        
        # Fake vulnerable search (SQL Injection honeypot)
        @self.app.route('/search')
        def search():
            query = request.args.get('q', '')
            
            self._log_attack('search_sql_injection_test', request, extra={'query': query})
            
            # Simulate SQL injection detection
            sql_patterns = ["'", "--", ";", "union", "select", "drop", "insert", "delete"]
            
            if any(pattern in query.lower() for pattern in sql_patterns):
                logger.warning(f"🎯 Potential SQL Injection: {query}")
                
                # Fake SQL error (attractive to attackers)
                if "union" in query.lower() and "select" in query.lower():
                    return """
                    Error: You have an error in your SQL syntax; 
                    check the manual that corresponds to your MySQL server version 
                    for the right syntax to use near 'UNION SELECT' at line 1
                    """, 500
            
            return jsonify({
                "results": [],
                "query": query,
                "count": 0
            })
        
        # Catch-all for other paths
        @self.app.errorhandler(404)
        def not_found(e):
            self._log_attack('unknown_path', request, extra={'path': request.path})
            return """
            <!DOCTYPE html>
            <html><head><title>404 Not Found</title></head>
            <body><h1>Not Found</h1>
            <p>The requested URL was not found on this server.</p>
            </body></html>
            """, 404
    
    def _log_attack(self, attack_type: str, request, extra: dict = None):
        """Log an attack attempt"""
        attack = {
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'source_ip': request.remote_addr,
            'source_port': request.environ.get('REMOTE_PORT'),
            'method': request.method,
            'path': request.path,
            'query_string': request.query_string.decode('utf-8'),
            'headers': dict(request.headers),
            'user_agent': request.headers.get('User-Agent'),
            'body': request.get_data(as_text=True) if request.data else None,
        }
        
        if extra:
            attack.update(extra)
        
        self.attacks.append(attack)
        
        # Save to file
        self._save_attack(attack)
        
        logger.info(f"🕸️  Web attack: {attack_type} from {request.remote_addr} - {request.path}")
    
    def _save_attack(self, attack: dict):
        """Save attack to log file"""
        timestamp = datetime.now().strftime('%Y%m%d')
        log_file = os.path.join(self.log_dir, f'web_honeypot_{timestamp}.jsonl')
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')
    
    def _get_wordpress_template(self) -> str:
        """Return fake WordPress homepage HTML"""
        return """
        <!DOCTYPE html>
        <html lang="en-US">
        <head>
            <meta charset="UTF-8">
            <title>My Company Blog – Just another WordPress site</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                header { border-bottom: 2px solid #ccc; margin-bottom: 20px; }
                .post { margin-bottom: 30px; }
                .post h2 { color: #333; }
                footer { border-top: 2px solid #ccc; margin-top: 30px; padding-top: 10px; color: #666; }
            </style>
        </head>
        <body>
            <header>
                <h1>My Company Blog</h1>
                <p>Just another WordPress site</p>
                <nav>
                    <a href="/">Home</a> |
                    <a href="/wp-login.php">Login</a> |
                    <a href="/wp-admin/">Admin</a>
                </nav>
            </header>
            
            <article class="post">
                <h2><a href="#">Welcome to Our New Website</a></h2>
                <p class="meta">Posted on January 10, 2026 by admin</p>
                <p>Welcome to our new company blog. We'll be sharing updates about our 
                products and services here. Stay tuned for exciting news!</p>
                <p><a href="#">Read more →</a></p>
            </article>
            
            <article class="post">
                <h2><a href="#">Security Update Applied</a></h2>
                <p class="meta">Posted on January 5, 2026 by admin</p>
                <p>We've just updated our website with the latest security patches. 
                Your data is safe with us.</p>
            </article>
            
            <footer>
                <p>© 2026 My Company. Powered by WordPress.</p>
                <p><small>Version 5.8.2</small></p>
            </footer>
        </body>
        </html>
        """
    
    def _get_login_template(self) -> str:
        """Return fake WordPress login form"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Log In ‹ My Company Blog — WordPress</title>
            <style>
                body { background: #f0f0f1; font-family: sans-serif; }
                .login-form { background: #fff; max-width: 320px; margin: 100px auto; padding: 26px 24px 34px; }
                input { width: 100%; padding: 3px; margin: 5px 0; }
                button { background: #2271b1; color: white; border: none; padding: 10px; width: 100%; cursor: pointer; }
                .message { background: #fff; border-left: 4px solid #72aee6; padding: 12px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h1>My Company Blog</h1>
                <form method="post" action="/wp-login.php">
                    <p>
                        <label>Username or Email Address<br/>
                        <input type="text" name="log" id="user_login" />
                        </label>
                    </p>
                    <p>
                        <label>Password<br/>
                        <input type="password" name="pwd" id="user_pass" />
                        </label>
                    </p>
                    <p>
                        <button type="submit">Log In</button>
                    </p>
                </form>
                <p><a href="#">Lost your password?</a></p>
                <p>← <a href="/">Back to My Company Blog</a></p>
            </div>
        </body>
        </html>
        """
    
    def _get_login_error_template(self) -> str:
        """Return WordPress login error"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Log In ‹ My Company Blog — WordPress</title>
            <style>
                body { background: #f0f0f1; font-family: sans-serif; }
                .login-form { background: #fff; max-width: 320px; margin: 100px auto; padding: 26px 24px 34px; }
                input { width: 100%; padding: 3px; margin: 5px 0; }
                button { background: #2271b1; color: white; border: none; padding: 10px; width: 100%; cursor: pointer; }
                .error { background: #fff; border-left: 4px solid #d63638; padding: 12px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h1>My Company Blog</h1>
                
                <div class="error">
                    <strong>ERROR</strong>: The username or password you entered is incorrect. 
                    <a href="#">Lost your password?</a>
                </div>
                
                <form method="post" action="/wp-login.php">
                    <p>
                        <label>Username or Email Address<br/>
                        <input type="text" name="log" id="user_login" />
                        </label>
                    </p>
                    <p>
                        <label>Password<br/>
                        <input type="password" name="pwd" id="user_pass" />
                        </label>
                    </p>
                    <p>
                        <button type="submit">Log In</button>
                    </p>
                </form>
            </div>
        </body>
        </html>
        """
    
    def _get_phpmyadmin_template(self) -> str:
        """Return fake phpMyAdmin login"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>phpMyAdmin</title>
            <style>
                body { background: #f5f5f5; font-family: sans-serif; }
                .container { max-width: 400px; margin: 100px auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h1 { color: #666; }
                input { width: 95%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; }
                button { background: #f90; color: white; border: none; padding: 10px 20px; cursor: pointer; }
                .logo { text-align: center; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">
                    <h1>phpMyAdmin</h1>
                    <small>Version 4.9.7</small>
                </div>
                
                <form method="post">
                    <label>Username:</label><br/>
                    <input type="text" name="pma_username" /><br/>
                    
                    <label>Password:</label><br/>
                    <input type="password" name="pma_password" /><br/>
                    
                    <button type="submit">Go</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def start(self):
        """Start the web honeypot"""
        logger.info(f"🕸️  Web Honeypot starting on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
    
    def get_stats(self) -> dict:
        """Get statistics about attacks"""
        return {
            'total_attacks': len(self.attacks),
            'unique_ips': len(set(a['source_ip'] for a in self.attacks)),
            'attack_types': list(set(a['type'] for a in self.attacks))
        }


if __name__ == '__main__':
    honeypot = WebHoneypot()
    honeypot.start()
