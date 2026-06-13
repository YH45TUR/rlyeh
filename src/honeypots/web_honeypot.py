#!/usr/bin/env python3
"""
R'lyeh Honeypot – Web Honeypot Module
Simulates vulnerable web applications to attract and log attacks.

Changes vs original:
- BUG FIX: /wp-login.php now declares methods=['GET','POST'] so POSTs
  are accepted (was returning 405 Method Not Allowed).
- BUG FIX: request.json raises 415 in Flask>=2.3 when Content-Type is
  not application/json; using get_json(silent=True) returns None safely.
- MEMORY FIX: self.attacks is capped at MAX_ATTACKS entries to prevent
  unbounded memory growth in long-running deployments.
- /api/execute now reads both JSON body and form data safely.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Maximum attack records kept in memory.  Oldest entries are discarded first.
MAX_ATTACKS = int(os.getenv("RLYEH_WEB_MAX_ATTACKS", "1000"))


class WebHoneypot:
    """
    Web honeypot simulating a vulnerable WordPress installation and API endpoints.

    Logs every request to *log_dir* as newline-delimited JSON and keeps the
    last :data:`MAX_ATTACKS` entries in memory for the :meth:`get_stats` API.

    Args:
        host: Bind address. Default ``'0.0.0.0'``.
        port: Listen port. Default ``8080``.
        log_dir: Directory for daily JSONL attack logs.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        log_dir: str = "/var/log/rlyeh",
    ) -> None:
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.attacks: List[dict] = []
        self.app = Flask(__name__)

        # Silence Flask / Werkzeug default request logs (we log ourselves).
        self.app.logger.disabled = True
        logging.getLogger("werkzeug").disabled = True

        os.makedirs(log_dir, exist_ok=True)
        self._setup_routes()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the web honeypot (blocking)."""
        logger.info("🕸️  Web Honeypot starting on %s:%d", self.host, self.port)
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)

    def get_stats(self) -> dict:
        """Return aggregate statistics about logged attacks."""
        return {
            "total_attacks": len(self.attacks),
            "unique_ips": len({a["source_ip"] for a in self.attacks}),
            "attack_types": sorted({a["type"] for a in self.attacks}),
        }

    # ------------------------------------------------------------------
    # Route setup
    # ------------------------------------------------------------------

    def _setup_routes(self) -> None:
        """Register all fake vulnerable routes on self.app."""

        # ---- WordPress homepage ------------------------------------------
        @self.app.route("/")
        def wordpress_home():
            self._log_attack("wordpress_home", request)
            return render_template_string(self._get_wordpress_template())

        # ---- WordPress login ---------------------------------------------
        # FIX: added methods=['GET', 'POST'] – without this Flask only allows
        # GET, so automated brute-force POST requests were returning 405.
        @self.app.route("/wp-login.php", methods=["GET", "POST"])
        def wordpress_login():
            self._log_attack("wordpress_login", request)

            if request.method == "POST":
                username = request.form.get("log", "")
                password = request.form.get("pwd", "")  # noqa: F841 (logged via attack)
                logger.warning("🎣 WordPress login attempt: %s:***", username)
                return render_template_string(self._get_login_error_template())

            return render_template_string(self._get_login_template())

        # ---- WordPress admin ---------------------------------------------
        @self.app.route("/wp-admin/")
        def wordpress_admin():
            self._log_attack("wordpress_admin_access", request)
            return (
                """<!DOCTYPE html>
<html><head><title>WordPress › Error</title></head>
<body style="text-align:center;padding-top:100px;">
<p>You must log in to access the admin area.</p>
<p><a href="/wp-login.php">Log in</a></p>
</body></html>""",
                403,
            )

        # ---- phpMyAdmin --------------------------------------------------
        @self.app.route("/phpmyadmin/")
        @self.app.route("/phpMyAdmin/")
        @self.app.route("/pma/")
        def phpmyadmin():
            self._log_attack("phpmyadmin_access", request)
            return render_template_string(self._get_phpmyadmin_template())

        # ---- Fake API admin (common IDOR target) -------------------------
        @self.app.route("/api/admin")
        def api_admin():
            self._log_attack("api_admin_access", request)
            return jsonify({"status": "error", "message": "Unauthorized", "code": 401}), 401

        # ---- Fake users endpoint (IDOR honeypot) -------------------------
        @self.app.route("/api/users/<user_id>")
        def api_user(user_id: str):
            self._log_attack("api_user_access", request, extra={"user_id": user_id})
            fake_users: Dict[str, dict] = {
                "1": {"id": 1, "username": "admin", "email": "admin@company.com"},
                "2": {"id": 2, "username": "john", "email": "john@company.com"},
                "999": {
                    "id": 999,
                    "username": "backup_admin",
                    "email": "backup@company.com",
                    # Fake MD5 of "password" – intentionally exposed as a lure.
                    "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                },
            }
            if user_id in fake_users:
                return jsonify(fake_users[user_id])
            return jsonify({"error": "User not found"}), 404

        # ---- RCE honeypot ------------------------------------------------
        @self.app.route("/api/execute", methods=["POST"])
        def api_execute():
            self._log_attack("api_rce_attempt", request)

            # FIX: request.json raises 415 in Flask>=2.3 when Content-Type is
            # not application/json.  get_json(silent=True) returns None safely.
            command: str = request.form.get("cmd") or (
                (request.get_json(silent=True) or {}).get("cmd", "")
            )

            logger.critical("⚠️  RCE attempt: %s", command)

            fake_output = f"$ {command}\n"
            cmd_lower = command.lower()
            if "whoami" in cmd_lower:
                fake_output += "www-data\n"
            elif "id" in cmd_lower:
                fake_output += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            elif "ls" in cmd_lower or "dir" in cmd_lower:
                fake_output += "config.php\n.htaccess\nwp-content\nwp-admin\n"
            elif "cat" in cmd_lower or "type" in cmd_lower:
                fake_output += "fake file content here\n"
            elif "wget" in cmd_lower or "curl" in cmd_lower:
                fake_output += "Connecting... downloaded payload.sh\n"
            else:
                fake_output += f"{command}: command not found\n"

            return jsonify(
                {"status": "success", "output": fake_output, "execution_time": "0.023s"}
            )

        # ---- SQL Injection honeypot --------------------------------------
        @self.app.route("/search")
        def search():
            query = request.args.get("q", "")
            self._log_attack(
                "search_sqli_test", request, extra={"query": query}
            )

            sql_patterns = ["'", "--", ";", "union", "select", "drop", "insert", "delete"]
            if any(p in query.lower() for p in sql_patterns):
                logger.warning("🎯 Potential SQL Injection: %.200s", query)
                if "union" in query.lower() and "select" in query.lower():
                    return (
                        "Error: You have an error in your SQL syntax; "
                        "check the manual that corresponds to your MySQL server "
                        "version for the right syntax to use near 'UNION SELECT' at line 1",
                        500,
                    )

            return jsonify({"results": [], "query": query, "count": 0})

        # ---- Catch-all 404 -----------------------------------------------
        @self.app.errorhandler(404)
        def not_found(exc):  # noqa: F841
            self._log_attack("unknown_path", request, extra={"path": request.path})
            return (
                "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                "<body><h1>Not Found</h1>"
                "<p>The requested URL was not found on this server.</p>"
                "</body></html>",
                404,
            )

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_attack(
        self, attack_type: str, req, extra: Optional[dict] = None
    ) -> None:
        """Record *attack_type* from *req* to memory and to disk."""
        attack: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": attack_type,
            "source_ip": req.remote_addr,
            "source_port": req.environ.get("REMOTE_PORT"),
            "method": req.method,
            "path": req.path,
            "query_string": req.query_string.decode("utf-8", errors="replace"),
            "headers": dict(req.headers),
            "user_agent": req.headers.get("User-Agent"),
            "body": req.get_data(as_text=True) or None,
        }
        if extra:
            attack.update(extra)

        # FIX: cap in-memory list to prevent unbounded growth.
        self.attacks.append(attack)
        if len(self.attacks) > MAX_ATTACKS:
            self.attacks = self.attacks[-MAX_ATTACKS:]

        self._save_attack(attack)
        logger.info(
            "🕸️  Web attack: %s from %s – %s",
            attack_type,
            req.remote_addr,
            req.path,
        )

    def _save_attack(self, attack: dict) -> None:
        """Append *attack* to the daily JSONL log file."""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_file = os.path.join(self.log_dir, f"web_honeypot_{date_str}.jsonl")
        try:
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(attack) + "\n")
        except OSError as exc:
            logger.error("Failed to write attack log: %s", exc)

    # ------------------------------------------------------------------
    # HTML templates
    # ------------------------------------------------------------------

    @staticmethod
    def _get_wordpress_template() -> str:
        return """<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="UTF-8">
  <title>My Company Blog – Just another WordPress site</title>
  <style>
    body{font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px}
    header{border-bottom:2px solid #ccc;margin-bottom:20px}
    footer{border-top:2px solid #ccc;margin-top:30px;padding-top:10px;color:#666}
  </style>
</head>
<body>
  <header>
    <h1>My Company Blog</h1>
    <p>Just another WordPress site</p>
    <nav>
      <a href="/">Home</a> | <a href="/wp-login.php">Login</a> | <a href="/wp-admin/">Admin</a>
    </nav>
  </header>
  <article>
    <h2>Welcome to Our New Website</h2>
    <p>Posted on January 10, 2026 by admin</p>
    <p>Welcome to our new company blog. Stay tuned!</p>
  </article>
  <article>
    <h2>Security Update Applied</h2>
    <p>Posted on January 5, 2026 by admin</p>
    <p>We've just updated our website with the latest security patches.</p>
  </article>
  <footer>
    <p>© 2026 My Company. Powered by WordPress.</p>
    <p><small>Version 5.8.2</small></p>
  </footer>
</body>
</html>"""

    @staticmethod
    def _get_login_template() -> str:
        return """<!DOCTYPE html>
<html>
<head>
  <title>Log In ‹ My Company Blog — WordPress</title>
  <style>
    body{background:#f0f0f1;font-family:sans-serif}
    .box{background:#fff;max-width:320px;margin:100px auto;padding:26px 24px 34px}
    input{width:100%;padding:3px;margin:5px 0}
    button{background:#2271b1;color:white;border:none;padding:10px;width:100%;cursor:pointer}
  </style>
</head>
<body>
  <div class="box">
    <h1>My Company Blog</h1>
    <form method="post" action="/wp-login.php">
      <p><label>Username or Email Address<br/><input type="text" name="log"/></label></p>
      <p><label>Password<br/><input type="password" name="pwd"/></label></p>
      <p><button type="submit">Log In</button></p>
    </form>
    <p><a href="#">Lost your password?</a></p>
    <p>← <a href="/">Back to My Company Blog</a></p>
  </div>
</body>
</html>"""

    @staticmethod
    def _get_login_error_template() -> str:
        return """<!DOCTYPE html>
<html>
<head>
  <title>Log In ‹ My Company Blog — WordPress</title>
  <style>
    body{background:#f0f0f1;font-family:sans-serif}
    .box{background:#fff;max-width:320px;margin:100px auto;padding:26px 24px 34px}
    input{width:100%;padding:3px;margin:5px 0}
    button{background:#2271b1;color:white;border:none;padding:10px;width:100%;cursor:pointer}
    .error{background:#fff;border-left:4px solid #d63638;padding:12px;margin-bottom:20px}
  </style>
</head>
<body>
  <div class="box">
    <h1>My Company Blog</h1>
    <div class="error">
      <strong>ERROR</strong>: The username or password you entered is incorrect.
      <a href="#">Lost your password?</a>
    </div>
    <form method="post" action="/wp-login.php">
      <p><label>Username or Email Address<br/><input type="text" name="log"/></label></p>
      <p><label>Password<br/><input type="password" name="pwd"/></label></p>
      <p><button type="submit">Log In</button></p>
    </form>
  </div>
</body>
</html>"""

    @staticmethod
    def _get_phpmyadmin_template() -> str:
        return """<!DOCTYPE html>
<html>
<head>
  <title>phpMyAdmin</title>
  <style>
    body{background:#f5f5f5;font-family:sans-serif}
    .box{max-width:400px;margin:100px auto;background:white;padding:20px;
         box-shadow:0 0 10px rgba(0,0,0,.1)}
    input{width:95%;padding:10px;margin:10px 0;border:1px solid #ccc}
    button{background:#f90;color:white;border:none;padding:10px 20px;cursor:pointer}
  </style>
</head>
<body>
  <div class="box">
    <h1 style="text-align:center">phpMyAdmin</h1>
    <small style="display:block;text-align:center">Version 4.9.7</small>
    <form method="post">
      <label>Username:</label><br/>
      <input type="text" name="pma_username"/><br/>
      <label>Password:</label><br/>
      <input type="password" name="pma_password"/><br/>
      <button type="submit">Go</button>
    </form>
  </div>
</body>
</html>"""


if __name__ == "__main__":
    honeypot = WebHoneypot()
    honeypot.start()
