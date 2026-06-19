import os
import re
import subprocess
from collections import defaultdict
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Path to the SSH log file. 
# Ubuntu/Debian uses '/var/log/auth.log'. RHEL/CentOS uses '/var/log/secure'.
LOG_FILE_PATH = "/var/log/auth.log"
MOCK_LOG_PATH = "mock_auth.log"

# Thresholds for Brute Force Detection
FAILED_ATTEMPT_THRESHOLD = 5

def get_log_file():
    """Returns the real log path if accessible, otherwise falls back to a mock file."""
    if os.path.exists(LOG_FILE_PATH) and os.access(LOG_FILE_PATH, os.R_OK):
        return LOG_FILE_PATH
    
    # Create a mock file for local testing if the system log isn't accessible
    if not os.path.exists(MOCK_LOG_PATH):
        with open(MOCK_LOG_PATH, "w") as f:
            f.write("Jun 16 12:01:05 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2\n")
            f.write("Jun 16 12:01:08 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54322 ssh2\n")
            f.write("Jun 16 12:01:12 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54323 ssh2\n")
            f.write("Jun 16 12:01:15 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54324 ssh2\n")
            f.write("Jun 16 12:01:19 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54325 ssh2\n")
            f.write("Jun 16 12:01:22 server sshd[1111]: Failed password for invalid user admin from 192.168.1.100 port 54326 ssh2\n")
            f.write("Jun 16 12:05:00 server sshd[2222]: Accepted password for ubuntu from 192.168.1.50 port 54330 ssh2\n")
    return MOCK_LOG_PATH

def parse_ssh_logs():
    log_file = get_log_file()
    login_events = []
    failed_counts = defaultdict(int)
    brute_force_alerts = []

    # Regex patterns for SSH log analysis
    failed_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
    success_pattern = re.compile(r"Accepted password for (\S+) from (\S+) port")

    try:
        with open(log_file, "r") as f:
            # Read lines (reversing to get the latest events first)
            lines = f.readlines()
            
            for line in lines:
                time_str = " ".join(line.split()[:3]) # Extracts 'Month Day HH:MM:SS'
                
                # Check for Failed Attempts
                failed_match = failed_pattern.search(line)
                if failed_match:
                    username, ip = failed_match.groups()
                    login_events.append({
                        "time": time_str,
                        "username": username,
                        "ip": ip,
                        "status": "Failed"
                    })
                    failed_counts[ip] += 1
                    
                    # If failures exceed threshold, trigger alert metrics
                    if failed_counts[ip] >= FAILED_ATTEMPT_THRESHOLD:
                        alert = {
                            "ip": ip,
                            "username": username,
                            "count": failed_counts[ip],
                            "message": f"CRITICAL: Brute force detected on user '{username}'!"
                        }
                        if alert not in brute_force_alerts:
                            brute_force_alerts.append(alert)
                    continue

                # Check for Successful Attempts
                success_match = success_pattern.search(line)
                if success_match:
                    username, ip = success_match.groups()
                    login_events.append({
                        "time": time_str,
                        "username": username,
                        "ip": ip,
                        "status": "Success"
                    })
                    
    except Exception as e:
        print(f"Error reading log file: {e}")

    # Return the 50 most recent events
    return login_events[::-1][:50], brute_force_alerts

def get_active_users():
    """Fetches currently logged-in active shell users using the system 'who' command."""
    try:
        # Executes 'who' command to get real-time active terminal sessions
        output = subprocess.check_output("who", shell=True).decode()
        active_users = set()
        for line in output.splitlines():
            if line.strip():
                active_users.add(line.split()[0])
        return list(active_users)
    except Exception:
        # Fallback if command fails or runs on non-Linux testing environment
        return ["ubuntu"] 

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/logs")
def api_logs():
    logins, alerts = parse_ssh_logs()
    active = get_active_users()
    return jsonify({
        "logins": logins,
        "alerts": alerts,
        "active_users": active
    })

if __name__ == "__main__":
    # Note: Running on port 5000. Might require sudo to read /var/log/auth.log
    app.run(debug=True, host="0.0.0.0", port=5000)
