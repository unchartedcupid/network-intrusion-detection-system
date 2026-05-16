# alerts.py
# This module handles displaying and saving alerts
# When an attack is detected, this module shows and records it

import datetime
import json
import os

# Alert severity colors for terminal display
COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "RESET":    "\033[0m",   # Reset
    "BOLD":     "\033[1m",   # Bold
    "CYAN":     "\033[96m",  # Cyan
}

# Alert log file path
LOG_FILE = os.path.join(
    os.path.dirname(__file__), "..", "logs", "alerts.log"
)

def format_alert_terminal(alert):
    """Format an alert for display in the terminal with colors"""
    severity = alert["severity"]
    color = COLORS.get(severity, COLORS["RESET"])
    reset = COLORS["RESET"]
    bold = COLORS["BOLD"]
    cyan = COLORS["CYAN"]

    line = "─" * 60
    output = f"""
{color}{bold}{'!'*3} ALERT DETECTED {'!'*3}{reset}
{line}
{bold}ID        :{reset} {alert['id']}
{bold}Time      :{reset} {cyan}{alert['timestamp']}{reset}
{color}{bold}Type      :{reset} {color}{alert['attack_type']}{reset}
{color}{bold}Severity  :{reset} {color}{severity}{reset}
{bold}Source IP :{reset} {alert['src_ip']}
{bold}Target IP :{reset} {alert['dst_ip']}
{bold}Details   :{reset} {alert['details']}
{line}
"""
    return output

def display_alert(alert):
    """Print alert to terminal"""
    print(format_alert_terminal(alert))

def save_alert_to_log(alert):
    """
    Save alert to log file for record keeping
    Each alert is saved as a JSON line in the log file
    """
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            # Save as JSON so we can parse it later
            log_entry = {k: v for k, v in alert.items() if k != "raw"}
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[-] Could not save alert to log: {e}")

def process_alert(alert):
    """
    Main function to handle a new alert
    Displays it and saves it to log
    """
    display_alert(alert)
    save_alert_to_log(alert)

def load_alerts_from_log():
    """Load all saved alerts from the log file"""
    alerts = []
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alerts.append(json.loads(line))
    except Exception as e:
        print(f"[-] Could not load alerts: {e}")
    return alerts

def get_alert_statistics(alerts):
    """Generate statistics from a list of alerts"""
    stats = {
        "total": len(alerts),
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "by_type": {}
    }

    for alert in alerts:
        # Count by severity
        severity = alert.get("severity", "LOW")
        if severity in stats:
            stats[severity] += 1

        # Count by attack type
        attack_type = alert.get("attack_type", "UNKNOWN")
        if attack_type not in stats["by_type"]:
            stats["by_type"][attack_type] = 0
        stats["by_type"][attack_type] += 1

    return stats

def print_alert_summary(alerts):
    """Print a summary of all alerts"""
    stats = get_alert_statistics(alerts)
    cyan = COLORS["CYAN"]
    reset = COLORS["RESET"]
    bold = COLORS["BOLD"]

    print(f"\n{'='*60}")
    print(f"           ALERT SUMMARY")
    print(f"{'='*60}")
    print(f"  Total Alerts    : {bold}{stats['total']}{reset}")
    print(f"  Critical        : {COLORS['CRITICAL']}{stats['CRITICAL']}{reset}")
    print(f"  High            : {COLORS['HIGH']}{stats['HIGH']}{reset}")
    print(f"  Medium          : {COLORS['MEDIUM']}{stats['MEDIUM']}{reset}")
    print(f"  Low             : {COLORS['LOW']}{stats['LOW']}{reset}")

    if stats["by_type"]:
        print(f"\n  {bold}By Attack Type:{reset}")
        for attack, count in stats["by_type"].items():
            print(f"    {cyan}{attack}{reset}: {count}")
    print(f"{'='*60}")
