# dashboard.py
# This module shows a live terminal dashboard
# It updates in real time showing network activity and alerts

import os
import datetime
import time
from alerts import COLORS

def clear_screen():
    """Clear the terminal screen"""
    os.system("clear")

def print_banner():
    """Print the NIDS banner"""
    cyan = COLORS["CYAN"]
    reset = COLORS["RESET"]
    red = COLORS["CRITICAL"]
    bold = COLORS["BOLD"]

    print(f"""{cyan}{bold}
╔══════════════════════════════════════════════════════════╗
║        Network Intrusion Detection System (NIDS)         ║
║                      Version 1.0                         ║
║              Academic Cybersecurity Project              ║
╚══════════════════════════════════════════════════════════╝{reset}
{red}[!] AUTHORIZED USE ONLY - Monitor only networks you own{reset}
""")

def print_live_stats(packet_count, alert_count, start_time, recent_alerts):
    """
    Print live statistics during monitoring
    This updates every second to show current status
    """
    cyan = COLORS["CYAN"]
    reset = COLORS["RESET"]
    bold = COLORS["BOLD"]
    red = COLORS["CRITICAL"]
    yellow = COLORS["HIGH"]
    green = COLORS["LOW"]

    # Calculate elapsed time
    elapsed = datetime.datetime.now() - start_time
    elapsed_str = str(elapsed).split(".")[0]  # Remove microseconds

    # Calculate packets per second
    total_seconds = elapsed.total_seconds()
    pps = packet_count / total_seconds if total_seconds > 0 else 0

    print(f"\n{'─'*60}")
    print(f"  {bold}LIVE MONITORING STATUS{reset}")
    print(f"{'─'*60}")
    print(f"  {cyan}Runtime        :{reset} {elapsed_str}")
    print(f"  {cyan}Packets Seen   :{reset} {packet_count}")
    print(f"  {cyan}Packets/sec    :{reset} {pps:.1f}")
    print(f"  {red}Total Alerts   :{reset} {alert_count}")
    print(f"{'─'*60}")

    # Show recent alerts
    if recent_alerts:
        print(f"\n  {bold}RECENT ALERTS:{reset}")
        # Show last 5 alerts
        for alert in recent_alerts[-5:]:
            severity = alert["severity"]
            color = COLORS.get(severity, reset)
            print(f"  {color}[{severity}]{reset} {alert['attack_type']} from {alert['src_ip']} at {alert['timestamp']}")
    else:
        print(f"\n  {green}No alerts detected yet — network looks clean{reset}")

    print(f"\n  Press Ctrl+C to stop monitoring and generate report")

def show_startup_screen(interface):
    """Show startup information before monitoring begins"""
    clear_screen()
    print_banner()

    cyan = COLORS["CYAN"]
    reset = COLORS["RESET"]
    bold = COLORS["BOLD"]

    print(f"{'─'*60}")
    print(f"  {bold}STARTING NIDS MONITOR{reset}")
    print(f"{'─'*60}")
    print(f"  {cyan}Interface      :{reset} {interface}")
    print(f"  {cyan}Start Time     :{reset} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {cyan}Detection Rules:{reset} Port Scan, Ping Flood, SYN Flood,")
    print(f"                   ARP Spoofing, Brute Force")
    print(f"{'─'*60}")
    print(f"\n  Initializing capture engine...")
    time.sleep(1)
    print(f"  Loading detection rules...")
    time.sleep(1)
    print(f"  Starting monitor...\n")
    time.sleep(0.5)
