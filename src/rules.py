# rules.py
# This module contains all detection rules
# Think of rules like a security guard's checklist
# Each rule defines what suspicious activity looks like

import datetime

# ── THRESHOLDS ──
# These numbers define when something becomes suspicious
THRESHOLDS = {
    # If we see more than 15 ports scanned from same IP in 5 seconds = port scan
    "port_scan_threshold": 15,
    "port_scan_window": 5,

    # If we see more than 100 pings from same IP in 1 second = ping flood
    "ping_flood_threshold": 100,
    "ping_flood_window": 1,

    # If we see more than 100 SYN packets from same IP in 1 second = SYN flood
    "syn_flood_threshold": 100,
    "syn_flood_window": 1,

    # If same IP sends more than 10 ARP replies = ARP spoofing
    "arp_spoof_threshold": 10,
    "arp_spoof_window": 5,

    # If more than 10 failed logins from same IP in 30 seconds = brute force
    "brute_force_threshold": 10,
    "brute_force_window": 30,
}

# ── LOGIN PORTS ──
# These are ports where brute force attacks commonly happen
LOGIN_PORTS = [22, 23, 21, 80, 443, 8080, 3389, 5900]

# ── SUSPICIOUS PORTS ──
# These ports are commonly used by attackers
SUSPICIOUS_PORTS = [
    4444,   # Metasploit default listener
    1337,   # Common hacker port
    31337,  # Elite hacker port
    6666,   # Malware commonly uses this
    6667,   # IRC - often used by botnets
    9001,   # Tor default port
]

class RuleEngine:
    """
    The main rule engine that tracks traffic patterns
    and detects attacks based on defined rules
    """

    def __init__(self):
        # These dictionaries track activity per IP address
        # Key = IP address, Value = list of timestamps/events

        # Track which ports each IP has tried to connect to
        self.port_scan_tracker = {}

        # Track ICMP (ping) packets per IP
        self.ping_tracker = {}

        # Track SYN packets per IP
        self.syn_tracker = {}

        # Track ARP replies per IP
        self.arp_tracker = {}

        # Track failed login attempts per IP
        self.brute_force_tracker = {}

        # Store all detected alerts
        self.alerts = []

    def clean_old_entries(self, tracker, window_seconds):
        """
        Remove old entries from tracker that are outside the time window
        This prevents memory from filling up with old data
        """
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(seconds=window_seconds)

        for ip in list(tracker.keys()):
            # Keep only recent entries within the time window
            tracker[ip] = [
                t for t in tracker[ip]
                if t > cutoff
            ]
            # Remove IP entirely if no recent activity
            if not tracker[ip]:
                del tracker[ip]

    def create_alert(self, attack_type, src_ip, dst_ip, severity, details):
        """Create a standardized alert dictionary"""
        alert = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": severity,
            "details": details,
            "id": len(self.alerts) + 1
        }
        self.alerts.append(alert)
        return alert

    def check_port_scan(self, packet_info):
        """
        Rule 1: Port Scan Detection
        A port scan happens when one IP tries to connect to
        many different ports in a short time
        """
        src_ip = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        protocol = packet_info.get("protocol")

        # Only check TCP and UDP packets
        if not src_ip or not dst_port or protocol not in ["TCP", "UDP"]:
            return None

        now = datetime.datetime.now()
        window = THRESHOLDS["port_scan_window"]

        # Initialize tracker for this IP if first time seeing it
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = []

        # Record this port connection attempt
        self.port_scan_tracker[src_ip].append({
            "time": now,
            "port": dst_port
        })

        # Clean old entries outside the time window
        cutoff = now - datetime.timedelta(seconds=window)
        self.port_scan_tracker[src_ip] = [
            e for e in self.port_scan_tracker[src_ip]
            if e["time"] > cutoff
        ]

        # Count unique ports tried in this window
        recent_ports = set(
            e["port"] for e in self.port_scan_tracker[src_ip]
        )

        # If too many unique ports tried = port scan detected!
        if len(recent_ports) >= THRESHOLDS["port_scan_threshold"]:
            alert = self.create_alert(
                attack_type="PORT_SCAN",
                src_ip=src_ip,
                dst_ip=packet_info.get("dst_ip"),
                severity="HIGH",
                details=f"Port scan detected: {len(recent_ports)} unique ports tried in {window}s. Ports: {list(recent_ports)[:10]}"
            )
            # Reset tracker to avoid repeated alerts
            self.port_scan_tracker[src_ip] = []
            return alert

        return None

    def check_ping_flood(self, packet_info):
        """
        Rule 2: Ping Flood / DoS Detection
        A ping flood happens when an IP sends hundreds of
        pings per second to overwhelm a device
        """
        src_ip = packet_info.get("src_ip")
        protocol = packet_info.get("protocol")

        # Only check ICMP packets
        if not src_ip or protocol != "ICMP":
            return None

        now = datetime.datetime.now()
        window = THRESHOLDS["ping_flood_window"]

        if src_ip not in self.ping_tracker:
            self.ping_tracker[src_ip] = []

        self.ping_tracker[src_ip].append(now)

        # Remove old entries
        cutoff = now - datetime.timedelta(seconds=window)
        self.ping_tracker[src_ip] = [
            t for t in self.ping_tracker[src_ip]
            if t > cutoff
        ]

        # Count pings in window
        ping_count = len(self.ping_tracker[src_ip])

        if ping_count >= THRESHOLDS["ping_flood_threshold"]:
            alert = self.create_alert(
                attack_type="PING_FLOOD",
                src_ip=src_ip,
                dst_ip=packet_info.get("dst_ip"),
                severity="HIGH",
                details=f"Ping flood detected: {ping_count} ICMP packets in {window} second(s)"
            )
            self.ping_tracker[src_ip] = []
            return alert

        return None

    def check_syn_flood(self, packet_info):
        """
        Rule 3: SYN Flood Detection
        A SYN flood sends thousands of connection requests
        but never completes them, overwhelming the target
        """
        src_ip = packet_info.get("src_ip")
        flags = packet_info.get("flags")
        protocol = packet_info.get("protocol")

        # Only check TCP SYN packets (flags contain S but not A)
        if not src_ip or protocol != "TCP":
            return None

        # SYN flag is set but ACK is not = new connection attempt
        if flags and "S" in str(flags) and "A" not in str(flags):
            now = datetime.datetime.now()
            window = THRESHOLDS["syn_flood_window"]

            if src_ip not in self.syn_tracker:
                self.syn_tracker[src_ip] = []

            self.syn_tracker[src_ip].append(now)

            # Remove old entries
            cutoff = now - datetime.timedelta(seconds=window)
            self.syn_tracker[src_ip] = [
                t for t in self.syn_tracker[src_ip]
                if t > cutoff
            ]

            syn_count = len(self.syn_tracker[src_ip])

            if syn_count >= THRESHOLDS["syn_flood_threshold"]:
                alert = self.create_alert(
                    attack_type="SYN_FLOOD",
                    src_ip=src_ip,
                    dst_ip=packet_info.get("dst_ip"),
                    severity="CRITICAL",
                    details=f"SYN flood detected: {syn_count} SYN packets in {window} second(s)"
                )
                self.syn_tracker[src_ip] = []
                return alert

        return None

    def check_arp_spoofing(self, packet_info):
        """
        Rule 4: ARP Spoofing Detection
        ARP spoofing is when an attacker sends fake ARP replies
        to trick devices into sending traffic to the attacker
        """
        protocol = packet_info.get("protocol")
        src_ip = packet_info.get("src_ip")
        src_mac = packet_info.get("src_mac")

        # Only check ARP packets
        if protocol != "ARP" or not src_ip or not src_mac:
            return None

        now = datetime.datetime.now()
        window = THRESHOLDS["arp_spoof_window"]

        # Use IP as key, store MAC addresses seen for this IP
        if src_ip not in self.arp_tracker:
            self.arp_tracker[src_ip] = {"macs": set(), "times": []}

        self.arp_tracker[src_ip]["macs"].add(src_mac)
        self.arp_tracker[src_ip]["times"].append(now)

        # Remove old time entries
        cutoff = now - datetime.timedelta(seconds=window)
        self.arp_tracker[src_ip]["times"] = [
            t for t in self.arp_tracker[src_ip]["times"]
            if t > cutoff
        ]

        # If same IP is using multiple MAC addresses = ARP spoofing!
        mac_count = len(self.arp_tracker[src_ip]["macs"])
        recent_count = len(self.arp_tracker[src_ip]["times"])

        if mac_count > 1 or recent_count >= THRESHOLDS["arp_spoof_threshold"]:
            alert = self.create_alert(
                attack_type="ARP_SPOOFING",
                src_ip=src_ip,
                dst_ip=packet_info.get("dst_ip"),
                severity="CRITICAL",
                details=f"ARP spoofing detected: IP {src_ip} seen with {mac_count} different MAC addresses"
            )
            self.arp_tracker[src_ip] = {"macs": set(), "times": []}
            return alert

        return None

    def check_brute_force(self, packet_info):
        """
        Rule 5: Brute Force Login Detection
        Detects repeated connection attempts to login services
        like SSH, Telnet, FTP suggesting password guessing
        """
        src_ip = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        flags = packet_info.get("flags")
        protocol = packet_info.get("protocol")

        # Only check TCP connections to login ports
        if not src_ip or not dst_port or protocol != "TCP":
            return None

        # Only care about SYN packets to login ports
        if dst_port not in LOGIN_PORTS:
            return None

        if flags and "S" in str(flags):
            now = datetime.datetime.now()
            window = THRESHOLDS["brute_force_window"]

            key = f"{src_ip}:{dst_port}"
            if key not in self.brute_force_tracker:
                self.brute_force_tracker[key] = []

            self.brute_force_tracker[key].append(now)

            # Remove old entries
            cutoff = now - datetime.timedelta(seconds=window)
            self.brute_force_tracker[key] = [
                t for t in self.brute_force_tracker[key]
                if t > cutoff
            ]

            attempt_count = len(self.brute_force_tracker[key])

            if attempt_count >= THRESHOLDS["brute_force_threshold"]:
                service = {
                    22: "SSH", 23: "Telnet", 21: "FTP",
                    80: "HTTP", 443: "HTTPS", 3389: "RDP"
                }.get(dst_port, f"Port {dst_port}")

                alert = self.create_alert(
                    attack_type="BRUTE_FORCE",
                    src_ip=src_ip,
                    dst_ip=packet_info.get("dst_ip"),
                    severity="HIGH",
                    details=f"Brute force detected: {attempt_count} login attempts to {service} in {window}s"
                )
                self.brute_force_tracker[key] = []
                return alert

        return None

    def check_suspicious_port(self, packet_info):
        """
        Bonus Rule: Suspicious Port Detection
        Alerts when traffic is seen on ports commonly
        used by malware and hackers
        """
        dst_port = packet_info.get("dst_port")
        src_port = packet_info.get("src_port")
        src_ip = packet_info.get("src_ip")

        for port in SUSPICIOUS_PORTS:
            if dst_port == port or src_port == port:
                alert = self.create_alert(
                    attack_type="SUSPICIOUS_PORT",
                    src_ip=src_ip,
                    dst_ip=packet_info.get("dst_ip"),
                    severity="MEDIUM",
                    details=f"Traffic on suspicious port {port} detected"
                )
                return alert

        return None

    def analyze_packet(self, packet_info):
        """
        Run ALL rules against a single packet
        Returns list of any alerts triggered
        """
        triggered_alerts = []

        # Run each rule
        rules = [
            self.check_port_scan,
            self.check_ping_flood,
            self.check_syn_flood,
            self.check_arp_spoofing,
            self.check_brute_force,
            self.check_suspicious_port,
        ]

        for rule in rules:
            try:
                alert = rule(packet_info)
                if alert:
                    triggered_alerts.append(alert)
            except Exception as e:
                pass

        return triggered_alerts
