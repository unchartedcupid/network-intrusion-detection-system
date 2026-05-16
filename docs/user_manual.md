# NIDS User Manual
**Version:** 1.0
**Project:** Network Intrusion Detection System
**Author:** Victor

---

## 1. What is this tool?

This is a Network Intrusion Detection System (NIDS).
It monitors your network in real time and alerts you
when it detects suspicious or malicious activity.

Think of it like a security camera for your network —
it watches everything and raises an alarm when something
looks wrong.

---

## 2. System Requirements

| Requirement | Details |
|-------------|---------|
| Operating System | Kali Linux / Ubuntu |
| Python Version | 3.x |
| Privileges | Root/sudo required |
| RAM | Minimum 2GB |
| Network | Wired or WiFi connection |

---

## 3. Installation

**Step 1: Clone or download the project**
```bash
git clone https://github.com/unchartedcupid/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

**Step 2: Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Step 3: Install required libraries**
```bash
pip install scapy psutil colorama
pip freeze > requirements.txt
```

---

## 4. How to Run

**Start the NIDS:**
```bash
sudo /home/victor/MYCYBERLAB/network-intrusion-detection-system/venv/bin/python3 src/main.py
```

**What you will see:**
1. Banner showing NIDS version and warning
2. Network interface being monitored
3. Live packet count updating
4. Alerts appearing in red/yellow when attacks detected
5. Final summary when capture is complete
6. HTML report automatically generated

---

## 5. Understanding Alerts

### Severity Levels

| Level | Color | Meaning | Action |
|-------|-------|---------|--------|
| CRITICAL | Red | Severe attack | Investigate immediately |
| HIGH | Yellow | Serious threat | Investigate soon |
| MEDIUM | Blue | Moderate risk | Review when possible |
| LOW | Green | Minor issue | Log for records |

### Alert Types Explained

**PORT_SCAN**
Someone is probing your network looking for open doors.
This is usually the first step before an attack.
*Action: Block the source IP at your firewall*

**PING_FLOOD**
A device is sending hundreds of pings per second trying
to overwhelm another device and make it crash.
*Action: Block ICMP traffic from that source IP*

**SYN_FLOOD**
An attacker is sending thousands of incomplete connection
requests to crash a service.
*Action: Enable SYN cookies on affected device*

**ARP_SPOOFING**
A device is pretending to be another device to intercept
network traffic. This is a man-in-the-middle attack.
*Action: Use static ARP entries, enable Dynamic ARP Inspection*

**BRUTE_FORCE**
Someone is repeatedly trying to log into a service like
SSH or Telnet by guessing passwords.
*Action: Block source IP, enable fail2ban, use strong passwords*

---

## 6. Reading the HTML Report

After each scan a report is saved to:reports/nids_report.html
Open it with:
```bash
firefox reports/nids_report.html
```

**The report contains:**
- Summary cards showing total packets and alert counts
- Packet breakdown by protocol (TCP/UDP/ICMP/ARP)
- Detailed list of every alert with source and target IPs
- Timestamp for each detected event

---
## 7. Log Files

**Alert log:**

logs/alerts.log

Every alert is saved here as a JSON line.
You can open it with any text editor.

**Session log:**

logs/session.json

Full session data including all alerts and packet count.

---

## 8. False Positives

A false positive is when the NIDS raises an alert but
there is no real attack. This happens because:

- School/office networks have high ARP traffic
- Multiple devices sharing an IP can look like spoofing
- Network scans by IT administrators look like attacks

**How to handle false positives:**
- Investigate the source IP first
- Check if it belongs to a known device
- Adjust thresholds in rules.py if needed

---

## 9. Adjusting Detection Sensitivity

Open `src/rules.py` and find the THRESHOLDS section:

```python
THRESHOLDS = {
    "port_scan_threshold": 15,   # Lower = more sensitive
    "ping_flood_threshold": 100, # Lower = more sensitive
    "syn_flood_threshold": 100,  # Lower = more sensitive
}
```

Lower numbers = more alerts (more sensitive)
Higher numbers = fewer alerts (less sensitive)

---

## 10. Ethical and Legal Notice

This tool must only be used on:
- Networks you personally own
- Networks where you have written permission to monitor

Unauthorized network monitoring is illegal under
computer misuse laws in most countries.

This tool was built for educational purposes only.
