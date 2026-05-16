# sniffer.py
# This module captures all network packets passing through the interface
# Think of it as the "ears" of our NIDS - it listens to everything

from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
import datetime
import threading

# Global packet storage - all captured packets go here
captured_packets = []
packet_count = 0
is_running = False

def get_network_interfaces():
    """Get list of available network interfaces on this machine"""
    interfaces = get_if_list()
    print("\n[*] Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"    {i}: {iface}")
    return interfaces

def get_default_interface():
    """Automatically detect the best interface to sniff on"""
    try:
        # conf.iface gives us the default interface scapy would use
        return conf.iface
    except:
        return "eth0"

def extract_packet_info(packet):
    """
    Extract useful information from a captured packet
    Returns a dictionary with all the important details
    """
    info = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": "UNKNOWN",
        "src_ip": None,
        "dst_ip": None,
        "src_mac": None,
        "dst_mac": None,
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "length": len(packet),
        "ttl": None,
        "payload": None,
        "raw": packet
    }

    # Extract Ethernet layer info (MAC addresses)
    if packet.haslayer(Ether):
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # Extract IP layer info
    if packet.haslayer(IP):
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["ttl"] = packet[IP].ttl

    # Extract TCP info (most web traffic uses TCP)
    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        # TCP flags tell us what kind of packet this is
        # S=SYN, A=ACK, F=FIN, R=RST, P=PSH
        info["flags"] = str(packet[TCP].flags)

    # Extract UDP info
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport

    # Extract ICMP info (ping packets)
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"
        info["icmp_type"] = packet[ICMP].type
        # ICMP type 8 = ping request, type 0 = ping reply

    # Extract ARP info (used to find MAC addresses)
    elif packet.haslayer(ARP):
        info["protocol"] = "ARP"
        info["src_ip"] = packet[ARP].psrc
        info["dst_ip"] = packet[ARP].pdst
        info["src_mac"] = packet[ARP].hwsrc
        info["arp_op"] = packet[ARP].op
        # ARP op 1 = who has this IP? op 2 = I have this IP!

    return info

def packet_callback(packet):
    """
    This function runs automatically every time a packet is captured
    It extracts info and adds it to our captured_packets list
    """
    global packet_count, captured_packets

    # Extract all useful info from packet
    packet_info = extract_packet_info(packet)

    # Add to our list
    captured_packets.append(packet_info)
    packet_count += 1

    # Print live feedback every 10 packets so we know it's working
    if packet_count % 10 == 0:
        print(f"  [*] Captured {packet_count} packets...")

    return packet_info

def start_sniffing(interface=None, packet_limit=1000, callback=None):
    """
    Start capturing packets on the network
    interface   = which network card to listen on
    packet_limit = how many packets to capture before stopping
    callback    = function to call for each packet (for analysis)
    """
    global is_running, captured_packets, packet_count

    # Reset counters
    captured_packets = []
    packet_count = 0
    is_running = True

    # Auto detect interface if not specified
    if interface is None:
        interface = get_default_interface()

    print(f"\n[*] Starting packet capture on interface: {interface}")
    print(f"[*] Will capture {packet_limit} packets")
    print("[*] Press Ctrl+C to stop early\n")

    def combined_callback(packet):
        """Run both our storage callback and any external callback"""
        packet_info = packet_callback(packet)
        if callback:
            callback(packet_info, packet)

    try:
        # Start sniffing!
        # store=False means don't store raw packets in memory (saves RAM)
        # prn = function to call for each packet
        # count = how many packets to capture
        sniff(
            iface=interface,
            prn=combined_callback,
            count=packet_limit,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user")
    except Exception as e:
        print(f"\n[-] Error during sniffing: {e}")
    finally:
        is_running = False
        print(f"\n[+] Capture complete: {packet_count} packets captured")

    return captured_packets

def get_packet_summary(packets):
    """
    Generate a summary of all captured packets
    Shows breakdown by protocol
    """
    summary = {
        "total": len(packets),
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "ARP": 0,
        "OTHER": 0,
        "unique_ips": set(),
        "unique_ports": set()
    }

    for pkt in packets:
        proto = pkt.get("protocol", "OTHER")
        if proto in summary:
            summary[proto] += 1
        else:
            summary["OTHER"] += 1

        # Track unique IPs and ports we've seen
        if pkt.get("src_ip"):
            summary["unique_ips"].add(pkt["src_ip"])
        if pkt.get("dst_ip"):
            summary["unique_ips"].add(pkt["dst_ip"])
        if pkt.get("src_port"):
            summary["unique_ports"].add(pkt["src_port"])

    # Convert set to count for display
    summary["unique_ips"] = len(summary["unique_ips"])
    summary["unique_ports"] = len(summary["unique_ports"])

    return summary

def print_summary(summary):
    """Print packet capture summary nicely"""
    print("\n" + "="*50)
    print("         PACKET CAPTURE SUMMARY")
    print("="*50)
    print(f"  Total Packets  : {summary['total']}")
    print(f"  TCP Packets    : {summary['TCP']}")
    print(f"  UDP Packets    : {summary['UDP']}")
    print(f"  ICMP Packets   : {summary['ICMP']}")
    print(f"  ARP Packets    : {summary['ARP']}")
    print(f"  Other          : {summary['OTHER']}")
    print(f"  Unique IPs     : {summary['unique_ips']}")
    print(f"  Unique Ports   : {summary['unique_ports']}")
    print("="*50)

# Test this module directly
if __name__ == "__main__":
    print("Testing packet sniffer...")
    print("Capturing 50 packets...\n")

    packets = start_sniffing(packet_limit=50)
    summary = get_packet_summary(packets)
    print_summary(summary)
