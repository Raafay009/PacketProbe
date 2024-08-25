#!/usr/bin/env python3

import scapy.all as scapy
import logging
import signal
import sys
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from threading import Thread
from colorama import Fore, Style, init
from pyfiglet import figlet_format

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(filename='packet_capture.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Keywords for content filtering
FILTER_KEYWORDS = ['password', 'username', 'confidential']

def display_banner():

    ascii_art = figlet_format("Packet Probe", font="slant")
    print(Fore.GREEN + Style.BRIGHT + ascii_art)
    print(Fore.GREEN + Style.BRIGHT + """
    ===============================================================
          	Advanced Network Packet Capturing Tool
    ===============================================================
    
    Capabilities:
    - Real-time Packet Capture: Monitors network traffic across all interfaces.
    - Deep Packet Inspection: Scans payloads for sensitive keywords.
    - Protocol Detection: Analyzes TCP, UDP, HTTP, FTP, and DNS traffic.
    - Payload Filtering: Flags large or sensitive payloads.
    - Logging: Records packet details and detected anomalies
    """)
    

def inspect_payload(payload):
    # Convert payload to string
    payload_str = payload.decode(errors='ignore')
    
    # Check for filter keywords
    for keyword in FILTER_KEYWORDS:
        if keyword in payload_str.lower():
            return f"Alert: Payload contains filtered keyword '{keyword}'"
    
    # Example of protocol decoding (basic HTTP)
    if payload_str.startswith("GET") or payload_str.startswith("POST"):
        return f"HTTP Request Detected: {payload_str[:200]}"  # Show first 200 chars
    
    return None

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto

            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                protocol_name = 'TCP'
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                sport = udp_layer.sport
                dport = udp_layer.dport
                protocol_name = 'UDP'
            else:
                sport = dport = protocol_name = 'N/A'

            # Log the packet with deep inspection details
            log_message = (f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol_name}, "
                           f"Src Port: {sport}, Dst Port: {dport}, Payload: {packet.summary()}")
            logging.info(log_message)
            
            # Additional DPI: Display payload content
            if packet.haslayer(Raw):
                payload = packet.getlayer(Raw).load
                payload_message = inspect_payload(payload)
                
                if payload_message:
                    logging.info(payload_message)
                
                # Anomaly detection: Flag unusually large payloads
                if len(payload) > 1024:  # Example threshold (1 KB)
                    anomaly_message = f"Anomaly: Large Payload Detected ({len(payload)} bytes)"
                    logging.info(anomaly_message)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def signal_handler(sig, frame):
    print("\nStopping packet capture...")
    sys.exit(0)

def capture_packets(interface):
    print(f"Starting packet capture on {interface}. Press Ctrl+C to terminate.")
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

def prompt_user():
    choice = input(Fore.YELLOW + "Do you want to start packet capture? (Y/N): ").strip().lower()
    return choice == 'y'

def main():
    # Display banner and prompt user
    display_banner()
    
    if not prompt_user():
        print(Fore.RED + "Packet capture not started.")
        sys.exit(0)
    
    # Setup signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Detect network interfaces
    interfaces = scapy.get_if_list()
    print(Fore.CYAN + f"Available network interfaces: {interfaces}")
    
    # Create threads to capture on each interface
    threads = []
    
    for interface in interfaces:
        if interface != 'lo':  # Skip the loopback interface if not needed
            thread = Thread(target=capture_packets, args=(interface,))
            thread.start()
            threads.append(thread)
    
    # Join threads to ensure they run until the script is stopped
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
