import sys
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configure logging
def setup_logger(interface):
    log_filename = f"sniffer_{interface}_log.txt"
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return log_filename

# Packet handling function
def handle_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "UNKNOWN"
        details = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            details = f"{src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            details = f"{src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            details = f"{src_ip} -> {dst_ip} (ICMP Type: {packet[ICMP].type})"

        log_entry = f"{protocol} Packet: {details}"
        logging.info(log_entry)

        # Print to console if verbose mode is enabled
        if verbose:
            print(log_entry)

# Main function
def main(interface, verbose_mode):
    global verbose
    verbose = verbose_mode  # Set global verbose flag

    log_file = setup_logger(interface)
    print(f"[*] Sniffing on interface: {interface}")
    print(f"[*] Logging packets to: {log_file}")

    try:
        sniff(iface=interface, prn=handle_packet, store=0)
    except PermissionError:
        print("[!] Error: Insufficient permissions. Try running with sudo.")
    except Exception as e:
        print(f"[!] Error: {e}")

# Run script
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)

    interface = sys.argv[1]
    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"

    main(interface, verbose)
