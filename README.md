# Basic-Network-Sniffer
This Python script captures and logs network packets on a specified interface. It uses the `scapy` library to sniff network traffic and logs information about TCP, UDP, and ICMP packets. The script is designed to be simple and customizable for network monitoring and analysis.

## Features:
- Sniff packets from a specified network interface.
- Logs packet details to a file (`sniffer_<interface>_log.txt`).
- Supports logging of TCP, UDP, and ICMP packet information.
- Optionally prints packet details to the console (Verbose mode).
- Easy to use via command-line interface.

## Requirements:
- Python 3.x
- `scapy` library (can be installed via `pip install scapy`)

## Usage:

### Command-line Arguments:
1. **Interface**: The network interface to sniff (e.g., `eth0`, `wlan0`, `en0`).
2. **Verbose (optional)**: If provided, the script will print packet details to the console.

### Basic Command:
```bash
python sniffer.py <interface>
```

### Command with Verbose Mode:
```bash
python sniffer.py <interface> verbose
```

### Example:
```bash
python sniffer.py eth0
```
This will start sniffing packets on the `eth0` interface and log the results to `sniffer_eth0_log.txt`.

### Example with Verbose Mode:
```bash
python sniffer.py eth0 verbose
```
This will start sniffing packets on the `eth0` interface, log the results to `sniffer_eth0_log.txt`, and also print the packet details to the console.

## How It Works:
1. The script uses the `scapy` library to sniff packets on the given network interface.
2. For each packet captured, the script checks for the presence of IP layers and determines the type of packet (TCP, UDP, or ICMP).
3. The script logs the packet details to a log file and, if verbose mode is enabled, prints them to the console.
4. The log file is named `sniffer_<interface>_log.txt`.

## Logging Format:
Each log entry will include:
- Timestamp of the packet capture.
- The protocol (TCP, UDP, ICMP).
- The source and destination IP addresses and port numbers (if applicable).

Example log entry:
```
2025-02-03 12:45:23 - TCP Packet: 192.168.1.1:12345 -> 192.168.1.2:80
```

## Error Handling:
- If the script encounters insufficient permissions, you may see an error message suggesting you run the script with elevated privileges (e.g., using `sudo` on Linux).
- General exceptions are caught and displayed to help with troubleshooting.

## Notes:
- Running the script may require elevated privileges (root/sudo) depending on your operating system.
- The `scapy` library must be installed. You can install it with:
  ```bash
  pip install scapy
  ```
