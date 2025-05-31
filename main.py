import socket
import os
import time
import re

# ANSI escape codes for colored output
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    """Prints a cool ASCII art banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}========================================
       ___  ___ _ ____   ____ _  _______
      | __)(__ | _) \ / (__ | \/ (_____)
      | _|  / /| _)  V  _/ |    <  _)
      |___)(___|___)  \/ (___|_/\_(__)
{Colors.RESET}
{Colors.GREEN}  Simple Port Scanner for Windows
  Powered by Python | Created by Revex
{Colors.CYAN}========================================{Colors.RESET}
"""
    print(banner)

def is_valid_ip(ip):
    """Validates an IP address."""
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern, ip))

def scan_port(ip, port, timeout=1):
    """Scans a single port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0  # 0 means port is open
    except Exception:
        return port, False

def scan_ports(ip, start_port=1, end_port=1024):
    """Scans a range of ports on the target IP."""
    open_ports = []
    print(f"{Colors.YELLOW}[*] Scanning {ip} for open ports ({start_port}-{end_port})...{Colors.RESET}")
    time.sleep(1)  # Dramatic effect
    for port in range(start_port, end_port + 1):
        port, is_open = scan_port(ip, port)
        if is_open:
            open_ports.append(port)
        if port % 100 == 0:  # Progress update
            print(f"{Colors.YELLOW}[*] Scanned port {port}...{Colors.RESET}")
    return open_ports

def display_ports(ip, open_ports):
    """Displays open ports in a stylized format."""
    if not open_ports:
        print(f"{Colors.YELLOW}[!] No open ports found on {ip}.{Colors.RESET}")
        return
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== Open Ports on {ip} ==={Colors.RESET}")
    print(f"{Colors.GREEN}Found {len(open_ports)} open port(s):{Colors.RESET}")
    print(f"{Colors.CYAN}{'Port':<10} | {'Status':<10}{Colors.RESET}")
    print(f"{Colors.CYAN}{'-'*10} | {'-'*10}{Colors.RESET}")
    for port in sorted(open_ports):
        print(f"{Colors.GREEN}{port:<10} | Open{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*10} | {'='*10}{Colors.RESET}")

def main():
    """Main function for the port scanner."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    if os.name != 'nt':
        print(f"{Colors.RED}[!] This tool is designed for Windows.{Colors.RESET}")
        return

    ip = input(f"{Colors.YELLOW}[*] Enter target IP address (e.g., 192.168.1.1): {Colors.RESET}").strip()
    if not is_valid_ip(ip):
        print(f"{Colors.RED}[!] Invalid IP address format.{Colors.RESET}")
        return

    try:
        start_port = int(input(f"{Colors.YELLOW}[*] Enter start port (default: 1): {Colors.RESET}").strip() or 1)
        end_port = int(input(f"{Colors.YELLOW}[*] Enter end port (default: 1024): {Colors.RESET}").strip() or 1024)
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print(f"{Colors.RED}[!] Invalid port range. Use 1-65535.{Colors.RESET}")
            return
    except ValueError:
        print(f"{Colors.RED}[!] Invalid input. Ports must be numbers.{Colors.RESET}")
        return

    open_ports = scan_ports(ip, start_port, end_port)
    display_ports(ip, open_ports)

    print(f"\n{Colors.YELLOW}[*] Scan completed. Press Enter to exit.{Colors.RESET}")
    input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Program interrupted by user.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] An unexpected error occurred: {e}{Colors.RESET}")