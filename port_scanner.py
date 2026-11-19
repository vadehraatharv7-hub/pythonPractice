from concurrent.futures import ThreadPoolExecutor
import socket
from datetime import datetime
import sys
import errno
import argparse




def parse_arguments():
    parser = argparse.ArgumentParser(
                        prog='PortScanner',
                        description='Port Scanner',
                        epilog='Usage: python3 port_scanner.py -t target.com -p startport-endport/ port /port1,port2,port3...')
    
    
    parser.add_argument('-p', '--port', default='1-1024', help='Port range (e.g., 20-80) or single port (e.g 22)')
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of threads to use. (e.g 10)')
    parser.add_argument('-To', '--timeout', type=float, default=1.0, help='Timeout')


    
    args = parser.parse_args()
    return args

def grab_banner(sock):
    
    try:
        sock.settimeout(2.0)
        
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                return banner.splitlines()[0]
        except socket.timeout:
            pass  

        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        
        if banner:
            return banner.splitlines()[0]
        return "No banner"
    except Exception:
        return "No banner"

    




def scan_ports(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = None
    try:
        result = s.connect_ex((host, port))
        if result == 0:
            state = "open"
            banner = grab_banner(s)
        elif result == errno.ECONNREFUSED:
            state = "closed"
        elif result in (errno.ETIMEDOUT, errno.EAGAIN, errno.EINPROGRESS, errno.EHOSTUNREACH, errno.ENETUNREACH):
            state = "filtered"
        else:
            state = "unknown"

        return state, banner

    finally:
        s.close()


def main():
    args = parse_arguments()
    ports_to_scan = []
    try:
        for part in args.port.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports_to_scan.extend(range(start, end + 1))
            else:
                ports_to_scan.append(int(part))

        if any(p < 1 or p > 65535 for p in ports_to_scan):
            raise ValueError("Ports must be between 1 and 65535.")
        
    except ValueError as e:
        print(f"Invalid port input: {e}")
        sys.exit(1)

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve {args.target}")
        sys.exit(1)


    print(f"\nScanning {args.target}....")
    began = datetime.now()

    ports = ports_to_scan
    ips = [ip] * len(ports)
    timeouts = [args.timeout] * len(ports)



    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(scan_ports, ips, ports, timeouts))
    open_ports =[]
    closed_ports_counter = 0
    filtered_ports = []
    unknown_ports = []

    banners = {}
    for port, (state, banner) in zip(ports, results):
        if state == "open":
            open_ports.append(port)
            banners[port] = banner
        elif state == "closed":
            closed_ports_counter += 1
        elif state == "filtered":
            filtered_ports.append(port)
        else:
            unknown_ports.append(port)

    open_ports.sort()
    filtered_ports.sort()
    unknown_ports.sort()

    if open_ports:
        print(f"\n{'PORT':<8}{'STATE':<10}{'BANNER':<40}")
        print("-" * 58)
        for port in open_ports:
            print(f"{port:<8}{'open':<10}{banners[port]:<40}")
    else:
        print("\nNo open ports found.")

    if filtered_ports:
        print(f"\nFiltered ports: {', '.join(map(str, filtered_ports))}")

    print(f"\nScan completed in {datetime.now() - began}")
    print(f"Open: {len(open_ports)}  Closed: {closed_ports_counter}  "
          f"Filtered: {len(filtered_ports)}  Unknown: {len(unknown_ports)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nUser Exited")
