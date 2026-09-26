import socket
import nmap
from datetime import datetime


# -----------------------------------------
# PORT SCANNING
# -----------------------------------------
def port_scan(target, start_port, end_port):

    print(
        f"Scanning target: {target} "
        f"for open ports from {start_port} to {end_port}..."
    )

    open_ports = []

    for port in range(start_port, end_port + 1):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        # Faster timeout
        sock.settimeout(0.1)

        try:
            result = sock.connect_ex(
                (target, port)
            )

            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port} is OPEN")

        except socket.error:
            pass

        finally:
            sock.close()

    print(f"Open ports found: {open_ports}")

    return open_ports


# -----------------------------------------
# BANNER GRABBING
# -----------------------------------------
def banner_grab(target, port):

    print(
        f"Grabbing banner for {target}:{port}"
    )

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect(
            (target, port)
        )

        banner = sock.recv(
            1024
        ).decode(
            "utf-8",
            errors="ignore"
        )

        sock.close()

        if banner:
            return banner.strip()

        return None

    except Exception:
        return None


# -----------------------------------------
# VULNERABILITY SCANNING
# -----------------------------------------
def vulnerability_scan(target):

    print(
        f"Scanning target {target} "
        f"for vulnerabilities..."
    )

    try:

        nm = nmap.PortScanner()

        nm.scan(
            hosts=target,
            arguments="-O -sV --script=vuln"
        )

        if target in nm.all_hosts():
            return nm[target]

        return None

    except Exception as e:

        print(
            f"Error during vulnerability scan: {e}"
        )

        return None


# -----------------------------------------
# COMPLETE NETWORK SCAN
# -----------------------------------------
def network_scan(target, start_port, end_port):

    print(
        f"Starting network scan for target: {target}..."
    )

    start_time = datetime.now()

    # -------------------------------------
    # 1. PORT SCANNING
    # -------------------------------------
    open_ports = port_scan(
        target,
        start_port,
        end_port
    )

    # -------------------------------------
    # 2. BANNER GRABBING
    # -------------------------------------
    if open_ports:

        for port in open_ports:

            banner = banner_grab(
                target,
                port
            )

            if banner:

                print(
                    f"Banner for {target}:{port}: "
                    f"{banner}"
                )

            else:

                print(
                    f"No banner found for "
                    f"{target}:{port}"
                )

    else:

        print("No open ports found.")

    # -------------------------------------
    # 3. VULNERABILITY SCANNING
    # -------------------------------------
    vuln_info = vulnerability_scan(
        target
    )

    if vuln_info:

        # Hostnames
        if "hostnames" in vuln_info:

            print(
                f"Hostnames: "
                f"{vuln_info['hostnames']}"
            )

        # Operating System
        if "osmatch" in vuln_info:

            print(
                f"Operating System: "
                f"{vuln_info['osmatch']}"
            )

        # TCP information
        if "tcp" in vuln_info:

            print(
                f"TCP Information: "
                f"{vuln_info['tcp']}"
            )

    else:

        print(
            "No vulnerability information "
            "was returned."
        )

    # -------------------------------------
    # 4. COMPLETION TIME
    # -------------------------------------
    end_time = datetime.now()

    print(
        f"Scan completed in: "
        f"{end_time - start_time}"
    )


# -----------------------------------------
# MAIN PROGRAM
# -----------------------------------------
if __name__ == "__main__":

    target = input(
        "Enter the target IP or Hostname: "
    ).strip()

    start_port = int(
        input(
            "Enter the starting port for scanning: "
        )
    )

    end_port = int(
        input(
            "Enter the ending port for scanning: "
        )
    )

    # Validate port range
    if start_port < 1 or end_port > 65535:

        print(
            "Invalid port range. "
            "Use ports between 1 and 65535."
        )

    elif start_port > end_port:

        print(
            "Starting port must be less than "
            "or equal to ending port."
        )

    else:

        network_scan(
            target,
            start_port,
            end_port
        )