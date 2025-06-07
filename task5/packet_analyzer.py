from scapy.all import sniff, IP, TCP, UDP, Raw
import socket

MAJOR_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
}

def get_service_name(port):
    return MAJOR_PORTS.get(port, "Unknown")

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto

        protocol = {6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))

        print("\n--- Packet Captured ---")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        # Show ports if TCP or UDP
        if protocol == "TCP" and TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"Source Port    : {sport} ({get_service_name(sport)})")
            print(f"Destination Port: {dport} ({get_service_name(dport)})")

        elif protocol == "UDP" and UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"Source Port    : {sport} ({get_service_name(sport)})")
            print(f"Destination Port: {dport} ({get_service_name(dport)})")

        # Show payload (if any)
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                payload = raw_data.decode('utf-8', errors='replace')
                print(f"Payload (truncated to 100 chars): {payload[:100]}")
            except Exception:
                print("Payload: [binary data]")

def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"Error: Could not resolve '{target}' to an IP address.")
        return None

def main():
    print("Packet Sniffer - Capture packets to/from a specific IP or URL")
    print("Ethical reminder: Use only on networks you own or have permission to monitor.\n")

    target = input("Enter target IP address or URL: ").strip()
    ip = resolve_ip(target)
    if not ip:
        return

    print(f"Sniffing packets to/from {ip}. Press Ctrl+C to stop.\n")

    # BPF filter: capture only packets where source or destination is the target IP
    bpf_filter = f"ip host {ip}"

    sniff(filter=bpf_filter, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
