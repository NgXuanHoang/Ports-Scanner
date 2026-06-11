import socket
import threading
from scapy.all import *
import scapy.all as scapy
import asyncio
import psutil
import networkx as nx
import matplotlib.pyplot as plt
import concurrent.futures
import shodan
import json
from scapy.interfaces import ifaces
import ipaddress

lock = threading.Lock()

SHODAN_API_KEY = "NSMUVugy9X98QBI7zsq2k2MtNJkDgHHK"
api = shodan.Shodan(SHODAN_API_KEY)


def shodan_lookup(ip, cancel_event=None):
    try:
        if cancel_event and cancel_event.is_set():
            return "Scan cancelled by user."
        result = api.host(ip)
        if cancel_event and cancel_event.is_set():
            return "Scan cancelled by user."

        output = []
        output.append(f"Thông tin về địa chỉ IP: {ip}")
        output.append("-" * 60)
        output.append(f"Tổ chức: {result.get('org', 'Không có thông tin')}")
        output.append(f"Nhà cung cấp dịch vụ (ISP): {result.get('isp', 'Không có thông tin')}")
        output.append(f"Hệ điều hành: {result.get('os', 'Không có thông tin')}")
        output.append(
            f"Vị trí: {result.get('city', 'Không có thông tin')} , {result.get('country_name', 'Không có thông tin')}")
        output.append(f"ASN: {result.get('asn', 'Không có thông tin')}")
        output.append("Tên miền liên quan: " + ", ".join(result.get("domains", ["Không có thông tin"])))
        output.append("Danh sách hostname: " + ", ".join(result.get("hostnames", ["Không có thông tin"])))
        output.append(f"Số lượng cổng mở: {len(result.get('ports', []))}")
        output.append("\nDanh sách cổng mở:")
        output.append("-" * 30)

        for service in result.get("data", []):
            if cancel_event and cancel_event.is_set():
                return "Scan cancelled by user."
            port = service.get("port")
            protocol = service.get("_shodan", {}).get("module", "Không xác định")
            output.append(f"Cổng: {port} - Giao thức: {protocol}")

        output.append("-" * 60)
        return "\n".join(output)

    except shodan.APIError as error:
        return f"Lỗi Shodan API: {error}"


def tcp_connect_scan(ip, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if cancel_event and cancel_event.is_set():
        sock.close()
        return (port, "Cancelled")
    sock.close()
    if result == 0:
        return (port, "Open")
    else:
        return (port, "Closed")


def syn_scan(target, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sport = scapy.RandShort()
    resp = scapy.sr1(scapy.IP(dst=target) / scapy.TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    if resp is not None:
        if resp.haslayer(scapy.TCP):
            if resp[scapy.TCP].flags == 18:
                reset = scapy.sr1(scapy.IP(dst=target) / scapy.TCP(sport=sport, dport=port, flags="R"), timeout=1,
                                  verbose=0)
                return (port, "Open")
            elif resp[scapy.TCP].flags == 20:
                return (port, "Closed")
        elif resp.haslayer(scapy.ICMP):
            if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]:
                return (port, "Filtered")
    return (port, "Filtered")


def xmas_scan(target, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sport = scapy.RandShort()
    resp = sr1(scapy.IP(dst=target) / scapy.TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    if resp is None:
        return (port, "Open|Filtered")
    elif resp.haslayer(scapy.TCP):
        if resp[scapy.TCP].flags == 20:
            return (port, "Closed")
    elif resp.haslayer(scapy.ICMP):
        if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return (port, "Filtered")


def fin_scan(target, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sport = scapy.RandShort()
    resp = sr1(scapy.IP(dst=target) / scapy.TCP(sport=sport, dport=port, flags="F"), timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    if resp is None:
        return (port, "Open|Filtered")
    elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 20:
        return (port, "Closed")
    elif resp.haslayer(scapy.ICMP):
        if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return (port, "Filtered")


def null_scan(target, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sport = scapy.RandShort()
    resp = sr1(scapy.IP(dst=target) / scapy.TCP(sport=sport, dport=port, flags=""), timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    if resp is None:
        return (port, "Open|Filtered")
    elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 20:
        return (port, "Closed")
    elif resp.haslayer(scapy.ICMP):
        if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return (port, "Filtered")


def udp_scan(target, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    sport = scapy.RandShort()
    resp = scapy.sr1(scapy.IP(dst=target) / scapy.UDP(sport=sport, dport=port), timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return (port, "Cancelled")
    if resp is not None:
        if resp.haslayer(scapy.UDP):
            return (port, "Open")
        elif resp.haslayer(scapy.ICMP):
            if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) == 3:
                return (port, "Closed")
            elif int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 9, 10, 13]:
                return (port, "Filtered")
    return (port, "Open|Filtered")



def detect_firewall(ip, port, cancel_event=None):
    if cancel_event and cancel_event.is_set():
        return f"Port {port}: Scan cancelled by user."
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if cancel_event and cancel_event.is_set():
        return f"Port {port}: Scan cancelled by user."
    if response is None:
        return f"Port {port}: Firewall detected (No Response)"
    if response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:
            return f"Port {port}: Firewall detected/Closed Port"
        elif response.getlayer(TCP).flags == 0x12:
            return f"Port {port}: No Firewall (Open)"
    if response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code == 3:
            return f"Port {port}: Port Closed (ICMP Port Unreachable)"
        else:
            return f"Firewall Detected (ICMP Error) at port:{port}"
    return f"Port {port}: Undetermined"



# def detect_services(ip):
#     services = {}
#     detected = {}
#
#     service_payloads = {
#         21: "HELP\r\n",               # FTP
#         22: "\r\n",                   # SSH
#         23: "\r\n",                   # Telnet
#         25: "EHLO test\r\n",          # SMTP
#         80: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode(),  # HTTP
#         110: "USER test\r\n",         # POP3
#         143: ". LOGIN test test\r\n",# IMAP
#         443: "\r\n",                  # HTTPS
#         3306: "\x00",                 # MySQL
#     }
#
#     for port, payload in service_payloads.items():
#         syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
#         response = sr1(syn_packet, timeout=1, verbose=0)
#         if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
#             ack = IP(dst=ip) / TCP(dport=port, flags="A", seq=100, ack=response.seq + 1)
#             send(ack, verbose=0)
#             psh = IP(dst=ip) / TCP(dport=port, sport=12345, flags="PA", seq=101, ack=response.seq + 1) / Raw(load=payload)
#             banner_response = sr1(psh, timeout=2, verbose=0)
#             if banner_response and banner_response.haslayer(Raw):
#                 try:
#                     banner = banner_response[Raw].load.decode(errors="ignore").strip()
#                     services[port] = f"Open ({banner})"
#                 except:
#                     services[port] = f"Open (Unreadable banner)"
#             else:
#                 services[port] = "Open (No banner)"
#         elif response is None:
#             services[port] = "No response"
#         else:
#             services[port] = "Closed or Filtered"
#     for port, status in services.items():
#         if "Open" in status:
#             detected[port] = status
#
#     return detected



port_service_map = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}
def detect_services(ip, cancel_event=None):
    print(f"Detecting services on {ip}...")
    services = {}
    detected = {}
    common_ports_local = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]
    for port in common_ports_local:
        if cancel_event and cancel_event.is_set():
            return {"Cancelled": True}
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)
        if response is None:
            services[port] = "No response"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                ack_packet = IP(dst=ip) / TCP(dport=port, flags="A", seq=1, ack=response.seq + 1)
                send(ack_packet, verbose=0)
                service_name = port_service_map.get(port)
                services[port] = f"Open ({service_name})"
            elif response.getlayer(TCP).flags == 0x14 or response.getlayer(TCP).flags == 0x4:
                services[port] = "Closed"
        else:
            services[port] = "Unknown response"
    for port, status in services.items():
        if "Open" in status:
            detected[port] = status
    return detected


def detect_os(ip, cancel_event=None):
    print(f"Detecting OS for {ip}...")
    if cancel_event and cancel_event.is_set():
        return "Cancelled"
    packet = scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S")
    response = scapy.sr1(packet, timeout=1, verbose=False)
    if cancel_event and cancel_event.is_set():
        return "Cancelled"
    if response:
        ttl = response.ttl
        if ttl <= 64:
            return "Linux/Unix-based OS"
        elif ttl <= 128:
            return "Windows OS"
        else:
            return "Network Device / Router"
    else:
        return "Unknown"


def find_devices(start_ip, end_ip, local_network, cancel_event=None):
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
    except ipaddress.AddressValueError:
        print("IP address Invalid")
        return []

    if start > end:
        print("IP address Invalid.")
        return []
    network = ipaddress.ip_network(local_network, strict=0)
    devices = []
    if start in network and end in network:
        ip_list = [str(ip) for ip in range(int(start), int(end) + 1)]
        arp_request = ARP(pdst=ip_list)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, unanswered = srp(packet, timeout=2, verbose=0)
        for sent, received in answered:
            if cancel_event and cancel_event.is_set():
                print("Scan cancelled by user.")
                return devices
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
                status = "Active"
            except socket.herror:
                hostname = "Unknown"
                status = "Active"
            os_guess = detect_os(received.psrc)
            services = detect_services(received.psrc)
            devices.append({
                "IP": received.psrc,
                "MAC": received.hwsrc,
                "Hostname": hostname,
                "Status": status,
                "OS": os_guess,
                "Service": services
            })
        for sent in unanswered:
            if cancel_event and cancel_event.is_set():
                print("Scan cancelled by user.")
                return devices
            ip = str(ipaddress.IPv4Address(int(sent[0].pdst)))
            devices.append({
                "IP": ip,
                "MAC": "N/A",
                "Hostname": "Unknown",
                "Status": "Inactive",
                "OS": "Unknown",
                "Service": {},
            })
    else:
        ip_list = [str(ip) for ip in range(int(start), int(end) + 1)]
        for ip in ip_list:
            if cancel_event and cancel_event.is_set():
                print("Scan cancelled by user.")
                return devices
            ip_str = str(ipaddress.IPv4Address(int(ip)))
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except socket.herror:
                hostname = "Unknown"
            services = detect_services(ip_str)
            if services:
                os_guess = detect_os(ip_str)
                devices.append({
                    "IP": ip_str,
                    "MAC": "N/A",
                    "Hostname": hostname,
                    "Status": "Active",
                    "OS": os_guess,
                    "Service": services,
                })
            else:
                devices.append({
                    "IP": ip_str,
                    "MAC": "N/A",
                    "Hostname": "Unknown",
                    "Status": "Inactive",
                    "OS": "Unknown",
                    "Service": {},
                })

    devices.sort(key=lambda x: x["Status"] == "Inactive")
    if not devices:
        print("No devices found.")
    else:
        print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'Status':<20} {'OS':<40} {'Service':<50}")
        print("-" * 180)
        for device in devices:
            services_str = '{' + ', '.join([f"{port}: {name}" for port, name in device['Service'].items()]) + '}' if \
                device['Service'] else '{}'
            print(
                f"{device['IP']:<15} {device['MAC']:<20} {device['Hostname']:<20} {device['Status']:<20} {device['OS']:<40} {services_str.center(50)}")
    return devices


def draw_network_map(devices):
    print("Drawing Network Map...")
    active_devices = [device for device in devices if device['Status'] == "Active"]
    if not active_devices:
        print("No active devices to display.")
        return
    G = nx.Graph()
    for device in active_devices:
        label = f"{device['IP']}\n{device['Hostname']}" if device['Hostname'] != "Unknown" else device['IP']
        G.add_node(label)
    gateway = None
    for device in active_devices:
        if device['IP'].endswith(".1") or device['IP'].endswith(".254"):
            gateway = f"{device['IP']}\n{device['Hostname']}" if device['Hostname'] != "Unknown" else device['IP']
            break
    if not gateway:
        gateway = "Gateway"
        G.add_node(gateway)
    for device in active_devices:
        node_label = f"{device['IP']}\n{device['Hostname']}" if device['Hostname'] != "Unknown" else device['IP']
        if node_label != gateway:
            G.add_edge(gateway, node_label)
    pos = nx.spring_layout(G, seed=42)
    fig = plt.figure(figsize=(10, 7))
    fig.canvas.manager.set_window_title("Network Map")
    nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=1500, font_size=10, font_weight="bold")
    plt.title("Network Map")
    plt.show()


