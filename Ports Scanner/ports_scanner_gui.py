import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from ports_scanner_source_code import *

cancel_event_network = None
cancel_event_ip = None
cancel_event_firewall = None

def detect_firewall_custom(ip, ports, cancel_event=None):
    results = []
    for port in ports:
        if cancel_event and cancel_event.is_set():
            return "Scan cancelled by user."
        try:
            res = detect_firewall(ip, port, cancel_event)
            results.append(res)
        except Exception as e:
            results.append(f"Port {port}: Error: {e}")
    return "\n".join(results)


def run_firewall_scan():
    result_firewall.delete(1.0, tk.END)
    target_ip = entry_target_ip_firewall.get().strip()
    port_mode = port_type_var_firewall.get()
    if not target_ip:
        result_firewall.insert(tk.END, "[!] Please enter a target IP.\n")
        return

    global cancel_event_firewall
    cancel_event_firewall = threading.Event()

    def scan():
        if port_mode == "Port List":
            port = entry_one_port_firewall.get()
            try:
                ports = [int(p.strip()) for p in port.split(",") if p.strip().isdigit()]
                if not ports:
                    raise ValueError
            except ValueError:
                result_ip.insert(tk.END, "[!] Invalid port.\n")
                return
            result_firewall.insert(tk.END,
                                   f"Detecting Firewall on {target_ip} at port {', '.join(map(str, ports))}...\n\n")

        else:
            try:
                start_port = int(entry_from_port_firewall.get())
                end_port = int(entry_to_port_firewall.get())
            except ValueError:
                result_firewall.insert(tk.END, "[!] Invalid port range.\n")
                return
            if start_port > end_port:
                result_firewall.insert(tk.END, "[!] Start port must be <= end port.\n")
                return
            result_firewall.insert(tk.END,
                                   f"Detecting Firewall on {target_ip} from port {start_port} to {end_port}...\n\n")
            ports = list(range(start_port, end_port + 1))

        res = detect_firewall_custom(target_ip, ports, cancel_event_firewall)
        result_firewall.insert(tk.END, res)

    threading.Thread(target=scan).start()


def cancel_firewall_scan():
    global cancel_event_firewall
    if cancel_event_firewall is not None:
        cancel_event_firewall.set()

def load_services(file_path="nmap-services.txt"):
    services = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.startswith('#') or line.strip() == '':
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    port_proto = parts[1]
                    if '/' in port_proto:
                        port, proto = port_proto.split('/')
                        services[(int(port), proto)] = name
    except FileNotFoundError:
        pass
    return services


services = load_services()


def cancel_single_ip_scan():
    global cancel_event_ip
    if cancel_event_ip is not None:
        cancel_event_ip.set()


def call_scan_method(method, ip, ports, port_type, cancel_event):
    ans = []
    closed_count = 0
    filtered_count = 0

    try:
        scan_function = globals()[f"{method.lower()}_scan"]
    except KeyError:
        return f"[!] Scan type not supported: {method}\n"

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        if cancel_event.is_set():
            return "Scan cancelled by user."
        results = list(executor.map(lambda port: scan_function(ip, port, cancel_event), ports))

    output = ""
    for port, status in results:
        service_name = services.get((port, "tcp"), "Unknown")

        if port_type == "Port List":
            ans.append((port, f"Port {port} ({service_name}): {status}"))
        else:
            if "Open" in status or "Open|Filtered" in status:
                ans.append((port, f"Port {port} ({service_name}): {status}"))
            elif "Filtered" in status:
                filtered_count += 1
            elif "Closed" in status:
                closed_count += 1

    if port_type == "Ports Range":
        output += f"Not Shown: {filtered_count} filtered ports\n"
        output += f"Not Shown: {closed_count} closed ports\n"

    for _, line in sorted(ans, key=lambda x: x[0]):
        output += line + "\n"

    output += "\n\nScan complete."
    return output


def run_single_ip_scan():
    result_ip.delete(1.0, tk.END)
    target_ip = entry_target_ip2.get().strip()
    method = method_var.get()
    port_type = port_type_var.get()
    if not target_ip:
        result_ip.insert(tk.END, "[!] Please enter a target IP.\n")
        return

    global cancel_event_ip
    cancel_event_ip = threading.Event()

    def scan():
        if port_type == "Port List":
            port = entry_one_port.get()
            try:
                ports = [int(p.strip()) for p in port.split(",") if p.strip().isdigit()]
                if not ports:
                    raise ValueError
            except ValueError:
                result_ip.insert(tk.END, "[!] Invalid port.\n")
                return
            result_ip.insert(tk.END,
                             f"Scanning {target_ip} on port {', '.join(map(str, ports))} using {method} scan...\n\n")
            result = call_scan_method(method, target_ip, ports, "Port List", cancel_event_ip)
            if cancel_event_ip.is_set():
                result_ip.delete("1.0", tk.END)
                result_ip.insert(tk.END, "Scan cancelled by user.\n")
                return
            result_ip.insert(tk.END, result)
        elif port_type == "Ports Range":
            try:
                start_port = int(entry_from_port.get())
                end_port = int(entry_to_port.get())
            except ValueError:
                result_ip.insert(tk.END, "[!] Invalid port range.\n")
                return
            if start_port > end_port:
                result_ip.insert(tk.END, "[!] Start port must be <= end port.\n")
                return
            result_ip.insert(tk.END, f"Target IP: {target_ip}\n")
            result_ip.insert(tk.END, f"Start port: {start_port}\n")
            result_ip.insert(tk.END, f"End port: {end_port}\n")
            result_ip.insert(tk.END, f"Scan type : {method}\n")
            result_ip.insert(tk.END,
                             f"Scanning {target_ip} from port {start_port} to {end_port} using {method} scan...\n\n")
            ports = list(range(start_port, end_port + 1))
            result = call_scan_method(method, target_ip, ports, "Ports Range", cancel_event_ip)
            if cancel_event_ip.is_set():
                result_ip.delete("1.0", tk.END)
                result_ip.insert(tk.END, "Scan cancelled by user.\n")
                return
            result_ip.insert(tk.END, result)
        else:
            result_ip.insert(tk.END, "[!] Please select a valid port scan type.\n")

    threading.Thread(target=scan).start()


def update_port_fields():
    if port_type_var.get() == "Port List":
        lbl_from_port.grid_remove()
        entry_from_port.grid_remove()
        lbl_to_port.grid_remove()
        entry_to_port.grid_remove()
        lbl_one_port.grid(row=3, column=2, padx=5, pady=5, sticky="e")
        entry_one_port.grid(row=3, column=3, padx=5, pady=5, sticky="w")
    else:
        lbl_one_port.grid_remove()
        entry_one_port.grid_remove()
        lbl_from_port.grid(row=3, column=2, padx=5, pady=5, sticky="e")
        entry_from_port.grid(row=3, column=3, padx=5, pady=5, sticky="w")
        lbl_to_port.grid(row=3, column=4, padx=5, pady=5, sticky="e")
        entry_to_port.grid(row=3, column=5, padx=5, pady=5, sticky="w")


def update_port_fields_firewall():
    if port_type_var_firewall.get() == "Port List":
        lbl_from_port_firewall.grid_remove()
        entry_from_port_firewall.grid_remove()
        lbl_to_port_firewall.grid_remove()
        entry_to_port_firewall.grid_remove()
        lbl_one_port_firewall.grid(row=3, column=2, padx=5, pady=5, sticky="e")
        entry_one_port_firewall.grid(row=3, column=3, padx=5, pady=5, sticky="w")
    else:
        lbl_one_port_firewall.grid_remove()
        entry_one_port_firewall.grid_remove()
        lbl_from_port_firewall.grid(row=3, column=2, padx=5, pady=5, sticky="e")
        entry_from_port_firewall.grid(row=3, column=3, padx=5, pady=5, sticky="w")
        lbl_to_port_firewall.grid(row=3, column=4, padx=5, pady=5, sticky="e")
        entry_to_port_firewall.grid(row=3, column=5, padx=5, pady=5, sticky="w")


root = tk.Tk()
root.title("Ports Scanner")
root.geometry("800x700")

logo = tk.PhotoImage(file="Ports Scanner.png")
root.iconphoto(True, logo)

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# --- Tab 1: Single IP Scan ---
tab1 = ttk.Frame(notebook)
notebook.add(tab1, text="Single IP Scan")

lbl_target_ip2 = ttk.Label(tab1, text="Target IP:")
lbl_target_ip2.grid(row=2, column=0, sticky="w", padx=5, pady=5)
entry_target_ip2 = ttk.Entry(tab1, width=30)
entry_target_ip2.grid(row=2, column=1, sticky="w", padx=5, pady=5)

port_type_var = tk.StringVar(value="Port List")
ttk.Radiobutton(tab1, text="Port List", variable=port_type_var, value="Port List", command=update_port_fields).grid(row=2,column=2,padx=5,pady=5,sticky="w")
ttk.Radiobutton(tab1, text="Ports Range", variable=port_type_var, value="Ports Range", command=update_port_fields).grid(
    row=2, column=3, padx=5, pady=5, sticky="w")

lbl_scan_type = ttk.Label(tab1, text="Type Scan:")
lbl_scan_type.grid(row=3, column=0, padx=5, pady=5, sticky="w")
method_var = tk.StringVar(value="SYN")
method_menu = ttk.Combobox(tab1, textvariable=method_var, values=["SYN", "TCP_CONNECT", "XMAS", "FIN", "NULL", "UDP"],
                           width=14,
                           state="readonly")
method_menu.grid(row=3, column=1, padx=5, pady=5, sticky="w")

lbl_one_port = ttk.Label(tab1, text="Port List:")
entry_one_port = ttk.Entry(tab1, width=10)
lbl_from_port = ttk.Label(tab1, text="From:")
entry_from_port = ttk.Entry(tab1, width=10)
lbl_to_port = ttk.Label(tab1, text="To:")
entry_to_port = ttk.Entry(tab1, width=10)
update_port_fields()

ttk.Button(tab1, text="Cancel Scan", width=15, command=cancel_single_ip_scan).grid(row=9, column=4, padx=5, pady=5)
ttk.Button(tab1, text="Scan", width=15, command=run_single_ip_scan).grid(row=9, column=5, padx=5, pady=5)

ttk.Label(tab1, text="Result").grid(row=10, column=0, columnspan=8, sticky="w", padx=5, pady=5)
tab1.grid_rowconfigure(11, weight=1)
for col in range(8):
    tab1.grid_columnconfigure(col, weight=1)
result_ip = ScrolledText(tab1, height=15, width=90)
result_ip.grid(row=11, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")

# --- Tab 2: Network Scan ---
tab2 = ttk.Frame(notebook)
notebook.add(tab2, text="Network Scan")

lbl_start_ip = ttk.Label(tab2, text="Start IP:")
lbl_start_ip.grid(row=2, column=0, sticky="w", padx=5, pady=5)
entry_start_ip = ttk.Entry(tab2, width=30)
entry_start_ip.grid(row=2, column=1, sticky="w", padx=5, pady=5)

lbl_end_ip = ttk.Label(tab2, text="End IP:")
lbl_end_ip.grid(row=3, column=0, sticky="w", padx=5, pady=5)
entry_end_ip = ttk.Entry(tab2, width=30)
entry_end_ip.grid(row=3, column=1, sticky="w", padx=5, pady=5)


lbl_local_network = ttk.Label(tab2, text="Local Network:")
lbl_local_network.grid(row=4, column=0, sticky="w", padx=5, pady=5)
entry_local_network = ttk.Entry(tab2, width=30)
entry_local_network.grid(row=4, column=1, sticky="w", padx=5, pady=5)

ttk.Button(tab2, text="Cancel Scan", width=15, command=lambda: cancel_network_scan()).grid(row=9, column=4, padx=5,pady=5)
ttk.Button(tab2, text="Scan", width=15, command=lambda: threading.Thread(target=run_network_scan).start()).grid(row=9,column=5,padx=5,pady=5)

os_var = tk.BooleanVar()
service_var = tk.BooleanVar()
mac_var = tk.BooleanVar()
network_map = tk.BooleanVar()

ttk.Checkbutton(tab2, text="MAC Address", variable=mac_var).grid(row=5, column=0, sticky="w", padx=5, pady=5)
ttk.Checkbutton(tab2, text="OS", variable=os_var).grid(row=6, column=0, sticky="w", padx=5, pady=5)
ttk.Checkbutton(tab2, text="Service", variable=service_var).grid(row=7, column=0, sticky="w", padx=5, pady=5)
ttk.Checkbutton(tab2, text="Network Map", variable=network_map).grid(row=8, column=0, sticky="w", padx=5, pady=5)

ttk.Label(tab2, text="Result").grid(row=10, column=0, columnspan=8, sticky="w", padx=5, pady=5)
tab2.grid_rowconfigure(11, weight=1)
for col in range(8):
    tab2.grid_columnconfigure(col, weight=1)
text_frame = tk.Frame(tab2)
text_frame.grid(row=11, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")
result_tab2 = tk.Text(text_frame, height=15, width=90, wrap="none")
result_tab2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar_y = tk.Scrollbar(text_frame, orient=tk.VERTICAL, command=result_tab2.yview)
scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
scrollbar_x = tk.Scrollbar(tab2, orient=tk.HORIZONTAL, command=result_tab2.xview)
scrollbar_x.grid(row=12, column=0, columnspan=8, padx=5, sticky="ew")
result_tab2.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

# --- Tab 3: Shodan Lookup ---
tab3 = ttk.Frame(notebook)
notebook.add(tab3, text="Shodan Lookup")
lbl_target_shodan = ttk.Label(tab3, text="Target IP for Shodan:")
lbl_target_shodan.grid(row=2, column=0, sticky="w", padx=5, pady=5)
entry_target_shodan = ttk.Entry(tab3, width=30)
entry_target_shodan.grid(row=2, column=1, sticky="w", padx=5, pady=5)
ttk.Button(tab3, text="Scan", width=15, command=lambda: threading.Thread(target=run_shodan_scan).start()).grid(row=9,
                                                                                                               column=5,
                                                                                                               padx=5,
                                                                                                               pady=5)
ttk.Label(tab3, text="Result").grid(row=10, column=0, columnspan=8, sticky="w", padx=5, pady=5)
tab3.grid_rowconfigure(11, weight=1)
for col in range(8):
    tab3.grid_columnconfigure(col, weight=1)
result_shodan = ScrolledText(tab3, height=15, width=90)
result_shodan.grid(row=11, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")

# --- Tab 4: Detect Firewall ---
tab4 = ttk.Frame(notebook)
notebook.add(tab4, text="Detect Firewall")
lbl_target_ip_firewall = ttk.Label(tab4, text="Target IP:")
lbl_target_ip_firewall.grid(row=2, column=0, sticky="w", padx=5, pady=5)
entry_target_ip_firewall = ttk.Entry(tab4, width=30)
entry_target_ip_firewall.grid(row=2, column=1, sticky="w", padx=5, pady=5)
port_type_var_firewall = tk.StringVar(value="Port List")
ttk.Radiobutton(tab4, text="Port List", variable=port_type_var_firewall, value="Port List",
                command=update_port_fields_firewall).grid(row=2, column=2, padx=5, pady=5, sticky="w")
ttk.Radiobutton(tab4, text="Ports Range", variable=port_type_var_firewall, value="Ports Range",
                command=update_port_fields_firewall).grid(row=2, column=3, padx=5, pady=5, sticky="w")

lbl_one_port_firewall = ttk.Label(tab4, text="Port list:")
entry_one_port_firewall = ttk.Entry(tab4, width=10)
lbl_from_port_firewall = ttk.Label(tab4, text="From:")
entry_from_port_firewall = ttk.Entry(tab4, width=10)
lbl_to_port_firewall = ttk.Label(tab4, text="To:")
entry_to_port_firewall = ttk.Entry(tab4, width=10)
update_port_fields_firewall()

ttk.Button(tab4, text="Cancel Scan", width=15, command=cancel_firewall_scan).grid(row=9, column=4, padx=5, pady=5)
ttk.Button(tab4, text="Scan", width=15, command=run_firewall_scan).grid(row=9, column=5, padx=5, pady=5)

ttk.Label(tab4, text="Result").grid(row=10, column=0, columnspan=8, sticky="w", padx=5, pady=5)
tab4.grid_rowconfigure(11, weight=1)
for col in range(8):
    tab4.grid_columnconfigure(col, weight=1)
result_firewall = ScrolledText(tab4, height=15, width=90)
result_firewall.grid(row=11, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")



def run_network_scan():
    result_tab2.delete(1.0, tk.END)
    start_ip = entry_start_ip.get().strip()
    end_ip = entry_end_ip.get().strip()
    local_network_input = entry_local_network.get().strip()
    if local_network_input:
        local_network = local_network_input
    else:
        try:
            ip_parts = start_ip.split('.')
            if len(ip_parts) == 4:
                local_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            else:
                local_network = "0.0.0.0/0"
        except Exception as e:
            local_network = "0.0.0.0/0"

    if not start_ip or not end_ip:
        result_tab2.insert(tk.END, "[!] Please enter Start IP and End IP.\n")
        return

    global cancel_event_network
    cancel_event_network = threading.Event()

    def scan():
        result_tab2.insert(tk.END, f"Scanning IP range: {start_ip} to {end_ip} on network {local_network}...\n\n")
        devices = find_devices(start_ip, end_ip, local_network, cancel_event_network)
        if cancel_event_network.is_set():
            result_tab2.delete("1.0", tk.END)
            result_tab2.insert(tk.END, "Scan cancelled by user.\n")
            return
        if not devices:
            result_tab2.insert(tk.END, "No devices found.\n")
            return

        devices.sort(key=lambda x: x["Status"] == "Inactive")
        header = f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'Status':<10} {'OS':<40} {'Service':<50}\n"
        result_tab2.insert(tk.END, header)
        result_tab2.insert(tk.END, "-" * 150 + "\n")

        for device in devices:
            ip = device['IP']
            mac = device.get('MAC', 'N/A')
            hostname = device.get('Hostname', 'N/A')
            status = device.get('Status', 'N/A')
            os_guess = device.get('OS', 'N/A')
            if service_var.get():
                services = '{' + ', '.join([f"{port}: {name}" for port, name in device.get('Service').items()]) + '}' if \
                    device['Service'] else '{}'
            else:
                services = "N/A"
            line = f"{ip:<15} {mac:<20} {hostname:<20} {status:<10} {os_guess:<20} {services:<50}\n"
            result_tab2.insert(tk.END, line)

        if network_map.get():
            draw_network_map(devices)

    threading.Thread(target=scan).start()


def run_shodan_scan():
    result_shodan.delete(1.0, tk.END)
    ip = entry_target_shodan.get().strip()
    if not ip:
        result_shodan.insert(tk.END, "[!] Please enter IP.\n")
        return

    def lookup():
        result_shodan.insert(tk.END, f"[+] Looking up Shodan for IP: {ip}...\n\n")
        info = shodan_lookup(ip)
        result_shodan.insert(tk.END, info)

    threading.Thread(target=lookup).start()


def cancel_network_scan():
    global cancel_event_network
    if cancel_event_network is not None:
        cancel_event_network.set()


# Khởi tạo giao diện
update_port_fields()
update_port_fields_firewall()
root.mainloop()
