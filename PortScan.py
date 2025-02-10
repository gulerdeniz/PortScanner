import nmap
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter.ttk import Progressbar
from scapy.all import *
from scapy.layers.inet import IP, TCP


logging.basicConfig(level=logging.INFO, format='%(message)s')


nm = nmap.PortScanner()


def get_service_name(port):
    """Get service name from port number."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown Service"


def ping_host(host):
    """Check if the host is active using ICMP ping."""
    param = '-n' if os.name == 'nt' else '-c'
    command = ['ping', param, '1', host]
    return subprocess.call(command) == 0


def ping_host_gui():
    target = entry_target.get()
    if not target:
        messagebox.showerror("Input Error", "Please enter a target IP/Domain to ping.")
        return

    # ping
    try:
        progress_bar.start()
        if ping_host(target):
            text_result.delete(1.0, tk.END)
            text_result.insert(tk.END, f"Host {target} is reachable.\n")
        else:
            text_result.delete(1.0, tk.END)
            text_result.insert(tk.END, f"Host {target} is not reachable.\n")
        progress_bar.stop()
    except Exception as e:
        progress_bar.stop()
        messagebox.showerror("Error", f"Error while pinging the host: {str(e)}")


def scan_tcp_port(host, port):
    """Scan TCP port SOCK_STREAM=TCP"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection
        result = sock.connect_ex((host, port))
        if result == 0:
            service = get_service_name(port)
            return f"Port {port} (TCP) is open - {service}"
        else:
            return f"Port {port} (TCP) is closed"
    except Exception as e:
        return f"Error scanning port {port}: {e}"
    finally:
        if sock:
            sock.close()


def scan_udp_port(target, port):
    """Scan UDP port SOCK_DGRAM=UDP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)  # timeout   

    try:
        if port == 53:
            # DNS 2/2/2/2/2 behaviour ID/FLAG/QUESTION/ANSWER....
            dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x04test\x00\x00\x01\x00\x01"
            sock.sendto(dns_query, (target, port))
        else:
            # Send a dummy packet to the port
            sock.sendto(b"", (target, port))

        # Try to receive the response
        data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
        return f"Port {port} (UDP) is open. Response from {addr}"

    except socket.timeout:
        # If no response is received, assume the port is closed or filtered
        return f"Port {port} (UDP) is closed or filtered (timeout)"

    except Exception as e:
        # Handle any other exceptions (e.g., network unreachable)
        return f"Error scanning port {port} (UDP): {str(e)}"

    finally:
        sock.close()  # Make sure the socket is closed after the scan


def reset_half_open(ip, ports):
    """Reset half-open connections AR=ACK+RST"""
    sr(IP(dst=ip)/TCP(dport=ports, flags='AR'), timeout=1)


def is_open_syn(ip, ports, timeout=0.2):
    """SYN scan s=syn"""
    results = {port: None for port in ports}
    to_reset = []
    p = IP(dst=ip)/TCP(dport=ports, flags='S')  # Forging SYN packet
    answers, un_answered = sr(p, timeout=timeout)  # Send the packets
    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer.flags == 0x12:  # SYN-ACK
            to_reset.append(tcp_layer.sport)
            service_name = get_service_name(tcp_layer.sport)  # Get service name
            results[tcp_layer.sport] = f"open - {service_name}"
        elif tcp_layer.flags == 0x14:  # RST
            results[tcp_layer.sport] = False

    # reset ports
    reset_half_open(ip, to_reset)
    return results


def parse_ports(port_range):
    """Parse port range into a list or do perform single port"""
    ports = []
    try:
        # Split the input range
        parts = port_range.split('-')
        if len(parts) == 2:
            start_port = int(parts[0])
            end_port = int(parts[1])
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Invalid port range. Ports must be between 1 and 65535.")
            ports = list(range(start_port, end_port + 1))
        else:
            # If the range is just a single port number
            port = int(parts[0])
            if port < 1 or port > 65535:
                raise ValueError("Invalid port. Ports must be between 1 and 65535.")
            ports = [port]
    except ValueError as e:
        messagebox.showerror("Input Error", f"Invalid port range: {str(e)}")
    return ports


def syn_scan_gui():
    target = entry_target.get()
    port_range = entry_ports.get()

    if not target or not port_range:
        messagebox.showerror("Input Error", "Please enter both target and port range!")
        return

    # Parse the port range string
    ports = parse_ports(port_range)
    if not ports:
        return

    # SYN scan
    def syn_scan():
        try:
            progress_bar.start()

            results = is_open_syn(target, ports)  # Perform SYN scan
            text_result.delete(1.0, tk.END)  # Clear previous results

            # Display results
            for port, status in results.items():
                status_str = "open" if status else "closed"
                text_result.insert(tk.END, f"Port {port} is {status_str}.\n")

            progress_bar.stop()

        except Exception as e:
            progress_bar.stop()
            messagebox.showerror("Error", f"Error during SYN scan: {str(e)}")

    threading.Thread(target=syn_scan, daemon=True).start()


def reset_half_open_gui():
    target = entry_target.get()
    port_range = entry_ports.get()

    if not target or not port_range:
        messagebox.showerror("Input Error", "Please enter both target and port range!")
        return

    # Parse the port range string
    ports = parse_ports(port_range)
    if not ports:
        return

    # reset half-open connections
    def reset_connections():
        try:
            progress_bar.start()

            reset_half_open(target, ports)  # Reset

            text_result.delete(1.0, tk.END)  # Clear results
            text_result.insert(tk.END, f"Half-open connections for ports {ports} have been reset.\n")

            progress_bar.stop()

        except Exception as e:
            progress_bar.stop()
            messagebox.showerror("Error", f"Error resetting half-open connections: {str(e)}")

    threading.Thread(target=reset_connections, daemon=True).start()


def scan_tcp_port_gui():
    target = entry_target.get()
    port_range = entry_ports.get()

    if not target or not port_range:
        messagebox.showerror("Input Error", "Please enter both target and port range!")
        return

    # Parse the port range string
    ports = parse_ports(port_range)
    if not ports:
        return

    def tcp_scan():
        try:
            progress_bar.start()

            results = []
            for port in ports:
                result = scan_tcp_port(target, port)  # Scan the TCP port
                results.append(result)

            text_result.delete(1.0, tk.END)  # Clear previous results
            for result in results:
                text_result.insert(tk.END, f"{result}\n")

            progress_bar.stop()

        except Exception as e:
            progress_bar.stop()
            messagebox.showerror("Error", f"Error during TCP scan: {str(e)}")

    threading.Thread(target=tcp_scan, daemon=True).start()


def scan_udp_port_gui():
    target = entry_target.get()
    port_range = entry_ports.get()

    if not target or not port_range:
        messagebox.showerror("Input Error", "Please enter both target and port range!")
        return

    # Parse the port range string
    ports = parse_ports(port_range)
    if not ports:
        return

    # Function to perform UDP scan
    def udp_scan():
        try:
            progress_bar.start()

            results = []
            for port in ports:
                result = scan_udp_port(target, port)  # Scan the UDP port
                results.append(result)

            text_result.delete(1.0, tk.END)  # Clear previous results
            for result in results:
                text_result.insert(tk.END, f"{result}\n")

            progress_bar.stop()

        except Exception as e:
            progress_bar.stop()
            messagebox.showerror("Error", f"Error during UDP scan: {str(e)}")

    # Run the scan in a separate thread
    threading.Thread(target=udp_scan, daemon=True).start()


def clear_results():
    """Clear the results"""
    text_result.delete(1.0, tk.END)


def save_results():
    """Save the results"""
    results = text_result.get(1.0, tk.END).strip()
    if not results:
        messagebox.showwarning("No Results", "There are no results to save!")
        return

    # Open file dialog to choose save location
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(results)
        messagebox.showinfo("Saved", "Results saved successfully!")

# Main window


root = tk.Tk()
root.title("Python Port Scanner")
root.geometry("600x500")

# Target IP/Domain
label_target = tk.Label(root, text="Target IP/Domain:")
label_target.pack(pady=5)
entry_target = tk.Entry(root, width=50)
entry_target.pack(pady=5)

# Port Range
label_ports = tk.Label(root, text="Port Range (e.g., 1-1024):")
label_ports.pack(pady=5)
entry_ports = tk.Entry(root, width=50)
entry_ports.pack(pady=5)

# Buttons
btn_ping = tk.Button(root, text="Ping Host", command=ping_host_gui)
btn_ping.pack(pady=5)

btn_tcp_scan = tk.Button(root, text="Scan TCP Port", command=scan_tcp_port_gui)
btn_tcp_scan.pack(pady=5)

btn_udp_scan = tk.Button(root, text="Scan UDP Port", command=scan_udp_port_gui)
btn_udp_scan.pack(pady=5)

# SYN scan and Reset Half-Open
btn_syn_scan = tk.Button(root, text="SYN Scan", command=syn_scan_gui)
btn_syn_scan.pack(pady=5)

btn_reset_half_open = tk.Button(root, text="Reset Half-Open Connections", command=reset_half_open_gui)
btn_reset_half_open.pack(pady=5)

btn_clear = tk.Button(root, text="Clear Results", command=clear_results)
btn_clear.pack(pady=5)

btn_save = tk.Button(root, text="Save Results", command=save_results)
btn_save.pack(pady=5)

# Progress Bar
progress_bar = Progressbar(root, length=200, mode='indeterminate')
progress_bar.pack(pady=10)

# Scrolled Text Area for results
text_result = scrolledtext.ScrolledText(root, width=70, height=15)
text_result.pack(pady=10)

# Start the main event loop
root.mainloop()
