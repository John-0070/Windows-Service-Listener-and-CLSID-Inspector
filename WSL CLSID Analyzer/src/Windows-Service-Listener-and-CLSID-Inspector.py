import psutil
import socket
import time
import winreg  # Windows-only
from datetime import datetime
from tabulate import tabulate

def get_service_name(port, proto):
    """Retrieve human-readable service name for a specified port and protocol."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "Unknown Service"

def get_process_info(pid):
    """Fetch extensive process information based on Process ID (PID), including command line, memory, and CPU usage."""
    try:
        process = psutil.Process(pid)
        return {
            "PID": pid,
            "Process Name": process.name(),
            "User": process.username(),
            "Status": process.status(),
            "Creation Time": datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "Command Line": ' '.join(process.cmdline()),
            "Memory Usage": f"{process.memory_info().rss / (1024 * 1024):.2f} MB",
            "CPU Usage (%)": process.cpu_percent(interval=0.1)
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {
            "PID": pid,
            "Process Name": "N/A",
            "User": "N/A",
            "Status": "N/A",
            "Creation Time": "N/A",
            "Command Line": "N/A",
            "Memory Usage": "N/A",
            "CPU Usage (%)": "N/A"
        }

def get_clsid_for_service(service_name):
    """Retrieve the CLSID and additional details for a Windows service by name from the registry."""
    clsid_info = {
        "CLSID": "N/A",
        "Service Path": "N/A",
        "Description": "N/A"
    }
    try:
        # Access Windows services in the registry
        reg_path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as service_key:
            # Retrieve CLSID, if available
            try:
                clsid_info["CLSID"] = winreg.QueryValueEx(service_key, "Clsid")[0]
            except FileNotFoundError:
                clsid_info["CLSID"] = "Not Available"
            
            # Retrieve service executable path
            try:
                clsid_info["Service Path"] = winreg.QueryValueEx(service_key, "ImagePath")[0]
            except FileNotFoundError:
                clsid_info["Service Path"] = "Not Available"
            
            # Retrieve service description
            try:
                clsid_info["Description"] = winreg.QueryValueEx(service_key, "Description")[0]
            except FileNotFoundError:
                clsid_info["Description"] = "Not Available"
                
    except FileNotFoundError:
        pass  # Service not found in registry
    return clsid_info

def enumerate_services(detailed=False):
    """Enumerate all active listening services with absolute core details."""
    connections = psutil.net_connections(kind='inet')
    services = []

    for conn in connections:
        if conn.status == psutil.CONN_LISTEN:
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            service_name = get_service_name(conn.laddr.port, proto)
            process_info = get_process_info(conn.pid) if conn.pid else {
                "PID": "N/A", "Process Name": "N/A", "User": "N/A",
                "Status": "N/A", "Creation Time": "N/A", "Command Line": "N/A",
                "Memory Usage": "N/A", "CPU Usage (%)": "N/A"
            }
            clsid_info = get_clsid_for_service(service_name) if service_name != "Unknown Service" else {}

            service_entry = {
                "Service": service_name,
                "Port": conn.laddr.port,
                "Protocol": proto,
                "Status": conn.status,
                **process_info,
                **clsid_info  # Adds CLSID and other registry info to each entry
            }
            if detailed:
                service_entry.update({
                    "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "Socket Type": "Stream" if proto == "tcp" else "Datagram"
                })
            services.append(service_entry)

    return services

def log_services(services):
    """Log each service entry along with registry and process details."""
    with open("detailed_service_log.txt", "a") as f:
        f.write(f"\n--- Log Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        f.write(tabulate(services, headers="keys", tablefmt="grid"))
        f.write("\n")

def continuous_monitoring(interval=10, detailed=False):
    """Continuously monitor, log services, and output CLSID information at specified intervals."""
    try:
        while True:
            services = enumerate_services(detailed=detailed)
            if services:
                print(tabulate(services, headers="keys", tablefmt="grid"))
                log_services(services)
            else:
                print("No listening services found.")
            print("\nWaiting for the next monitoring interval...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    print("Choose an option:")
    print("1. Single scan")
    print("2. Continuous monitoring")

    choice = input("Enter choice (1/2): ")
    if choice == '1':
        detailed = input("Show detailed information? (y/n): ").strip().lower() == 'y'
        services = enumerate_services(detailed=detailed)
        if services:
            print(tabulate(services, headers="keys", tablefmt="grid"))
        else:
            print("No listening services found.")
    elif choice == '2':
        interval = input("Enter monitoring interval in seconds (default 10): ")
        detailed = input("Show detailed information? (y/n): ").strip().lower() == 'y'
        interval = int(interval) if interval.isdigit() else 10
        continuous_monitoring(interval, detailed=detailed)
