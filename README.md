# Windows Service Listener and CLSID Inspector

A comprehensive diagnostic utility for Windows systems that enumerates all active network listening services, fetches corresponding process and registry information (including CLSIDs), and logs everything in a detailed, structured format.

## Features

- Lists all open TCP/UDP ports in LISTEN state
- Retrieves:
  - Process ID, name, status, and memory usage
  - Full command line and user context
  - Service executable path and CLSID from registry
- Optionally shows detailed socket info (local/remote addresses, protocol type)
- Continuous monitoring mode with interval-based snapshots
- Logs results to `detailed_service_log.txt` with timestamps

## Use Cases

- Malware analysis and forensics
- System hardening and enumeration
- Network or host-based threat hunting
- CLSID/DLL correlation for COM/DCOM diagnostics

# Limitations
- Windows-only: Uses winreg and psutil Windows-specific implementations.

- Permission Required: Elevated privileges may be needed to access some service/process details.

- CLSID Lookup: Only services present in HKLM\SYSTEM\CurrentControlSet\Services\ with valid Clsid keys are resolved.

- Remote Address Handling: Remote address may appear as N/A for LISTEN-only sockets.

- Performance: For systems with a large number of services or in continuous mode, ensure sufficient memory and disk space for logging.

# To Be Added
- Export to CSV, JSON, or SQLite

- Alerting for newly spawned or terminated services

- CLI flags for automation/integration (e.g., --interval, --detailed)

- Integration with Event Log or WMI for additional insight

- TLS detection on open ports

- CLSID-to-DLL resolution with COM inspection

- GUI dashboard (Tkinter or web-based)
