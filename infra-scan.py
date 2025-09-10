#!/usr/bin/env python3

import os
import sys
import argparse
import glob
import signal
import ipaddress
import shutil
import json
from datetime import datetime
from pathlib import Path

try:
    import nmap
except ImportError:
    print("Error: python-nmap module not found")
    print("Install with: pip install python-nmap")
    sys.exit(1)

try:
    import openpyxl
    from openpyxl.styles import Font, Alignment
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


class NetworkScanner:
    """
    A class to perform sequential network scanning using nmap.
    It supports session management, splitting large networks, and result consolidation.
    """
    # Constants
    CSV_HEADER = 'host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe'
    SESSIONS_DIR = 'sessions'
    SESSION_DATA_FILE = 'session_data.json'
    NETS_FILE = 'nets.txt'
    SCAN_SUMMARY_FILE = 'scan_summary.txt'
    PROCESSED_MARKER_PREFIX = '.processed_'
    def __init__(self, session_id=None, service_scan=False, tcp_top_ports=None, udp_top_ports=400, output_dir='results', generate_excel=False):
        """
        Initialises the NetworkScanner.

        Args:
            session_id (str, optional): A specific ID for the session. If None, one is generated.
            service_scan (bool): If True, performs a service version detection scan (-sV).
            tcp_top_ports (int, optional): Scans the top N TCP ports. If None, scans all ports.
            udp_top_ports (int): Scans the top N UDP ports.
            output_dir (str): Output directory for real-time result copying.
            generate_excel (bool): If True, generates Excel files from CSV results.
        """
        self.shutdown_requested = False
        
        # Session and output configuration
        self.session_id = session_id or self._get_timestamp('session')
        os.makedirs(self.SESSIONS_DIR, exist_ok=True)
        self.temp_dir = os.path.join(self.SESSIONS_DIR, self.session_id)
        
        # Real-time result copying
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Progress tracking
        self.total_ranges = 0
        self.completed_ranges = 0
        
        # Nmap configuration
        self.nm = nmap.PortScanner()
        self.service_scan = service_scan
        self.tcp_top_ports = tcp_top_ports
        self.udp_top_ports = udp_top_ports
        
        # Excel generation configuration
        self.generate_excel = generate_excel

        # **FIX:** Initialize session attributes to prevent AttributeErrors on early exit
        self.subnet_mapping = {}
        self.split_to_original = {}
        self.completed_subnets = {}
        
        # Static timestamps for consistent scan-level operations
        self.session_create_time = self._get_timestamp('full')
        self.scan_start_time = None  # Set when scanning actually begins
        
    
    def log_message(self, message, group_dir=None, force=False):
        """Prints a timestamped log message."""
        # Suppress certain messages during shutdown unless forced
        if self.shutdown_requested and not force:
            if any(x in message for x in ['ERROR -', 'Skipping', 'Completed', 'Finished all scans']):
                return
        
        timestamp = self._get_timestamp('log')
        if group_dir:
            print(f"[{timestamp}] {group_dir}: {message}")
        else:
            print(f"[{timestamp}] {message}")
    
    def split_large_networks(self, ip_ranges):
        """Splits large networks (/24 or larger) into /27 blocks for parallel scanning."""
        self.subnet_mapping = {}  # original -> list of splits
        self.split_to_original = {}  # split -> original
        split_ranges = []
        
        for ip_range in ip_ranges:
            try:
                # Handle CIDR notation
                if '/' in ip_range:
                    network = ipaddress.IPv4Network(ip_range, strict=False)
                    
                    # If network is /24 or larger, split it for faster scanning
                    if network.prefixlen <= 24:
                        self.log_message(f"Splitting large network {network} into /27 blocks")
                        splits = []
                        for subnet in network.subnets(new_prefix=27):
                            subnet_str = str(subnet)
                            splits.append(subnet_str)
                            split_ranges.append(subnet_str)
                            self.split_to_original[subnet_str] = str(network)
                        self.subnet_mapping[str(network)] = splits
                    else:
                        # Small network, no splitting needed
                        network_str = str(network)
                        split_ranges.append(network_str)
                        self.subnet_mapping[network_str] = [network_str]
                        self.split_to_original[network_str] = network_str
                else:
                    # Handle IP ranges like 192.168.1.1-50 or single IPs
                    split_ranges.append(ip_range)
                    self.subnet_mapping[ip_range] = [ip_range]
                    self.split_to_original[ip_range] = ip_range
                    
            except ipaddress.AddressValueError as e:
                self.log_message(f"Warning: Invalid IP range '{ip_range}': {e}")
                # Still add it in case it's a valid nmap range format
                split_ranges.append(ip_range)
                self.subnet_mapping[ip_range] = [ip_range]
                self.split_to_original[ip_range] = ip_range
        
        return split_ranges
    
    def create_session_structure(self, split_ranges):
        """Creates a temporary directory structure for the scanning session."""
        os.makedirs(self.temp_dir, exist_ok=True)
        self.log_message(f"Created session directory: {self.temp_dir}")
        
        # Prepare session metadata for saving
        session_data = {
            'subnet_mapping': self.subnet_mapping,
            'split_to_original': self.split_to_original,
            'completed_subnets': {original: False for original in self.subnet_mapping},
            'created': datetime.now().isoformat(),
            'session_id': self.session_id,
            'service_scan': self.service_scan,
            'tcp_top_ports': self.tcp_top_ports,
            'udp_top_ports': self.udp_top_ports
        }
        
        # Save session metadata to a JSON file for resuming
        session_file = os.path.join(self.temp_dir, self.SESSION_DATA_FILE)
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        # Create single subdirectory for sequential processing
        net_dirs = []
        net_name = "net001"
        net_path = os.path.join(self.temp_dir, net_name)
        os.makedirs(net_path, exist_ok=True)
        
        # Put all ranges in a single nets.txt file
        nets_file = os.path.join(net_path, self.NETS_FILE)
        with open(nets_file, 'w') as f:
            f.write(f"# Auto-generated net {net_name}\n")
            f.write(f"# Created: {self.session_create_time}\n")
            for ip_range in split_ranges:
                f.write(f"{ip_range}\n")
        
        net_dirs.append(net_path)
        self.log_message(f"Created {net_name} with {len(split_ranges)} IP ranges")
        
        return net_dirs

    def _load_session_data(self):
        """Loads session data from the session_data.json file."""
        session_file = os.path.join(self.temp_dir, self.SESSION_DATA_FILE)
        if not os.path.exists(session_file):
            self.log_message("Warning: No session data found, treating as legacy session")
            self.subnet_mapping = {}
            self.split_to_original = {}
            self.completed_subnets = {}
            return False

        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
                self.subnet_mapping = session_data.get('subnet_mapping', {})
                self.split_to_original = session_data.get('split_to_original', {})
                self.completed_subnets = session_data.get('completed_subnets', {})
                # Restore scan settings from the session file
                if 'service_scan' in session_data:
                    self.service_scan = session_data['service_scan']
                if 'tcp_top_ports' in session_data:
                    self.tcp_top_ports = session_data['tcp_top_ports']
                if 'udp_top_ports' in session_data:
                    self.udp_top_ports = session_data['udp_top_ports']
                self.log_message(f"Loaded session data with {len(self.subnet_mapping)} original subnets")
            return True
        except Exception as e:
            self.log_message(f"Warning: Could not load session data: {e}")
            self.subnet_mapping = {}
            self.split_to_original = {}
            self.completed_subnets = {}
            return False

    def resume_session(self, session_id):
        """Resumes a previous scanning session by loading its state."""
        session_dir = os.path.join(self.SESSIONS_DIR, session_id)
        if not os.path.exists(session_dir):
            self.log_message(f"ERROR: Session directory '{session_dir}' not found")
            return []
        
        self.temp_dir = session_dir
        self.session_id = session_id
        self.log_message(f"Resuming session: {session_id}")
        
        # Load session data using the centralized method
        self._load_session_data()
        
        # Find all net directories (e.g., net001, net002) in the session
        net_dirs = []
        for item in os.listdir(session_dir):
            net_path = os.path.join(session_dir, item)
            if os.path.isdir(net_path) and item.startswith('net'):
                nets_file = os.path.join(net_path, self.NETS_FILE)
                if os.path.isfile(nets_file):
                    net_dirs.append(net_path)
        
        return sorted(net_dirs)
    
    def discover_hosts(self, ip_range, output_file, net_dir):
        """Performs host discovery (-sn) and returns a list of live hosts."""
        try:
            self.log_message(f"Discovering live hosts in {ip_range}...", net_dir)
            
            # A ping-only scan is fast and efficient for finding live hosts
            result = self.nm.scan(hosts=ip_range, arguments='-sn -T4 --min-rate=1000')
            
            live_hosts = [host for host, data in result.get('scan', {}).items() if data['status']['state'] == 'up']
            
            if not live_hosts:
                self.log_message(f"No live hosts found in {ip_range}", net_dir)
                return []
            
            with open(output_file, 'w') as f:
                for host in live_hosts:
                    f.write(f"{host}\n")
            
            self.log_message(f"Found {len(live_hosts)} live hosts in {ip_range}", net_dir)
            return live_hosts
            
        except Exception as e:
            self.log_message(f"ERROR - Failed host discovery for {ip_range}: {str(e)}", net_dir)
            return []

    def _write_scan_results(self, scan_result, output_prefix, scan_type_name, protocol, host_count):
        """Helper to write scan results to .csv and .nmap files."""
        # Save results to a CSV file
        csv_file = f"{output_prefix}.csv"
        with open(csv_file, 'w') as f:
            f.write(self.nm.csv())

        # Create a human-readable nmap-style text file
        nmap_file = f"{output_prefix}.nmap"
        self._write_nmap_file(nmap_file, scan_result, scan_type_name, protocol, host_count)

    def scan_tcp_ports(self, live_hosts, output_prefix, net_dir, host_count):
        """Performs a TCP port scan on a list of live hosts."""
        port_msg = f"top {self.tcp_top_ports} ports" if self.tcp_top_ports else "all ports"
        port_args = f"--top-ports={self.tcp_top_ports}" if self.tcp_top_ports else "-p-"
        scan_type = '-sS' if os.geteuid() == 0 else '-sT'
        
        return self._perform_scan(
            live_hosts, output_prefix, net_dir, host_count,
            f'{scan_type} -T4 {port_args} --min-rate=1000 --max-retries=2 -Pn',
            "TCP Port scan", "tcp", f"TCP port scanning {host_count} live hosts ({port_msg})..."
        )
    
    def scan_udp_ports(self, live_hosts, output_prefix, net_dir, host_count):
        """Performs a UDP port scan on a list of live hosts."""
        # UDP scans require raw socket access, hence root privileges
        if os.geteuid() != 0:
            self.log_message(f"Skipping UDP scan (requires root privileges)", net_dir)
            return True
        
        return self._perform_scan(
            live_hosts, output_prefix, net_dir, host_count,
            f'-sU -T4 --top-ports={self.udp_top_ports} --max-retries=2 -Pn',
            "UDP Port scan", "udp", f"UDP port scanning {host_count} live hosts (top {self.udp_top_ports} ports)..."
        )
    
    def scan_service_detection(self, live_hosts, output_prefix, net_dir, host_count):
        """Performs a service detection scan (-sV) on a list of live hosts."""
        scan_type = '-sS' if os.geteuid() == 0 else '-sT'
        
        return self._perform_scan(
            live_hosts, output_prefix, net_dir, host_count,
            f'{scan_type} -sV -T4 --version-intensity 5 -Pn',
            "Service detection scan", "tcp", f"Service detection scanning {host_count} live hosts..."
        )
    
    def _perform_scan(self, live_hosts, output_prefix, net_dir, host_count, nmap_args, scan_type_name, protocol, log_message):
        """Generic method to perform any type of nmap scan."""
        try:
            self.log_message(log_message, net_dir)
            hosts_str = ' '.join(live_hosts)
            
            result = self.nm.scan(hosts=hosts_str, arguments=nmap_args)
            
            self._write_scan_results(result, output_prefix, scan_type_name, protocol, host_count)
            self.log_message(f"Completed {scan_type_name.lower()} for {host_count} hosts", net_dir)
            return True
            
        except Exception as e:
            self.log_message(f"ERROR - Failed {scan_type_name.lower()}: {str(e)}", net_dir)
            return False
    
    def _write_nmap_file(self, nmap_file, scan_result, scan_type_name, protocol, host_count):
        """Write nmap-style text output file."""
        with open(nmap_file, 'w') as f:
            f.write(f"# {scan_type_name} results for {host_count} hosts\n")
            f.write(f"# Scan started at {self.scan_start_time or self._get_timestamp('full')}\n")
            
            if 'scan' not in scan_result:
                return

            for host, host_info in scan_result.get('scan', {}).items():
                hostname = host_info['hostnames'][0]['name'] if host_info['hostnames'] else 'Unknown'
                f.write(f"\nHost: {host} ({hostname})\n")
                f.write(f"Status: {host_info['status']['state']}\n")
                
                if protocol in host_info:
                    f.write(f"Open {protocol.upper()} ports:\n")
                    for port, port_info in host_info[protocol].items():
                        service_info = self._format_service_info(port_info, scan_type_name)
                        f.write(f"  {port}/{protocol} {port_info['state']} {port_info['name']}{service_info}\n")
    
    def _format_service_info(self, port_info, scan_type_name):
        """Format service information for port scan results."""
        if scan_type_name != "Service detection scan":
            return ""
        
        service_info = ""
        prod = port_info.get('product', '')
        ver = port_info.get('version', '')
        extra = port_info.get('extrainfo', '')
        if prod: service_info += f" {prod}"
        if ver: service_info += f" {ver}"
        if extra: service_info += f" ({extra})"
        return service_info
    
    @staticmethod
    def _get_timestamp(format_type='log'):
        """Get formatted timestamp string.
        
        Args:
            format_type (str): 'log' for log messages, 'file' for filenames, 
                              'full' for full datetime, 'session' for session IDs
        """
        now = datetime.now()
        if format_type == 'log':
            return now.strftime('%H:%M:%S')
        elif format_type == 'file':
            return now.strftime('%H%M%S')
        elif format_type == 'full':
            return now.strftime('%Y-%m-%d %H:%M:%S')
        elif format_type == 'session':
            return now.strftime('%Y%m%d-%H%M%S')
        else:
            return now.strftime('%Y-%m-%d %H:%M:%S')
    
    def _sanitize_subnet_name(self, subnet):
        """Sanitize subnet name for use in filenames."""
        return subnet.replace('/', '_').replace(':', '_')
    
    def _get_processed_marker_path(self, net_dir, counter):
        """Get the path to a processed marker file."""
        return os.path.join(net_dir, f'{self.PROCESSED_MARKER_PREFIX}{counter}')
    
    def _read_nets_file(self, nets_file):
        """Read and parse a nets.txt file, returning list of IP ranges."""
        if not os.path.exists(nets_file):
            return []
        
        try:
            with open(nets_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return []
    
    def _read_nets_file_with_counters(self, nets_file):
        """Read nets.txt file and return (counter, ip_range) tuples."""
        if not os.path.exists(nets_file):
            return []
        
        try:
            with open(nets_file, 'r') as f:
                lines = f.readlines()
            
            results = []
            for counter, line in enumerate(lines, 1):
                ip_range = line.strip()
                if ip_range and not ip_range.startswith('#'):
                    results.append((counter, ip_range))
            return results
        except Exception:
            return []
    
    def copy_completed_results_realtime(self, net_dir, counter, ip_range):
        """Copy completed scan results to output directory immediately after completion."""
        try:
            # Get the original subnet this range belongs to
            original_subnet = self.split_to_original.get(ip_range, ip_range)
            subnet_name = self._sanitize_subnet_name(original_subnet)
            
            # Copy files that exist for this scan
            files_copied = 0
            for scan_type in ['live_hosts', 'tcp_scan', 'udp_scan', 'service_scan']:
                for ext in ['txt', 'csv', 'nmap']:
                    src_file = os.path.join(net_dir, f'{scan_type}_{counter}.{ext}')
                    if os.path.exists(src_file):
                        # Create timestamped filename to avoid conflicts
                        timestamp = self._get_timestamp('file')
                        dst_filename = f"{subnet_name}_{scan_type}_{counter}_{timestamp}.{ext}"
                        dst_path = os.path.join(self.output_dir, dst_filename)
                        shutil.copy2(src_file, dst_path)
                        files_copied += 1
            
            if files_copied > 0:
                self.log_message(f"Copied {files_copied} result files for {ip_range} to {self.output_dir}", net_dir)
                
        except Exception as e:
            self.log_message(f"Warning: Could not copy results for {ip_range}: {e}", net_dir)
    
    def update_progress(self):
        """Update and display scan progress."""
        self.completed_ranges += 1
        if self.total_ranges > 0:
            progress = (self.completed_ranges / self.total_ranges) * 100
            self.log_message(f"Progress: {self.completed_ranges}/{self.total_ranges} ranges ({progress:.1f}%)")

    def scan_net(self, net_dir):
        """Orchestrates the scanning of all IP ranges in a given network directory."""
        if self.shutdown_requested:
            return
            
        self.log_message(f"Starting host discovery for {net_dir}")
        nets_file = os.path.join(net_dir, self.NETS_FILE)
        
        # Read nets file with counters
        net_ranges = self._read_nets_file_with_counters(nets_file)
        if not net_ranges:
            self.log_message(f"ERROR - Could not read {self.NETS_FILE} in {net_dir}")
            return

        # The counter links the scan files (e.g., tcp_scan_1.csv) to the line in nets.txt
        for counter, ip_range in net_ranges:
            if self.shutdown_requested:
                break

            try:
                # Check if this range was already processed (resuming)
                processed_marker = self._get_processed_marker_path(net_dir, counter)
                if os.path.exists(processed_marker):
                    self.log_message(f"Skipping already processed range: {ip_range}", net_dir)
                    self.update_progress()
                    continue
                
                self.log_message(f"Processing range {ip_range}...", net_dir)
                
                # Step 1: Host discovery
                live_hosts_file = os.path.join(net_dir, f'live_hosts_{counter}.txt')
                live_hosts = self.discover_hosts(ip_range, live_hosts_file, net_dir)
                
                # Only proceed with port scans if hosts were found
                if live_hosts:
                    host_count = len(live_hosts)
                    
                    # Step 2: TCP port scan
                    tcp_output_prefix = os.path.join(net_dir, f'tcp_scan_{counter}')
                    tcp_success = self.scan_tcp_ports(live_hosts, tcp_output_prefix, net_dir, host_count)
                    
                    # Step 2b: Service detection scan (optional)
                    if self.service_scan and tcp_success:
                        service_output_prefix = os.path.join(net_dir, f'service_scan_{counter}')
                        self.scan_service_detection(live_hosts, service_output_prefix, net_dir, host_count)
                    
                    # Step 3: UDP port scan
                    udp_output_prefix = os.path.join(net_dir, f'udp_scan_{counter}')
                    self.scan_udp_ports(live_hosts, udp_output_prefix, net_dir, host_count)
                
                # Copy results to output directory immediately
                if not self.shutdown_requested:
                    self.copy_completed_results_realtime(net_dir, counter, ip_range)
                    # Mark as processed
                    Path(processed_marker).touch()
                    self.update_progress()
                    
                    # Update session completion tracking
                    self.mark_range_completed(ip_range)

            except Exception as e:
                self.log_message(f"ERROR - Exception processing IP range '{ip_range}' in {net_dir}: {str(e)}")
        
        self.log_message(f"Finished all scans for {net_dir}")
    
    def update_session_data(self):
        """Updates the session_data.json file with the current completion status."""
        if not hasattr(self, 'temp_dir') or not os.path.exists(self.temp_dir):
            return
        
        session_file = os.path.join(self.temp_dir, self.SESSION_DATA_FILE)
        try:
            # Read existing data to avoid overwriting other session properties
            session_data = {}
            if os.path.exists(session_file):
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
            
            # Update the completion status and save back to the file
            if hasattr(self, 'completed_subnets'):
                session_data['completed_subnets'] = self.completed_subnets
            
            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
                
        except Exception as e:
            self.log_message(f"Warning: Could not update session data: {e}")
    
    def mark_all_completed_subnets(self, net_dirs):
        """Checks all results globally to mark original subnets as complete."""
        if not hasattr(self, 'subnet_mapping') or not self.subnet_mapping:
            return
        
        all_completed_splits = set()
        for net_dir in net_dirs:
            nets_file = os.path.join(net_dir, self.NETS_FILE)
            if not os.path.exists(nets_file): continue
            
            try:
                with open(nets_file, 'r') as f:
                    lines = f.readlines()
            except: continue
            
            # Iterate through the raw lines just like scan_net to get the correct counter
            for counter, line in enumerate(lines, 1):
                split = line.strip()
                if not split or split.startswith('#'):
                    continue
                
                # Check for the .processed sentinel file with the correct counter
                if os.path.exists(os.path.join(net_dir, f'{self.PROCESSED_MARKER_PREFIX}{counter}')):
                    all_completed_splits.add(split)
        
        # If all splits of an original subnet are complete, mark it as such
        updates_made = False
        for original_subnet, splits in self.subnet_mapping.items():
            if not self.completed_subnets.get(original_subnet, False):
                if all(split in all_completed_splits for split in splits):
                    self.completed_subnets[original_subnet] = True
                    self.log_message(f"Marked {original_subnet} as completed ({len(splits)} splits)")
                    updates_made = True
        
        if updates_made:
            self.update_session_data()
    
    def signal_handler(self, signum, frame):
        """Handles interrupt signals (Ctrl+C) for a graceful shutdown."""
        if not self.shutdown_requested:
            print("\nReceived interrupt signal. Saving current progress and shutting down...")
            self.shutdown_requested = True
            
            # Save current progress immediately
            print("Saving current scan results...")
            if hasattr(self, 'net_dirs_ref'):
                # Force update completion status before shutdown
                self.mark_all_completed_subnets(self.net_dirs_ref)
            
            # Shut down the executor, allowing currently running tasks to finish
            self.executor.shutdown(wait=True)
            print("Shutdown complete. Partial results saved to output directory.")
    
    def mark_range_completed(self, ip_range):
        """Mark an individual IP range as completed and update subnet completion status."""
        try:
            original_subnet = self.split_to_original.get(ip_range, ip_range)
            splits = self.subnet_mapping.get(original_subnet, [original_subnet])
            
            # Check if all splits for this original subnet are now completed
            all_completed = True
            for split in splits:
                # Find the processed marker for this split across all net directories
                found_processed = False
                if hasattr(self, 'net_dirs_ref'):
                    for net_dir in self.net_dirs_ref:
                        nets_file = os.path.join(net_dir, self.NETS_FILE)
                        if os.path.exists(nets_file):
                            with open(nets_file, 'r') as f:
                                for counter, line in enumerate(f.readlines(), 1):
                                    if line.strip() == split:
                                        processed_marker = self._get_processed_marker_path(net_dir, counter)
                                        if os.path.exists(processed_marker):
                                            found_processed = True
                                            break
                if not found_processed:
                    all_completed = False
                    break
            
            if all_completed and not self.completed_subnets.get(original_subnet, False):
                self.completed_subnets[original_subnet] = True
                self.log_message(f"Completed all splits for {original_subnet}")
                self.update_session_data()
                
        except Exception as e:
            self.log_message(f"Warning: Could not update completion status for {ip_range}: {e}")
    
    def count_total_ranges(self, net_dirs):
        """Count total IP ranges to scan for progress tracking."""
        total = 0
        for net_dir in net_dirs:
            nets_file = os.path.join(net_dir, self.NETS_FILE)
            total += len(self._read_nets_file(nets_file))
        return total

    def run_scans(self, net_dirs):
        """Runs scans sequentially on all network directories."""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Store net_dirs reference for completion tracking and set scan start time
        self.net_dirs_ref = net_dirs
        self.scan_start_time = self._get_timestamp('full')
        
        # Initialize progress tracking
        self.total_ranges = self.count_total_ranges(net_dirs)
        self.completed_ranges = 0
        
        print(f"Found {len(net_dirs)} networks to scan sequentially")
        print(f"Total IP ranges to process: {self.total_ranges}")
        print(f"Results will be copied to: {self.output_dir}")
        print(f"Networks: {' '.join(net_dirs)}\n")
        
        try:
            # Process each network directory sequentially
            for net_dir in net_dirs:
                if self.shutdown_requested:
                    break
                try:
                    self.scan_net(net_dir)
                    self.log_message(f"Completed scanning for {net_dir}")
                except Exception as e:
                    self.log_message(f"ERROR - Scan failed for {net_dir}: {str(e)}")
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)
        
        if not self.shutdown_requested:
            print("\nAll scans completed!")
        else:
            print("\nScans interrupted. Partial results have been saved to output directory.")
            
        # Show results summary
        result_files = glob.glob(os.path.join(self.output_dir, "*"))
        print(f"\nResults saved to {self.output_dir}: {len(result_files)} files")
        
        # Final check to update completion status
        self.mark_all_completed_subnets(net_dirs)
    
    def _ensure_session_data_loaded(self):
        """Ensures session data is loaded if it hasn't been already."""
        if hasattr(self, 'subnet_mapping') and self.subnet_mapping:
            return
        
        # Load data and provide empty fallbacks if loading fails
        self._load_session_data()
        if not hasattr(self, 'subnet_mapping'): self.subnet_mapping = {}
        if not hasattr(self, 'split_to_original'): self.split_to_original = {}
        if not hasattr(self, 'completed_subnets'): self.completed_subnets = {}
    
    def collect_results(self, net_dirs, output_dir):
        """Collects all scan results and consolidates them into a final output directory."""
        try:
            os.makedirs(output_dir, exist_ok=True)
            self.log_message(f"Collecting results into: {output_dir}")
            
            self._ensure_session_data_loaded()
            
            # Fallback to legacy mode for old sessions without mapping data
            if not self.subnet_mapping:
                self.log_message("No subnet mapping found, collecting all results")
                return self._collect_results_legacy(net_dirs, output_dir)

            # IMPORTANT: Force refresh completion status from actual scan files
            # This is critical for interrupted scans where completion status might be stale
            if hasattr(self, 'subnet_mapping') and self.subnet_mapping:
                self.mark_all_completed_subnets(net_dirs)
            else:
                self.log_message("Warning: No subnet mapping available for completion tracking")

            # Ensure completed_subnets is initialized 
            if not hasattr(self, 'completed_subnets'):
                self.completed_subnets = {}
                
            # If we have subnet mapping but no completion data, initialize all as incomplete
            if self.subnet_mapping and not self.completed_subnets:
                for original_subnet in self.subnet_mapping:
                    self.completed_subnets[original_subnet] = False
                self.log_message(f"Initialized {len(self.completed_subnets)} subnets as incomplete")

            completed = [s for s, c in self.completed_subnets.items() if c]
            incomplete = [s for s, c in self.completed_subnets.items() if not c]
            self.log_message(f"Found {len(completed)} completed subnets, {len(incomplete)} incomplete")

            for subnet in completed:
                self._consolidate_results_for_subnet(subnet, net_dirs, output_dir, is_partial=False)
            
            for subnet in incomplete:
                self._consolidate_results_for_subnet(subnet, net_dirs, output_dir, is_partial=True)

            self.log_message(f"Consolidated results for {len(completed)} completed and {len(incomplete)} partial subnets")
            self._create_summary_file(output_dir, completed, incomplete, net_dirs)

        except Exception as e:
            self.log_message(f"ERROR - Failed to collect results: {str(e)}")

    def _get_subnet_host_summary(self, original_subnet, net_dirs):
        """Get a summary of live hosts found for a subnet."""
        try:
            splits = self.subnet_mapping.get(original_subnet, [original_subnet])
            total_hosts = set()
            
            for net_dir in net_dirs:
                nets_file = os.path.join(net_dir, self.NETS_FILE)
                net_ranges = self._read_nets_file_with_counters(nets_file)
                
                for counter, split in net_ranges:
                    if split in splits:
                        live_hosts_file = os.path.join(net_dir, f'live_hosts_{counter}.txt')
                        if os.path.exists(live_hosts_file):
                            try:
                                with open(live_hosts_file, 'r') as f:
                                    hosts = [line.strip() for line in f if line.strip()]
                                    total_hosts.update(hosts)
                            except:
                                pass
            
            if total_hosts:
                return f"{len(total_hosts)} live hosts found"
            return "No live hosts found"
        except:
            return "Unknown"
    
    def _get_completed_split_ranges(self, original_subnet, net_dirs):
        """Get list of completed split ranges for a subnet."""
        splits = self.subnet_mapping.get(original_subnet, [original_subnet])
        completed_splits = []
        
        for net_dir in net_dirs:
            nets_file = os.path.join(net_dir, self.NETS_FILE)
            net_ranges = self._read_nets_file_with_counters(nets_file)
            
            for counter, split in net_ranges:
                if split in splits and os.path.exists(self._get_processed_marker_path(net_dir, counter)):
                    completed_splits.append(split)
        
        return completed_splits
    
    def _create_summary_file(self, output_dir, completed, incomplete, net_dirs):
        """Creates a detailed scan_summary.txt file with progress information."""
        summary_file = os.path.join(output_dir, self.SCAN_SUMMARY_FILE)
        total_original = len(completed) + len(incomplete)
        total_splits_completed = sum(len(self._get_completed_split_ranges(subnet, net_dirs)) for subnet in completed + incomplete)
        total_splits = sum(len(self.subnet_mapping.get(subnet, [subnet])) for subnet in completed + incomplete)
        
        with open(summary_file, 'w') as f:
            f.write("Network Scan Summary\n")
            f.write("===================\n\n")
            f.write(f"Session ID: {self.session_id}\n")
            f.write(f"Scan Status: {self._get_timestamp('full')}\n")
            f.write(f"Overall Progress: {total_splits_completed}/{total_splits} blocks completed ({(total_splits_completed/total_splits*100):.1f}%)\n")
            f.write(f"Subnet Progress: {len(completed)}/{total_original} subnets completed ({(len(completed)/total_original*100):.1f}%)\n\n")
            
            # Completed subnets section
            if completed:
                f.write("✓ COMPLETED SUBNETS\n")
                f.write("===================\n")
                for subnet in completed:
                    splits = self.subnet_mapping.get(subnet, [subnet])
                    host_summary = self._get_subnet_host_summary(subnet, net_dirs)
                    
                    if len(splits) == 1:
                        f.write(f"✓ {subnet} - {host_summary}\n")
                    else:
                        f.write(f"✓ {subnet} - Split into {len(splits)} blocks ({host_summary})\n")
                        completed_ranges = self._get_completed_split_ranges(subnet, net_dirs)
                        f.write(f"   All {len(splits)} blocks completed: {', '.join(splits[:3])}{'...' if len(splits) > 3 else ''}\n")
                    f.write("\n")
            
            # Incomplete subnets section
            if incomplete:
                f.write("⚠ INCOMPLETE SUBNETS\n")
                f.write("===================\n")
                for subnet in incomplete:
                    splits = self.subnet_mapping.get(subnet, [subnet])
                    completed_ranges = self._get_completed_split_ranges(subnet, net_dirs)
                    remaining_ranges = [s for s in splits if s not in completed_ranges]
                    host_summary = self._get_subnet_host_summary(subnet, net_dirs)
                    
                    progress_pct = (len(completed_ranges) / len(splits)) * 100 if splits else 0
                    
                    f.write(f"⚠ {subnet} - {len(completed_ranges)}/{len(splits)} blocks completed ({progress_pct:.1f}%)\n")
                    f.write(f"   {host_summary}\n")
                    
                    if completed_ranges:
                        f.write(f"   ✓ Completed blocks: {', '.join(completed_ranges[:3])}{'...' if len(completed_ranges) > 3 else ''}\n")
                    
                    if remaining_ranges:
                        f.write(f"   ⏳ Remaining blocks: {', '.join(remaining_ranges[:3])}{'...' if len(remaining_ranges) > 3 else ''}\n")
                    
                    f.write("\n")
                
                f.write("RESUMPTION INSTRUCTIONS\n")
                f.write("======================\n")
                f.write(f"To continue scanning incomplete subnets, use:\n")
                f.write(f"  python3 {os.path.basename(sys.argv[0])} --resume {self.session_id}\n\n")
                f.write("Only the remaining blocks will be scanned. Completed blocks will be skipped.\n")
            
            # No subnets case
            if not completed and not incomplete:
                f.write("No subnets found or processed.\n")
        
        self.log_message(f"Created detailed scan summary: {summary_file}")

    def _count_completed_splits(self, original_subnet, net_dirs):
        """Counts how many split-scans have completed for a given original subnet."""
        splits = self.subnet_mapping.get(original_subnet, [original_subnet])
        completed_count = 0
        
        for net_dir in net_dirs:
            nets_file = os.path.join(net_dir, self.NETS_FILE)
            net_ranges = self._read_nets_file_with_counters(nets_file)
            
            for counter, split in net_ranges:
                if split in splits and os.path.exists(self._get_processed_marker_path(net_dir, counter)):
                    completed_count += 1
        return completed_count
    
    def _collect_results_legacy(self, net_dirs, output_dir):
        """Collects results for old sessions that don't have subnet mapping data."""
        total_files = 0
        for net_dir in net_dirs:
            net_name = os.path.basename(net_dir)
            files_to_copy = glob.glob(os.path.join(net_dir, "*.nmap")) + \
                            glob.glob(os.path.join(net_dir, "*.csv")) + \
                            glob.glob(os.path.join(net_dir, "live_hosts_*.txt"))
            
            for src_file in files_to_copy:
                dst_filename = f"{net_name}_{os.path.basename(src_file)}"
                shutil.copy2(src_file, os.path.join(output_dir, dst_filename))
                total_files += 1
        
        self.log_message(f"Collected {total_files} result files (legacy mode)")

    def _consolidate_results_for_subnet(self, original_subnet, net_dirs, output_dir, is_partial):
        """Consolidates all result files for a given original subnet."""
        status_suffix = "partial" if is_partial else "consolidated"
        subnet_name = self._sanitize_subnet_name(original_subnet)
        splits = self.subnet_mapping.get(original_subnet, [original_subnet])
        all_live_hosts = set()
        scanned_blocks_count = 0

        for net_dir in net_dirs:
            nets_file = os.path.join(net_dir, self.NETS_FILE)
            net_ranges = self._read_nets_file_with_counters(nets_file)
            
            for counter, split_range in net_ranges:
                if split_range in splits:
                    # A scan is considered processed if the marker file exists.
                    processed_marker = self._get_processed_marker_path(net_dir, counter)
                    if not os.path.exists(processed_marker):
                        continue

                    scanned_blocks_count += 1
                    
                    # Consolidate live hosts from this split
                    live_hosts_file = os.path.join(net_dir, f'live_hosts_{counter}.txt')
                    if os.path.exists(live_hosts_file):
                        with open(live_hosts_file, 'r') as f:
                            all_live_hosts.update(host.strip() for host in f if host.strip())

                    # Consolidate all scan types (TCP, UDP, Service)
                    for scan_type in ['tcp_scan', 'udp_scan', 'service_scan']:
                        for ext in ['csv', 'nmap']:
                            src_file = os.path.join(net_dir, f'{scan_type}_{counter}.{ext}')
                            if os.path.exists(src_file):
                                dst_filename = f"{subnet_name}_{scan_type}_{status_suffix}.{ext}"
                                dst_path = os.path.join(output_dir, dst_filename)
                                if ext == 'csv':
                                    self._merge_csv_results(src_file, dst_path, original_subnet)
                                else:
                                    self._merge_nmap_results(src_file, dst_path, original_subnet)
        
        # Create final live hosts file from all collected hosts
        if all_live_hosts:
            hosts_filename = f"{subnet_name}_live_hosts_{status_suffix}.txt"
            with open(os.path.join(output_dir, hosts_filename), 'w') as f:
                header = f"# {status_suffix.capitalize()} live hosts for {original_subnet}"
                if is_partial:
                    header += f" ({scanned_blocks_count}/{len(splits)} blocks scanned)"
                f.write(header + "\n")
                f.write('\n'.join(sorted(all_live_hosts)) + "\n")
        
        return scanned_blocks_count

    def _merge_csv_results(self, src_file, dst_path, original_subnet):
        """Merge CSV scan results, combining data from multiple splits"""
        try:
            # Read source CSV data
            with open(src_file, 'r') as f:
                src_content = f.read().strip()
            
            # If source is empty, skip
            if not src_content:
                return
            
            # If destination doesn't exist, create it with header and data
            if not os.path.exists(dst_path):
                with open(dst_path, 'w') as f:
                    f.write(f"# Consolidated scan results for {original_subnet}\n")
                    f.write(f"# Generated: {self._get_timestamp('full')}\n")
                    f.write(src_content + '\n')
            else:
                # Append data (skip header if present in source)
                lines = src_content.split('\n')
                data_lines = []
                
                for line in lines:
                    line = line.strip()
                    # Skip empty lines and header lines
                    if line and not line.startswith('#') and not line.startswith(self.CSV_HEADER):
                        data_lines.append(line)
                
                if data_lines:
                    with open(dst_path, 'a') as f:
                        for line in data_lines:
                            f.write(line + '\n')
                
        except Exception as e:
            self.log_message(f"Warning: Could not merge CSV results: {e}")
    
    def _merge_nmap_results(self, src_file, dst_path, original_subnet):
        """Merges nmap text results by appending host data."""
        try:
            with open(src_file, 'r') as f:
                src_content = f.read()
            
            if not os.path.exists(dst_path):
                with open(dst_path, 'w') as f:
                    f.write(f"# Consolidated scan results for {original_subnet}\n")
                    f.write(f"# Generated: {self._get_timestamp('full')}\n\n")
            
            # Append content, skipping header comments from the source file
            with open(dst_path, 'a') as f:
                for line in src_content.split('\n'):
                    if not line.startswith('#'):
                        f.write(line + '\n')
                
        except Exception as e:
            self.log_message(f"Warning: Could not merge nmap results: {e}")
    
    def _generate_excel_from_csv(self, csv_file, output_dir):
        """Generate Excel file from CSV data."""
        if not OPENPYXL_AVAILABLE:
            return
        
        try:
            # Create Excel filename by replacing .csv with .xlsx
            excel_filename = csv_file.replace('.csv', '.xlsx')
            excel_path = os.path.join(output_dir, os.path.basename(excel_filename))
            
            # Read CSV data
            rows = []
            with open(csv_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        if line.startswith(self.CSV_HEADER):
                            # Split header on semicolons
                            rows.append(line.split(';'))
                        elif ';' in line:
                            # Split data rows on semicolons
                            rows.append(line.split(';'))
            
            if not rows:
                return
                
            # Create Excel workbook and worksheet
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Scan Results"
            
            # Write data to worksheet
            for row_idx, row_data in enumerate(rows, 1):
                for col_idx, cell_value in enumerate(row_data, 1):
                    cell = ws.cell(row=row_idx, column=col_idx, value=cell_value)
                    
                    # Format header row
                    if row_idx == 1:
                        cell.font = Font(bold=True)
                        cell.alignment = Alignment(horizontal='center')
            
            # Auto-size columns
            for column in ws.columns:
                max_length = 0
                column_letter = column[0].column_letter
                
                for cell in column:
                    try:
                        if cell.value and len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                
                adjusted_width = min(max_length + 2, 50)  # Cap at 50 characters
                ws.column_dimensions[column_letter].width = adjusted_width
            
            # Save Excel file
            wb.save(excel_path)
            self.log_message(f"Generated Excel file: {os.path.basename(excel_path)}")
            
        except Exception as e:
            self.log_message(f"Warning: Could not generate Excel file from {csv_file}: {e}")
    
    def _generate_excel_files(self, output_dir):
        """Generate Excel files from all CSV files in output directory."""
        if not self.generate_excel or not OPENPYXL_AVAILABLE:
            return
        
        csv_files = glob.glob(os.path.join(output_dir, "*.csv"))
        if not csv_files:
            return
            
        self.log_message(f"Generating Excel files from {len(csv_files)} CSV files...")
        
        for csv_file in csv_files:
            self._generate_excel_from_csv(csv_file, output_dir)
    
    def cleanup_session(self):
        """Cleans up the temporary session directory if all subnets are completed."""
        if not os.path.exists(self.temp_dir):
            return
        
        self._ensure_session_data_loaded()

        # If subnet mapping is missing (e.g., legacy session), err on the side of caution and preserve.
        if not self.subnet_mapping:
            self.log_message("Session preserved: Could not determine completion status (no subnet mapping).")
            self.log_message(f"Resume with: --resume {self.session_id}")
            return

        # A subnet is incomplete if it's not marked as complete in the tracking dictionary.
        incomplete_subnets = [
            s for s in self.subnet_mapping
            if not self.completed_subnets.get(s, False)
        ]
        
        if incomplete_subnets:
            self.log_message(f"Session preserved: {len(incomplete_subnets)} subnets incomplete")
            self.log_message(f"Resume with: --resume {self.session_id}")
            return
        
        # If no incomplete subnets, it's safe to clean up
        try:
            shutil.rmtree(self.temp_dir)
            self.log_message(f"Cleaned up session directory: {self.temp_dir}")
        except Exception as e:
            self.log_message(f"Warning: Failed to cleanup session directory: {e}")


def main():
    """Main function to parse arguments and run the scanner."""
    # --- 1. Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Network infrastructure scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific IP ranges
  python3 parallel_scan_v2_sonnet.py -t 192.168.1.0/24 10.0.0.0/24
  
  # Scan from file
  python3 parallel_scan_v2_sonnet.py -f targets.txt
  
  # Create a session and run with root for faster scans
  sudo python3 parallel_scan_v2_sonnet.py --session-id myscan -t 192.168.1.0/24
  
  # Resume a previous session
  python3 parallel_scan_v2_sonnet.py --resume myscan
  
  # Enable service detection and specify an output directory
  python3 parallel_scan_v2_sonnet.py --version -t 192.168.1.0/24 -o my_scan_results
  
  # Generate Excel files along with CSV results
  python3 parallel_scan_v2_sonnet.py --excel -t 192.168.1.0/24
        """
    )
    
    parser.add_argument('-t', '--targets', nargs='+', help='IP ranges/networks to scan')
    parser.add_argument('-f', '--file', help='File containing IP ranges/networks (one per line)')
    parser.add_argument('--session-id', help='Custom session ID for resumable scanning')
    parser.add_argument('--resume', help='Resume a previous scanning session by session ID')
    parser.add_argument('--list-sessions', action='store_true', help='List available session directories')
    parser.add_argument('--version', action='store_true', help='Perform service detection scan (-sV) on open ports')
    parser.add_argument('--tcp-top-ports', type=int, nargs='?', const=1000, help='Scan top N TCP ports (default: all; 1000 if no number given)')
    parser.add_argument('--udp-top-ports', type=int, default=400, help='Scan top N UDP ports (default: 400)')
    parser.add_argument('-o', '--output-dir', default='results', help='Output directory for final scan results (default: results)')
    parser.add_argument('--excel', action='store_true', help='Generate Excel (.xlsx) files from scan results (requires openpyxl)')
    
    args = parser.parse_args()
    
    # --- 2. Handle Special Modes (List Sessions) ---
    if args.list_sessions:
        if os.path.exists(self.SESSIONS_DIR):
            sessions = [d for d in os.listdir(self.SESSIONS_DIR) if os.path.isdir(os.path.join(self.SESSIONS_DIR, d))]
            if sessions:
                print("Available sessions:")
                for session_id in sorted(sessions):
                    print(f"  {session_id}")
            else:
                print("No sessions found")
        else:
            print("No sessions directory found")
        sys.exit(0)
    
    
    # --- 3. Initialize Scanner ---
    # Warn about Excel dependencies if requested but not available
    if args.excel and not OPENPYXL_AVAILABLE:
        print("Warning: openpyxl module not installed, Excel generation is disabled")
        print("Install with: pip install openpyxl")
    
    scanner = NetworkScanner(
        session_id=args.session_id, 
        service_scan=args.version,
        tcp_top_ports=args.tcp_top_ports,
        udp_top_ports=args.udp_top_ports,
        output_dir=args.output_dir,
        generate_excel=args.excel
    )
    
    # --- 4. Determine Mode (Resume vs. New Scan) ---
    net_dirs = []
    if args.resume:
        net_dirs = scanner.resume_session(args.resume)
        if not net_dirs:
            sys.exit(1)
    else:
        ip_ranges = []
        if args.targets:
            ip_ranges.extend(args.targets)
        
        if args.file:
            if not os.path.isfile(args.file):
                parser.error(f"File '{args.file}' not found")
            try:
                with open(args.file, 'r') as f:
                    ip_ranges.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
            except Exception as e:
                parser.error(f"Error reading file '{args.file}': {e}")
        
        if not ip_ranges:
            parser.error("No IP ranges specified. Use -t, -f, or --resume.")
        
        print(f"Session ID: {scanner.session_id}")
        split_ranges = scanner.split_large_networks(ip_ranges)
        print(f"Processing {len(ip_ranges)} input ranges -> {len(split_ranges)} scan blocks")
        
        net_dirs = scanner.create_session_structure(split_ranges)
    
    # --- 5. Execute Scans and Cleanup ---
    try:
        scanner.run_scans(net_dirs)
        
        # Always collect remaining results into consolidated files
        print("\nConsolidating final results...")
        scanner.collect_results(net_dirs, args.output_dir)
        
        # Generate Excel files if requested
        if args.excel:
            scanner._generate_excel_files(args.output_dir)

        if scanner.shutdown_requested:
            print("\nScan aborted by user. All available results have been saved.")
        else:
            print("\nAll scans completed successfully!")
            
    finally:
        # cleanup_session correctly preserves the session if scans are incomplete.
        scanner.cleanup_session()


if __name__ == "__main__":
    main()