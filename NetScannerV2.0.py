#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetScanner 2.0 - Advanced Network Discovery Tool
Author: Cyb0rgBytes
Version: 2.0
Description: Enhanced network scanning with modern UI, advanced features, and visual effects
"""

import argparse
import sys
import time
import json
import csv
import os
import warnings
from datetime import datetime

# UI Libraries
from colorama import init, Fore, Style, Back
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

# Try to import optional packages
try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False
    print("[yellow]Warning: pyfiglet not installed. Using simple banner.[/yellow]")

# Suppress warnings
warnings.filterwarnings("ignore")

# Initialize
init(autoreset=True)
console = Console()

# Import scapy with proper handling
try:
    # First try the common import
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    try:
        # Alternative import
        import scapy.all as scapy
        ARP = scapy.ARP
        Ether = scapy.Ether
        srp = scapy.srp
        SCAPY_AVAILABLE = True
    except ImportError:
        SCAPY_AVAILABLE = False
        console.print("[bold red]Error: scapy is not installed![/bold red]")
        console.print("Install it with: pip install scapy")
        sys.exit(1)

class AnimatedBanner:
    """Creates animated banner effects"""
    
    @staticmethod
    def display():
        """Display animated banner"""
        if PYFIGLET_AVAILABLE:
            try:
                banner = pyfiglet.figlet_format("NetScanner 2.0", font="slant")
                console.print(f"[bold cyan]{banner}[/bold cyan]")
            except:
                banner = """
╔╗╔┌─┐┬ ┬┌─┐┌─┐┬ ┬┌─┐┌┬┐┬┌─┐
║║║├┤ ││││ ┬│ ││││├─┤ │ │└─┐
╝╚╝└─┘└┴┘└─┘└─┘└┴┘┴ ┴ ┴ ┴└─┘
                """
                console.print(f"[bold cyan]{banner}[/bold cyan]")
        else:
            banner = """
╔╗╔┌─┐┬ ┬┌─┐┌─┐┬ ┬┌─┐┌┬┐┬┌─┐
║║║├┤ ││││ ┬│ ││││├─┤ │ │└─┐
╝╚╝└─┘└┴┘└─┘└─┘└┴┘┴ ┴ ┴ ┴└─┘
            """
            console.print(f"[bold cyan]{banner}[/bold cyan]")
        
        console.print("[bold yellow]════════════════════════════════════════════════════════════[/bold yellow]")
        console.print("[bold green]Network Discovery & Security Assessment Tool[/bold green]")
        console.print(f"[bold magenta]Author: Cyb0rgBytes | Version: 2.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold magenta]")
        console.print("[bold yellow]════════════════════════════════════════════════════════════[/bold yellow]\n")

class ArgumentParser:
    """Enhanced argument parsing"""
    
    @staticmethod
    def get_arguments():
        parser = argparse.ArgumentParser(
            description="Advanced Network Scanner with multiple features",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  sudo python3 NetScannerV2.py --target 192.168.1.0/24
  sudo python3 NetScannerV2.py --target 192.168.1.1-100 --ports 22,80,443
  sudo python3 NetScannerV2.py --target 10.0.0.0/24 --export json --verbose
  sudo python3 NetScannerV2.py --target 192.168.1.0/24 --vendor --timeout 2
            """
        )
        
        parser.add_argument("-t", "--target", dest="target", help="Target IP range (e.g., 192.168.1.0/24)", required=True)
        parser.add_argument("-i", "--interface", dest="interface", help="Network interface to use", default=None)
        parser.add_argument("-p", "--ports", dest="ports", help="Ports to scan (e.g., 22,80,443 or 1-1000)", default=None)
        parser.add_argument("-to", "--timeout", dest="timeout", type=int, help="Timeout in seconds", default=1)
        parser.add_argument("-r", "--retry", dest="retry", type=int, help="Number of retries", default=1)
        parser.add_argument("-e", "--export", dest="export", choices=['json', 'csv', 'xml', 'txt'], help="Export results")
        parser.add_argument("-o", "--output", dest="output", help="Output filename", default=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output")
        parser.add_argument("--vendor", dest="vendor_lookup", action="store_true", help="Enable MAC vendor lookup", default=True)
        parser.add_argument("--discovery", dest="discovery", choices=['arp', 'icmp', 'both'], help="Discovery method", default='arp')
        
        return parser.parse_args()

class MACVendorLookup:
    """MAC address vendor lookup"""
    
    OUI_DB = {
        '00:0C:29': 'VMware', '00:50:56': 'VMware', '00:1A:73': 'Google', '00:1B:63': 'Apple',
        '00:1D:4F': 'Cisco', '00:21:5A': 'Dell', '00:23:AE': 'HP', '00:24:8C': 'Dell',
        '00:25:4B': 'Apple', '00:26:BB': 'Apple', '08:00:27': 'VirtualBox', '08:18:1A': 'Cisco',
        '0C:4D:E9': 'Apple', '10:9A:DD': 'Apple', '14:10:9F': 'Apple', '18:3A:2D': 'Google',
        '1C:1A:C0': 'Apple', '24:A0:74': 'Apple', '28:CF:DA': 'Apple', '28:CF:E9': 'Apple',
        '34:12:98': 'Apple', '3C:07:54': 'Apple', '3C:15:C2': 'Apple', '3C:D9:2B': 'HP',
        '40:0E:85': 'Sony', '44:8A:5B': 'Huawei', '4C:32:75': 'Apple', '54:26:96': 'Apple',
        '54:72:4F': 'Apple', '60:03:08': 'Apple', '64:B9:E8': 'Google', '68:5B:35': 'Apple',
        '6C:3E:6D': 'Apple', '70:56:81': 'Apple', '78:31:C1': 'Apple', '78:4B:87': 'Apple',
        '78:CA:39': 'Apple', '84:38:35': 'Apple', '84:B1:53': 'Apple', '88:53:D4': 'Apple',
        '8C:85:90': 'Apple', '90:60:F1': 'Apple', '90:72:40': 'Apple', '94:94:26': 'Apple',
        '98:01:A7': 'Apple', 'A4:C3:61': 'Apple', 'AC:BC:32': 'Apple', 'B8:27:EB': 'Raspberry Pi',
        'B8:E8:56': 'Apple', 'BC:67:78': 'Apple', 'C8:69:CD': 'Apple', 'CC:20:E8': 'Apple',
        'D0:23:DB': 'Apple', 'D8:96:95': 'Apple', 'DC:A4:CA': 'Apple', 'E4:CE:8F': 'Apple',
        'F0:18:98': 'Apple', 'F0:24:75': 'Apple', 'F0:76:6F': 'Apple', 'F0:99:BF': 'Apple',
        'F4:F5:24': 'Apple', 'F4:F5:D8': 'Google', 'FC:F1:52': 'Sony',
    }
    
    @classmethod
    def lookup(cls, mac_address):
        """Lookup vendor from MAC address"""
        if not mac_address or mac_address == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"
        
        oui = mac_address[:8].upper()
        return cls.OUI_DB.get(oui, "Unknown")

class NetworkScanner:
    """Advanced network scanner"""
    
    def __init__(self, interface=None, timeout=1, retry=1, verbose=False):
        self.interface = interface
        self.timeout = timeout
        self.retry = retry
        self.verbose = verbose
        
    def scan_with_progress(self, ip_range, discovery_method='arp'):
        """Scan network with progress animation"""
        devices = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Scanning network...", total=100)
            
            # Animation phases
            for i in range(0, 101, 10):
                time.sleep(0.05)
                progress.update(task, advance=10)
                
                if i == 10:
                    progress.console.print("[yellow]• Initializing scanner...[/yellow]")
                elif i == 30:
                    progress.console.print("[yellow]• Crafting ARP packets...[/yellow]")
                elif i == 60:
                    progress.console.print("[yellow]• Broadcasting requests...[/yellow]")
                elif i == 80:
                    progress.console.print("[yellow]• Analyzing responses...[/yellow]")
            
            # Actual scan
            devices = self.scan(ip_range, discovery_method)
            progress.update(task, completed=100)
            
            if devices:
                progress.console.print(f"[bold green]✓ Scan complete! Found {len(devices)} devices[/bold green]")
            else:
                progress.console.print("[bold yellow]⚠ No devices found[/bold yellow]")
            
            return devices
    
    def scan(self, ip_range, discovery_method='arp'):
        """Perform network scan"""
        devices = []
        
        try:
            console.print(f"[cyan][*] Starting {discovery_method.upper()} scan on {ip_range}[/cyan]")
            
            if discovery_method in ['arp', 'both']:
                arp_devices = self._arp_scan(ip_range)
                devices.extend(arp_devices)
            
            # Add ICMP scan if needed
            if discovery_method in ['icmp', 'both'] and not devices:
                console.print("[yellow][*] ICMP scan placeholder - using ARP results[/yellow]")
                
        except PermissionError:
            console.print("[bold red][!] Permission denied. Run with sudo/administrator privileges[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red][!] Scan failed: {str(e)}[/red]")
            if self.verbose:
                import traceback
                console.print(f"[red]{traceback.format_exc()}[/red]")
        
        return devices
    
    def _arp_scan(self, ip_range):
        """ARP-based network discovery"""
        devices = []
        
        try:
            # Create ARP request
            arp_request = ARP(pdst=ip_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Send and receive
            answered, unanswered = srp(
                packet,
                timeout=self.timeout,
                retry=self.retry,
                verbose=self.verbose,
                iface=self.interface
            )
            
            # Process responses
            for sent, received in answered:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': MACVendorLookup.lookup(received.hwsrc),
                    'protocol': 'ARP',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                devices.append(device)
                
                if self.verbose:
                    console.print(f"[green][+] {device['ip']} -> {device['mac']} ({device['vendor']})[/green]")
        
        except Exception as e:
            console.print(f"[red][!] ARP scan error: {str(e)}[/red]")
        
        return devices

class ResultsDisplay:
    """Enhanced results display"""
    
    @staticmethod
    def display_table(devices, args):
        """Display results in formatted table"""
        if not devices:
            console.print("[bold red]No devices found on the network.[/bold red]")
            return
        
        # Create table
        table = Table(
            title=f"[bold cyan]Network Discovery Results ({len(devices)} devices)[/bold cyan]",
            box=box.ROUNDED,
            header_style="bold magenta",
            title_style="bold yellow",
            show_lines=True
        )
        
        # Add columns
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("IP Address", style="bold green", min_width=15)
        table.add_column("MAC Address", style="cyan", min_width=17)
        table.add_column("Vendor", style="yellow", min_width=20)
        table.add_column("Status", style="bold", width=8)
        table.add_column("Time", style="dim", width=8)
        
        # Add rows
        for idx, device in enumerate(devices, 1):
            status = "🟢" if device.get('ip') else "🔴"
            table.add_row(
                str(idx),
                device.get('ip', 'N/A'),
                device.get('mac', 'N/A'),
                device.get('vendor', 'Unknown'),
                status,
                device.get('timestamp', 'N/A')
            )
        
        console.print(table)
        
        # Statistics
        console.print(f"\n[bold green]📊 Statistics:[/bold green]")
        console.print(f"  • Target Range: {args.target}")
        console.print(f"  • Total Devices: {len(devices)}")
        
        # Vendor stats
        vendors = {}
        for device in devices:
            vendor = device.get('vendor', 'Unknown')
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        if vendors:
            console.print(f"  • Top Vendors:")
            for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:3]:
                console.print(f"    └─ {vendor}: {count} device(s)")
    
    @staticmethod
    def display_network_map(devices):
        """Display simple network visualization"""
        if not devices:
            return
        
        console.print("\n[bold cyan]🌐 Network Topology:[/bold cyan]")
        console.print("[yellow]┌─────────────────────────────────────────────┐[/yellow]")
        console.print("[yellow]│            Local Network Map               │[/yellow]")
        console.print("[yellow]├─────────────────────────────────────────────┤[/yellow]")
        
        for i, device in enumerate(devices[:6]):
            ip = device.get('ip', 'Unknown')
            vendor = device.get('vendor', 'Unknown')[:15]
            
            # Different icons for different vendors
            icon = "📱" if "Apple" in vendor else "💻" if "Dell" in vendor or "HP" in vendor else "🖥️" if "VMware" in vendor else "🔗"
            
            console.print(f"[cyan]│ {icon} {ip:<15} → {vendor:<15} [/cyan]")
        
        if len(devices) > 6:
            console.print(f"[cyan]│ ... and {len(devices) - 6} more devices [/cyan]")
        
        console.print("[yellow]└─────────────────────────────────────────────┘[/yellow]")

class ExportManager:
    """Handle export of results"""
    
    @staticmethod
    def export_results(devices, format_type, filename):
        """Export results to file"""
        if not devices:
            console.print("[yellow][!] No data to export[/yellow]")
            return False
        
        try:
            if format_type == 'json':
                ExportManager._export_json(devices, filename)
            elif format_type == 'csv':
                ExportManager._export_csv(devices, filename)
            elif format_type == 'xml':
                ExportManager._export_xml(devices, filename)
            elif format_type == 'txt':
                ExportManager._export_txt(devices, filename)
            
            console.print(f"[green]📁 Results exported to {filename}.{format_type}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][!] Export failed: {str(e)}[/red]")
            return False
    
    @staticmethod
    def _export_json(devices, filename):
        with open(f"{filename}.json", 'w') as f:
            json.dump(devices, f, indent=2, default=str)
    
    @staticmethod
    def _export_csv(devices, filename):
        with open(f"{filename}.csv", 'w', newline='') as f:
            if devices:
                writer = csv.DictWriter(f, fieldnames=devices[0].keys())
                writer.writeheader()
                writer.writerows(devices)
    
    @staticmethod
    def _export_xml(devices, filename):
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<network_scan>\n'
        xml_content += f'  <timestamp>{datetime.now()}</timestamp>\n'
        xml_content += f'  <devices count="{len(devices)}">\n'
        
        for device in devices:
            xml_content += '    <device>\n'
            for key, value in device.items():
                xml_content += f'      <{key}>{value}</{key}>\n'
            xml_content += '    </device>\n'
        
        xml_content += '  </devices>\n'
        xml_content += '</network_scan>'
        
        with open(f"{filename}.xml", 'w') as f:
            f.write(xml_content)
    
    @staticmethod
    def _export_txt(devices, filename):
        with open(f"{filename}.txt", 'w') as f:
            f.write(f"Network Scan Results\n")
            f.write("=" * 50 + "\n")
            f.write(f"Scan Time: {datetime.now()}\n")
            f.write(f"Devices Found: {len(devices)}\n")
            f.write("=" * 50 + "\n\n")
            
            for idx, device in enumerate(devices, 1):
                f.write(f"Device #{idx}:\n")
                f.write(f"  IP Address: {device.get('ip', 'N/A')}\n")
                f.write(f"  MAC Address: {device.get('mac', 'N/A')}\n")
                f.write(f"  Vendor: {device.get('vendor', 'Unknown')}\n")
                f.write(f"  Protocol: {device.get('protocol', 'N/A')}\n")
                f.write(f"  Time: {device.get('timestamp', 'N/A')}\n")
                f.write("-" * 40 + "\n")

class PortScanner:
    """Lightweight port scanner"""
    
    @staticmethod
    def quick_scan(ip, ports="22,80,443,8080"):
        """Quick port scan for common ports"""
        open_ports = []
        
        if not ports:
            port_list = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
        else:
            port_list = []
            for part in ports.split(','):
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        port_list.extend(range(start, end + 1))
                    except:
                        continue
                else:
                    try:
                        port_list.append(int(part))
                    except:
                        continue
        
        console.print(f"[cyan][*] Quick port scan on {ip}...[/cyan]")
        
        # This is a placeholder - in production, implement actual port scanning
        # with socket.connect_ex or using scapy
        
        return open_ports

class NetScannerV2:
    """Main application class"""
    
    def __init__(self):
        self.args = None
        self.scanner = None
        self.results = []
    
    def run(self):
        """Main execution flow"""
        # Display banner
        AnimatedBanner.display()
        
        # Parse arguments
        try:
            self.args = ArgumentParser.get_arguments()
        except SystemExit:
            return
        
        # Check for required permissions
        if os.name == 'posix' and os.geteuid() != 0:
            console.print("[bold yellow]⚠ Warning: Running without root privileges[/bold yellow]")
            console.print("[yellow]   Some features may not work properly[/yellow]")
            console.print("[yellow]   Consider running with: sudo python3 NetScannerV2.py[/yellow]\n")
        
        # Validate target
        if not self.args.target:
            console.print("[red][!] Target IP range is required[/red]")
            console.print("[yellow]   Example: --target 192.168.1.0/24[/yellow]")
            return
        
        # Initialize scanner
        self.scanner = NetworkScanner(
            interface=self.args.interface,
            timeout=self.args.timeout,
            retry=self.args.retry,
            verbose=self.args.verbose
        )
        
        # Show scan configuration
        console.print(f"[bold cyan]🔧 Scan Configuration:[/bold cyan]")
        console.print(f"  • Target: {self.args.target}")
        console.print(f"  • Method: {self.args.discovery.upper()}")
        console.print(f"  • Timeout: {self.args.timeout}s")
        console.print(f"  • Retries: {self.args.retry}")
        if self.args.vendor_lookup:
            console.print(f"  • Vendor Lookup: Enabled")
        console.print()
        
        # Perform scan with progress animation
        self.results = self.scanner.scan_with_progress(
            self.args.target,
            self.args.discovery
        )
        
        # Display results
        if self.results:
            ResultsDisplay.display_table(self.results, self.args)
            ResultsDisplay.display_network_map(self.results)
            
            # Optional port scanning
            if self.args.ports:
                console.print(f"\n[bold cyan]🔍 Port Scanning:[/bold cyan]")
                for device in self.results[:3]:  # Limit to 3 devices
                    PortScanner.quick_scan(device['ip'], self.args.ports)
        
        # Export results if requested
        if self.args.export and self.results:
            ExportManager.export_results(
                self.results,
                self.args.export,
                self.args.output
            )
        
        # Final summary
        self._display_summary()
    
    def _display_summary(self):
        """Display final summary"""
        console.print(f"\n[bold yellow]╔══════════════════════════════════════════╗[/bold yellow]")
        console.print(f"[bold yellow]║         Scan Complete!                  ║[/bold yellow]")
        console.print(f"[bold yellow]╚══════════════════════════════════════════╝[/bold yellow]")
        
        console.print(f"[green]📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/green]")
        console.print(f"[green]📡 Devices Found: {len(self.results)}[/green]")
        console.print(f"[green]⚡ Method: {self.args.discovery.upper()}[/green]")
        
        if self.args.export:
            console.print(f"[green]💾 Exported: {self.args.output}.{self.args.export}[/green]")
        
        console.print(f"\n[bold cyan]Thank you for using NetScanner 2.0![/bold cyan]")
        console.print(f"[dim]Author: Cyb0rgBytes | https://github.com/Cyb0rgBytes[/dim]")

def main():
    """Application entry point"""
    try:
        app = NetScannerV2()
        app.run()
        
    except KeyboardInterrupt:
        console.print(f"\n[yellow][!] Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][!] Unexpected error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    # Check dependencies
    try:
        import rich
    except ImportError:
        print("Error: 'rich' package not installed.")
        print("Install with: pip install rich colorama")
        sys.exit(1)
    
    # Check for optional packages
    if not PYFIGLET_AVAILABLE:
        console.print("[yellow]Note: Install 'pyfiglet' for enhanced banner: pip install pyfiglet[/yellow]")
    
    main()