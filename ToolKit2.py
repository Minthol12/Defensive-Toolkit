import asyncio
import os
import subprocess
import psutil
import socket
import hashlib
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

console = Console()

# --- CONFIGURATION ---
# Ensure this is your RAW GitHub Gist link
LICENSE_SERVER_URL = "https://gist.githubusercontent.com/Minthol12/8e3e297e368f49d0582fa9e1c2800087/raw/2d8fcd1edcbf67fa3943435431d195a117024466/keys.txt" 
LICENSE_FILE = "shadow_license.key"

class ShadowToolkit:
    def __init__(self):
        self.hwid = self.generate_hwid()
        self.premium = self.check_license_locally()

    def generate_hwid(self): 
        node = str(socket.gethostname())
        # Use a simpler hardware ID for WSL stability
        return hashlib.sha256(node.encode()).hexdigest()[:16].upper()

    def check_license_locally(self):
        if os.path.exists(LICENSE_FILE):
            try:
                with open(LICENSE_FILE, "r") as f:
                    saved_data = f.read().strip().split(":")
                    if len(saved_data) == 2:
                        key, saved_hwid = saved_data
                        return saved_hwid == self.hwid
            except: return False
        return False

    async def verify_new_key(self, provided_key):
        console.print("[yellow]Connecting to SHADOW Verification Server...[/yellow]")
        try:
            response = requests.get(LICENSE_SERVER_URL, timeout=10)
            valid_keys = [k.strip() for k in response.text.splitlines()]
            
            if provided_key.strip() in valid_keys:
                with open(LICENSE_FILE, "w") as f:
                    f.write(f"{provided_key.strip()}:{self.hwid}")
                return True
            return False
        except: return False

    def run_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            return f"Error: {e}"

# --- THE 10 COMMANDS SUITE ---
async def run_advanced_suite(toolkit):
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(Panel(f"[bold magenta]SHADOW PRO: THE DECAGON SUITE[/bold magenta]\n[dim]HWID: {toolkit.hwid}[/dim]", border_style="magenta", box=box.DOUBLE_EDGE))
        
        table = Table(title="ADVANCED OPERATIONS", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Type", style="bold")

        # Defense
        table.add_row("1", "Deep Port Audit", "[green]DEFENSE[/green]")
        table.add_row("2", "Active Socket Monitor", "[green]DEFENSE[/green]")
        table.add_row("3", "Kernel Hardening", "[green]DEFENSE[/green]")
        table.add_row("4", "Brute-Force Log Triage", "[green]DEFENSE[/green]")
        table.add_row("5", "File Integrity Snapshot", "[green]DEFENSE[/green]")
        # Offensive/Hybrid
        table.add_row("6", "ICMP Stress Simulation", "[red]OFFENSIVE[/red]")
        table.add_row("7", "Stealth Banner Grab", "[red]OFFENSIVE[/red]")
        table.add_row("8", "DNS Cache Auditor", "[red]OFFENSIVE[/red]")
        table.add_row("9", "OS Fingerprinting", "[red]OFFENSIVE[/red]")
        table.add_row("10", "GLOBAL KILL-SWITCH", "[bold red]CRITICAL[/bold red]")

        console.print(table)
        choice = Prompt.ask("\nExecute Pro Command", choices=[str(i) for i in range(11)], default="0")

        if choice == "0": break
        
        # --- TOOL 1: Deep Port Audit ---
        elif choice == "1":
            target = Prompt.ask("Target IP", default="127.0.0.1")
            console.print(f"[yellow]Scanning {target}...[/yellow]")
            output = toolkit.run_cmd(f"nmap -F {target}")
            console.print(Panel(output, title="Nmap Results"))

        # --- TOOL 2: Active Socket Monitor (THE SNITCH) ---
        elif choice == "2":
            console.print("[yellow]Listing all active network connections...[/yellow]")
            # 'ss' shows established connections and listening ports
            output = toolkit.run_cmd("ss -atupn")
            console.print(Panel(output, title="Live Sockets"))

        # --- TOOL 3: Kernel Hardening (GHOST MODE) ---
        elif choice == "3":
            console.print("[bold cyan]Activating Ghost Mode Hardening...[/bold cyan]")
            # This makes your computer ignore pings and prevents redirect attacks
            toolkit.run_cmd("sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1")
            toolkit.run_cmd("sudo sysctl -w net.ipv4.conf.all.accept_redirects=0")
            console.print("[green]DONE: Your PC is now invisible to pings.[/green]")

        # --- TOOL 4: Log Triage ---
        elif choice == "4":
            output = toolkit.run_cmd("grep 'Failed password' /var/log/auth.log | tail -n 10")
            console.print(Panel(output if output else "No attacks detected.", title="Auth Logs"))

        # --- TOOL 5: Integrity Snapshot ---
        elif choice == "5":
            output = toolkit.run_cmd("find . -maxdepth 1 -type f -exec md5sum {} +")
            console.print(Panel(output, title="MD5 Hashes"))

        # --- TOOL 6: ICMP Stress Test ---
        elif choice == "6":
            target = Prompt.ask("Target IP")
            toolkit.run_cmd(f"sudo ping -f -c 200 {target}")
            console.print("[red]Stress burst sent.[/red]")

        # --- TOOL 7: Stealth Banner Grab (THE INTERROGATOR) ---
        elif choice == "7":
            target = Prompt.ask("Target IP", default="127.0.0.1")
            port = Prompt.ask("Port", default="80")
            console.print(f"[yellow]Connecting to {target}:{port} to grab ID...[/yellow]")
            # Uses netcat (nc) to grab the service version info
            output = toolkit.run_cmd(f"nc -v -z -w 2 {target} {port} 2>&1")
            console.print(Panel(output, title="Service Info"))

        # --- TOOL 8: DNS Auditor ---
        elif choice == "8":
            domain = Prompt.ask("Domain", default="google.com")
            output = toolkit.run_cmd(f"host -a {domain}")
            console.print(Panel(output, title="DNS Records"))

        # --- TOOL 9: OS Fingerprinting (THE DETECTIVE) ---
        elif choice == "9":
            target = Prompt.ask("Target IP")
            # Uses the TTL value from a ping to guess the OS
            ping_data = toolkit.run_cmd(f"ping -c 1 {target}")
            if "ttl=64" in ping_data.lower():
                res = "Likely LINUX/UNIX"
            elif "ttl=128" in ping_data.lower():
                res = "Likely WINDOWS"
            else:
                res = "Unknown / Firewall protected"
            console.print(Panel(f"Target: {target}\nResult: [bold cyan]{res}[/bold cyan]"))

        # --- TOOL 10: KILL SWITCH ---
        # --- TOOL 10: ULTIMATE KILL SWITCH ---
        elif choice == "10":
            console.print("[bold red]INITIATING TOTAL SYSTEM PURGE...[/bold red]")
            
            # 1. KILL NETWORK (Linux/WSL Side)
            interfaces = psutil.net_if_addrs()
            for iface in interfaces:
                if iface == 'lo': continue
                toolkit.run_cmd(f"sudo ip link set {iface} down")
            
            # 2. DEFINE THE WINDOWS EXECUTIONER
            win_kill = "/mnt/c/Windows/System32/taskkill.exe"

            # 3. YOUR EXTENDED BROWSER LIST
            # This contains every single process you identified
            target_browsers = [
                "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
                "vivaldi.exe", "tor.exe", "safari.exe", "iexplore.exe", "edge.exe",
                "chromium.exe", "com.microsoft.edgecp.exe", "com.microsoft.edgemcp.exe",
                "com.microsoft.edge.exe", "com.chrome.browser.exe", "com.firefox.browser.exe",
                "com.opera.browser.exe", "com.brave.browser.exe", "com.vivaldi.browser.exe",
                "com.tor.browser.exe", "com.safari.browser.exe", "com.iexplore.browser.exe",
                "com.chromium.browser.exe", "com.edgecp.browser.exe", "com.edgemcp.browser.exe",
                "com.edge.browser.exe", "com.chrome.exe", "com.firefox.exe", 
                "com.opera.exe", "com.brave.exe", "com.vivaldi.exe"
            ]

            console.print("[yellow]Force-closing all browser sessions...[/yellow]")
            
            for browser in target_browsers:
                # Runs the kill command for each browser in your list
                # '> /dev/null 2>&1' makes it run silently in the background
                toolkit.run_cmd(f"{win_kill} /F /IM {browser} /T > /dev/null 2>&1")
            
            # 4. FINAL LINUX CLEANUP (Just in case they are running inside Linux)
            toolkit.run_cmd("pkill -9 chrome || pkill -9 firefox || pkill -9 brave")
            
            console.print("[bold white on red] BLACKOUT COMPLETE: NETWORK DEAD & APPS PURGED [/bold white on red]")

        input("\nPress Enter to return...")
# --- MAIN MENU ---
async def main():
    toolkit = ShadowToolkit()
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        status = "[bold green]PREMIUM[/bold green]" if toolkit.premium else "[bold red]FREE[/bold red]"
        console.print(Panel(f"SHADOW TOOLKIT | {status}", style="cyan", box=box.DOUBLE_EDGE))

        console.print("\n[1] Network Audit\n[2] Log Intelligence\n[3] Integrity Snapshot\n[4] Resource Monitor\n[5] [magenta]ADVANCED COMMAND SUITE (PRO)[/magenta]\n[0] Exit")

        choice = Prompt.ask("\nSelect Action", choices=["0","1","2","3","4","5"])

        if choice == "5":
            if not toolkit.premium:
                console.print(Panel("[red]ACCESS DENIED[/red]\n\nEnter your 12-character high-entropy key.", title="LOCKED"))
                new_key = Prompt.ask("License Key")
                if await toolkit.verify_new_key(new_key):
                    toolkit.premium = True
                    console.print("[green]PRO UNLOCKED.[/green]")
                    await run_advanced_suite(toolkit)
                else:
                    console.print("[red]Invalid Key.[/red]")
                    input("Press Enter...")
            else:
                await run_advanced_suite(toolkit)

        elif choice == "1": # Network Audit
            target = Prompt.ask("Target IP", default="127.0.0.1")
            console.print(f"[yellow]Scanning {target}...[/yellow]")
            output = toolkit.run_cmd(f"nmap -F {target}")
            console.print(Panel(output, title="Network Audit Results"))
            input("\nPress Enter to return...")

        elif choice == "2": # Log Intelligence
            console.print("[yellow]Searching system logs for threats...[/yellow]")
            # Note: This requires 'sudo' to work!
            output = toolkit.run_cmd("grep 'Failed password' /var/log/auth.log | tail -n 10")
            console.print(Panel(output if output else "No suspicious login attempts found.", title="Log Intelligence"))
            input("\nPress Enter to return...")

        elif choice == "3": # Integrity Snapshot
            path = Prompt.ask("Directory to snapshot", default=".")
            output = toolkit.run_cmd(f"find {path} -maxdepth 1 -type f -exec md5sum {{}} +")
            console.print(Panel(output, title="File Integrity Hashes"))
            input("\nPress Enter to return...")

        elif choice == "4": # Resource Monitor
            console.print("[yellow]Gathering System Health Data...[/yellow]")
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            console.print(Panel(f"CPU: [bold cyan]{cpu}%[/bold cyan]\nRAM: [bold magenta]{ram}%[/bold magenta]\nDisk: [bold yellow]{disk}%[/bold yellow]", title="System Resources"))
            input("\nPress Enter to return...")
        # ---------------------------------

        elif choice == "0": break

if __name__ == "__main__":
    asyncio.run(main())
