import argparse
import logging
import os
import signal
import subprocess
import shlex
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

# --- Configuration Constants ---
# Default timeout for most VBoxManage operations (in seconds).
# Use 'None' for very long operations like full duplication.
VBOX_TIMEOUT = 60 

# Timeout for gracefully waiting for VM power off
VM_POWEROFF_TIMEOUT = 90

# Directory for lock and PID files (Use /tmp for transient files)
TEMP_DIR = Path("/tmp")
# Updated prefix to match tool name 'isol8'
LOCK_FILE_PREFIX = "isol8_vm_" 
TCPDUMP_PID_FILE = TEMP_DIR / "isol8_tcpdump.pid"

# --- ANSI Color Codes for Logging ---
class ANSIColors:
    """Class holding ANSI escape codes for terminal coloring."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
class ColoredFormatter(logging.Formatter):
    """Custom formatter to add color based on log level."""
    
    FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"
    
    LEVEL_COLORS = {
        logging.DEBUG: ANSIColors.RESET,
        logging.INFO: ANSIColors.GREEN,
        logging.WARNING: ANSIColors.YELLOW,
        logging.ERROR: ANSIColors.RED,
        logging.CRITICAL: ANSIColors.RED,
    }

    def format(self, record):
        """Applies color to the log record based on its level."""
        color = self.LEVEL_COLORS.get(record.levelno, ANSIColors.RESET)
        formatter = logging.Formatter(color + self.FORMAT + ANSIColors.RESET, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

# --- Logging Setup ---
# Apply the custom handler and formatter
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler]) 


# --- Custom Exceptions ---

class ToolError(Exception):
    """Custom exception for errors during command execution."""
    pass

class SnapshotError(ToolError):
    """Raised when a required snapshot is not found or invalid."""
    pass

class VMLockError(ToolError):
    """Raised when the VM lock cannot be acquired."""
    pass

# --- Helper Functions for System Interaction ---

def run(cmd: List[str], check: bool = True, timeout: Optional[int] = VBOX_TIMEOUT, **kwargs: Any) -> str:
    """
    Executes a command and returns its stdout.
    """
    cmd_str = shlex.join(cmd)
    logging.debug("Executing command: %s", cmd_str)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
            **kwargs
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with exit code {e.returncode}: {cmd_str}\nStderr: {e.stderr.strip()}"
        logging.error(error_msg)
        raise ToolError(error_msg)
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {timeout} seconds: {cmd_str}"
        logging.error(error_msg)
        raise ToolError(error_msg)
    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]}. Is VirtualBox installed and in PATH?"
        logging.error(error_msg)
        raise ToolError(error_msg)

# --- Lock Management ---

class VMLock:
    """Context manager for exclusive VM access using file locking."""
    
    def __init__(self, vm_name: str):
        self.vm_name = vm_name
        self.lock_file = TEMP_DIR / f"{LOCK_FILE_PREFIX}{vm_name}.lock"
        self.file_descriptor: Optional[int] = None

    def __enter__(self):
        try:
            # Open file in write mode, establishing if it doesn't exist
            self.file_descriptor = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            logging.info("Acquired lock on VM: %s", self.vm_name)
            return self
        except FileExistsError:
            msg = f"Lock file already exists for VM '{self.vm_name}'. Is another analysis running?"
            raise VMLockError(msg)
        except Exception as e:
            raise VMLockError(f"Failed to acquire VM lock: {e}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_descriptor is not None:
            os.close(self.file_descriptor)
            self.file_descriptor = None
        if self.lock_file.exists():
            self.lock_file.unlink()
            logging.info("Released lock on VM: %s", self.vm_name)

def check_vbox_preflight():
    """Checks if VBoxManage is accessible."""
    try:
        run(["VBoxManage", "--version"], check=True, timeout=5)
        logging.info("VBoxManage check passed.")
    except ToolError as e:
        raise ToolError(f"VirtualBox pre-flight check failed: {e}")

# --- VirtualBox Interaction Functions ---

def get_vm_info(vm_name: str) -> Dict[str, str]:
    """Retrieves and parses VM info into a dictionary."""
    try:
        output = run(["VBoxManage", "showvminfo", vm_name, "--machinereadable"], check=True)
        info = {}
        for line in output.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                info[key.strip().strip('"')] = value.strip().strip('"')
        return info
    except ToolError as e:
        # Re-raise the error to be caught later
        raise ToolError(f"Failed to get info for VM '{vm_name}'. Does it exist? Error: {e}")

def get_all_vms() -> Dict[str, str]:
    """Retrieves all registered VMs as {name: uuid}."""
    try:
        output = run(["VBoxManage", "list", "vms"], check=True)
        vms = {}
        for line in output.splitlines():
            # Example: "VM Name" {UUID}
            parts = line.split('{', 1)
            if len(parts) == 2:
                name = parts[0].strip().strip('"')
                uuid = parts[1].strip().strip('}')
                vms[name] = uuid
                
        # Filter out VMs that are temporary duplicates (if they exist from a previous failed run)
        vms = {name: uuid for name, uuid in vms.items() if "_ANALYSIS_" not in name}
        return vms
    except ToolError as e:
        raise ToolError(f"Failed to list Virtual Machines: {e}")

def get_available_snapshots(vm_info: Dict[str, str]) -> List[str]:
    """Extracts all snapshot names from VM info."""
    available_snapshots = []
    for key, value in vm_info.items():
        if key.startswith("SnapshotName"):
            available_snapshots.append(value)
    return available_snapshots

def resolve_snapshot_name(vm_name: str, initial_snapshot_name: str) -> str:
    """
    Checks if the requested snapshot exists. If not, falls back to 'clean-base' 
    and finally prompts the user to select from available options.
    """
    vm_info = get_vm_info(vm_name)
    
    if vm_info.get("VMState") != "poweroff":
        raise SnapshotError(f"Base VM '{vm_name}' must be powered off before duplication.")

    available_snapshots = get_available_snapshots(vm_info)
    
    # --- NON-INTERACTIVE RESOLUTION ATTEMPT ---
    
    # 1. Try the user's requested name (e.g., 'CleanBase')
    if initial_snapshot_name in available_snapshots:
        logging.info("Snapshot check passed. Using '%s' as the clean base.", initial_snapshot_name)
        return initial_snapshot_name
        
    # 2. Try the specified standard snapshot name 'clean-base'
    fallback_snapshot = "clean-base"
    if fallback_snapshot in available_snapshots:
        logging.warning("Initial snapshot '%s' not found. Automatically falling back to standard snapshot '%s'.", 
                        initial_snapshot_name, fallback_snapshot)
        return fallback_snapshot

    # --- INTERACTIVE RESOLUTION FALLBACK ---
    
    # If the execution reaches here, neither default nor fallback snapshot was found.
    error_message = (
        f"Snapshot '{initial_snapshot_name}' and automatic standard fallback ('{fallback_snapshot}') "
        f"not found on base VM '{vm_name}'.\n\n"
        "Please select a valid snapshot to proceed."
    )
    
    if not available_snapshots:
        error_message += "\n\nNo snapshots were found on this VM."
        raise SnapshotError(error_message)

    print(f"\n{error_message}")
    print("\nAvailable Snapshots:")
    
    snapshot_map = {str(i+1): name for i, name in enumerate(available_snapshots)}
    
    # Start interactive loop
    while True:
        # Display options
        for i, name in enumerate(available_snapshots):
            print(f"[{i+1}] {name}")
            
        try:
            choice = input("Select snapshot number or type the full name (or Ctrl+C to exit): ").strip()
            
            if choice in snapshot_map:
                selected_snapshot = snapshot_map[choice]
                logging.info("Selected snapshot: %s", selected_snapshot)
                return selected_snapshot
            elif choice in available_snapshots:
                logging.info("Entered snapshot name: %s", choice)
                return choice
            else:
                print("Invalid selection. Please choose a number from the list or type a valid name.")
        except EOFError:
            raise SnapshotError("Snapshot selection cancelled by user.")
        except KeyboardInterrupt:
            # Re-raise to trigger main cleanup/exit logic
            raise SystemExit(1)


def duplicate_linked(source_vm: str, duplicate_vm: str, snapshot_name: str, dry_run: bool = False):
    """Clones a new linked duplicate from a specified snapshot."""
    cmd = [
        "VBoxManage", "clonevm", source_vm, 
        "--options", "link", 
        "--snapshot", snapshot_name, 
        "--name", duplicate_vm, 
        "--register"
    ]
    if dry_run:
        logging.info("[dry-run] would clone linked duplicate: %s from %s @ %s", duplicate_vm, source_vm, snapshot_name)
        return
    
    run(cmd, check=True)
    logging.info("Linked duplicate cloned: %s", duplicate_vm)

def duplicate_full(source_vm: str, target_vm: str, dry_run: bool = False):
    """Generates a full, independent replica from a source VM."""
    cmd = ["VBoxManage", "clonevm", source_vm, "--mode", "all", "--name", target_vm, "--register"]
    if dry_run:
        logging.info("[dry-run] would generate full replica: %s from %s", target_vm, source_vm)
        return
    
    # Use None timeout for critical, long operations like full duplication
    run(cmd, check=True, timeout=None) 
    logging.info("Full replica generated: %s (containing dirty state)", target_vm)

def dispose_vm(vm_name: str, erase_files: bool = True, dry_run: bool = False):
    """Removes a VM from VirtualBox and optionally erases its disk files."""
    delete_option = "--delete" if erase_files else ""
    cmd = ["VBoxManage", "unregistervm", vm_name]
    if erase_files:
        cmd.append(delete_option)
        
    if dry_run:
        logging.info("[dry-run] would remove and erase VM: %s", vm_name)
        return
        
    # NOTE: check=False is used here because unregistervm can sometimes fail for transient VBox reasons
    # even when the VM is actually gone, but we will add a secondary check in the main workflow.
    logging.info("Removing VM: %s (Erase files: %s)", vm_name, erase_files)
    run(cmd, check=False) 

def harden_vm(vm_name: str, args: argparse.Namespace, dry_run: bool = False):
    """Applies hardening settings for secure malware analysis."""
    
    # Settings to disable guest interaction and security risks
    settings = {
        "clipboard": "disabled",
        "draganddrop": "disabled",
        "usb": "off",
        "audio": "null",
        "natnet1": "disabled", # Disable default NAT interface
    }

    logging.info("Applying hardening settings to %s...", vm_name)
    
    if dry_run:
        logging.info("[dry-run] would apply hardening settings.")
        return

    for key, value in settings.items():
        run(["VBoxManage", "modifyvm", vm_name, "--{0}".format(key), value], check=False)
        
    # --- Network Configuration ---
    if args.air_gapped:
        # Completely remove the network adapter for air-gapped analysis
        run(["VBoxManage", "modifyvm", vm_name, "--nic1", "none"], check=False)
        logging.info("VM hardening complete. **VM is fully air-gapped (no network adapter).**")
    else:
        # Add a Host-Only adapter for isolated network traffic capture
        network_commands = [
            ("nic1", "hostonly"),
            ("hostonlyadapter1", "vboxnet0"), # Ensure 'vboxnet0' exists on your host
        ]
        for key, value in network_commands:
            run(["VBoxManage", "modifyvm", vm_name, "--{0}".format(key), value], check=False)
        logging.info("VM hardening complete. Isolated on vboxnet0.")


def start_vm(vm_name: str, gui: bool, dry_run: bool = False):
    """Starts the VM in specified mode."""
    mode = "gui" if gui else "headless"
    cmd = ["VBoxManage", "startvm", vm_name, "--type", mode]
    
    if dry_run:
        logging.info("[dry-run] would commence VM: %s in %s mode.", vm_name, mode)
        return

    logging.info("Commencing VM: %s in %s mode.", vm_name, mode)
    # Start VM without waiting for it to exit
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    # Give the VM time to boot up
    time.sleep(5) 
    logging.info("VM start command issued.")

def poweroff_vm(vm_name: str, dry_run: bool = False):
    """Performs an ACPI shutdown."""
    cmd = ["VBoxManage", "controlvm", vm_name, "acpipowerbutton"]
    if dry_run:
        logging.info("[dry-run] would send ACPI power button to VM: %s", vm_name)
        return

    logging.info("Sending ACPI power button to VM: %s...", vm_name)
    run(cmd, check=False)
    time.sleep(2) # Give VM a moment to recognize the signal

def force_poweroff_vm(vm_name: str, dry_run: bool = False):
    """Performs an immediate, ungraceful power off."""
    cmd = ["VBoxManage", "controlvm", vm_name, "poweroff"]
    if dry_run:
        logging.info("[dry-run] would force poweroff VM: %s", vm_name)
        return

    logging.warning("Forcing power off VM: %s...", vm_name)
    run(cmd, check=False)

def wait_for_poweroff(vm_name: str, timeout: int = VM_POWEROFF_TIMEOUT) -> bool:
    """Waits for the VM to reach the 'poweroff' state, up to a timeout."""
    start_time = time.monotonic()
    logging.info("Waiting for VM '%s' to power off gracefully (max %d seconds)...", vm_name, timeout)
    
    while (time.monotonic() - start_time) < timeout:
        try:
            state = get_vm_info(vm_name).get("VMState")
            if state == "poweroff":
                logging.info("VM is powered off.")
                return True
            if state == "running":
                time.sleep(2) # Check every 2 seconds
            else:
                # Other states like 'stopping', 'aborted', etc.
                time.sleep(1) 
        except ToolError:
            # If VM info fails (e.g., VM was unregistered already, though unlikely here)
            logging.warning("Could not get VM state during shutdown wait. Assuming powered off.")
            return True
            
    logging.warning("VM '%s' did not power off gracefully within the %d second timeout.", vm_name, timeout)
    return False

# --- TCPDUMP / TSHARK Monitoring ---

def start_tcpdump(args: argparse.Namespace, dry_run: bool) -> tuple[Optional[subprocess.Popen], Optional[Path]]:
    """
    Initiates host-side network capture using either tcpdump (Linux/macOS) or tshark (Windows guest).
    """
    
    output_file = Path(f"/tmp/network_capture_{os.getpid()}.pcap")
    
    if args.os == "windows":
        # Use tshark for Windows guest environments (common in analysis)
        tool_name = "tshark"
        # Command: sudo tshark -i <interface> -w <file>
        cmd = ["sudo", "tshark", "-i", args.interface, "-w", str(output_file)]
    else:
        # Use tcpdump for Linux/macOS guests
        tool_name = "tcpdump"
        # Command: sudo tcpdump -i <interface> -w <file> -s0 (snap length 0 for full packets)
        cmd = ["sudo", "tcpdump", "-i", args.interface, "-w", str(output_file), "-s0"]

    if dry_run:
        logging.info("[dry-run] would initiate network capture on interface %s (Tool: %s).", args.interface, tool_name)
        return None, None
        
    logging.info("Initiating host-side network capture using %s on %s. Output: %s", tool_name, args.interface, output_file)
    try:
        # Use Popen to run asynchronously
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Give it a moment to start and check for immediate errors
        time.sleep(1) 
        if p.poll() is not None:
            # Check if capture tool started and immediately failed (e.g., bad interface, tool not found, no sudo)
            stderr = p.stderr.read().decode().strip()
            raise ToolError(f"{tool_name} failed to start. Error: {stderr}")

        # Write PID to file for cleanup in case the main script is interrupted
        with open(TCPDUMP_PID_FILE, "w") as f:
            f.write(str(p.pid))
        
        logging.info("%s process commenced (PID: %d).", tool_name, p.pid)
        return p, output_file
        
    except Exception as e:
        logging.error("Failed to start network capture (%s): %s", tool_name, e)
        raise ToolError(f"Failed to start network capture ({tool_name}): {e}")

def stop_tcpdump(p: Optional[subprocess.Popen], timeout: int = 10):
    """Terminates the network capture process (tcpdump or tshark), handling PID file and potential sudo invocation."""
    
    # 1. Handle process object if available (preferred method)
    if p is not None:
        logging.info("Stopping network capture (pid=%d) via Popen object.", p.pid)
        try:
            p.terminate() # Send SIGTERM
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logging.warning("Network capture process did not exit gracefully; killing.")
            p.kill()
    else:
        # 2. Handle cleanup via PID file (for external signal or manual cleanup)
        if TCPDUMP_PID_FILE.exists():
            try:
                with open(TCPDUMP_PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                
                logging.info("Found stale capture PID %d in file. Attempting to terminate.", pid)
                
                # CRITICAL FIX: Must use sudo kill to stop root-owned processes
                kill_term_cmd = ["sudo", "kill", "-TERM", str(pid)]
                logging.debug("Running TERM command: %s", shlex.join(kill_term_cmd))
                run(kill_term_cmd, check=False, timeout=5)
                
                # Wait, then use SIGKILL if process still exists
                time.sleep(1)
                
                # Check if process still running using 'ps -p PID'
                if run(["ps", "-p", str(pid)], check=False) != "":
                    kill_kill_cmd = ["sudo", "kill", "-KILL", str(pid)]
                    logging.warning("Process %d still active. Running KILL command: %s", pid, shlex.join(kill_kill_cmd))
                    run(kill_kill_cmd, check=False, timeout=5)
                    
            except (ValueError, FileNotFoundError):
                logging.debug("Capture PID file exists but process is already gone or file corrupted.")
            except Exception as e:
                # Catching ToolError from `run` wrapper
                logging.error("Failed to kill capture process from PID file: %s", e)
    
    # 3. Clean up PID file
    if TCPDUMP_PID_FILE.exists():
        TCPDUMP_PID_FILE.unlink()
        logging.debug("Capture PID file removed.")

# --- Main Workflow ---

def analysis_workflow(vm_name: str, snapshot_name: str, args: argparse.Namespace):
    """
    Main workflow for duplicating, running, and dismantling the analysis VM.
    """
    
    base_vm_name = vm_name
    resolved_snapshot_name = snapshot_name 
    duplicate_vm_name = f"{base_vm_name}_ANALYSIS_{os.getpid()}"
    keep_vm_name = f"{base_vm_name}_DIRTY_{time.strftime('%Y%m%d%H%M%S')}" if args.keep_current else None
    
    tcpdump_proc: Optional[subprocess.Popen] = None
    pcap_path: Optional[Path] = None
    
    # Setup for signal handling (allows clean exit on Ctrl+C)
    def signal_handler(sig, frame):
        logging.error("\nReceived signal %d. Initiating emergency cleanup...", sig)
        # Attempt to clean up network capture if it was started
        stop_tcpdump(tcpdump_proc) 
        # Emergency poweroff and dispose the duplicate if it exists
        logging.warning("Attempting force poweroff and dispose of %s...", duplicate_vm_name)
        force_poweroff_vm(duplicate_vm_name)
        dispose_vm(duplicate_vm_name, erase_files=True)
        # Re-raise the signal to exit the program
        raise SystemExit(1)
        
    # Register handlers for SIGINT (Ctrl+C) and SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        
        # 1. Acquire lock to prevent concurrent runs on the base VM
        with VMLock(base_vm_name):
            
            # 2. Clone Linked Duplicate
            duplicate_linked(base_vm_name, duplicate_vm_name, resolved_snapshot_name, args.dry_run)
            
            # 3. Harden the Duplicate (Network, USB, Clipboard off)
            # Pass the args object to harden_vm to check for --air-gapped
            harden_vm(duplicate_vm_name, args, args.dry_run)
            
            # 4. Commence Monitoring (if requested)
            if args.tcpdump:
                # Pass the full args object for OS-specific tool selection (tcpdump/tshark)
                tcpdump_proc, pcap_path = start_tcpdump(args, args.dry_run)
                
            # 5. Commence the VM
            start_vm(duplicate_vm_name, args.gui, args.dry_run)
            
            # 6. Monitor and wait for auto-shutdown timeout
            if args.auto_shutdown is not None and args.auto_shutdown > 0:
                logging.info("VM running. Auto-shutdown scheduled in %d seconds.", args.auto_shutdown)
                
                # Simple loop to wait for the timeout
                start_time = time.monotonic()
                while (time.monotonic() - start_time) < args.auto_shutdown:
                    time.sleep(1)
                    
                logging.info("Timeout reached after %d seconds. Initiating ACPI shutdown.", args.auto_shutdown)
                poweroff_vm(duplicate_vm_name, args.dry_run)
                
                # Robustly wait for shutdown instead of fixed sleep
                if not args.dry_run:
                    wait_for_poweroff(duplicate_vm_name, timeout=VM_POWEROFF_TIMEOUT)
            
            else:
                logging.info("VM running. Waiting for manual shutdown or Ctrl+C...")
                # Wait indefinitely until the user manually stops the VM or sends a signal
                while get_vm_info(duplicate_vm_name).get("VMState") != "poweroff":
                    time.sleep(5)
                logging.info("VM '%s' has shut down gracefully.", duplicate_vm_name)

    except (VMLockError, ToolError, SystemExit) as e:
        # These are expected errors or controlled exits; just log and cleanup will run
        logging.error("Workflow failed: %s", e)
        
    except Exception as e:
        # Catch unexpected Python errors
        logging.critical("An unexpected error occurred: %s", e, exc_info=True)
        
    finally:
        logging.info("--- CLEANUP PHASE INITIATED ---")
        
        # 7. Stop Monitoring and report PCAP path
        if args.tcpdump and not args.dry_run:
            stop_tcpdump(tcpdump_proc)
            if pcap_path and pcap_path.exists():
                logging.info(ANSIColors.YELLOW + "Network capture saved successfully at: %s" + ANSIColors.RESET, pcap_path)
            else:
                logging.warning("Network capture file was not found at expected path: %s", pcap_path)
            
        # Check VM state for final cleanup decisions
        try:
            vm_state = get_vm_info(duplicate_vm_name).get("VMState")
        except ToolError:
            vm_state = "unknown (likely removed)"

        # 8. Ensure VM is powered off before duplicating/disposing
        if vm_state not in ["poweroff", "unknown (likely removed)"]:
            logging.warning("VM is not powered off (State: %s). Forcing power off.", vm_state)
            force_poweroff_vm(duplicate_vm_name, args.dry_run)

        # 9. Handle 'Keep Current State'
        if args.keep_current and keep_vm_name:
            logging.info("Preserving dirty state as full replica: %s", keep_vm_name)
            try:
                # Renamed function call in workflow
                duplicate_full(duplicate_vm_name, keep_vm_name, args.dry_run)
            except ToolError as e:
                logging.error("Failed to preserve dirty state (full generation failed): %s", e)
        
        # 10. Dispose of the Ephemeral Linked Duplicate (First Attempt)
        if not args.dry_run:
            dispose_vm(duplicate_vm_name, erase_files=True)
            logging.info("Ephemeral analysis duplicate '%s' dismantled.", duplicate_vm_name)
            
            # --- CRITICAL FIX: AGGRESSIVE VERIFICATION AND FALLBACK CLEANUP ---
            if duplicate_vm_name in get_all_vms():
                logging.critical(
                    ANSIColors.RED + 
                    "CRITICAL FAILURE: Temporary VM '%s' is still registered after the first disposal attempt."
                    " Attempting emergency force poweroff and disposal." + 
                    ANSIColors.RESET, 
                    duplicate_vm_name
                )
                
                # Second, forceful attempt
                force_poweroff_vm(duplicate_vm_name)
                dispose_vm(duplicate_vm_name, erase_files=True)
                
                # Final check after aggressive cleanup
                if duplicate_vm_name in get_all_vms():
                    logging.critical(
                        ANSIColors.RED + 
                        "ABSOLUTE FAILURE: Could not remove duplicate VM. Please remove '%s' MANUALLY from VirtualBox Manager." + 
                        ANSIColors.RESET, 
                        duplicate_vm_name
                    )
                else:
                    logging.info(ANSIColors.GREEN + "Aggressive cleanup succeeded." + ANSIColors.RESET)
            # --- END CRITICAL FIX ---
            
        else:
            logging.info("[dry-run] Cleanup complete. Duplicate '%s' would have been dismantled.", duplicate_vm_name)

# --- Argument Parsing ---

def main():
    """Parses arguments, resolves VM and snapshot names, and runs the analysis workflow."""
    parser = argparse.ArgumentParser(
        # Updated description
        description="Isol8: Securely run malware analysis in a disposable VirtualBox linked duplicate.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "--vm", 
        required=False, 
        help="The name of the base VirtualBox VM to duplicate from (e.g., Win10MalwareBase)."
    )
    parser.add_argument(
        "--snapshot", 
        default="CleanBase", 
        help="The name of the clean snapshot to use for the linked duplicate. Automatically attempts 'clean-base' if this name is unavailable (Default: CleanBase)."
    )
    parser.add_argument(
        "--os", 
        choices=["windows", "linux", "macos"],
        default="linux", 
        help="The operating system of the GUEST VM. Used to select appropriate host-side analysis tools (e.g., tshark vs. tcpdump). (Default: linux)"
    )
    parser.add_argument(
        "--gui", 
        action="store_true", 
        help="Commence the VM in GUI mode instead of headless mode."
    )
    parser.add_argument(
        "--auto-shutdown", 
        type=int, 
        default=None, 
        help="Time (in seconds) after which to send an ACPI shutdown signal (e.g., 300 for 5 mins)."
    )
    parser.add_argument(
        "--keep-current", 
        action="store_true", 
        help="After analysis, generate a permanent full replica of the dirty state before disposal."
    )
    parser.add_argument(
        "--tcpdump", 
        action="store_true", 
        help="Commence host-side network traffic capture using the appropriate tool (tcpdump/tshark)."
    )
    parser.add_argument(
        "--air-gapped", 
        action="store_true", 
        help="Completely disconnects the VM from the network by removing the network adapter (air-gapped mode)."
    )
    parser.add_argument(
        "--interface", 
        default="vboxnet0", 
        help="The host network interface to monitor (Default: vboxnet0)."
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Perform all checks and log actions without actually running VBoxManage or subprocess commands."
    )
    
    args = parser.parse_args()
    
    try:
        # 1. Pre-flight checks
        check_vbox_preflight()

        # 2. Network Isolation Conflict Check
        if args.air_gapped and args.tcpdump:
            raise ToolError("Cannot use --air-gapped and --tcpdump together. Network capture requires a network interface.")
        
        # 3. Interactive VM Selection Logic
        vm_name = args.vm
        if not vm_name:
            vms = get_all_vms()
            if not vms:
                logging.error("No registered Virtual Machines found.")
                # Fall through to argument check below if no VMs found
            else:
                print("\nAvailable Virtual Machines:")
                vm_names = list(vms.keys())
                for i, name in enumerate(vm_names):
                    print(f"[{i+1}] {name}")
                
                # Prompt user for selection
                while True:
                    try:
                        choice = input("Select VM number or type full name: ").strip()
                        if choice.isdigit():
                            index = int(choice) - 1
                            if 0 <= index < len(vm_names):
                                vm_name = vm_names[index]
                                break
                            else:
                                print("Invalid number. Please choose a number from the list.")
                        elif choice in vm_names:
                            vm_name = choice
                            break
                        else:
                            print("Invalid VM name or number.")
                    except EOFError:
                        print("\nSelection cancelled.")
                        return

        if not vm_name:
            logging.error("A VM name is required. Please provide a valid VM name or register a VM.")
            parser.print_help()
            exit(1)
        
        # 4. Snapshot Resolution Logic 
        resolved_snapshot = resolve_snapshot_name(vm_name, args.snapshot)
        
        # 5. Execute the workflow with resolved names
        if args.tcpdump and os.geteuid() != 0:
            tool_used = "tshark" if args.os == "windows" else "tcpdump"
            logging.warning("NETWORK CAPTURE WARNING: Running %s typically requires 'sudo' privileges. You may be prompted for a password.", tool_used)

        analysis_workflow(vm_name, resolved_snapshot, args)
        
    except (ToolError, SystemExit) as e:
        # Catch fatal errors during pre-flight or resolution
        if isinstance(e, ToolError):
            logging.critical("Fatal setup error: %s", e)
        # SystemExit is raised by signal handler or explicit exit
        exit(1)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user (Ctrl+C). Exiting cleanly.")
        exit(1)


if __name__ == "__main__":
    main()
