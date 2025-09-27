#!/usr/bin/env python3
"""
AntiVMaLinux - Production-ready VirtualBox containment/ephemeral-run tool for malware analysis.

Key features:
 - Robust state management and concurrency control using file locking.
 - Mandatory clean snapshot validation/formation.
 - Ephemeral linked clones workflow (clone -> harden -> run -> monitor -> destroy).
 - Mandatory host-only hardening for safety (clipboard, dnd, usb, shared folders disabled).
 - TCPDump host-side capture with automatic rotation (now optional via --no-pcap).
 - Active VM state monitoring and automatic shutdown based on time limit.
 - Robust logging, retries, and cleanup via signal handling and finally blocks.
"""
from __future__ import annotations

import argparse
import datetime
import errno
import logging
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Tuple, List

# ---------------- CONFIG/CONSTANTS ----------------
APP_NAME = "AntiVMaLinux"
DEFAULT_CLEAN_NAME = "clean-base"
POLL_INTERVAL = 4  # seconds: How often to check VM state and timeout
SNAP_RETRY = 3
SNAP_RETRY_DELAY = 2
LOCK_DIR = Path(tempfile.gettempdir())
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DEFAULT_PCAP_DIR = Path.home() / "antivma_pcaps"
PCAP_ROTATE_COUNT = 10
DEFAULT_HOSTONLY_ADAPTER = "vboxnet0"
VBOX_TIMEOUT = 60 # seconds: Default timeout for critical VBoxManage calls
TCPDUMP_PID_FILE = LOCK_DIR / "antivma-tcpdump.pid"
# --------------------------------------------------

class ToolError(Exception):
    """Custom exception for errors related to tool execution or configuration."""
    pass

# ---------- utility subprocess wrapper ----------
def run(cmd: List[str], capture=True, check=False, timeout: Optional[int]=VBOX_TIMEOUT) -> subprocess.CompletedProcess:
    """Wrapper for subprocess.run with error handling and logging."""
    logging.debug("RUN: %s", shlex.join(cmd))
    try:
        # Use shell=False is crucial for security and consistent behavior
        cp = subprocess.run(cmd, capture_output=capture, text=True, check=check, timeout=timeout)
        # Only log success check=False commands return code if non-zero
        if not check and cp.returncode != 0:
             logging.debug("=> non-fatal exit=%s stdout(%.200s) stderr(%.200s)", cp.returncode, (cp.stdout or "")[:200], (cp.stderr or "")[:200])

        if check and cp.returncode != 0:
            # Explicitly raise for commands that require success
            raise subprocess.CalledProcessError(cp.returncode, cmd, cp.stdout, cp.stderr)
            
        return cp
    except FileNotFoundError:
        raise ToolError(f"Command not found: {cmd[0]}. Ensure VirtualBox (VBoxManage) is installed and in PATH.")
    except subprocess.TimeoutExpired:
        raise ToolError(f"Timeout (>{timeout}s) while running: {' '.join(cmd)}. This may indicate a VBoxManage hang.")
    except subprocess.CalledProcessError as e:
        # Re-raise VBoxManage specific errors with enhanced context
        error_message = f"VBoxManage failed ({e.returncode}): {' '.join(cmd)}\n"
        if 'not found' in (e.stderr or e.stdout or ""):
             error_message += "HINT: The VM or snapshot name might be incorrect, or the host-only adapter is missing.\n"
        error_message += f"stdout: {e.stdout}\nstderr: {e.stderr}"
        raise ToolError(error_message)

def ensure_vboxmanage():
    """Checks for the presence of VBoxManage early to fail fast."""
    try:
        run(["VBoxManage", "--version"], check=True, timeout=10)
        logging.info("VBoxManage check passed.")
    except ToolError as e:
        raise ToolError(f"VBoxManage check failed: {e}")

# ---------- VBoxManage checks and state ----------
def vbox_version() -> str:
    """Returns the VirtualBox version string."""
    cp = run(["VBoxManage", "--version"], timeout=10)
    return (cp.stdout or cp.stderr or "").strip()

def list_vms() -> List[str]:
    """Lists all registered VM names."""
    cp = run(["VBoxManage", "list", "vms"])
    vms = []
    for ln in (cp.stdout or "").splitlines():
        if ln.strip().startswith('"'):
            try:
                # Extract the VM name between the first pair of double quotes
                vms.append(ln.split('"')[1])
            except Exception:
                continue
    return vms

def vm_exists(vm_name: str) -> bool:
    """Checks if a VM is registered."""
    return vm_name in list_vms()

def get_vm_info_raw(vm_name: str) -> str:
    """Gets machine-readable configuration for a VM."""
    # Check existence first to provide a better error message if missing
    if not vm_exists(vm_name):
        raise ToolError(f"VM '{vm_name}' not found. Available VMs: {list_vms()}")

    cp = run(["VBoxManage", "showvminfo", vm_name, "--machinereadable"])
    return cp.stdout or ""

def get_vm_state(vm_name: str) -> str:
    """Returns the current execution state of a VM (e.g., 'poweroff', 'running')."""
    try:
        raw = get_vm_info_raw(vm_name)
    except ToolError:
        # get_vm_info_raw raises ToolError if VM is not found
        return "unknown"
        
    for line in raw.splitlines():
        if line.startswith("VMState="):
            return line.split("=",1)[1].strip().strip('"')
    return "unknown"

# ---------- snapshot helpers ----------
def snapshot_list(vm_name: str) -> str:
    """Returns the detailed snapshot list output."""
    cp = run(["VBoxManage", "snapshot", vm_name, "list", "--details"])
    return cp.stdout or ""

def snapshot_exists(vm_name: str, snap_name: str) -> bool:
    """Checks if a snapshot exists for the given VM."""
    try:
        out = snapshot_list(vm_name)
        # Check for various formats VBoxManage might use
        return (f"Name:            {snap_name}" in out or 
                f"Name: {snap_name}" in out or 
                f"\"{snap_name}\"" in out)
    except ToolError as e:
        # If the VM doesn't exist, list will fail, treat as snapshot not found
        logging.debug("Error listing snapshots for %s: %s", vm_name, e)
        return False


def take_snapshot(vm_name: str, snap_name: str, description: str = "", dry_run: bool = False):
    """Takes a snapshot with retry logic."""
    if not dry_run and get_vm_state(vm_name) != "poweroff":
        # Check VM state *before* attempting snapshot
        raise ToolError(f"Cannot take snapshot. VM '{vm_name}' must be powered off. Current state: {get_vm_state(vm_name)}")

    cmd = ["VBoxManage", "snapshot", vm_name, "take", snap_name, "--description", description]
    if dry_run:
        logging.info("[dry-run] would take snapshot: %s", snap_name)
        return
    
    # Updated description string
    if "Auto-formed" in description:
        description = "Auto-formed persistent clean base snapshot"

    last_exc = None
    for i in range(1, SNAP_RETRY + 1):
        try:
            # Use check=True in run wrapper
            run(cmd, check=True)
            logging.info("Snapshot '%s' formed for VM '%s'", snap_name, vm_name)
            return
        except ToolError as e:
            last_exc = e
            logging.warning("Snapshot attempt %d/%d failed: %s", i, SNAP_RETRY, e)
            time.sleep(SNAP_RETRY_DELAY)
    raise ToolError(f"Failed to form snapshot after {SNAP_RETRY} retries: {last_exc}")

# ---------- ephemeral clone helpers ----------
def clone_linked(vm_name: str, snapshot: str, clone_name: str, dry_run: bool = False):
    """Forms a linked clone from a base snapshot."""
    cmd = ["VBoxManage", "clonevm", vm_name, "--snapshot", snapshot, "--options", "link", "--name", clone_name, "--register"]
    if dry_run:
        logging.info("[dry-run] would form linked clone: %s from snapshot %s", clone_name, snapshot)
        return
    run(cmd, check=True)
    logging.info("Linked clone formed: %s", clone_name)

def clone_full(source_vm: str, target_vm: str, dry_run: bool = False):
    """Forms a full, independent clone from a source VM."""
    cmd = ["VBoxManage", "clonevm", source_vm, "--mode", "all", "--name", target_vm, "--register"]
    if dry_run:
        logging.info("[dry-run] would form full clone: %s from %s", target_vm, source_vm)
        return
    run(cmd, check=True)
    logging.info("Full clone formed: %s (containing dirty state)", target_vm)


def unregister_delete_vm(vm_name: str, dry_run: bool = False):
    """
    Safely powers off if needed, and forces the VM out of any VBox lock, 
    then deletes and unregisters the VM.
    """
    if not vm_exists(vm_name):
        logging.debug("VM '%s' does not exist, skipping deletion.", vm_name)
        return

    if not dry_run:
        state = get_vm_state(vm_name)
        
        # 1. Force poweroff to release any VBox internal locks
        if state not in ("poweroff", "aborted", "unknown"):
             logging.info("Forcing poweroff of VM '%s' (State: %s) before deletion.", vm_name, state)
             try:
                 # Use poweroff twice if needed, and allow it to fail non-critically
                 run(["VBoxManage", "controlvm", vm_name, "poweroff"], check=False, timeout=10)
                 # Give VBox a moment to clean up internal state
                 time.sleep(1)
             except ToolError as e:
                 # Log but continue to unregister --delete
                 logging.warning("Failed to gracefully poweroff %s: %s. Continuing with deletion.", vm_name, e)

    # 2. Attempt final deletion
    cmd = ["VBoxManage", "unregistervm", vm_name, "--delete"]
    if dry_run:
        logging.info("[dry-run] would unregister & delete VM: %s", vm_name)
        return
    try:
        run(cmd, check=True)
        logging.info("VM unregistered and deleted: %s", vm_name)
    except ToolError as e:
        # Check if the error is still a VBOX_E_INVALID_OBJECT_STATE (internal lock)
        if "locked" in (e.stderr or ""):
            logging.error("Final cleanup failed due to persistent internal lock on VM '%s'. Please manually close and delete the VM via VirtualBox GUI.", vm_name)
        else:
            logging.warning("Failed to unregister/delete VM %s: %s", vm_name, e)

# ---------- hardening helpers ----------
def disable_risky_features(vm_name: str, dry_run: bool = False):
    """Disables guest interaction features for safety."""
    # Fixed logging typo: removed extraneous parenthesis
    logging.info("Applying mandatory hardening: Disabling clipboard, drag-and-drop, and USB.")
    cmd = ["VBoxManage", "modifyvm", vm_name, 
           "--clipboard", "disabled", 
           "--draganddrop", "disabled", 
           "--usb", "off"]
    if dry_run:
        logging.info("[dry-run] would: %s", shlex.join(cmd))
        return
    run(cmd, check=True)

def set_hostonly(vm_name: str, adapter_name: str, dry_run: bool = False):
    """
    Sets the first NIC to a host-only network adapter for isolation 
    and explicitly disables all other NICs for maximum containment.
    """
    logging.info("Applying mandatory hardening: Ensuring full network isolation.")
    
    # 1. Disable all NICs from 2 to 8 to prevent unexpected connections (NAT/Bridged)
    logging.info("Disabling NICs 2 through 8 to ensure full isolation.")
    for i in range(2, 9):
        # Explicitly set subsequent NICs to 'none'. We use check=False and rely on
        # debug logging to handle cases where the VM has < 8 NIC slots.
        cmd = ["VBoxManage", "modifyvm", vm_name, f"--nic{i}", "none"]
        if dry_run:
            logging.debug("[dry-run] would disable NIC: %s", shlex.join(cmd))
            continue
            
        run(cmd, check=False) # Non-fatal if less than 8 NICs exist
            
    # 2. Configure NIC 1 as the isolated host-only adapter
    logging.info("Setting VM NIC1 to host-only adapter %s", adapter_name)
    cmd = ["VBoxManage", "modifyvm", vm_name, "--nic1", "hostonly", "--hostonlyadapter1", adapter_name]
    if dry_run:
        logging.info("[dry-run] would: %s", shlex.join(cmd))
        return
    # This command MUST succeed, and its failure will clearly report if adapter_name is missing
    run(cmd, check=True)

def remove_shared_folders(vm_name: str, dry_run: bool = False):
    """Removes all defined shared folders to prevent host file access."""
    # Needs to handle ToolError if VM doesn't exist, though clonevm handles that generally
    try:
        raw = get_vm_info_raw(vm_name)
    except ToolError:
        logging.debug("VM not found, skipping shared folder removal.")
        return

    names = set()
    for line in raw.splitlines():
        if line.startswith("SharedFolderNameMachineMapping"):
            try:
                _, val = line.split("=",1)
                names.add(val.strip().strip('"'))
            except Exception:
                continue
    
    if not names:
        logging.info("No shared folders detected to remove.")
        return
        
    for name in names:
        logging.info("Removing shared-folder: %s.", name)
        cmd = ["VBoxManage", "sharedfolder", "remove", vm_name, "--name", name]
        if dry_run:
            logging.info("[dry-run] would: %s", shlex.join(cmd))
            continue
        run(cmd, check=True)
        logging.info("Removed shared folder: %s", name)

# ---------- host-side pcap capture ----------
def prune_pcaps(pcap_dir: Path, max_files: int = PCAP_ROTATE_COUNT):
    """
    Deletes oldest PCAP files to ensure the total number of files does not
    exceed 'max_files' after the new PCAP file is written.
    """
    if not pcap_dir.exists():
        return
    
    # Filter for .pcap files and sort by modification time (oldest first)
    pcaps = sorted([f for f in pcap_dir.glob("*.pcap") if f.is_file()], 
                   key=lambda f: f.stat().st_mtime)

    # Use '>' to delete files only when we exceed the max count, aligned with user request
    while len(pcaps) > max_files:
        old = pcaps.pop(0)
        logging.info("Pruning old PCAP (exceeds limit %d): %s", max_files, old.name)
        try:
            old.unlink()
        except OSError as e:
            logging.warning("Failed to delete old PCAP %s: %s", old.name, e)

def start_tcpdump(interface: str, out_path: Path, dry_run: bool = False) -> Tuple[Optional[subprocess.Popen], Path]:
    """Starts tcpdump in background, handles PID file, and checks for root requirements."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if tcpdump and sudo exist
    if not shutil.which("tcpdump"):
         raise ToolError("tcpdump not found. Install tcpdump to capture network traffic.")
    if os.getuid() != 0 and not shutil.which("sudo"):
         raise ToolError("You are not root and 'sudo' is not found. tcpdump usually requires root privileges.")

    # Use sudo if not running as root
    cmd_prefix = ["sudo"] if os.getuid() != 0 else []
    cmd = cmd_prefix + ["tcpdump", "-i", interface, "-w", str(out_path)] 
    
    if dry_run:
        logging.info("[dry-run] would run tcpdump: %s", shlex.join(cmd))
        return None, out_path
    
    if os.getuid() != 0:
        # Note the potential for the password prompt here
        logging.warning("tcpdump requires root permissions; running via 'sudo'. Ensure passwordless sudo is configured for tcpdump or be prepared to enter a password.")

    try:
        # Popen to run non-blocking
        # NOTE: If this stalls due to a password prompt, it will still proceed with the VM start
        # but the capture won't start until the password is entered.
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Write PID file for reliable cleanup
        with open(TCPDUMP_PID_FILE, "w") as f:
            f.write(str(p.pid))

        logging.info("Started tcpdump (pid=%d) on %s -> %s (PID file: %s)", p.pid, interface, out_path, TCPDUMP_PID_FILE)
        return p, out_path
    except Exception as e:
        # Cleanup PID file if formation failed after popen
        if TCPDUMP_PID_FILE.exists():
            TCPDUMP_PID_FILE.unlink()
        raise ToolError(f"Failed to start tcpdump: {e}")


def stop_tcpdump(p: Optional[subprocess.Popen], timeout: int = 10):
    """Terminates the tcpdump process, handling PID file and potential sudo invocation."""
    
    # 1. Handle process object if available (preferred method)
    if p is not None:
        logging.info("Stopping tcpdump (pid=%d) via Popen object.", p.pid)
        try:
            p.terminate() # Send SIGTERM
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logging.warning("tcpdump did not exit gracefully; killing.")
            p.kill()
    else:
        # 2. Handle cleanup via PID file (for external signal or manual cleanup)
        if TCPDUMP_PID_FILE.exists():
            try:
                with open(TCPDUMP_PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                
                logging.info("Found stale tcpdump PID %d in file. Attempting to terminate.", pid)
                # Use kill -TERM
                os.kill(pid, signal.SIGTERM) 
                # Give it a moment, then kill if needed (requires sudo privileges)
                time.sleep(1)
                os.kill(pid, signal.SIGKILL)
            except (ValueError, FileNotFoundError, ProcessLookupError):
                logging.debug("tcpdump PID file exists but process is already gone or file corrupted.")
            except Exception as e:
                logging.warning("Failed to kill tcpdump process from PID file: %s", e)
    
    # 3. Clean up PID file
    if TCPDUMP_PID_FILE.exists():
        TCPDUMP_PID_FILE.unlink()

# ---------- locking ----------
def is_pid_running(pid: int) -> bool:
    """Checks if a given PID is currently active using os.kill(pid, 0)."""
    if pid <= 0:
        return False
    try:
        # Signal 0 checks existence and permissions
        os.kill(pid, 0)
        return True
    except OSError as err:
        # EPERM means process exists but we don't have permission (still running)
        if err.errno == errno.EPERM: 
            return True
        # ESRCH means no such process (not running)
        if err.errno == errno.ESRCH:
            return False
        # Catch other errors
        logging.debug("Error checking PID %d: %s", pid, err)
        return False

def acquire_lock(vm_name: str) -> Path:
    """Acquires a process lock on the VM name, handling stale locks."""
    lock_path = LOCK_DIR / f"antivma-{vm_name}.lock"
    
    # Attempt to acquire the lock immediately (handles the clean case)
    try:
        # O_CREAT: create if not exists (Cannot be renamed as it's an OS constant)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as fh:
            fh.write(str(os.getpid()))
        logging.info("Acquired lock %s", lock_path)
        return lock_path
    except OSError as e:
        if e.errno == errno.EEXIST:
            # Lock file already exists, check if it's stale
            try:
                with open(lock_path, "r") as fh:
                    pid_str = fh.read().strip()
                pid = int(pid_str)
                
                if not is_pid_running(pid):
                    logging.warning("Stale lock file detected (PID %d is dead). Removing and retrying lock acquisition.", pid)
                    lock_path.unlink()
                    
                    # Retry the acquisition now that the old lock is gone
                    return acquire_lock(vm_name)
                else:
                    # Lock is held by an active process
                    raise ToolError(f"Lock file exists ({lock_path}) - process {pid} is actively running. Cannot proceed.")
            except (ValueError, FileNotFoundError):
                # File corrupted or disappeared, attempt to remove it and retry
                try:
                    lock_path.unlink()
                    return acquire_lock(vm_name)
                except Exception:
                    raise ToolError(f"Lock file exists but is unreadable/uncritical ({lock_path}). Manual intervention needed.")
            except Exception:
                raise # Re-raise unknown error
        raise

def release_lock(lock_path: Path):
    """Releases the process lock."""
    try:
        lock_path.unlink()
        logging.debug("Released lock: %s", lock_path)
    except FileNotFoundError:
        pass

# ---------- signal handling ----------
terminate_requested = False
def _signal_handler(signum, frame):
    """Sets a flag to gracefully terminate the main loop on SIGINT or SIGTERM."""
    global terminate_requested
    logging.warning("Signal %s received - marking termination. Cleaning up soon...", signum)
    terminate_requested = True

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------- VM pruning (targets persistent VMs formed by clone_full) ----------
def prune_before_snapshots(vm_name: str, dry_run: bool = False, keep: Optional[int] = 5):
    """
    Deletes oldest persistent 'before-restore-' VMs formed by the --keep-current flag, 
    keeping a maximum count. This targets full clone VM instances, not snapshots.
    """
    
    all_vms = list_vms()
    
    # Filter for persistent VMs matching the 'before-restore' pattern formed by this tool
    candidates = []
    for vm in all_vms:
        if vm.startswith("before-restore-"):
            # Simple sorting by name works as the timestamp is the prefix
            candidates.append(vm) 
                
    candidates.sort() # Sort chronologically (oldest first)
    
    if keep is not None and len(candidates) > keep:
        to_delete = candidates[:-keep]
        logging.info("Pruning %d old persistent 'before-restore-' VMs (keeping %d).", len(to_delete), keep)
        
        for s in to_delete:
            logging.info("Deleting old persistent VM: %s", s)
            # Use the VM deletion function which handles poweroff and --delete
            unregister_delete_vm(s, dry_run=dry_run)
    else:
        logging.info("No old persistent 'before-restore-' VMs to prune (found %d, keeping up to %d).", len(candidates), keep or 0)


# ---------- main workflow ----------
def main(argv=None):
    parser = argparse.ArgumentParser(prog=APP_NAME, description="AntiVMaLinux - production-ready VirtualBox containment tool.")
    parser.add_argument("--vm", "-v", required=True, help="Base VM name (must be powered off).")
    parser.add_argument("--clean-name", default=DEFAULT_CLEAN_NAME, help=f"Persistent clean snapshot name (default: {DEFAULT_CLEAN_NAME}).")
    parser.add_argument("--keep-current", action="store_true", help="Preserve dirty state by forming a persistent full clone before destruction (name: before-restore-<ts>).")
    parser.add_argument("--gui", action="store_true", help="Start VM in GUI mode (default: headless).")
    parser.add_argument("--auto-shutdown", type=int, default=0, help="Seconds after which ACPI shutdown is triggered (0=manual monitor).")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute destructive commands.")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--hostonly-adapter", default=DEFAULT_HOSTONLY_ADAPTER, help=f"Host-only adapter to isolate VM (default: {DEFAULT_HOSTONLY_ADAPTER}).")
    # Added new flag to disable PCAP capture
    parser.add_argument("--no-pcap", action="store_true", help="Skip host-side network traffic capture (tcpdump).")
    parser.add_argument("--pcap-dir", default=DEFAULT_PCAP_DIR, type=Path, help=f"Directory for PCAPs (default: {DEFAULT_PCAP_DIR}).")
    parser.add_argument("--pcap-interface", default=DEFAULT_HOSTONLY_ADAPTER, help="Interface for host-side capture (default: same as --hostonly-adapter).")
    parser.add_argument("--prune-keep", type=int, default=5, help="Maximum number of persistent 'before-restore' VMs to keep.")
    args = parser.parse_args(argv)

    # --- Setup ---
    log_file = Path.home() / f"{APP_NAME}.log"
    handlers = [
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=5)
    ]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=LOG_FORMAT, handlers=handlers)

    logging.info("Starting %s. VBox version: %s", APP_NAME, vbox_version())

    lock_path = None
    clone_name = None
    tcpdump_proc = None
    
    try:
        # Pre-flight Checks (Fail fast)
        ensure_vboxmanage()

        # Lock (must be done before checking VM state to ensure exclusivity)
        lock_path = acquire_lock(args.vm) # Critical locking

        # Base VM checks
        if not vm_exists(args.vm):
            raise ToolError(f"Base VM '{args.vm}' not found. Available VMs: {list_vms()}")
            
        if get_vm_state(args.vm) != "poweroff":
             raise ToolError(f"Base VM '{args.vm}' must be powered off before cloning. Current state: {get_vm_state(args.vm)}. Please power off the VM.")

        # 1. Clean Snapshot Validation/Formation
        if not snapshot_exists(args.vm, args.clean_name):
            logging.warning("Clean snapshot '%s' not found. Forming it now from current state.", args.clean_name)
            take_snapshot(args.vm, args.clean_name, "Auto-formed persistent clean base snapshot", dry_run=args.dry_run)
        
        # Prune old dirty persistent VMs before starting the run
        prune_before_snapshots(args.vm, dry_run=args.dry_run, keep=args.prune_keep)
        
        # 2. Ephemeral Clone Setup
        clone_name = f"{args.vm}-ephemeral-{int(time.time())}"
        clone_linked(args.vm, args.clean_name, clone_name, dry_run=args.dry_run)
        
        # 3. Mandatory Hardening of the Clone
        disable_risky_features(clone_name, dry_run=args.dry_run)
        remove_shared_folders(clone_name, dry_run=args.dry_run)
        set_hostonly(clone_name, args.hostonly_adapter, dry_run=args.dry_run)

        # 4. Prune PCAPs & Start Capture (OPTIONAL)
        if not args.no_pcap:
            prune_pcaps(args.pcap_dir)
            pcap_file = args.pcap_dir / f"{clone_name}.pcap"
            tcpdump_proc, _ = start_tcpdump(args.pcap_interface, pcap_file, dry_run=args.dry_run)
        else:
            logging.info("Skipping network traffic capture (--no-pcap specified).")


        # 5. Start VM
        logging.info("Starting ephemeral VM: %s", clone_name)
        start_type = "gui" if args.gui else "headless"
        start_cmd = ["VBoxManage", "startvm", clone_name, "--type", start_type]
        if not args.dry_run:
            run(start_cmd, check=True) # THIS IS WHERE THE STALL OCCURRED PREVIOUSLY

        # 6. Monitor Loop
        start_time = time.time()
        shutdown_triggered = False

        logging.info("VM running. Auto-shutdown set to %d seconds (0=manual monitor).", args.auto_shutdown)
        while not terminate_requested:
            # Check VM state actively
            state = get_vm_state(clone_name)
            if state in ("poweroff", "aborted"):
                logging.info("VM detected powered off or aborted (state=%s). Exiting monitor.", state)
                break
            
            elapsed = time.time() - start_time
            
            # Auto-shutdown logic
            if args.auto_shutdown > 0 and not shutdown_triggered and elapsed >= args.auto_shutdown:
                logging.info("Auto-shutdown time reached (%.1fs elapsed vs %ds limit). Sending ACPI power button.", elapsed, args.auto_shutdown)
                if not args.dry_run:
                    try:
                        # Attempt graceful shutdown
                        run(["VBoxManage", "controlvm", clone_name, "acpipowerbutton"], check=True)
                    except ToolError as e:
                        logging.warning("ACPI request failed: %s. VM must be monitored manually or killed later.", e)
                shutdown_triggered = True # Ensures we only send the command once

            time.sleep(POLL_INTERVAL)
        
        # 7. Preserve Dirty State (--keep-current)
        if args.keep_current:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            before_name = f"before-restore-{ts}"
            
            # 7a. Power off clone first if it wasn't already (must be poweroff for clone_full)
            if not args.dry_run:
                state = get_vm_state(clone_name)
                if state not in ("poweroff", "aborted", "unknown"):
                    logging.warning("VM state is %s; forcing poweroff before forming persistent copy.", state)
                    run(["VBoxManage", "controlvm", clone_name, "poweroff"], check=True)

            # 7b. Form a full, persistent clone of the dirty ephemeral VM
            logging.info("Preserving dirty state: Forming full clone '%s'", before_name)
            # This is the key: full clone preserves the state and registers a new VM.
            clone_full(clone_name, before_name, dry_run=args.dry_run)


    except ToolError as e:
        logging.error("ToolError: %s", e)
        return 1
    except Exception as e:
        logging.exception("Unexpected fatal error: %s", e)
        return 2
    finally:
        # 8. Cleanup in finally block
        # Stop TCPdump via PID file/Popen object
        if tcpdump_proc:
            stop_tcpdump(tcpdump_proc) 
        
        if clone_name:
            # This ensures cleanup even if the run fails mid-way.
            # The function unregister_delete_vm now includes a force-poweroff attempt.
            unregister_delete_vm(clone_name, dry_run=args.dry-run) 
        if lock_path:
            release_lock(lock_path)
        
    logging.info("AntiVMaLinux finished successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
