# AntiVMaLinux
## VirtualBox Containment Tool for Malware Analysis

**Python-based automation for ephemeral VM workflows with network isolation**

---

## Overview

AntiVMaLinux automates VirtualBox VM operations to provide isolated environments for malware analysis. The tool uses linked clones and enforced network isolation to reduce risk during suspicious file examination.

**What it does**: Spawns temporary VMs from clean snapshots, applies security settings, monitors execution, and destroys the environment  
**What it doesn't do**: Prevent all possible escape vectors, guarantee perfect isolation, or replace proper network segmentation  

---

## Technical Architecture

### Core Components
- **Base VM Management**: Snapshot validation and linked clone operations
- **Security Enforcement**: Network isolation and feature disabling
- **Process Control**: File locking and state monitoring  
- **Resource Management**: Automated cleanup and disk space management

### Workflow Sequence
```
1. Validate base VM exists and is powered off
2. Check/establish clean snapshot
3. Generate linked clone from snapshot
4. Apply security hardening to clone
5. Start VM and monitor state
6. Optionally preserve dirty state
7. Destroy ephemeral clone
```

---

## Installation & Setup

### Prerequisites
```bash
# Required software
VirtualBox 6.0+ (with VBoxManage in PATH)
Python 3.8+
tcpdump (for network capture)
sudo access for tcpdump

# Network setup
Host-only adapter configured (typically vboxnet0)
```

### Initial Configuration
```bash
# Verify VirtualBox installation
VBoxManage --version

# Check host-only adapter
VBoxManage list hostonlyifs

# Test sudo tcpdump access
sudo tcpdump -i vboxnet0 -c 1

# Validate base VM
VBoxManage list vms
VBoxManage showvminfo "YourBaseVM" | grep State
```

### Base VM Preparation
Your base VM should be:
- Powered off before tool execution
- Pre-configured for analysis (tools installed, etc.)
- Regularly backed up outside VirtualBox

---

## Usage

### Basic Operation
```bash
# Standard analysis session
./antivmalinux.py --vm "Windows10-Analysis"

# With GUI and 30-minute timeout
./antivmalinux.py --vm "Ubuntu-Sandbox" --gui --auto-shutdown 1800

# Test without making changes
./antivmalinux.py --vm "TestVM" --dry-run --verbose
```

### Command Reference
| Option | Description | Default |
|--------|-------------|---------|
| `--vm` | Base VM name (required) | None |
| `--clean-name` | Snapshot name for clean state | clean-base |
| `--keep-current` | Preserve dirty state as full clone | False |
| `--gui` | Start VM with GUI | headless |
| `--auto-shutdown N` | ACPI shutdown after N seconds | 0 (manual) |
| `--hostonly-adapter` | Network adapter name | vboxnet0 |
| `--pcap-dir` | PCAP storage location | ~/antivma_pcaps |
| `--prune-keep N` | Max preserved dirty VMs | 5 |
| `--dry-run` | Show actions without executing | False |
| `--verbose` | Debug logging | False |

---

## Security Implementation

### Network Isolation
- NIC 1: Host-only adapter (specified by user)
- NICs 2-8: Explicitly disabled to prevent bypass attempts
- No NAT, bridged, or internal network access

### VM Hardening  
Applied to every ephemeral clone:
```bash
--clipboard disabled    # Prevents host clipboard access
--draganddrop disabled  # Blocks file transfer via GUI
--usb off              # Disables USB device passthrough
# Shared folders removed if present
```

### Process Isolation
- File locking prevents concurrent tool execution
- Ephemeral clones use minimal disk space (linked to base)
- Clean snapshots remain untouched during analysis

### Limitations
- Host-only network must be properly configured
- Tool cannot prevent all VM escape techniques
- Relies on VirtualBox security model
- Requires proper host system hardening

---

## File Locations

### Logs and Temporary Files
```
~/AntiVMaLinux.log          # Main log file (5MB max, 5 files)
~/antivma_pcaps/            # Network captures  
/tmp/antivma-*.lock         # Process locks
```

### VM Naming Convention
```
{BaseVM}-ephemeral-{timestamp}     # Temporary analysis VM
before-restore-{timestamp}         # Preserved dirty state (if --keep-current)
```

---

## Troubleshooting

### Common Issues

**"VM not found"**
```bash
# Check exact VM name
VBoxManage list vms
```

**"Lock file exists"**  
```bash
# Tool now automatically detects and removes stale locks from dead processes
# Manual removal only needed if process detection fails
rm /tmp/antivma-YourVM.lock
```

**"Permission denied for tcpdump"**
```bash
# Tool automatically detects root vs sudo requirements
# Ensure passwordless sudo for tcpdump or run as root
sudo -n tcpdump --version
```

**"Host-only adapter not found"**
```bash
# List available adapters
VBoxManage list hostonlyifs
# Tool provides enhanced error messages for missing adapters
```

**"VBoxManage timeout or hang"**
```bash
# Tool now has 60-second timeouts for VBoxManage operations
# Check system resources and VirtualBox service status
systemctl status vboxdrv  # On systemd systems
```

### Recovery Procedures
```bash
# List running ephemeral VMs
VBoxManage list runningvms | grep ephemeral

# Force shutdown
VBoxManage controlvm "VM-Name" poweroff

# Remove registered VM
VBoxManage unregistervm "VM-Name" --delete

# Clean up old preserved VMs
VBoxManage list vms | grep before-restore
```

---

## Integration

### Monitoring
```bash
# Check tool status
pgrep -f antivmalinux.py

# Monitor disk usage
du -h ~/antivma_pcaps/
df -h /tmp/

# Review recent logs
tail -f ~/AntiVMaLinux.log
```

### Automation
```bash
# Scheduled analysis (cron example)
0 9 * * 1-5 /path/to/antivmalinux.py --vm "DailyAnalysis" --auto-shutdown 3600

# Script integration
if ./antivmalinux.py --vm "Scanner" --auto-shutdown 300 --dry-run; then
    echo "Ready for analysis"
fi
```

### Log Parsing
```bash
# Extract error events
grep "ToolError" ~/AntiVMaLinux.log

# Monitor PCAP generation
grep "Started tcpdump" ~/AntiVMaLinux.log

# Track VM lifecycle
grep -E "(Linked clone|unregistered)" ~/AntiVMaLinux.log
```

---

## Performance Considerations

### Disk Space
- Linked clones: ~100MB per instance
- Full clones (preserved): Same size as base VM
- PCAPs: Variable based on network activity
- Logs: 25MB maximum (5 x 5MB files)

### Memory Usage
- Tool itself: Minimal Python overhead
- VMs: As configured in base VM settings
- Host system should have sufficient RAM for base VM requirements

### Network Load
- Host-only traffic only
- PCAP files grow based on VM network activity
- No external network impact due to isolation

---

## Maintenance

### Regular Tasks
```bash
# Weekly: Review disk usage
du -sh ~/antivma_pcaps/ ~/.VirtualBox/

# Monthly: Clean old preserved VMs manually if needed
VBoxManage list vms | grep before-restore

# As needed: Validate clean snapshots
./antivmalinux.py --vm "BaseVM" --dry-run --verbose
```

### Updates
- Monitor VirtualBox releases for security updates
- Test tool with new VirtualBox versions before deployment
- Keep base VMs updated with latest analysis tools
- Regular backup of clean snapshots

---

## Known Limitations

1. **Host Dependency**: Relies on host system security
2. **VirtualBox Security**: Inherits VirtualBox vulnerabilities  
3. **Network Configuration**: Manual host-only adapter setup required
4. **Resource Constraints**: Limited by available disk space and memory
5. **Timing Dependencies**: VM state changes may have race conditions
6. **Privilege Requirements**: Needs sudo for network capture

---

## Support Information

**Tested Environments:**
- VirtualBox 6.1.x and 7.0.x
- Python 3.8-3.11
- Linux hosts (Ubuntu 20.04+, RHEL 8+)

**Log Levels:**
- INFO: Standard operational messages
- DEBUG: Detailed execution information (--verbose)
- WARNING: Non-fatal issues
- ERROR: Operation failures

**Exit Codes:**
- 0: Success
- 1: ToolError (configuration/execution issue)  
- 2: Unexpected error (programming/system issue)

For operational issues, review logs and verify prerequisites before escalating.

---

## Disclaimer

This tool is provided as-is with no warranties or guarantees. It may fail to contain malware, could have security vulnerabilities, and might not work in your environment. Users are responsible for:

- Testing thoroughly in isolated environments before production use
- Understanding the security limitations and residual risks  
- Having backup and recovery procedures in place
- ...

The publisher is *not* responsible for any damage, data loss, security breaches, or other consequences resulting from use of this tool.
