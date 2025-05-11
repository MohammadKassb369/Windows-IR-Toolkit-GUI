# Windows-IR-Toolkit-GUI

Windows IR Toolkit GUI
Detect ransomware execution attempts
Check for lateral movement (PsExec, WMI)
Identify malicious persistence (scheduled tasks, WMI subscriptions, registry autoruns)
Detect data exfiltration attempts via USB
Collect evidence for later detailed analysis

| Button                    | What it does                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| Check Persistence         | Lists autorun registry keys (`HKLM`, `HKCU`)                                                |
| Check Network Connections | Shows active network connections & ports (`netstat -ano`)                                   |
| List Processes            | Lists all running processes (`tasklist`)                                                    |
| Dump Event Logs           | Exports the full `Security` event log (`wevtutil epl`)                                      |
| List Scheduled Tasks      | Lists all scheduled tasks (`schtasks`)                                                      |
| Check User Accounts       | Lists all local user accounts (`net user`)                                                  |
| Check Services            | Lists all running Windows services (`sc query`)                                             |
| Check Ransomware Events   | Checks Security log for key ransomware Event IDs (`4104`, `4624`, `4688`, `4720`, `1102`)   |
| Check Shadow Copies       | Lists available volume shadow copies (`vssadmin list shadows`)                              |
| Check USB History         | Lists USB devices previously plugged into the system (Registry)                             |
| Sweep Encrypted Files     | Scans `C:\` for suspicious encrypted file extensions (`*.locked`, `*.encrypted`)            |
| Check Prefetch Files      | Lists Windows prefetch files (`dir C:\\Windows\\Prefetch`)                                  |
| Check WMI Persistence     | Lists WMI subscriptions, often used for stealth persistence                                 |
| Check Restore Points      | Lists System Restore points                                                                 |
| **Check for PsExec**      | Searches running processes for evidence of `psexec` (common attacker lateral movement tool) |


# Typical Usage Flow
Run python Ransomware_ir_toolkit-GUI.py

Start from top → click buttons one by one OR click Run All Modules.
If needed, click Export Results to save findings as .txt or .csv.

# Requirements

Windows system (recommended to run as Administrator)
Python 3.8+ installed (Python 3.12 compatible)
No additional Python libraries required
