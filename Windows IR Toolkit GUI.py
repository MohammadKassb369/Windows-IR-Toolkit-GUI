import subprocess
import os
import tkinter as tk
from tkinter import scrolledtext, filedialog

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def gui_wrapper(func, title, output_box):
    result = func()
    output_box.insert(tk.END, f"\n--- {title} ---\n{result}\n")
    return result

def check_persistence():
    output = run_command("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    output += "\n" + run_command("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    return output

def check_network_connections():
    return run_command("netstat -ano")

def list_processes():
    return run_command("tasklist")

def dump_event_logs():
    log_file = os.path.join(os.getcwd(), "SecurityEvents.evtx")
    cmd = f"powershell -Command \"wevtutil epl Security {log_file}\""
    result = run_command(cmd)
    return result + f"\nEvent logs saved to: {log_file}"

def list_scheduled_tasks():
    return run_command("schtasks /query /fo LIST /v")

def check_user_accounts():
    return run_command("net user")

def check_services():
    return run_command("sc query")

def check_ransomware_event_logs():
    output = ""
    event_ids = [4104, 4624, 4688, 4720, 1102]
    for eid in event_ids:
        cmd = f"powershell -Command \"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={eid}}} | Format-Table TimeCreated, Id, Message -AutoSize\""
        output += run_command(cmd) + "\n"
    return output

def check_shadow_copies():
    return run_command("vssadmin list shadows")

def check_usb_history():
    return run_command("reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /s")

def sweep_encrypted_files():
    search_path = "C:\\"
    extensions = ["*.locked", "*.encrypted"]
    output = ""
    for ext in extensions:
        cmd = f"powershell -Command \"Get-ChildItem -Path '{search_path}' -Recurse -Filter '{ext}' -ErrorAction SilentlyContinue | Select-Object FullName\""
        output += run_command(cmd) + "\n"
    return output

def check_prefetch_files():
    return run_command("dir C:\\Windows\\Prefetch")

def check_wmi_persistence():
    cmd = "powershell -Command \"Get-WmiObject -Namespace root\\subscription -Class __EventFilter, __EventConsumer, __FilterToConsumerBinding\""
    return run_command(cmd)

def check_restore_points():
    cmd = "powershell -Command \"Get-ComputerRestorePoint\""
    return run_command(cmd)

def check_psexec():
    return run_command("tasklist | findstr psexec")

def start_gui():
    window = tk.Tk()
    window.title("Windows Incident Response Toolkit")

    output_box = scrolledtext.ScrolledText(window, width=100, height=30)
    output_box.pack()

    modules = [
        ("Check Persistence", check_persistence),
        ("Check Network Connections", check_network_connections),
        ("List Processes", list_processes),
        ("Dump Event Logs", dump_event_logs),
        ("List Scheduled Tasks", list_scheduled_tasks),
        ("Check User Accounts", check_user_accounts),
        ("Check Services", check_services),
        ("Check Ransomware Events", check_ransomware_event_logs),
        ("Check Shadow Copies", check_shadow_copies),
        ("Check USB History", check_usb_history),
        ("Sweep Encrypted Files", sweep_encrypted_files),
        ("Check Prefetch Files", check_prefetch_files),
        ("Check WMI Persistence", check_wmi_persistence),
        ("Check Restore Points", check_restore_points),
        ("Check for PsExec", check_psexec)
    ]

    def clear_output():
        output_box.delete(1.0, tk.END)

    def export_results():
        text = output_box.get(1.0, tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(text)

    def run_all():
        for (text, function) in modules:
            gui_wrapper(function, text, output_box)

    for (text, function) in modules:
        tk.Button(window, text=text, width=40, command=lambda f=function, t=text: gui_wrapper(f, t, output_box)).pack()

    tk.Button(window, text="Clear Console", width=40, command=clear_output).pack()
    tk.Button(window, text="Export Results", width=40, command=export_results).pack()
    tk.Button(window, text="Run All Modules", width=40, command=run_all).pack()

    window.mainloop()

def main():
    start_gui()

if __name__ == "__main__":
    main()

