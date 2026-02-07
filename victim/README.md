# Victim Workspace

This directory contains the ransomware payload simulation.

## Components

- `ransomware.py`: The main ransomware script. It performs encryption, displays the lock screen (Kiosk Mode), and communicates with the C2 server.

## Setup & Running

1.  **Prerequisites**:
    - Ensure the C2 server is running.
    - Python 3 installed on the victim machine.
    - Install dependencies: `pip install requests cryptography` (or use the requirements from the root).
    - **Linux Note**: For best Kiosk effect, run in a desktop environment. The script uses Tkinter.

2.  **Configuration**:
    - Open `ransomware.py`.
    - Update the `ATTACKER_PUBLIC_KEY` variable with the key displayed by the C2 server.
    - (Optional) Update `C2_SERVER_URL` if the server is not on `localhost:5000`.

3.  **Prepare Test Data**:
    - The script targets `~/test_data` by default. Create this folder and add some dummy files (`.txt`, `.jpg`, `.docx`, etc.).

4.  **Execute**:
    ```bash
    python ransomware.py
    ```

## Features

- **Persistence**: Saves `cerberus_id.txt` to resume the session. **Key Backup**: Saves `cerberus_key.bak` temporarily to prevent data loss if crashed before check-in.
- **Lockdown**:
  - **Linux Optimized**: Uses `grab_set()` to steal all mouse/keyboard input.
  - **Aggressive Focus**: Constantly forces window to top every 50ms.
  - **Exit Blocking**: Disables Alt+F4, Escape, and attempts to block Ctrl+C.
- **Heartbeat Polling**: Automatically checks for the decryption key every 5 seconds.
- **Auto-Decryption**: Automatically decrypts files once the key is received from the C2 server.
