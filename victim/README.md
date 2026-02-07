# Victim Workspace

This directory contains the ransomware payload simulation.

## Components

- `ransomware.py`: The main ransomware script. It performs encryption, displays the lock screen (Kiosk Mode), and communicates with the C2 server.

## Setup & Running

1.  **Prerequisites**:
    - Ensure the C2 server is running.
    - Python 3 installed on the victim machine.
    - Install dependencies: `pip install requests cryptography` (or use the requirements from the root).

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

- **Persistence**: Saves `cerberus_id.txt` to resume the session after a restart without re-encrypting.
- **Lockdown**: Hides the console window and uses aggressive focus grabbing to prevent closing the window.
- **File Encryption**: Encrypts target file types using AES-GCM.
- **Heartbeat Polling**: Automatically checks for the decryption key every 10 seconds.
- **Auto-Decryption**: Automatically decrypts files once the key is received from the C2 server.
