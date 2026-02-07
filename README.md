# Cerberus Ransomware Simulation

This project is a safe, educational simulation of a ransomware attack, demonstrating advanced concepts like Command & Control (C2) infrastructure, cryptography, and persistent client-server interaction.

**⚠️ FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE ON UNAUTHORIZED SYSTEMS. ⚠️**

## Architecture

1.  **Attacker C2 (`attacker/`)**: A Flask-based server that manages victims, generates RSA keys, and serves decryption keys directly via API upon "payment".
2.  **Victim Payload (`victim/`)**: A Python script that encrypts files, locks the screen (hidden console, always-on-top), and polls the server for a key. It includes persistence to survive reboots.

## Quick Start

1.  **Start C2 Server**:
    - `cd attacker`
    - `pip install -r requirements.txt`
    - `python c2_server.py`
    - **Copy the Public Key** from the output.

2.  **Run Victim Payload**:
    - `cd victim`
    - Edit `ransomware.py`: Paste the Public Key into `ATTACKER_PUBLIC_KEY`.
    - Create `~/test_data` with dummy files.
    - `python ransomware.py`

3.  **Simulate Recovery**:
    - Go to C2 Dashboard (`http://localhost:5000`).
    - Click "Mark as Paid".
    - Watch the victim screen unlock automatically!
