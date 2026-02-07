# Attacker Workspace

This directory contains the Command and Control (C2) server for the Cerberus ransomware simulation.

## Components

- `c2_server.py`: The C2 server written in Flask. It handles victim check-ins, RSA key generation, and the dashboard.
- `requirements.txt`: Python dependencies for the server.

## Setup & Running

1.  **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

2.  **Start the Server**:

    ```bash
    python c2_server.py
    ```

3.  **Get the Public Key**:
    When the server starts, it will print an RSA Public Key to the console. **You must copy this key** and paste it into the `ransomware.py` script in the `victim/` directory.

4.  **Access Dashboard**:
    Open `http://localhost:5000` in your browser to view victims and manage keys.

## Features

- **Victim Dashboard**: View status of all infected clients.
- **Direct Key Delivery**: Decryption keys are served directly via the API upon payment (no external dead drops).
- **Simulated Payment**: "Mark as Paid" button to release the decryption key immediately.
- **Heartbeat Handling**: Responds to client polling with status updates and keys.
