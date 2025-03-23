# Python Daemon for Redfish Requests

This project provides a Python program that acts as a daemon (background service) to handle Redfish-like requests.

Before send requests to redfish, a session token must be obtained:

```bash
curl -k -X POST https://pve-node/redfish/v1/SessionService/Sessions -H "Content-Type: application/json" -d '{"UserName": "username", "Password": "password"}'
```

The return will be:

```json
{"Id": "a8ddb5f86aedee1fcfc3b25e2a68d30a", "UserName": "root@pam", "token": "a8ddb5f86aedee1fcfc3b25e2a68d30a"}
```

And the redfish requests will require the token:

```bash
curl -k -X GET -H "X-Auth-Token: a8ddb5f86aedee1fcfc3b25e2a68d30a" https://pve-node/redfish/v1
```

The following functions are implemented:

### 1. Power on
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "On"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "On"}' https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 2. Power off
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "ForceOff"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "ForceOff"}' https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 3. Reboot
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "ForceRestart"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "ForceRestart"}' https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 4. Suspend (custom)
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "Pause"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "Pause"}' https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 5. Resume (custom)
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "Resume"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "Resume"}' https://pve_node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 6. Stop (custom)
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset
  - **Post request**:  '{"ResetType": "ForceStop"}'
  ```bash
  curl -k -X POST -H "X-Auth-Token: some-token" -d '{"ResetType": "ForceStop"}' https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.Reset

  ```
### 7. Virtual CD
  - **mount cd:**
    - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.MountISO
    - **Post request**: '{"Action": "Mount", "ISOPath": "debian-12.8.0-amd64-netinst.iso"}'
    ```bash
    curl -k -X POST -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.MountISO -d '{"Action": "Mount", "ISOPath": "zfs-images:iso/debian-12.8.0-amd64-netinst.iso"}'
    ```
  - **eject cd:**
    - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.MountISO
    - **Post request**: '{"Action": "Eject"}'
    ```bash
    curl -k -X POST -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>/Actions/ComputerSystem.MountISO -d '{"Action": "Eject"}'
    ```
### 8. Get vm status
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>
  ```bash
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>
  ```

### 9. Get VM Configuration (custom extension)
  - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/Config
  ```bash
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>/Config
  ```

### 10. Get redfish information
  - **redfish endpoint:** /redfish/v1/
  ```bash
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/
  ```
### 11. Get VM systems under control of redfish
  - **redfish endpoint:** /redfish/v1/Systems
  ```bash
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systemd
  ```


# Installation

Steps to Set Up the Virtual Environment and systemd Service

1. Create the Virtual Environment

Assuming your script is saved as redfish\_daemon.py in /opt/redfish_daemon/:

bash

```bash
# Create project directory
sudo mkdir -p /opt/redfish_daemon
cd /opt/redfish_daemon

# Create virtual environment
python3 -m venv venv

# Activate it and install dependencies
source venv/bin/activate
pip install proxmoxer requests
deactivate
```
Install redfish-proxmox.service file in the directory /etc/systemd/system .

2. Enable and Start the Service

bash

```bash
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable redfish-proxmox.service

# Start the service
sudo systemctl start redfish-proxmox.service

# Check status
sudo systemctl status redfish-proxmox.service
```


# Implemented Endpoints in the Program

The code covers the following Redfish endpoints and functionalities:

1.  **Service Root (/redfish/v1/)**:
    -   Provides the entry point to the Redfish service with links to other resources (e.g., Systems).
2.  **Systems Collection (/redfish/v1/Systems)**:
    -   Lists all VMs as Redfish "Systems" with their VM IDs.
3.  **System Resource (/redfish/v1/Systems/{vm\_id})**:
    -   Retrieves detailed VM status and configuration (e.g., power state, memory, CPU, CDROM).
4.  **Custom Config Endpoint (/redfish/v1/Systems/{vm\_id}/Config)**:
    -   Non-standard endpoint for retrieving VM configuration details.
5.  **Reset Action (/redfish/v1/Systems/{vm\_id}/Actions/ComputerSystem.Reset)**:
    -   Supports power operations: On, ForceOff, ForceRestart, Pause, Resume, ForceStop.
6.  **Mount ISO Action (/redfish/v1/Systems/{vm\_id}/Actions/ComputerSystem.MountISO)**:
    -   Custom action to mount or eject virtual CD media.
7.  **Update Config Action (/redfish/v1/Systems/{vm\_id}/Actions/ComputerSystem.UpdateConfig)**:
    -   Custom action to update VM configuration.
8.  **Session Service (/redfish/v1/SessionService/Sessions)**:
    -   Implements session-based authentication.

