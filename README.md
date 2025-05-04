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
### 7. Virtual Media
  - **mount virtual media:**
    - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia
    - **Post request**: '{"Image": "zfs-images:iso/debian-12.8.0-amd64-netinst.iso"}'

    ```bash
    curl -k -X POST -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia -d '{"Image": "zfs-images:iso/debian-12.8.0-amd64-netinst.iso"}'
    ```
  - **eject media:**
    - **redfish endpoint:** /redfish/v1/Systems/<vm_id>/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia
    - **Post request**: None
    ```bash
    curl -k -X POST -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia
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
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems
  ```
### 12. Get VM Bios data (type 1)
  - **redfish endpoint:** /redfish/v1/Systems
  ```bash
  curl -k -X GET -H "X-Auth-Token: some-token" https://pve-node/redfish/v1/Systems/<vm_id>/Bios/SMBIOS
  ```
### 13 Boot Management (PATCH)
  - **redfish endpoint:** https://pve-m5/redfish/v1/Systems/101
  - **data request:** '{"Boot": {"BootSourceOverrideTarget": "Hdd", "BootSourceOverrideEnabled": "Once"}}'
  - **BootSourceOverrideTarget:** "Pxe" | "Cd" | "Hdd"
  - **BootSourceOverrideEnabled:** "Once" | "Continuous" | "Disabled"

  For boot from HD:

  ```bash
  curl -k -X PATCH -H "Content-Type: application/json" -H "X-Auth-Token: cac09af04a2b9d338a0616110fb78a1d" \
    -d '{"Boot": {"BootSourceOverrideTarget": "Hdd", "BootSourceOverrideEnabled": "Once"}}' \
    https://pve-m5/redfish/v1/Systems/101
  ```
  For boot from PXE:
  ```bash
  curl -k -X PATCH -H "Content-Type: application/json" -H "X-Auth-Token: cac09af04a2b9d338a0616110fb78a1d" \
    -d '{"Boot": {"BootSourceOverrideTarget": "Pxe", "BootSourceOverrideEnabled": "Once"}}' \
    https://pve-m5/redfish/v1/Systems/101
  ```
  For boot from CD:
  ```bash
  curl -k -X PATCH -H "Content-Type: application/json" -H "X-Auth-Token: cac09af04a2b9d338a0616110fb78a1d" \
    -d '{"Boot": {"BootSourceOverrideTarget": "Cd", "BootSourceOverrideEnabled": "Once"}}' \
    https://pve-m5/redfish/v1/Systems/101
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


3. Ensure openssl is Installed

Check if openssl is available:

bash

```bash
openssl version
```

If it’s not installed, install it:

bash

```bash
apt update
apt install openssl
```

4. Generate the Certificate and Key

Run this command to create a private key and self-signed certificate in one go:

bash

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

-   \-x509: Creates a self-signed certificate.
    
-   \-newkey rsa:2048: Generates a 2048-bit RSA key.
    
-   \-keyout key.pem: Outputs the private key to key.pem.
    
-   \-out cert.pem: Outputs the certificate to cert.pem.
    
-   \-days 365: Valid for 1 year (adjust as needed).
    
-   \-nodes: Skips passphrase protection (simpler for testing).
    

You’ll be prompted to enter some details (e.g., country, organization). For a test cert, you can press Enter to leave them blank or fill in minimal info:

```text
Country Name (2 letter code) [AU]: 
State or Province Name (full name) [Some-State]: 
Locality Name (eg, city) []: 
Organization Name (eg, company) [Internet Widgits Pty Ltd]: 
Organizational Unit Name (eg, section) []: 
Common Name (e.g. server FQDN or YOUR name) []: pve-m5
Email Address []: 
```

-   Set Common Name to pve-m5 (your hostname) to match your server.
    

This creates two files: key.pem (private key) and cert.pem (certificate).

5. Move Files to Your Daemon Directory

For convenience, move them to /opt/redfish\_daemon:

bash

```bash
mv cert.pem /opt/redfish_daemon/
mv key.pem  opt/redfish_daemon/
cd /opt/redfish_daemon
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
    -   Implements session-based authentication when AUTH == "Session".
9.  **Processors (/redfish/v1/Systems/{vm\_id}/Processors)**:
    -   Collect processors information
10.  **Storage (/redfish/v1/Systems/{vm\_id}/Storage)**:
    -   Collect Storage information
11.  **Ethernet interfaces (/redfish/v1/Systems/{vm\_id}/EthernetInterfaces)**:
    -   Collect ethernet information

### Redfish Endpoints Not Included

The Redfish specification defines a broad set of resources and endpoints for managing physical hardware, many of which don’t directly apply to Proxmox’s virtualized environment or were not implemented in the program.

#### 1\. **Chassis (/redfish/v1/Chassis)**

-   **Description**: Represents physical enclosures or hardware chassis (e.g., server racks, blades).
-   **Why Missing**: Proxmox manages VMs, not physical hardware. There’s no direct equivalent to a chassis in a virtualized environment unless if mapped into the Proxmox node itself (e.g., PROXMOX\_NODE), but this isn’t implemented.
-   **Potential Implementation**: Map the Proxmox node to a single Chassis resource, exposing node-level metrics (e.g., temperature, power), but this would require Proxmox API access to physical host data, which is limited.

#### 2\. **Managers (/redfish/v1/Managers)**

-   **Description**: Represents management controllers (e.g., BMCs like iLO or iDRAC) for remote management.
-   **Why Missing**: Proxmox doesn’t expose a BMC-like interface for VMs. The daemon itself could be considered a "manager," but this isn’t modeled.
-   **Potential Implementation**: Simulate a Managers endpoint representing the Proxmox server or the daemon, with details like network interfaces or firmware versions, but it’s not critical for VM control.

#### 3\. **Power (/redfish/v1/Chassis/{chassis\_id}/Power)**

-   **Description**: Provides detailed power metrics (e.g., voltage, wattage, power supplies).
-   **Why Missing**: VMs don’t have physical power supplies or sensors; power states are abstracted (running, stopped, etc.).
-   **Limitation**: Reset actions handle power control, but granular power metrics aren’t available in Proxmox’s VM API.

#### 4\. **Thermal (/redfish/v1/Chassis/{chassis\_id}/Thermal)**

-   **Description**: Reports temperature sensors, fans, and cooling systems.
-   **Why Missing**: VMs lack physical sensors; thermal data applies to the host, not individual VMs.
-   **Potential Implementation**: Host-level thermal data could be exposed if the Proxmox API provides it, but it’s not VM-specific.

#### 5\. **Processors (/redfish/v1/Systems/{system\_id}/Processors)**

-   **Description**: Details individual CPUs (e.g., model, clock speed, cache).
-   **Why Missing**: ProcessorSummary in get\_vm\_status includes Count (cores) and Sockets, but detailed CPU info (e.g., vendor, frequency) isn’t exposed because Proxmox abstracts this for VMs.
-   **Potential Implementation**: Limited by Proxmox; could hardcode QEMU-specific details, but they wouldn’t reflect runtime state.

#### 6\. **Memory (/redfish/v1/Systems/{system\_id}/Memory)**

-   **Description**: Lists individual memory modules (e.g., DIMMs, capacity, speed).
-   **Why Missing**: MemorySummary provides total memory in GiB, but Proxmox doesn’t track virtual memory as separate modules.
-   **Limitation**: Virtual memory is a single allocation, not physical DIMMs, so this endpoint isn’t fully applicable.

#### 7\. **Storage (/redfish/v1/Systems/{system\_id}/Storage)**

-   **Description**: Manages physical storage controllers, drives, and volumes.
-   **Why Missing**: SimpleStorage includes a CDROM entry, but Proxmox VMs don’t expose detailed storage (e.g., virtual disks) in a Redfish-compatible way beyond basic config (ide2, etc.).
-   **Potential Implementation**: Expand SimpleStorage to list virtual disks (e.g., scsi0, virtio0) from the VM config, but it’s not implemented.

#### 8\. **Network Interfaces (/redfish/v1/Systems/{system\_id}/NetworkInterfaces)**

-   **Description**: Details network adapters and their configuration.
-   **Why Missing**: Proxmox VM config includes network devices (e.g., net0), but the daemon doesn’t expose them as Redfish resources.
-   **Potential Implementation**: Parse netX config entries and map them to NetworkInterfaces with MAC addresses and link status.

#### 9\. **Ethernet Interfaces (/redfish/v1/Managers/{manager\_id}/EthernetInterfaces)**

-   **Description**: Network details for the management controller.
-   **Why Missing**: No Managers endpoint exists, and VM network interfaces aren’t directly tied to the daemon’s network.
-   **Potential Implementation**: Could represent the Proxmox host’s network, but it’s not VM-specific.

#### 10\. **Event Service (/redfish/v1/EventService)**

-   **Description**: Manages event subscriptions for notifications (e.g., alerts, logs).
-   **Why Missing**: Not implemented; Proxmox doesn’t natively support Redfish-style eventing for VMs.
-   **Potential Implementation**: Simulate by polling VM status changes and sending events, but this requires additional infrastructure.

#### 11\. **Log Services (/redfish/v1/Systems/{system\_id}/LogServices)**

-   **Description**: Provides access to system logs (e.g., SEL, audit logs).
-   **Why Missing**: Proxmox logs are host-level or task-based, not VM-specific in a Redfish-compatible format.
-   **Potential Implementation**: Map Proxmox task logs to a LogService, but it’s not straightforward.

#### 12\. **Secure Boot (/redfish/v1/Systems/{system\_id}/SecureBoot)**

-   **Description**: Controls Secure Boot settings.
-   **Why Missing**: Not applicable to Proxmox VMs; Secure Boot is guest-OS dependent and not managed via Proxmox API.

#### 13\. **Update Service (/redfish/v1/UpdateService)**

-   **Description**: Manages firmware and software updates.
-   **Why Missing**: Applies to physical hardware or host-level updates, not VMs.
-   **Potential Implementation**: Could simulate for VM templates or QEMU updates, but it’s out of scope.

#### 14\. **Task Service (/redfish/v1/TaskService)**

-   **Description**: Tracks asynchronous tasks (e.g., power operations).
-   **Why Missing**: Your daemon returns task IDs (e.g., in power\_on), but there’s no endpoint to query task status.
-   **Potential Implementation**: Store task states in sessions and expose via TaskService.

#### 15\. **Account Service (/redfish/v1/AccountService)**

-   **Description**: Manages user accounts and roles.
-   **Why Missing**: Authentication is handled via Proxmox credentials or tokens, not Redfish accounts.
-   **Potential Implementation**: Integrate with Proxmox user management, but it’s redundant with your SessionService.

### Summary of Key Omissions

-   **Hardware-Centric Endpoints**: Chassis, Power, Thermal, Managers, Processors, Memory, Storage (beyond CDROM), NetworkInterfaces, EthernetInterfaces, BIOS, SecureBoot, UpdateService.
    -   **Reason**: Proxmox VMs lack physical hardware equivalents.
-   **Management Features**: EventService, LogServices, TaskService, AccountService.
    -   **Reason**: Not implemented, though partially feasible with additional effort.
-   **Granular VM Details**: Detailed CPU, memory, storage, and network info.
    -   **Reason**: Limited by Proxmox API and abstraction.


