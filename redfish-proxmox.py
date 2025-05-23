import ssl
import socketserver
from http.server import BaseHTTPRequestHandler
import json
import os
import sys, getopt
from functools import partial
from proxmoxer import ProxmoxAPI                # type: ignore
from proxmoxer.core import ResourceException    # type: ignore
import secrets  # For token generation
import time
import base64
import logging
from logging.handlers import SysLogHandler

# Configure logging to send to system journal
logger = logging.getLogger('redfish-proxmox')
logging_enabled = os.getenv("REDFISH_LOGGING_ENABLED", "true").lower() == "true"
if logging_enabled:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s:%(lineno)d: %(message)s',
        handlers=[SysLogHandler(address='/dev/log')]
    )
    logger.setLevel(logging.DEBUG)
else:
    logger.handlers = [logging.NullHandler()]

# Proxmox configuration from environment variables with fallbacks
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "pve-node-hostname")
PROXMOX_USER = os.getenv("PROXMOX_USER", "username")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "password")
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "pve=-node-name")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# Options
# -A <Authn>, --Auth <Authn> -- Authentication type to use:  Authn={ None | Basic | Session (default) }
# -S <Secure>, --Secure=<Secure> -- <Secure>={ None | Always (default) }
AUTH = "Session"
SECURE = "Always"

# In-memory session store
sessions = {}


def handle_proxmox_error(operation, exception, vm_id=None):
    """
    Handle Proxmox API exceptions and return a Redfish-compliant error response.
    
    Args:
        operation (str): The operation being performed (e.g., "Power On", "Reboot").
        exception (Exception): The exception raised by ProxmoxAPI (typically ResourceException).
        vm_id (int, optional): The VM ID, if applicable, for more specific error messages.
    
    Returns:
        tuple: (response_dict, status_code) for Redfish response.
    """
    if not isinstance(exception, ResourceException):
        # Handle unexpected non-Proxmox errors
        return {
            "error": {
                "code": "Base.1.0.GeneralError",
                "message": f"Unexpected error during {operation}: {str(exception)}",
                "@Message.ExtendedInfo": [{
                    "MessageId": "Base.1.0.GeneralError",
                    "Message": "An unexpected error occurred on the server."
                }]
            }
        }, 500

    # Extract Proxmox error details
    status_code = exception.status_code
    message = str(exception)
    vm_context = f" for VM {vm_id}" if vm_id is not None else ""

    # Map Proxmox status codes to Redfish error codes
    if status_code == 403:
        redfish_error_code = "Base.1.0.InsufficientPrivilege"
        extended_info = [{
            "MessageId": "Base.1.0.InsufficientPrivilege",
            "Message": f"The authenticated user lacks the required privileges to perform the {operation} operation{vm_context}."
        }]
    elif status_code == 404:
        redfish_error_code = "Base.1.0.ResourceMissingAtURI"
        extended_info = [{
            "MessageId": "Base.1.0.ResourceMissingAtURI",
            "Message": f"The resource{vm_context} was not found."
        }]
    elif status_code == 400:
        redfish_error_code = "Base.1.0.InvalidRequest"
        extended_info = [{
            "MessageId": "Base.1.0.InvalidRequest",
            "Message": f"The {operation} request was malformed or invalid."
        }]
    else:
        # Fallback for other Proxmox errors (e.g., 500, 503)
        redfish_error_code = "Base.1.0.GeneralError"
        extended_info = [{
            "MessageId": "Base.1.0.GeneralError",
            "Message": f"An error occurred during {operation}{vm_context}."
        }]

    return {
        "error": {
            "code": redfish_error_code,
            "message": f"{operation} failed: {message}",
            "@Message.ExtendedInfo": extended_info
        }
    }, status_code


def get_proxmox_api(headers):
    valid, message = validate_token(headers)
    if not valid:
        raise Exception(f"Authentication failed: {message}")

    if AUTH == "Basic":
        auth_header = headers.get("Authorization")
        credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
        username, password = credentials.split(":", 1)
        if '@' not in username:
            username += '@pam'
    elif AUTH == "Session":
        token = headers.get("X-Auth-Token")
        username, password = get_credentials(token)
    else:
        username = PROXMOX_USER  # Fallback for no auth
        password = PROXMOX_PASSWORD

    try:
        proxmox = ProxmoxAPI(
            PROXMOX_HOST,
            user=username,
            password=password,
            verify_ssl=VERIFY_SSL
        )
        return proxmox
    except Exception as e:
        raise Exception(f"Failed to connect to Proxmox API: {str(e)}")


def get_credentials(token):
    if token in sessions:
        session = sessions[token]
        return session["username"], session["password"]
    raise Exception("No credentials found for token")


# Power control functions (unchanged)
def power_on(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.start.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power On VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power On request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Power On", e, vm_id)


def power_off(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.shutdown.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power Off VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power Off request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Power Off", e, vm_id)


def reboot(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.reboot.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Reboot VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Reboot request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Reboot", e, vm_id)


def reset_vm(proxmox, vm_id):
    """
    Perform a hard reset of the Proxmox VM, equivalent to a power cycle.
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID
    
    Returns:
        Tuple of (response_dict, status_code) for Redfish response
    """
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.reset.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard Reset VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard reset request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard Reset", e, vm_id)


def suspend_vm(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.suspend.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Pause VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Pause request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Pause", e, vm_id)


def resume_vm(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.resume.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Resume VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Resume request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Resume", e, vm_id)


def stop_vm(proxmox, vm_id):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.stop.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard stop VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard stop request initiated for VM {vm_id}"}]
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard stop", e, vm_id)


# Add this new function to manage VirtualMedia state (replaces manage_virtual_cd)
def manage_virtual_media(proxmox, vm_id, action, iso_path=None):
    """
    Manage virtual media for a Proxmox VM, mapped to Redfish VirtualMedia actions.
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID
        action: "InsertMedia" or "EjectMedia"
        iso_path: Path to ISO (for InsertMedia)
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    try:
        vm_config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config
        # print(f"DEBUG: Action={action}, VM={vm_id}, Current ide2={vm_config.get()['ide2']}")
        if action == "InsertMedia":
            if not iso_path:
                return {
                    "error": {
                        "code": "Base.1.0.InvalidRequest",
                        "message": "ISO path is required for InsertMedia"
                    }
                }, 400
            config_data = {"ide2": f"{iso_path},media=cdrom"}
            task = vm_config.set(**config_data)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Insert Media for VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Mounted ISO {iso_path} to VM {vm_id}"}]
            }, 202
        elif action == "EjectMedia":
            config_data = {"ide2": "none,media=cdrom"}
            task = vm_config.set(**config_data)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Eject Media from VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Ejected ISO from VM {vm_id}"}]
            }, 202
        else:
            return {
                "error": {
                    "code": "Base.1.0.InvalidRequest",
                    "message": f"Unsupported action: {action}"
                }
            }, 400
    except Exception as e:
        return handle_proxmox_error(f"Virtual Media {action}", e, vm_id)


# Update VM config (unchanged)
def update_vm_config(proxmox, vm_id, config_data):
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(**config_data)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Update Configuration for VM {vm_id}",
            "TaskState": "Running",  # Initial state; client can poll for updates
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Configuration update initiated for VM {vm_id}"}]
        }, 202  # 202 Accepted indicates an asynchronous task
    except Exception as e:
        return handle_proxmox_error("Update Configuration", e, vm_id)


def reorder_boot_order(proxmox, vm_id, current_order, target):
    """
    Reorder Proxmox boot devices based on Redfish target, preserving all devices including multiple hard drives.
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_id (int): The VM ID to fetch config for
        current_order (str): Current boot order (e.g., "scsi0;ide2;net0" or empty).
        target (str): Redfish BootSourceOverrideTarget ("Pxe", "Cd", "Hdd").
    
    Returns:
        str: New boot order (e.g., "scsi0;ide0;ide2;net0"), or raises an exception if the target is not available.
    
    Raises:
        ValueError: If the requested boot device is not available.
    """
    logger.debug(f"Reordering boot for VM {vm_id}, target: {target}, current order: {current_order}")
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
    except Exception as e:
        logger.error(f"Failed to get VM {vm_id} config: {str(e)}")
        config = {}  # Fallback to empty config if retrieval fails

    # Split current order into devices; handle empty or unset cases
    if not current_order or "order=" not in current_order:
        devices = []
    else:
        devices = current_order.replace("order=", "").split(";")

    # Identify available devices from config
    disk_devs = []  # List of all hard drives (SCSI, SATA, IDE without media=cdrom)
    cd_dev = None   # CD-ROM device
    net_dev = None  # Network device

    # Check for hard drives and CD-ROMs (SCSI, SATA, IDE)
    for dev_type in ["scsi", "sata", "ide"]:
        for i in range(4):  # ide0-3, scsi0-3, sata0-3 (simplified range)
            dev_key = f"{dev_type}{i}"
            if dev_key in config:
                dev_value = config[dev_key]
                if "media=cdrom" in dev_value:
                    cd_dev = dev_key  # CD-ROM found
                elif dev_type in ["scsi", "sata"] or (dev_type == "ide" and "media=cdrom" not in dev_value):
                    disk_devs.append(dev_key)  # Hard drive found

    # Check for network devices
    for i in range(4):  # net0-3 (simplified range)
        net_key = f"net{i}"
        if net_key in config:
            net_dev = net_key
            break

    # Build the full list of available devices, preserving all from config and current order
    available_devs = [d for d in devices if d in config] if devices else []
    for dev in disk_devs + ([cd_dev] if cd_dev else []) + ([net_dev] if net_dev else []):
        if dev and dev not in available_devs:
            available_devs.append(dev)

    # Validate the target device availability
    if target == "Pxe" and not net_dev:
        raise ValueError("No network device available for Pxe boot")
    elif target == "Cd" and not cd_dev:
        raise ValueError("No CD-ROM device available for Cd boot")
    elif target == "Hdd" and not disk_devs:
        raise ValueError("No hard disk device available for Hdd boot")

    # Reorder based on target, keeping all devices
    new_order = []
    if target == "Pxe" and net_dev:
        new_order = [net_dev] + [d for d in available_devs if d != net_dev]
    elif target == "Cd" and cd_dev:
        new_order = [cd_dev] + [d for d in available_devs if d != cd_dev]
    elif target == "Hdd" and disk_devs:
        primary_disk = disk_devs[0]
        new_order = [primary_disk] + [d for d in available_devs if d != primary_disk]
    else:
        # This should not be reached due to earlier validation
        new_order = available_devs

    # Remove duplicates and ensure valid devices only
    unique_devices = list(dict.fromkeys(new_order))
    result = ";".join(unique_devices) if unique_devices else ""
    logger.debug(f"Computed new boot order for VM {vm_id}: {result}")
    return result


def get_bios(proxmox, vm_id):
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        firmware_type = config.get("bios", "seabios")
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Minimal BIOS info with link to SMBIOS details
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "Bios",
            "Name": "BIOS Settings",
            "FirmwareMode": firmware_mode,  # From previous enhancement
            "Attributes": {
                "BootOrder": config.get("boot", "order=scsi0;ide2;net0")
            },
            "Links": {
                "SMBIOS": {
                    "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS"
                }
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error("BIOS retrieval", e, vm_id)


def get_smbios_type1(proxmox, vm_id):
    """
    Retrieve SMBIOS Type 1 (System Information) data from Proxmox VM config,
    including firmware type (BIOS or UEFI).
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        smbios1 = config.get("smbios1", "")
        firmware_type = config.get("bios", "seabios")  # Default to seabios if not specified
        
        # Map Proxmox bios setting to Redfish-friendly terms
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"
        
        # Default SMBIOS values
        smbios_data = {
            "UUID": None,
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": None,
            "SKUNumber": None,
            "Family": None
        }

        # Parse smbios1 string if it exists
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)

                    # Attempt to decode Base64 if it looks encoded
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        # Only use decoded value if itâ��s valid UTF-8 and not a UUID
                        if key != "uuid" and decoded_value.isprintable():
                            value = decoded_value
                    except (base64.binascii.Error, UnicodeDecodeError):
                        pass  # Keep original value if decoding fails

                    if key == "uuid":
                        smbios_data["UUID"] = value
                    elif key == "manufacturer":
                        smbios_data["Manufacturer"] = value
                    elif key == "product":
                        smbios_data["ProductName"] = value
                    elif key == "version":
                        smbios_data["Version"] = value
                    elif key == "serial":
                        smbios_data["SerialNumber"] = value
                    elif key == "sku":
                        smbios_data["SKUNumber"] = value
                    elif key == "family":
                        smbios_data["Family"] = value

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "SMBIOS",
            "Name": "SMBIOS System Information",
            "FirmwareMode": firmware_mode,  # New field to indicate BIOS or UEFI
            "Attributes": {
                "SMBIOSType1": smbios_data
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error("SMBIOS retrieval", e, vm_id)


def get_vm_config(proxmox, vm_id):
    """
    Optional helper function for config details (not a standard Redfish endpoint).
    Returns a subset of data for custom use, but prefer get_vm_status for Redfish compliance.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        return {
            "Name": config.get("name", f"VM-{vm_id}"),
            "MemoryMB": config.get("memory", 0),
            "CPUCores": config.get("cores", 0),
            "Sockets": config.get("sockets", 1),
            "CDROM": config.get("ide2", "none")
        }
    except Exception as e:
        return handle_proxmox_error("Configuration retrieval", e, vm_id)


def validate_token(headers):
    if AUTH is None:
        return True, "No auth required"

    if AUTH == "Basic":
        auth_header = headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                username, password = credentials.split(":", 1)
                if '@' not in username:
                    username += '@pam'
                # Test the credentials
                proxmox = ProxmoxAPI(PROXMOX_HOST, user=username, password=password, verify_ssl=VERIFY_SSL)
                token = f"{username}-{password}"
                sessions[token] = {"created": time.time(), "username": username, "password": password}
                return True, username
            except Exception as e:
                return False, f"Invalid Basic Authentication credentials: {str(e)}"
        return False, "Basic Authentication required but no valid Authorization header provided"

    if AUTH == "Session":
        token = headers.get("X-Auth-Token")
        if token in sessions:
            session = sessions[token]
            if time.time() - session["created"] < 3600:
                return True, session["username"]
            else:
                del sessions[token]
                return False, "Token expired"
    return False, "Invalid or no token provided"


def get_processor_collection(proxmox, vm_id):
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        cpu_sockets = config.get("sockets", 1)
        members = [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/CPU{i+1}"} for i in range(cpu_sockets)]
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors",
            "@odata.type": "#ProcessorCollection.ProcessorCollection",
            "Name": "Processors Collection",
            "Members@odata.count": cpu_sockets,
            "Members": members
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor collection retrieval", e, vm_id)


def get_processor_detail(proxmox, vm_id, processor_id):
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        cpu_cores = config.get("cores", 1)
        cpu_sockets = config.get("sockets", 1)
        cpu_type = config.get("cpu", "kvm64")
        processor_architecture = "x86" if "kvm64" in cpu_type or "host" in cpu_type else "unknown"
        total_threads = config.get("vcpus", cpu_cores)

        # Validate processor_id (e.g., "CPU1", "CPU2")
        if not processor_id.startswith("CPU") or not processor_id[3:].isdigit():
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Invalid processor ID: {processor_id}"}}, 404
        cpu_index = int(processor_id[3:]) - 1  # CPU1 -> index 0, CPU2 -> index 1
        if cpu_index < 0 or cpu_index >= cpu_sockets:
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Processor {processor_id} not found"}}, 404

        # Distribute cores and threads across sockets
        cores_per_socket = cpu_cores // cpu_sockets
        threads_per_socket = total_threads // cpu_sockets
        # Handle remainder cores/threads by assigning to the first socket
        if cpu_index == 0:
            cores_per_socket += cpu_cores % cpu_sockets
            threads_per_socket += total_threads % cpu_sockets

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/{processor_id}",
            "@odata.type": "#Processor.v1_3_0.Processor",
            "Id": processor_id,
            "Name": processor_id,
            "ProcessorType": "CPU",
            "ProcessorArchitecture": processor_architecture,
            "InstructionSet": "x86-64",
            "Manufacturer": "QEMU",
            "Model": cpu_type,
            "ProcessorId": {
                "VendorID": "QEMU"
            },
            "Socket": f"Socket {cpu_index}",
            "TotalCores": cores_per_socket,
            "TotalThreads": threads_per_socket,
            "Status": {"State": "Enabled", "Health": "OK"}
        }
        return response
    except Exception as e:
        return handle_proxmox_error(f"Processor detail retrieval for {processor_id}", e, vm_id)


def get_storage_collection(proxmox, vm_id):
    try:
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage",
            "@odata.type": "#StorageCollection.StorageCollection",
            "Name": "Storage Collection",
            "Members@odata.count": 1,
            "Members": [
                {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1"}
            ]
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage collection retrieval", e, vm_id)


def parse_disk_size(drive_info):
    """
    Parse disk size from Proxmox config string (e.g., 'size=16G') and convert to bytes.
    
    Args:
        drive_info (str): Disk config string (e.g., 'Datastore1_local_RAIDZ:vm-302-disk-1,iothread=1,size=16G')
    
    Returns:
        int: Size in bytes, or 0 if parsing fails
    """
    try:
        # Split by commas and find size parameter
        parts = drive_info.split(",")
        size_part = next((part for part in parts if part.startswith("size=")), None)
        if not size_part:
            return 0

        # Extract size value and unit (e.g., '16G' -> '16', 'G')
        size_str = size_part.split("=")[1]
        unit = size_str[-1].upper()
        size_value = float(size_str[:-1])

        # Convert to bytes
        if unit == "G":
            return int(size_value * 1024 * 1024 * 1024)  # Gigabytes to bytes
        elif unit == "M":
            return int(size_value * 1024 * 1024)  # Megabytes to bytes
        elif unit == "T":
            return int(size_value * 1024 * 1024 * 1024 * 1024)  # Terabytes to bytes
        else:
            return 0  # Unknown unit
    except (ValueError, IndexError):
        return 0  # Parsing failed

def get_storage_detail(proxmox, vm_id, storage_id):
    try:
        if storage_id != "1":
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}}, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        drives = []
        for key in config:
            if key.startswith(("scsi", "sata", "ide")) and "unused" not in key:
                drive_id = key
                if "media=cdrom" in config[key]:
                    drives.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Drives/{drive_id}"})
                else:
                    drives.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Drives/{drive_id}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1",
            "@odata.type": "#Storage.v1_10_1.Storage",
            "Id": "1",
            "Name": "Local Storage Controller",
            "Description": "Virtual Storage Controller",
            "Status": {
                "State": "Enabled",
                "Health": "OK",
                "HealthRollup": "OK"
            },
            "Controllers": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Controllers"
            },
            "StorageControllers": [
                {
                    "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1#/StorageControllers/0",
                    "@odata.type": "#StorageController.v1_6_0.StorageController",
                    "MemberId": "0",
                    "Name": "Virtual Storage Controller",
                    "Status": {
                        "State": "Enabled",
                        "Health": "OK"
                    },
                    "Manufacturer": "QEMU",
                    "SupportedControllerProtocols": ["PCIe"],
                    "SupportedDeviceProtocols": ["SATA"],
                    "SupportedRAIDTypes": ["None"]
                }
            ],
            "Drives": drives,
            "Volumes": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Volumes"
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error(f"Storage detail retrieval for {storage_id}", e, vm_id)

def get_drive_detail(proxmox, vm_id, storage_id, drive_id):
    try:
        if storage_id != "1":
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}}, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if drive_id not in config or "unused" in drive_id:
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Drive {drive_id} not found"}}, 404

        drive_info = config[drive_id]
        is_cdrom = "media=cdrom" in drive_info
        media_type = "CDROM" if is_cdrom else "HDD"
        capacity_bytes = parse_disk_size(drive_info) if not is_cdrom else 0  # CDROMs have no capacity

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Drives/{drive_id}",
            "@odata.type": "#Drive.v1_4_0.Drive",
            "Id": drive_id,
            "Name": f"Drive {drive_id}",
            "MediaType": media_type,
            "CapacityBytes": capacity_bytes,
            "Status": {
                "State": "Enabled",
                "Health": "OK"
            },
            "Protocol": "SATA",
            "Manufacturer": "QEMU"
        }
        return response
    except Exception as e:
        return handle_proxmox_error(f"Drive detail retrieval for {drive_id}", e, vm_id)

def get_volume_collection(proxmox, vm_id, storage_id):
    try:
        if storage_id != "1":
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}}, 404

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Volumes",
            "@odata.type": "#VolumeCollection.VolumeCollection",
            "Name": "Volume Collection",
            "Members@odata.count": 0,
            "Members": []
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Volume collection retrieval", e, vm_id)


def get_controller_collection(proxmox, vm_id, storage_id):
    try:
        if storage_id != "1":
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}}, 404

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Controllers",
            "@odata.type": "#ControllerCollection.ControllerCollection",
            "Name": "Controller Collection",
            "Members@odata.count": 1,
            "Members": [
                {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1/Controllers/0"}
            ]
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Controller collection retrieval", e, vm_id)


def get_ethernet_interface_collection(proxmox, vm_id):
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        interfaces = []
        for key in config:
            if key.startswith("net"):
                value = config[key]
                parts = value.split(",")
                for part in parts:
                    if part.startswith("virtio="):
                        mac = part.split("=")[1]
                        interfaces.append({"id": key, "mac": mac})
                        break
        members = [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{iface['id']}"} for iface in interfaces]
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces",
            "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
            "Name": "Ethernet Interface Collection",
            "Description": "Network Interfaces for VM",
            "Members@odata.count": len(interfaces),
            "Members": members
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface collection retrieval", e, vm_id)


def get_ethernet_interface_detail(proxmox, vm_id, interface_id):
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if interface_id not in config:
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Interface {interface_id} not found"}}, 404

        value = config[interface_id]
        mac = None
        for part in value.split(","):
            if part.startswith("virtio="):
                mac = part.split("=")[1]
                break
        if not mac:
            return {"error": {"code": "Base.1.0.GeneralError", "message": "MAC address not found"}}, 500

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{interface_id}",
            "@odata.type": "#EthernetInterface.v1_4_0.EthernetInterface",
            "Id": interface_id,
            "Name": f"Ethernet Interface {interface_id}",
            "Description": f"Network Interface {interface_id}",
            "PermanentMACAddress": mac,
            "MACAddress": mac,
            "SpeedMbps": 1000,  # Static value; Proxmox doesn't provide this
            "FullDuplex": True,
            "Status": {
                "State": "Enabled",
                "Health": "OK"
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error(f"Ethernet interface detail retrieval for {interface_id}", e, vm_id)


def get_vm_status(proxmox, vm_id):
    try:
        status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()

        # Determine firmware mode and boot mode
        firmware_type = config.get("bios", "seabios")
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"
        boot_mode = "Legacy" if firmware_mode == "BIOS" else "UEFI"  # Define boot_mode

        # Map Proxmox status to Redfish PowerState and State
        redfish_status = "Off"
        state = "Enabled"  # Default for stopped VMs
        health = "OK"
        if status["status"] == "running":
            redfish_status = "On"
            state = "Enabled"
        elif status["status"] == "paused":
            redfish_status = "On"
            state = "Quiesced"
        elif status["status"] == "stopped":
            redfish_status = "Off"
            state = "Enabled"
        else:
            redfish_status = "Off"
            state = "Absent"
            health = "Critical"

        # Memory conversion
        memory_mb = config.get("memory", 0)
        try:
            memory_mb = float(memory_mb)
        except (ValueError, TypeError):
            memory_mb = 0
        memory_gib = memory_mb / 1024.0

        # CDROM info
        cdrom_info = config.get("ide2", "none")
        cdrom_media = "None" if "none" in cdrom_info else cdrom_info.split(",")[0]

        # Boot configuration with robust handling
        boot_order = config.get("boot", "")
        boot_target = "None"
        if boot_order:
            if boot_order.startswith("order="):
                boot_order = boot_order[len("order="):]
            devices = boot_order.split(";") if ";" in boot_order else [boot_order]
            for device in devices:
                if device.startswith("net"):
                    boot_target = "Pxe"
                    break
                elif device == "ide2":
                    boot_target = "Cd"
                    break
                elif device.startswith(("scsi", "sata", "ide")) and "media=cdrom" not in config.get(device, ""):
                    boot_target = "Hdd"
                    break
        boot_override_enabled = "Enabled" if redfish_status == "Off" else "Disabled"

        # SMBIOS Type 1 data
        smbios1 = config.get("smbios1", "")
        smbios_data = {
            "UUID": config.get("smbios1", "").split("uuid=")[1].split(",")[0] if "uuid=" in smbios1 else f"proxmox-vm-{vm_id}",
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": config.get("smbios1", "").split("serial=")[1].split(",")[0] if "serial=" in smbios1 else f"serial-vm-{vm_id}",
            "SKUNumber": None,
            "Family": None
        }
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        if decoded_value.isprintable():
                            value = decoded_value
                    except (base64.binascii.Error, UnicodeDecodeError):
                        pass
                    if key == "uuid":
                        smbios_data["UUID"] = value
                    elif key == "manufacturer":
                        smbios_data["Manufacturer"] = value
                    elif key == "product":
                        smbios_data["ProductName"] = value
                    elif key == "version":
                        smbios_data["Version"] = value
                    elif key == "serial":
                        smbios_data["SerialNumber"] = value
                    elif key == "sku":
                        smbios_data["SKUNumber"] = value
                    elif key == "family":
                        smbios_data["Family"] = value

        # Processor information
        cpu_cores = config.get("cores", 1)
        cpu_sockets = config.get("sockets", 1)
        cpu_type = config.get("cpu", "kvm64")
        processor_architecture = "x86" if "kvm64" in cpu_type or "host" in cpu_type else "unknown"
        total_threads = config.get("vcpus", cpu_cores)

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}",
            "@odata.type": "#ComputerSystem.v1_13_0.ComputerSystem",
            "@odata.context": "/redfish/v1/$metadata#ComputerSystem.ComputerSystem",
            "Id": str(vm_id),
            "Name": config.get("name", f"VM-{vm_id}"),
            "PowerState": redfish_status,
            "Status": {
                "State": state,
                "Health": health,
                "HealthRollup": "OK"
            },
            "Processors": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors",
                "@odata.count": 1,
                "Members": [
                    {
                        "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/CPU1",
                        "@odata.type": "#Processor.v1_3_0.Processor",
                        "Id": "CPU1",
                        "Name": "CPU1",
                        "ProcessorType": "CPU",
                        "ProcessorArchitecture": processor_architecture,
                        "InstructionSet": "x86-64",
                        "Manufacturer": "QEMU",
                        "Model": cpu_type,
                        "ProcessorId": {
                            "VendorID": "QEMU"
                        },
                        "Socket": f"CPU {cpu_sockets}",
                        "TotalCores": cpu_cores,
                        "TotalThreads": total_threads,
                        "Status": {"State": "Enabled", "Health": "OK"}
                    }
                ]
            },
            "Memory": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Memory",
                "TotalSystemMemoryGiB": round(memory_gib, 2),
                "Members": [
                    {
                        "@odata.id": f"/redfish/v1/Systems/{vm_id}/Memory/0",
                        "@odata.type": "#Memory.v1_0_0.Memory",
                        "Id": "0",
                        "Name": "Memory 0",
                        "CapacityMiB": memory_mb,
                        "MemoryType": "DRAM",
                        "Status": {"State": "Enabled", "Health": "OK"}
                    }
                ]
            },
            "Storage": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage"
            },
            "EthernetInterfaces": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces"
            },
            "Boot": {
                "BootSourceOverrideEnabled": boot_override_enabled,
                "BootSourceOverrideTarget": boot_target,
                "BootSourceOverrideTarget@Redfish.AllowableValues": ["Pxe", "Cd", "Hdd"],
                "BootSourceOverrideMode": boot_mode,
                "BootSourceOverrideMode@Redfish.AllowableValues": ["UEFI", "Legacy"]
            },
            "Actions": {
                "#ComputerSystem.Reset": {
                    "target": f"/redfish/v1/Systems/{vm_id}/Actions/ComputerSystem.Reset",
                    "ResetType@Redfish.AllowableValues": [
                        "On",
                        "GracefulShutdown",
                        "ForceOff",
                        "GracefulRestart",
                        "ForceRestart",
                        "Pause",
                        "Resume"
                    ]
                }
            },
            "Manufacturer": smbios_data["Manufacturer"],
            "Model": smbios_data["ProductName"],
            "SerialNumber": smbios_data["SerialNumber"],
            "SKU": smbios_data["SKUNumber"],
            "AssetTag": smbios_data["Family"],
            "Bios": {
                "odata.id": f"/redfish/v1/Systems/{vm_id}/Bios"
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Status retrieval", e, vm_id)


# Custom request handler
class RedfishRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log request details
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"GET Request: path={self.path}, headers=\n{headers_str}")

        path = self.path.rstrip("/")
        response = {}
        status_code = 200
        self.protocol_version = 'HTTP/1.1'

        valid, message = validate_token(self.headers)
        if not valid:
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            proxmox = get_proxmox_api(self.headers)
            parts = path.split("/")
            if path == "/redfish/v1":
                response = {
                    "@odata.id": "/redfish/v1",
                    "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
                    "Id": "RootService",
                    "Name": "Redfish Root Service",
                    "RedfishVersion": "1.0.0",
                    "Systems": {"@odata.id": "/redfish/v1/Systems"}
                }
            elif path == "/redfish/v1/Systems":
                try:
                    vm_list = proxmox.nodes(PROXMOX_NODE).qemu.get()
                    members = [{"@odata.id": f"/redfish/v1/Systems/{vm['vmid']}"} for vm in vm_list]
                    response = {
                        "@odata.id": "/redfish/v1/Systems",
                        "@odata.type": "#SystemCollection.SystemCollection",
                        "Name": "Systems Collection",
                        "Members": members,
                        "Members@odata.count": len(members)
                    }
                except Exception as e:
                    status_code = 500
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Failed to retrieve VM list: {str(e)}"}}
            elif path.startswith("/redfish/v1/Systems/"):
                if len(parts) == 5 and parts[4].isdigit():  # /redfish/v1/Systems/<vm_id>
                    vm_id = int(parts[4])
                    response = get_vm_status(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                # START NEW CODE: Handle /redfish/v1/Systems/<vm_id>/Bios
                elif len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                    vm_id = int(parts[4])
                    response = get_bios(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                # END NEW CODE
                elif len(parts) == 6 and parts[5] == "Processors":  # /redfish/v1/Systems/<vm_id>/Processors
                    vm_id = int(parts[4])
                    response = get_processor_collection(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 7 and parts[5] == "Processors":  # /redfish/v1/Systems/<vm_id>/Processors/<processor_id>
                    vm_id = int(parts[4])
                    processor_id = parts[6]
                    response = get_processor_detail(proxmox, vm_id, processor_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 6 and parts[5] == "Storage":  # /redfish/v1/Systems/<vm_id>/Storage
                    vm_id = int(parts[4])
                    response = get_storage_collection(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 7 and parts[5] == "Storage" and parts[6].isdigit():  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>
                    vm_id = int(parts[4])
                    storage_id = parts[6]
                    response = get_storage_detail(proxmox, vm_id, storage_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 9 and parts[5] == "Storage" and parts[7] == "Drives":  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Drives/<drive_id>
                    vm_id = int(parts[4])
                    storage_id = parts[6]
                    drive_id = parts[8]
                    response = get_drive_detail(proxmox, vm_id, storage_id, drive_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Volumes":  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Volumes
                    vm_id = int(parts[4])
                    storage_id = parts[6]
                    response = get_volume_collection(proxmox, vm_id, storage_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Controllers":  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Controllers
                    vm_id = int(parts[4])
                    storage_id = parts[6]
                    response = get_controller_collection(proxmox, vm_id, storage_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 6 and parts[5] == "EthernetInterfaces":  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces
                    vm_id = int(parts[4])
                    response = get_ethernet_interface_collection(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif len(parts) == 7 and parts[5] == "EthernetInterfaces":  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces/<interface_id>
                    vm_id = int(parts[4])
                    interface_id = parts[6]
                    response = get_ethernet_interface_detail(proxmox, vm_id, interface_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                else:
                    status_code = 404
                    response = {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}}
            else:
                status_code = 404
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}

        response_body = json.dumps(response).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)
        logger.debug(f"GET Response: path={self.path}, status={status_code}, body={json.dumps(response)}")


    def do_POST(self):
        # Log request details
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'

        try:
            post_data_str = post_data.decode('utf-8')
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"POST Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}")

        path = self.path
        response = {}
        token = None
        status_code = 200
        self.protocol_version = 'HTTP/1.1'

        if path == "/redfish/v1/SessionService/Sessions" and AUTH == "Session":
            try:
                data = json.loads(post_data.decode('utf-8'))
                username = data.get("UserName")
                password = data.get("Password")
                if not username or not password:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Missing credentials"}}
                else:
                    if not '@' in username:
                        username += '@pam'
                    proxmox = ProxmoxAPI(PROXMOX_HOST, user=username, password=password, verify_ssl=VERIFY_SSL)
                    token = secrets.token_hex(16)
                    sessions[token] = {"username": username, "password": password, "created": time.time()}
                    status_code = 201
                    response = {
                        "@odata.id": f"/redfish/v1/SessionService/Sessions/{token}",
                        "Id": token,
                        "UserName": username
                    }
            except Exception as e:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Authentication failed: {str(e)}"}}
        else:
            valid, message = validate_token(self.headers)
            if not valid:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
            else:
                proxmox = get_proxmox_api(self.headers)

                # Handle payload parsing based on endpoint
                if post_data:
                    try:
                        data = json.loads(post_data.decode('utf-8'))
                    except json.JSONDecodeError:
                        status_code = 400
                        response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                        response_body = json.dumps(response).encode('utf-8')
                        self.send_response(status_code)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(response_body)
                        # Log response
                        logger.debug(f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
                        return

                    data = json.loads(post_data.decode('utf-8'))
                    if path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.Reset" in path:
                        vm_id = path.split("/")[4]
                        reset_type = data.get("ResetType", "")
                        if reset_type == "On":
                            response, status_code = power_on(proxmox, int(vm_id))
                        elif reset_type == "GracefulShutdown":
                            response, status_code = power_off(proxmox, int(vm_id))
                        elif reset_type == "ForceOff":
                            response, status_code = stop_vm(proxmox, int(vm_id))
                        elif reset_type == "GracefulRestart":
                            response, status_code = reboot(proxmox, int(vm_id))
                        elif reset_type == "ForceRestart":
                            response, status_code = reset_vm(proxmox, int(vm_id))
                        elif reset_type == "Pause":
                            response, status_code = suspend_vm(proxmox, int(vm_id))
                        elif reset_type == "Resume":
                            response, status_code = resume_vm(proxmox, int(vm_id))
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.InvalidRequest",
                                    "message": f"Unsupported ResetType: {reset_type}",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.PropertyValueNotInList",
                                            "Message": f"The value '{reset_type}' for ResetType is not in the supported list: On, GracefulShutdown, ForceOff, GracefulRestart, ForceRestart, Pause, Resume.",
                                            "MessageArgs": [reset_type],
                                            "Severity": "Warning",
                                            "Resolution": "Select a supported ResetType value."
                                        }
                                    ]
                                }
                            }
                    elif path.startswith("/redfish/v1/Systems/") and "/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia" in path:
                        vm_id = path.split("/")[4]
                        iso_path = data.get("Image")
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "InsertMedia", iso_path)
                    elif path.startswith("/redfish/v1/Systems/") and "/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia" in path:
                        vm_id = path.split("/")[4]
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "EjectMedia")
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.UpdateConfig" in path:
                        vm_id = path.split("/")[4]
                        config_data = data
                        response, status_code = update_vm_config(proxmox, int(vm_id), config_data)
                    else:
                        status_code = 404
                        response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}

        # Convert response to JSON and calculate its length
        response_body = json.dumps(response).encode('utf-8')
        content_length = len(response_body)

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length)) 
        if token and path == "/redfish/v1/SessionService/Sessions":
            self.send_header("X-Auth-Token", token)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

        # Log response
        logger.debug(f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}")


    def do_PATCH(self):
        # Log request details
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            post_data_str = post_data.decode('utf-8')
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"PATCH Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}")

        path = self.path.rstrip("/")
        parts = path.split("/")
        response = {}
        status_code = 200
        self.protocol_version = 'HTTP/1.1'

        logger.debug(f"Processing PATCH request for path: {path}")

        valid, message = validate_token(self.headers)
        if not valid:
            logger.error(f"Authentication failed: {message}")
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            try:
                proxmox = get_proxmox_api(self.headers)
                logger.debug(f"Proxmox API connection established for VM operation")
            except Exception as e:
                logger.error(f"Failed to get Proxmox API: {str(e)}")
                status_code = 500
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Failed to connect to Proxmox API: {str(e)}"}}
                response_body = json.dumps(response).encode('utf-8')
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)
                logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
                return
            
            if len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                vm_id = parts[4]
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    if "Attributes" in data:
                        attributes = data["Attributes"]
                        if "FirmwareMode" in attributes:
                            mode = attributes["FirmwareMode"]
                            if mode not in ["BIOS", "UEFI"]:
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.PropertyValueNotInList",
                                        "message": f"Invalid FirmwareMode: {mode}"
                                    }
                                }
                            else:
                                bios_setting = "seabios" if mode == "BIOS" else "ovmf"
                                task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(bios=bios_setting)
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set BIOS Mode for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [{"Message": f"Set BIOS mode to {mode} for VM {vm_id}"}]
                                }
                                status_code = 202
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyUnknown",
                                    "message": "No supported attributes provided"
                                }
                            }
                    else:
                        status_code = 400
                        response = {
                            "error": {
                                "code": "Base.1.0.InvalidRequest",
                                "message": "Attributes object required in PATCH request"
                            }
                        }
                except json.JSONDecodeError:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                except Exception as e:
                    response, status_code = handle_proxmox_error("BIOS update", e, vm_id)
            elif path.startswith("/redfish/v1/Systems/") and len(parts) == 5:
                vm_id = path.split("/")[4]
                logger.debug(f"Processing boot configuration for VM {vm_id}")
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    logger.debug(f"Parsed payload: {json.dumps(data, indent=2)}")
                    # START NEW CODE: Handle sushy ironic drive's incorrect BootSourceOverrideMode request
                    if "Boot" in data and "BootSourceOverrideMode" in data["Boot"]:
                        logger.warning(f"Received non-standard BootSourceOverrideMode request at /redfish/v1/Systems/{vm_id}; redirecting to BIOS handling")
                        mode = data["Boot"]["BootSourceOverrideMode"]
                        # Map BootSourceOverrideMode to FirmwareMode
                        mode_map = {"UEFI": "UEFI", "Legacy": "BIOS"}
                        if mode not in mode_map:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyValueNotInList",
                                    "message": f"Invalid BootSourceOverrideMode: {mode}"
                                }
                            }
                        else:
                            firmware_mode = mode_map[mode]
                            bios_setting = "seabios" if firmware_mode == "BIOS" else "ovmf"
                            task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(bios=bios_setting)
                            response = {
                                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                "@odata.type": "#Task.v1_0_0.Task",
                                "Id": task,
                                "Name": f"Set BIOS Mode for VM {vm_id}",
                                "TaskState": "Completed",  # Changed from "Running" to indicate immediate completion
                                "TaskStatus": "OK",
                                "Messages": [{"Message": f"Set BIOS mode to {firmware_mode} for VM {vm_id}"}]
                            }
                            status_code = 200  # Changed from 202 to 200 for sushi driver
                            response_body = json.dumps(response).encode('utf-8')
                            self.send_response(status_code)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(response_body)))
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(response_body)
                            logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
                            return
                    # END NEW CODE
                    if "Boot" in data:
                        boot_data = data["Boot"]
                        if "BootSourceOverrideMode" in boot_data:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.ActionNotSupported",
                                    "message": "Changing BootSourceOverrideMode is not supported through this resource. Use the Bios resource to change the boot mode.",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.ActionNotSupported",
                                            "Message": "The property BootSourceOverrideMode cannot be changed through the ComputerSystem resource. To change the boot mode, use a PATCH request to the Bios resource.",
                                            "Severity": "Warning",
                                            "Resolution": "Send a PATCH request to /redfish/v1/Systems/<vm_id>/Bios with the desired FirmwareMode in Attributes."
                                        }
                                    ]
                                }
                            }
                        else:
                            target = boot_data.get("BootSourceOverrideTarget")
                            enabled = boot_data.get("BootSourceOverrideEnabled", "Once")
                            logger.debug(f"Boot parameters: target={target}, enabled={enabled}")

                            if target not in ["Pxe", "Cd", "Hdd"]:
                                logger.error(f"Invalid BootSourceOverrideTarget: {target}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideTarget: {target}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{target}' for BootSourceOverrideTarget is not in the supported list: Pxe, Cd, Hdd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported."
                                            }
                                        ]
                                    }
                                }
                            elif enabled not in ["Once", "Continuous", "Disabled"]:
                                logger.error(f"Invalid BootSourceOverrideEnabled: {enabled}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideEnabled: {enabled}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{enabled}' for BootSourceOverrideEnabled is not in the supported list: Once, Continuous, Disabled.",
                                                "MessageArgs": [enabled],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported value for BootSourceOverrideEnabled."
                                            }
                                        ]
                                    }
                                }
                            # Check the VM's current power state
                            logger.debug(f"Checking power state for VM {vm_id}")
                            try:
                                status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
                                logger.debug(f"VM {vm_id} status: {status['status']}")
                            except Exception as e:
                                logger.error(f"Failed to get VM {vm_id} status: {str(e)}")
                                status_code = 500
                                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Failed to get VM status: {str(e)}"}}

                            redfish_status = {
                                "running": "On",
                                "stopped": "Off",
                                "paused": "Paused",
                                "shutdown": "Off"
                            }.get(status["status"], "Unknown")
                            logger.debug(f"VM {vm_id} redfish_status: {redfish_status}")

                            # Proceed with boot order change
                            logger.debug(f"VM {vm_id}, proceeding with boot order change to {target}")
                            try:
                                config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
                                current_boot = config.get("boot", "")
                                logger.debug(f"Current boot order: {current_boot}")
                                new_boot_order = reorder_boot_order(proxmox, int(vm_id), current_boot, target)
                                logger.debug(f"New boot order: {new_boot_order}")
                                config_data = {"boot": f"order={new_boot_order}" if new_boot_order else ""}
                                task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(**config_data)
                                logger.debug(f"Boot order update task initiated: {task}")
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set Boot Order for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [{"Message": f"Boot order set to {target} ({new_boot_order}) for VM {vm_id}"}]
                                }
                                status_code = 202
                            except ValueError as e:
                                logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.ActionNotSupported",
                                        "message": f"Cannot set BootSourceOverrideTarget to {target}: {str(e)}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.ActionNotSupported",
                                                "Message": f"The requested boot device '{target}' is not available. Available boot devices are: Pxe, Cd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported or verify the VM configuration."
                                            }
                                        ]
                                    }
                                }
                            except Exception as e:
                                logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                response, status_code = handle_proxmox_error("Boot configuration", e, vm_id)
                    else:
                        logger.error("Boot object required in PATCH request")
                        status_code = 400
                        response = {"error": {"code": "Base.1.0.InvalidRequest", "message": "Boot object required in PATCH request"}}
                except json.JSONDecodeError:
                    logger.error("Invalid JSON payload")
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
            else:
                logger.error(f"Resource not found: {path}")
                status_code = 404
                response = {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}}

        response_body = json.dumps(response).encode('utf-8')
        content_length = len(response_body)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

        logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")


# Server function (unchanged)
def run_server(port=8000):
    server_address = ('', port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on port {port}...")
    httpd.serve_forever()


# Server function (unchanged)
def run_server_ssl(port=443):
    server_address = ('', port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)
    
    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/opt/redfish_daemon/cert.pem", keyfile="/opt/redfish_daemon/key.pem")  # Use real certs
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"Redfish server running on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    try:
        # Parsing argument
        opts, args = getopt.getopt(sys.argv[1:], "hA:S:", ["help", "Auth=","Secure="])

        # checking each argument
        for opt, arg in opts:
            if  opt in ("-h", "--help"):
                print('''
                  Common OPTIONS:
                        -A <Authn>,   --Auth <Authn>     -- Authentication type to use:  Authn={None|Basic|Session}  Default is None
                        -S <Secure>,  --Secure=<Secure>  -- <Secure>={Always | None } Default is Always
                '''
                )

            if opt in ("-S", "--Secure"):
                if arg == "None":
                    SECURE = None
                else:
                    SECURE = arg
            elif opt in ("-A", "--Auth"):
                if arg == "None":
                    AUTH = None
                else:
                    AUTH = arg
            
    except getopt.error as err:
        # output error, and return with an error code
        print (str(err))
        sys.exit(2)
    
    if SECURE == "Always":
        run_server_ssl()
    else:
        run_server()
