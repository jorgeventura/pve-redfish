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
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[SysLogHandler(address='/dev/log')]
)
logger = logging.getLogger('redfish-proxmox')
logger.setLevel(logging.DEBUG)

# Proxmox configuration (replace with your actual values)
PROXMOX_HOST = "localhost"
PROXMOX_USER = "user_with_access"       # Only required if using --Auth None
PROXMOX_PASSWORD = "user_passwd"        # the same here
PROXMOX_NODE = "pve-m5"
VERIFY_SSL = False

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
        str: New boot order (e.g., "scsi0;ide0;ide2;net0"), or an empty string if no devices match.
    """
    # Fetch VM configuration
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
    except Exception as e:
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

    # Reorder based on target, keeping all devices
    new_order = []
    if target == "Pxe" and net_dev:
        new_order = [net_dev] + [d for d in available_devs if d != net_dev]
    elif target == "Cd" and cd_dev:
        new_order = [cd_dev] + [d for d in available_devs if d != cd_dev]
    elif target == "Hdd" and disk_devs:
        # Prioritize the first hard drive (e.g., scsi0), then include others
        primary_disk = disk_devs[0]
        new_order = [primary_disk] + [d for d in available_devs if d != primary_disk]
    else:
        # Fallback: keep the existing order or use all available devices
        new_order = available_devs

    # Remove duplicates and ensure valid devices only
    unique_devices = list(dict.fromkeys(new_order))
    return ";".join(unique_devices) if unique_devices else ""


def get_vm_status(proxmox, vm_id):
    try:
        status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()

        redfish_status = {
            "running": "On",
            "stopped": "Off",
            "paused": "Paused",
            "shutdown": "Off"
        }.get(status["status"], "Unknown")

        memory_mb = config.get("memory", 0)
        try:
            memory_mb = float(memory_mb)
        except (ValueError, TypeError):
            memory_mb = 0
        memory_gib = memory_mb / 1024.0

        cdrom_info = config.get("ide2", "none")
        cdrom_media = "None" if "none" in cdrom_info else cdrom_info.split(",")[0]

        boot_order = config.get("boot", "order=scsi0;ide2;net0")
        boot_target = "Hdd"
        if "net" in boot_order and boot_order.index("net") < boot_order.index(";"):
            boot_target = "Pxe"
        elif "ide2" in boot_order and boot_order.index("ide2") < boot_order.index(";"):
            boot_target = "Cd"
        boot_override_enabled = "Enabled" if redfish_status == "Off" else "Disabled"

        # Extract and decode SMBIOS Type 1 data
        smbios1 = config.get("smbios1", "")
        smbios_data = {
            "UUID": config.get("smbios1", "").split("uuid=")[1].split(",")[0] if "uuid=" in config.get("smbios1", "") else f"proxmox-vm-{vm_id}",
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": config.get("smbios1", "").split("serial=")[1].split(",")[0] if "serial=" in config.get("smbios1", "") else f"serial-vm-{vm_id}",
            "SKUNumber": None,
            "Family": None
        }
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)
                    # Decode Base64 if applicable
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        if decoded_value.isprintable():  # Ensure it’s valid text
                            value = decoded_value
                    except (base64.binascii.Error, UnicodeDecodeError):
                        pass  # Use original value if decoding fails

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
            "@odata.id": f"/redfish/v1/Systems/{vm_id}",
            "@odata.type": "#ComputerSystem.v1_13_0.ComputerSystem",
            "@odata.context": "/redfish/v1/$metadata#ComputerSystem.ComputerSystem",
            "Id": str(vm_id),
            "Name": config.get("name", f"VM-{vm_id}"),
            "PowerState": redfish_status,
            "Status": {
                "State": "Enabled" if status["status"] in ["running", "paused"] else "Disabled",
                "Health": "OK" if status["status"] in ["running", "paused"] else "Critical"
            },
            "ProcessorSummary": {
                "Count": config.get("cores", 0),
                "Sockets": config.get("sockets", 1)
            },
            "MemorySummary": {
                "TotalSystemMemoryGiB": round(memory_gib, 2)
            },
            "SimpleStorage": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/SimpleStorage",
                "Devices": [{"Name": "CDROM", "Type": "CDROM", "CapacityBytes": 0, "Media": cdrom_media}]
            },
            "Boot": {
                "BootSourceOverrideEnabled": boot_override_enabled,
                "BootSourceOverrideTarget": boot_target,
                "BootSourceOverrideSupported": ["Pxe", "Cd", "Hdd"]
            },
            "Actions": {
                "#ComputerSystem.Reset": {
                    "target": f"/redfish/v1/Systems/{vm_id}/Actions/ComputerSystem.Reset",
                    "ResetType@Redfish.AllowableValues": ["On", "ForceOff", "ForceRestart", "Pause", "Resume", "ForceStop"]
                }
            },
            "Manufacturer": smbios_data["Manufacturer"],
            "Model": smbios_data["ProductName"],
            "SerialNumber": smbios_data["SerialNumber"],
            "SKU": smbios_data["SKUNumber"],
            "AssetTag": smbios_data["Family"],
            "Bios": {
                "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios"
            }
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Status retrieval", e, vm_id)


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
                        # Only use decoded value if it’s valid UTF-8 and not a UUID
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


# Custom request handler
class RedfishRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Log request details
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            post_data_str = post_data.decode('utf-8')
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"POST Request: path={self.path}, headers=\n{headers_str}\n, body={post_data_str}")

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
                        elif reset_type == "ForceOff":
                            response, status_code = power_off(proxmox, int(vm_id))
                        elif reset_type == "ForceRestart":
                            response, status_code = reboot(proxmox, int(vm_id))
                        elif reset_type == "Pause":
                            response, status_code = suspend_vm(proxmox, int(vm_id))
                        elif reset_type == "Resume":
                            response, status_code = resume_vm(proxmox, int(vm_id))
                        elif reset_type == "ForceStop":
                            response, status_code = stop_vm(proxmox, int(vm_id))
                        else:
                            status_code = 400
                            response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Unsupported ResetType: {reset_type}"}}
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

    def do_GET(self):
        # Log request details
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"GET Request: path={self.path}, headers=\n{headers_str}")

        path = self.path
        response = {}
        status_code = 200
        self.protocol_version = 'HTTP/1.1'
    
        valid, message = validate_token(self.headers)
        if not valid:
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            proxmox = get_proxmox_api(self.headers)
            path = self.path.rstrip("/")
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
            elif path.startswith("/redfish/v1/Systems/") and "/VirtualMedia" in path:
                vm_id = path.split("/")[4]
                if path == f"/redfish/v1/Systems/{vm_id}/VirtualMedia":
                    response = {
                        "@odata.id": f"/redfish/v1/Systems/{vm_id}/VirtualMedia",
                        "@odata.type": "#VirtualMediaCollection.VirtualMediaCollection",
                        "Name": "Virtual Media Collection",
                        "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/VirtualMedia/CDROM"}],
                        "Members@odata.count": 1
                    }
                elif path == f"/redfish/v1/Systems/{vm_id}/VirtualMedia/CDROM":
                    config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
                    cdrom_info = config.get("ide2", "none")
                    inserted = "none" not in cdrom_info
                    image = cdrom_info.split(",")[0] if inserted else None
                    response = {
                        "@odata.id": f"/redfish/v1/Systems/{vm_id}/VirtualMedia/CDROM",
                        "@odata.type": "#VirtualMedia.v1_0_0.VirtualMedia",
                        "Id": "CDROM",
                        "Name": "Virtual CD-ROM Drive",
                        "MediaTypes": ["CD"],
                        "Inserted": inserted,
                        "Image": image,
                        "Actions": {
                            "#VirtualMedia.InsertMedia": {
                                "target": f"/redfish/v1/Systems/{vm_id}/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia"
                            },
                            "#VirtualMedia.EjectMedia": {
                                "target": f"/redfish/v1/Systems/{vm_id}/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia"
                            }
                        }
                    }
                else:
                    status_code = 404
                    response = {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": "VirtualMedia resource not found"}}
            elif path.startswith("/redfish/v1/Systems/") and "/Bios" in path:
                vm_id = path.split("/")[4]
                if path == f"/redfish/v1/Systems/{vm_id}/Bios":
                    response = get_bios(proxmox, int(vm_id))
                    if isinstance(response, tuple):  # Handle error case
                        response, status_code = response
                elif path == f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS":
                    response = get_smbios_type1(proxmox, int(vm_id))
                    if isinstance(response, tuple):  # Handle error case
                        response, status_code = response
                else:
                    status_code = 404
                    response = {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": "BIOS resource not found"}}
            elif path.startswith("/redfish/v1/Systems/") and "/Config" in path:
                vm_id = path.split("/")[4]
                response = get_vm_config(proxmox, int(vm_id))
                if isinstance(response, tuple):  # Handle error case
                    response, status_code = response
            elif path.startswith("/redfish/v1/Systems/") and len(path.split("/")) > 4:
                vm_id = path.split("/")[4]
                response = get_vm_status(proxmox, int(vm_id))
                if isinstance(response, tuple):  # Handle error case
                    response, status_code = response
            else:
                status_code = 404
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}
    
        response_body = json.dumps(response).encode('utf-8')
        content_length = len(response_body)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

        # Log response
        logger.debug(f"GET Response: path={self.path}, status={status_code}, body={json.dumps(response)}")

    def do_PATCH(self):
        # Log request details
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            post_data_str = post_data.decode('utf-8')
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"PATCH Request: path={self.path}, headers=\n{headers_str}\n, body={post_data_str}")

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
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
            if path.startswith("/redfish/v1/Systems/") and len(path.split("/")) == 5:
                vm_id = path.split("/")[4]
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    if "Boot" in data:
                        boot_data = data["Boot"]
                        target = boot_data.get("BootSourceOverrideTarget")
                        enabled = boot_data.get("BootSourceOverrideEnabled", "Once")

                        if target not in ["Pxe", "Cd", "Hdd"]:
                            status_code = 400
                            response = {"error": {"code": "Base.1.0.InvalidRequest", "message": f"Unsupported BootSourceOverrideTarget: {target}"}}
                        elif enabled not in ["Once", "Continuous", "Disabled"]:
                            status_code = 400
                            response = {"error": {"code": "Base.1.0.InvalidRequest", "message": f"Unsupported BootSourceOverrideEnabled: {enabled}"}}
                        else:
                            # Check the VM's current power state
                            status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
                            redfish_status = {
                                "running": "On",
                                "stopped": "Off",
                                "paused": "Paused",
                                "shutdown": "Off"
                            }.get(status["status"], "Unknown")

                            # If VM is not Off, reject the boot order change
                            if redfish_status != "Off":
                                status_code = 400  # Bad Request
                                response = {
                                    "error": {
                                        "code": "Base.1.0.ActionNotSupported",
                                        "message": f"Cannot modify boot configuration while VM {vm_id} is {redfish_status}. BootSourceOverrideEnabled is Disabled.",
                                        "@Message.ExtendedInfo": [{
                                            "MessageId": "Base.1.0.ActionNotSupported",
                                            "Message": "The action to modify the boot order is not supported while the system is powered on or in a paused state. Power off the system and try again.",
                                            "MessageArgs": ["Boot order modification", redfish_status],
                                            "Severity": "Warning",
                                            "Resolution": "Power off the system using a Reset action (e.g., ForceOff) and retry the operation."
                                        }]
                                    }
                                }
                            else:
                                # Proceed with boot order change if VM is Off
                                config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
                                current_boot = config.get("boot", "")
                                new_boot_order = reorder_boot_order(proxmox, int(vm_id), current_boot, target)
                                config_data = {"boot": f"order={new_boot_order}" if new_boot_order else ""}
                                task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(**config_data)
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
                    else:
                        status_code = 400
                        response = {"error": {"code": "Base.1.0.InvalidRequest", "message": "Boot object required in PATCH request"}}
                except json.JSONDecodeError:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                except Exception as e:
                    response, status_code = handle_proxmox_error("Boot configuration", e, vm_id)
            else:
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

        # Log response
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