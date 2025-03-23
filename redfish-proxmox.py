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

# Proxmox configuration (replace with your actual values)
PROXMOX_HOST = "localhost"
PROXMOX_USER = "user_with_access"       # Only required if using --Auth None
PROXMOX_PASSWORD = "user_passwd"        # the same here
PROXMOX_NODE = "pve-node"
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


# Virtual CD management (unchanged)
def manage_virtual_cd(proxmox, vm_id, iso_path=None):
    try:
        vm_config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config
        if iso_path:
            config_data = {"ide2": f"{iso_path},media=cdrom"}
            task = vm_config.set(**config_data)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Mount ISO to VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Mounted ISO {iso_path} to VM {vm_id}"}]
            }, 202
        else:
            config_data = {"ide2": "none,media=cdrom"}
            task = vm_config.set(**config_data)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Eject ISO from VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Ejected ISO from VM {vm_id}"}]
            }, 202
    except Exception as e:
        return handle_proxmox_error("Virtual CD operation", e, vm_id)


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


def get_vm_status(proxmox, vm_id):
    """
    Retrieve the status and configuration of a VM and return a Redfish-compliant ComputerSystem resource.
    """
    try:
        # Get VM status from Proxmox
        status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()

        # Map Proxmox status to Redfish PowerState
        redfish_status = {
            "running": "On",
            "stopped": "Off",
            "paused": "Paused",
            "shutdown": "Off"
        }.get(status["status"], "Unknown")

        # Calculate memory in GiB (Redfish uses GiB, not MB)
        memory_mb = config.get("memory", 0)
        # Ensure memory_mb is a number; convert from string if necessary
        try:
            memory_mb = float(memory_mb)  # Handles both int and float-like strings
        except (ValueError, TypeError):
            memory_mb = 0  # Fallback to 0 if conversion fails
        memory_gib = memory_mb / 1024.0

        # Parse CDROM info (ide2 format: "storage:iso/filename.iso,media=cdrom" or "none,media=cdrom")
        cdrom_info = config.get("ide2", "none")
        cdrom_media = "None"
        if "none" not in cdrom_info:
            cdrom_media = cdrom_info.split(",")[0]  # e.g., "local:iso/ubuntu.iso"

        # Construct Redfish-compliant response
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
                "Devices": [
                    {
                        "Name": "CDROM",
                        "Type": "CDROM",
                        "CapacityBytes": 0,
                        "Media": cdrom_media
                    }
                ]
            },
            "Manufacturer": "Proxmox",
            "Model": "QEMU Virtual Machine"
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Status retrieval", e, vm_id)


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

        content_length = 0
        if self.headers['Content-Length'] is not None:
            content_length = int(self.headers['Content-Length'])
                
        post_data = self.rfile.read(content_length)
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
                try:
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
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.MountISO" in path:
                        vm_id = path.split("/")[4]
                        action = data.get("Action", "")
                        iso_path = data.get("ISOPath", None)
                        if action == "Mount" and iso_path:
                            response, status_code = manage_virtual_cd(proxmox, int(vm_id), iso_path=iso_path)
                        elif action == "Eject":
                            response, status_code = manage_virtual_cd(proxmox, int(vm_id))
                        else:
                            status_code = 400
                            response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid action or missing ISOPath"}}
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.UpdateConfig" in path:
                        vm_id = path.split("/")[4]
                        config_data = data
                        response, status_code = update_vm_config(proxmox, int(vm_id), config_data)
                    else:
                        status_code = 404
                        response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}
                except json.JSONDecodeError:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}

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

    # In RedfishRequestHandler.do_GET, replace the relevant elif block:
    def do_GET(self):
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
                    response = {
                        "error": {
                            "code": "Base.1.0.GeneralError",
                            "message": f"Failed to retrieve VM list: {str(e)}",
                            "@Message.ExtendedInfo": [{"MessageId": "Base.1.0.GeneralError"}]
                        }
                    }
            elif path.startswith("/redfish/v1/Systems/") and "/Config" in path:
                vm_id = path.split("/")[4]
                response = get_vm_config(proxmox, int(vm_id))  # Optional custom endpoint
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
                        -S <Secure>,  --Secure=<Secure>  -- <Secure>={Always | IfSendingCredentials | IfLoginOrAuthenticatedApi | None(default) }
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