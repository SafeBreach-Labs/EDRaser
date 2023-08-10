import socket
import psutil
from cpuid import CPUID
import struct
import subprocess


def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    res = s.getsockname()[0]
    s.close()    
    return res

def get_host_name(host_ip):
    return socket.gethostbyaddr(host_ip)[0]

def is_under_vmware():
    VM_TOOLS_PROCESS_NAME = "vmtoolsd"
    for proc in psutil.process_iter():
        try:
            if VM_TOOLS_PROCESS_NAME in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False
    
def decode_CPUID_values(ebx, ecx, edx):
    ebx = struct.unpack("<I", struct.pack(">I", ebx))[0]
    ecx = struct.unpack("<I", struct.pack(">I", ecx))[0]
    edx = struct.unpack("<I", struct.pack(">I", edx))[0]
    return (bytes.fromhex(hex(ebx)[2:]) + bytes.fromhex(hex(ecx)[2:]) + bytes.fromhex(hex(edx)[2:])).decode()
    
def get_HyperVisorName():
    q = CPUID()
    _, ebx, ecx, edx = q(0x40000000)
    return decode_CPUID_values(ebx, ecx, edx)

def is_running_under_VMware():
    return get_HyperVisorName() == "VMwareVMware"

def run_process(process, args):
    subprocess.run([process] + [args])
    