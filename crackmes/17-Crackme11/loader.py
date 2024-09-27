# --- by crackinglessons.com ---
# use x64dbg to determine target Array of Bytes (AOB) to search for (DATA_TO_FIND)
# and the bytes to replace it with (DATA_TO_REPLACE)
# make sure your AOB is long enough to be unique
# you don't have to replace the entire AOB 
# Usage:  python loader.py filename.exe
#
# it loads (run) the programe into memory then patches the memory

import ctypes
from ctypes import wintypes
import argparse
import psutil  # Required for process name lookup
import subprocess
import time  # For adding delay

# Constants for process access rights and memory states
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000

# Constants for executable memory protections
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXECUTABLE_PROTECTIONS = (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

# Define the byte sequence to find and the replacement bytes as space-separated strings
DATA_TO_FIND = '74 22 C7 45 BC 04 00 00 00'
DATA_TO_REPLACE = 'EB'

# Convert the space-separated hex strings to bytes
data_to_find_bytes = bytes(int(x, 16) for x in DATA_TO_FIND.split())
data_to_replace_bytes = bytes(int(x, 16) for x in DATA_TO_REPLACE.split())

# Define ctypes wrappers for necessary Windows API functions
OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
GetSystemInfo = ctypes.windll.kernel32.GetSystemInfo

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_ulonglong),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)]

def find_pid_by_name(process_name):
    """Find PID by a process name that contains the given string."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if process_name.lower() in proc.info['name'].lower():
            return proc.info['pid']
    return None

def scan_memory(process_handle, data):
    system_info = SYSTEM_INFO()
    GetSystemInfo(ctypes.byref(system_info))
    base_address = system_info.lpMinimumApplicationAddress
    max_address = system_info.lpMaximumApplicationAddress

    while base_address < max_address:
        mbi = MEMORY_BASIC_INFORMATION()
        base_address_casted = ctypes.c_void_p(base_address)
        if VirtualQueryEx(process_handle, base_address_casted, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break

        if mbi.State == MEM_COMMIT and (mbi.Protect in EXECUTABLE_PROTECTIONS):
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytesRead = ctypes.c_size_t(0)
            if ReadProcessMemory(process_handle, base_address_casted, buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
                buffer_array = bytearray(buffer)
                pos = buffer_array.find(data)
                if pos != -1:
                    return base_address_casted.value + pos

        base_address = base_address_casted.value + mbi.RegionSize

    return None

def main(process_identifier):
    # Start the target application
    try:
        subprocess.Popen(process_identifier)  # This assumes process_identifier is the application path
        print(f"Started '{process_identifier}'. Waiting for it to initialize...")
    except Exception as e:
        print(f"Error starting the application: {e}")
        return

    # Optional: Add a 5 secs delay to ensure the application has started and unpacked itself
    time.sleep(5)  # Adjust the delay as necessary

    pid = find_pid_by_name(process_identifier)
    if pid is None:
        print(f"Error: Could not find a process named '{process_identifier}'")
        return

    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print("Error: Could not open process")
        return

    address = scan_memory(process_handle, data_to_find_bytes)
    if address:
        data_to_write = data_to_replace_bytes + data_to_find_bytes[len(data_to_replace_bytes):]
        written = ctypes.c_size_t(0)
        address_casted = ctypes.c_void_p(address)
        if WriteProcessMemory(process_handle, address_casted, data_to_write, len(data_to_write), ctypes.byref(written)):
            print(f"Successfully wrote data to {hex(address)}")
        else:
            print("Error: Could not write to process memory")
    else:
        print("Error: Could not find the specified data in process memory")

    ctypes.windll.kernel32.CloseHandle(process_handle)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Launch an application and modify its memory.")
    parser.add_argument("process_identifier", type=str, help="Path to the target application.")
    args = parser.parse_args()

    main(args.process_identifier)
