# --- by crackinglessons.com ---
# use x64dbg to determine target Array of Bytes (AOB) to search for (DATA_TO_FIND)
# and the bytes to replace it with (DATA_TO_REPLACE)
# make sure your AOB is long enough to be unique
# you don't have to replace the entire AOB 
# Usage:  python patchmen.py process.exe, or,
#         python pathcmen.py PID

import ctypes
from ctypes import wintypes
import argparse
import psutil  # Required for process name lookup

# Constants for process access rights and memory states
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000

# Constants for executable memory protections
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXECUTABLE_PROTECTIONS = (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

# Define the byte sequence to find and the replacement bytes as space-separated strings
DATA_TO_FIND = '0F 85 82 00 00 00 E8 C0 17 00 00 85 C0 75 79'
DATA_TO_REPLACE = '90 90 90 90 90 90 90 90 90 90 90 90 90 90 90'

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
    # Determine if process_identifier is a PID or a process name
    try:
        pid = int(process_identifier)  # Try converting to int, assuming it's a PID
    except ValueError:
        # If conversion fails, assume it's a process name and find its PID
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
        # Prepare the data to write, filling in the rest of data_to_find_bytes if data_to_replace_bytes is shorter
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
    parser = argparse.ArgumentParser(description="Modify memory of a process by PID or process name.")
    parser.add_argument("process_identifier", type=str, help="Process ID (PID) or name of the target application.")
    args = parser.parse_args()

    main(args.process_identifier)

