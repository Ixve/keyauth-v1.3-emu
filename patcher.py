import os
import time
import json
import subprocess
import pymem as pm
import psutil as ps
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization



# IMPORTANT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!  #################################################
# The patcher will attempt to read from 0x400000 - 0x700000 and automatically find and replace #
# the public key, this is where I usually notice it sitting at first (Themida programs)        #
# however, if you want to use the legacy technique, flip the following switch to True          #
################################################################################################
legacy_offset = False



os.system("cls||clear")
def config_gen():
    print("[#] Generating new config file")
    if legacy_offset:
        global PUBKEY_OFFSET
        PUBKEY_OFFSET = str(input("Public key offset => "))
    global ORIG_PUBKEY, PROC_PATH
    
    ORIG_PUBKEY = str(input("Original public key => "))
    if not len(ORIG_PUBKEY) == int(64):
        print(f"[!] Public key is invalid, your key length: {len(ORIG_PUBKEY)}, expected length: 64")
        time.sleep(1.5)
        exit()

    PROC_PATH = str(input("Process path (Drag and drop) =>  "))
    try:
        if not os.path.basename(PROC_PATH).endswith(".exe"):
            print("[!] File extension is not exe, aborting")
            time.sleep(1.5)
    except:
        print(f"[!] Failed to get path base name, aborting")
        exit()

    if legacy_offset:
        data = {"PUBKEY_OFFSET": PUBKEY_OFFSET, "ORIG_PUBKEY": ORIG_PUBKEY, "PROC_PATH": PROC_PATH}
    else:
        data = {"ORIG_PUBKEY": ORIG_PUBKEY, "PROC_PATH": PROC_PATH}
        
    with open("patch_cfg.json", "w") as f:
        json.dump(data, f)


def load_config():
    if os.path.isfile("patch_cfg.json"):
        with open("patch_cfg.json", "r") as f:
            fr = json.load(f)
            try:
                if legacy_offset:
                    global PUBKEY_OFFSET
                    PUBKEY_OFFSET = fr["PUBKEY_OFFSET"]
                global ORIG_PUBKEY, PROC_PATH
                ORIG_PUBKEY = fr["ORIG_PUBKEY"]
                PROC_PATH = fr["PROC_PATH"]
            except KeyError:
                print("[!] Patcher config appears to be invalid - regenerating")
                config_gen()
    else:
        config_gen()


load_config()
PROC_NAME = os.path.basename(PROC_PATH)
USERPROFILE = os.getenv("USERPROFILE")

with open(f"{USERPROFILE}\\Documents\\cert\\ed.key", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)
pubkey = privkey.public_key()
pubkey_bytes = pubkey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

NEW_PUBKEY = pubkey_bytes.hex().encode()
ORIG_PUBKEY = ORIG_PUBKEY.encode()
print("[dbg] NEW_PUBKEY -> ", NEW_PUBKEY, "\n[dbg] ORIG_PUBKEY -> ", ORIG_PUBKEY)

def find_proc(procname):
    for process in ps.process_iter(['pid', 'name']):
        if process.info['name'] == procname:
            return process
    return None

def legacy_patch(proc_con, base_addr, offset, new_key):
    try:
        if offset.startswith('0x') or offset.startswith('0X'):
            offset_int = int(offset, 16)
        else:
            offset_int = int(offset)
        
        patch_addr = base_addr + offset_int
        
        if writemem(proc_con, patch_addr, new_key, len(new_key)):
            return True
        else:
            return False
            
    except ValueError as e:
        print(f"[legacy_patch] Invalid offset format: {offset} - {e}")
        return False
    except Exception as e:
        print(f"[legacy_patch] Error: {e}")
        return False

def mem_scan(proc_con, orig_key, new_key, base_addr):
    patched_count = 0

    try:
        orig_hex = orig_key.decode().upper().encode()
        new_hex = new_key.decode().upper().encode()

        current_addr = 0x400000
        chunk_size = 0x1000
        max_addr = 0x700000
        found_in_unmapped = False

        while current_addr < max_addr:
            try:
                data = proc_con.read_bytes(current_addr, chunk_size)

                offset = 0
                while True:
                    pos = data.find(orig_key, offset)
                    if pos == -1:
                        break
                    addr = current_addr + pos
                    print(f"[mem_scan] Found pubkey (pre-main module)): 0x{addr:X}")
                    if writemem(proc_con, addr, new_key, len(orig_key)):
                        patched_count += 1
                        if not found_in_unmapped:
                            found_in_unmapped = True
                    offset = pos + 1

                offset = 0
                while True:
                    pos = data.find(orig_hex, offset)
                    if pos == -1:
                        break
                    addr = current_addr + pos
                    print(f"[mem_scan] Found pubkey (pre-main module): 0x{addr:X}")
                    if writemem(proc_con, addr, new_hex, len(orig_hex)):
                        print(f"[mem_write] Patched pubkey (pre-main module): 0x{addr:X}")
                        patched_count += 1
                        if not found_in_unmapped:
                            found_in_unmapped = True
                    offset = pos + 1

            except Exception:
                pass

            current_addr += chunk_size

        current_addr = base_addr
        chunk_size = 0x1000
        max_scan = 0x300000

        while current_addr < base_addr + max_scan:
            try:
                data = proc_con.read_bytes(current_addr, chunk_size)

                pos = data.find(orig_key)
                if pos != -1:
                    addr = current_addr + pos
                    print(f"[mem_scan] Found pubkey (main module): 0x{addr:X}")
                    if writemem(proc_con, addr, new_key, len(orig_key)):
                        print(f"[mem_write] Patched pubkey (main module): 0x{addr:X}")
                        patched_count += 1
                        break

                pos = data.find(orig_hex)
                if pos != -1:
                    addr = current_addr + pos
                    print(f"[mem_scan] Found pubkey (main module): 0x{addr:X}")
                    if writemem(proc_con, addr, new_hex, len(orig_hex)):
                        print(f"[mem_write] Patched pubkey (main module): 0x{addr:X}")
                        patched_count += 1
                        break

            except Exception:
                pass

            current_addr += chunk_size

    except Exception as e:
        print(f"[mem_scan] Complete failure: {e}")
    return patched_count > 0


def writemem(proc_con, addr, new, expect_len):
    if len(new) != expect_len:
        return False
    
    try:
        try:            
            kernel32 = ctypes.windll.kernel32
            VirtualProtectEx = kernel32.VirtualProtectEx
            VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            VirtualProtectEx.restype = wintypes.BOOL
            
            old_protect = wintypes.DWORD()
            success = VirtualProtectEx(proc_con.process_handle, addr, len(new), 0x40, ctypes.byref(old_protect))
            
            if success:
                proc_con.write_bytes(addr, new, len(new))
                VirtualProtectEx(proc_con.process_handle, addr, len(new), old_protect.value, ctypes.byref(wintypes.DWORD()))
                
                readback = proc_con.read_bytes(addr, len(new))
                if readback == new:
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            return False
    except pm.exception.MemoryWriteError as e:
        return False
    except Exception as e:
        return False

if __name__ == "__main__":
    len_origkey = len(ORIG_PUBKEY)
    last_proc_death = None
    proc_alive = False

    print(f"[#] Target program: {PROC_NAME}")
    if legacy_offset:
        print(f"[?] Mode - legacy , offset: {PUBKEY_OFFSET}")
    else:
        print("[?] Mode - automatic scan")
    print("-------------------------\n")

    try:
        while True:
            target = find_proc(PROC_NAME)
            
            if not target:
                if proc_alive:
                    last_proc_death = time.time()
                    proc_alive = False
                    print(f"{PROC_NAME} has been terminated. Waiting 5 seconds before restart...")
                
                if last_proc_death is not None:
                    time_since_death = time.time() - last_proc_death
                    if time_since_death < 5:
                        remaining_wait = 5 - time_since_death
                        print(f"Waiting {int(remaining_wait)} more seconds before restart...")
                        time.sleep(1)
                        continue
                
                print(f"Starting {PROC_NAME}")
                try:
                    os.startfile(PROC_PATH)
                    target = find_proc(PROC_NAME)
                    if not target:
                        continue
                    else:
                        print(f"{PROC_NAME} started")
                        last_proc_death = None
                except Exception as e:
                    print(f"Error starting process: {e}")
                    time.sleep(2)
                    continue
            
            if not proc_alive:
                proc_alive = True
            
            proc_con = None
            
            try:
                proc_con = pm.Pymem(target.pid)
                base_addr = proc_con.process_base.lpBaseOfDll
                patch_state = False
                
                if legacy_offset:
                    patch_state = legacy_patch(proc_con, base_addr, PUBKEY_OFFSET, NEW_PUBKEY)
                else:
                    patch_state = mem_scan(proc_con, ORIG_PUBKEY, NEW_PUBKEY, base_addr)
                    
            except Exception as e:
                pass
            finally:
                if proc_con:
                    try:
                        proc_con.close_process()
                    except Exception as e:
                        pass

    except KeyboardInterrupt:
        print("\nPatcher stopped, goodbye.")
        time.sleep(1.5)
