import ctypes, ctypes.util
import mmap
import base64
import pyseccomp as sc
import sys

def no_new_privs():
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    PR_SET_NO_NEW_PRIVS = 38
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(NO_NEW_PRIVS) failed")

def setup_seccomp():
    f = sc.SyscallFilter(sc.ALLOW)
    for name in ["execve", "execveat", "fork", "vfork", "clone", "clone3"]:
        try:
            f.add_rule(sc.KILL, name)
        except Exception:
            pass
    f.load()

buf = mmap.mmap(-1, mmap.PAGESIZE, flags = mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
print(f"mmaped memory region at {hex(ctypes.addressof(ctypes.c_int.from_buffer(buf)))}")

ftype = ctypes.CFUNCTYPE(ctypes.c_int32)
fpointer = ctypes.c_void_p.from_buffer(buf)
f = ftype(ctypes.addressof(fpointer))

shellcode = base64.b64decode(input("Send over your shellcode: "))

bad = [0x48, 0xE8, 0xE9, 0xEB]
if any(b in shellcode for b in bad) or len(shellcode) > 0x70 :
    print("Bad Shellcode!")
    exit(1)

blocks = [shellcode[i:i+12] for i in range(0, len(shellcode), 12)]
final = bytes.fromhex("0BADC0DE").join(blocks)
init_shellcode = b'H1\xc0H1\xdbH1\xc9H1\xd2H1\xf6H1\xffM1\xc0M1\xc9M1\xd2M1\xdbM1\xe4M1\xedM1\xf6M1\xff'

setup_seccomp()

buf.write(init_shellcode + final)

sys.stdin.close()
f()