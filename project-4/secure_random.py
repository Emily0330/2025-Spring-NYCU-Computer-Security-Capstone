import subprocess
from pwn import *

conn = remote('140.113.207.245', 30171)
conn.recvuntil(b'Try to break my unbreakable secure random\n')
random_num = subprocess.run("./my_secure_random", shell=True, stdout=subprocess.PIPE)
# print(random_num.stdout) # random_num.stdout is in binary
conn.sendline(random_num.stdout)
conn.recvuntil(b'You succeed, here are your flag\n')
flag = conn.recvline().decode('ascii')
print(flag)
