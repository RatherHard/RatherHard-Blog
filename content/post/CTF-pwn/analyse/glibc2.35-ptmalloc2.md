---
title: glibc-2.35 ptmalloc2 分析
date: 2025-12-08 19:07:00
tags: 
    - pwn
    - heap
    - glibc
categories: glibc-analyse
---
# 重要结构

## 常数速查

以 64 位为准

```c
SIZE_SZ                         8
MALLOC_ALIGNMENT                16
MALLOC_ALIGN_MASK               0b1111
MINSIZE                         32
TCACHE_MAX_BINS                 64
TCACHE_FILL_COUNT               7
CHUNK_HDR_SZ                    16
SMALLBIN_WIDTH                  16
SMALLBIN_CORRECTION             0
MIN_LARGE_SIZE                  1024
```

## chunk

**chunk** 是内存分配的基本单位，它其实是一个内存块。chunk 被分配 (malloc) 后能够存储用户数据，空闲时 (free) 能够插入 bin 中，随时做好被分配的准备。

程序向操作系统申请一块连续的堆区域后，该块区域整体初始化为一个 **top chunk** ，第一次 malloc 的操作可以理解为从 top chunk 中分割出一块内存供程序使用。

我们把 chunk 划分为两个部分： **chunk_header** 和 **chunk_content**

```
+--------------------+        低地址
|    chunk_header    |
+--------------------+
|                    |
|                    |
|    chunk_content   |
|                    |
|                    |
+--------------------+        高地址
```

下面的 malloc_chunk 中的 mchunk_prev_size 和 mchunk_size 即 chunk_header

### malloc_chunk 结构体

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

主要字段说明如下：

- **mchunk_prev_size** ：8 字节，简称 **prev_size**，表示前一个 chunk 的大小。
- **mchunk_size** ：8 字节，简称 **size** ，表示当前 chunk 的大小。size 的低 3 位是标志位，3 个标志说明如下：
  - **PREV_INUSE** ( P 位)：最低位，表示前一个 chunk 是否在某个 bin 中，0 表示前一个 chunk 在某个 bin 中，1 表示前一个 chunk 不在任何 bin 中。
  - **IS_MMAPPED** ( M 位)：第二低位，表示当前 chunk 是否通过 mmap 分配， 1 是 0 否。若 M 位为 1 ，则忽略 A 位和 P 位。
  - **NON_MAIN_ARENA** ( A 位)：第三低位，表示当前 chunk 是否属于主线程的分配区（ malloc_state ）， 0 是 1 否。
- **fd** ：8 字节，指向下一个（先进入链表）空闲 chunk 的指针。这个字段仅在当前 chunk 是空闲时有效。如果当前 chunk 已分配，那么fd字段被复用为可用内存（ 8 字节）。
- **bk** ：指向前一个（后进入链表）空闲 chunk 的指针。该字段和fd功能类似。
- **fd_nextsize** ：8 字节，largebins 中指向下一个（先进入链表）比当前 chunk 小的空闲 chunk 。用于 largebins 快速查找不同大小的空闲 chunk ，提高分配效率，如果当前 chunk 是已分配的，那么 fd_nextsize 字段被复用为可用内存（ 8 字节）。
- **bk_nextsize** ：8 字节，largebins 中指向前一个（后进入链表）比当前 chunk 大的空闲 chunk ，和 fd_nextsize 功能类似。

## malloc_state 结构体

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

struct malloc_state 是 glibc 内存分配器的核心数据结构，通常被称为 **Arena** 。它保存了一个分配区的所有元数据、空闲链表状态以及统计信息。

以下是对其所有成员的深度解析：

**1. 并发控制与标志**
*   **`__libc_lock_define (, mutex);`**
    *   **用途**：互斥锁。
    *   **解析**：由于多个线程可能共享同一个 Arena，在进行分配或释放操作（修改 Bins 链表等）之前，线程必须先获取这把锁。主分配区和线程分配区都靠它实现线程安全。

*   **`int flags;`**
    *   **用途**：分配区状态标志。
    *   **解析**：存储一些底层状态。最重要的是 CONTIGUOUS_BIT (0x2) ，用于标记该 Arena 管理的内存空间是否是连续的（主分配区通常是连续的，通过 brk 扩展；非主分配区由多个 mmap 堆组成，可能不连续）。

*   **`int have_fastchunks;`**
    *   **用途**：快速标记 fastbins 是否为空。
    *   **解析**：这是一个布尔优化的标志。当有块进入 fastbin 时设为 1。在 malloc 的某些路径（如 malloc_consolidate ）中，它会先检查这个位，如果是 0 就直接跳过，从而节省扫描整个 fastbinsY 数组的时间。

**2. 核心堆块容器 (Bins)**
*   **`mfastbinptr fastbinsY[NFASTBINS];`**
    *   **用途**：**Fastbins** 链表数组。
    *   **解析**：专门处理小内存块（默认 64 位下 16~128 字节）的**单向链表**。Fastbin 中的块不会被合并（除非触发 consolidate），因此分配速度极快。NFASTBINS 通常为 10。

*   **`mchunkptr top;`**
    *   **用途**：**Top Chunk** 指针。
    *   **解析**：指向当前 Arena 中位置最高、也是最后一块待分配的大内存区域。当所有的 Bins（Fast, Small, Large, Unsorted）都无法满足分配需求时，malloc 会从 Top Chunk 中“切”出一块内存。如果 Top Chunk 也不够，则会调用 sbrk 或 mmap 向系统申请。

*   **`mchunkptr last_remainder;`**
    *   **用途**：**Last Remainder Chunk**。
    *   **解析**：这是一种特殊优化。当分配一个 Small Chunk，而 Unsorted Bin 中只有一块较大的空闲块时，大块会被分割，剩下的部分就存放在 last_remainder。这样可以提高**局部性**，即连续的小分配请求更有可能来自同一物理区域。

*   **`mchunkptr bins[NBINS * 2 - 2];`**
    *   **用途**：**普通 Bins** 数组（Unsorted, Small, Large）。
    *   **解析**：这是 malloc 的主要仓库。
        *   它是双向链表。
        *   `bins[0]` 不使用，`bins[1]` 是 **Unsorted Bin**（最近释放且未分类的块）。
        *   后续是 **Small Bins**（固定大小）和 **Large Bins**（范围大小）。
        *   为什么是 `* 2`？因为每个 bin 需要一对 fd（前驱）和 bk（后继）指针来表示链表头。

**3. 查询优化**
*   **`unsigned int binmap[BINMAPSIZE];`**
    *   **用途**：**Bins 位图**。
    *   **解析**：为了快速定位哪个 bin 里有空闲内存。位图中的每一位对应 bins 数组中的一个 bin。malloc 使用位运算指令（如 ffs ）快速找到非空的 bin，而不需要遍历 126 个 bin。

**4. 链表结构与统计**
*   **`struct malloc_state *next;`**
    *   **用途**：全局 Arena 链表。
    *   **解析**：所有的 Arena 都通过这个指针连成一串。main_arena 位于链表首部。当线程找不到可用 Arena 时，会沿着这个指针寻找。

*   **`struct malloc_state *next_free;`**
    *   **用途**：空闲 Arena 链表。
    *   **解析**：当一个线程退出时，它绑定的 Arena 会被放入这个“空闲链表”，以便下一个新创建的线程复用。

*   **`INTERNAL_SIZE_T attached_threads;`**
    *   **用途**：引用计数。
    *   **解析**：统计当前有多少个线程正在使用（绑定）这个 Arena。这有助于 glibc 决定是否需要创建新的 Arena 来降低竞争。

*   **`INTERNAL_SIZE_T system_mem;`**
    *   **用途**：当前分配区占用的系统内存总量。
    *   **解析**：记录了从操作系统（brk/mmap）拿到的总字节数。

*   **`INTERNAL_SIZE_T max_system_mem;`**
    *   **用途**：历史峰值内存。
    *   **解析**：记录 system_mem 曾达到的最大值。

## malloc_par 结构体

```c
struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;
  INTERNAL_SIZE_T top_pad;
  INTERNAL_SIZE_T mmap_threshold;
  INTERNAL_SIZE_T arena_test;
  INTERNAL_SIZE_T arena_max;

#if HAVE_TUNABLES
  /* Transparent Large Page support.  */
  INTERNAL_SIZE_T thp_pagesize;
  /* A value different than 0 means to align mmap allocation to hp_pagesize
     add hp_flags on flags.  */
  INTERNAL_SIZE_T hp_pagesize;
  int hp_flags;
#endif

  /* Memory map support */
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;

  /* Statistics */
  INTERNAL_SIZE_T mmapped_mem;
  INTERNAL_SIZE_T max_mmapped_mem;

  /* First address handed out by MORECORE/sbrk.  */
  char *sbrk_base;

#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};
```

struct malloc_par（通常在源码中以全局变量 mp_ 形式存在）是 glibc 内存分配器的**全局配置参数表**。

与 malloc_state（管理具体的内存块）不同，malloc_par 负责控制**分配器的整体行为策略**（如：什么时候用 mmap 而不是 sbrk ？ Tcache 的限制是多少？）。

以下是所有成员的分块解析：

**1. 核心可调参数 (Tunables)**
这些参数直接影响分配器的性能和内存碎片控制：

*   **`unsigned long trim_threshold;`**
    *   **用途**：收缩阈值。
    *   **解析**：当 top chunk 的大小超过这个值时，malloc 会尝试调用 malloc_trim 将空闲内存归还给操作系统。默认通常为 128KB。
*   **`INTERNAL_SIZE_T top_pad;`**
    *   **用途**：堆顶填充。
    *   **解析**：每次通过 sbrk 扩展堆时，会额外申请这么多的空间，以减少未来频繁调用系统调用的次数。
*   **`INTERNAL_SIZE_T mmap_threshold;`**
    *   **用途**：**mmap 阈值**（非常关键）。
    *   **解析**：当申请的字节数大于此值时，malloc 不从堆分配，而是直接调用 mmap。这有助于防止大块内存产生的空洞阻塞堆的收缩。
*   **`INTERNAL_SIZE_T arena_test;`**
    *   **用途**：Arena 冲突检测阈值。
    *   **解析**：用于决定何时创建新 Arena。在 64 位系统上，通常在 CPU 核心数较多时，以此为参考动态增加 Arena 数量。
*   **`INTERNAL_SIZE_T arena_max;`**
    *   **用途**：**Arena 最大数量限制**。
    *   **解析**：限制进程可以创建的 Arena 总数（通常 64 位下为 8 * 核心数 ）。防止 Arena 过多导致内存浪费。

**2. 大页内存支持 (Large Pages)**
*   **`INTERNAL_SIZE_T thp_pagesize;`**：透明大页（Transparent Large Pages）的大小。
*   **`INTERNAL_SIZE_T hp_pagesize;`**：显式大页（Huge Pages）的大小。
*   **`int hp_flags;`**：调用 mmap 时传递给内核的大页标志位（如 MAP_HUGETLB ）。

**3. Mmap 状态与动态阈值**
*   **`int n_mmaps;`**：当前正在使用的通过 mmap 分配的块的数量。
*   **`int n_mmaps_max;`**：历史上同时存在的 mmap 块的最大数量。
*   **`int max_n_mmaps;`**：允许的 mmap 块的最大数量限制。
*   **`int no_dyn_threshold;`**
    *   **解析**：glibc 默认会**动态调整** mmap_threshold（根据已释放的块大小自动调优）。如果用户通过 mallopt 手动设置了阈值，该变量会置 1，关闭自动调整逻辑。

**4. 统计信息**
*   **`INTERNAL_SIZE_T mmapped_mem;`**：当前通过 mmap 分配的内存总字节数。
*   **`INTERNAL_SIZE_T max_mmapped_mem;`**：历史上 mmapped_mem 达到的峰值。

**5. 堆基址**
*   **`char *sbrk_base;`**
    *   **解析**：程序第一次调用 sbrk 时返回的地址。它标记了主堆区域的起始位置，用于判断某个指针是否属于主堆。

**6. Tcache 机制参数**
*   **`size_t tcache_bins;`**
    *   **解析**：Tcache 链表的数量。默认是 **64**。
*   **`size_t tcache_max_bytes;`**
    *   **解析**：Tcache 能够容纳的最大块大小。默认通常是 **1032 字节**（64位）。超过此大小的 free 块不会进入 Tcache。
*   **`size_t tcache_count;`**
    *   **解析**：**每个 Tcache Bin 存放块的数量限制**。默认是 **7**。如果某个 size 的 Tcache 已经有 7 个块了，再 free 的块就会进入 Fastbin 或 Unsorted Bin。
*   **`size_t tcache_unsorted_limit;`**
    *   **解析**：当从 Unsorted Bin 批量取块填补 Tcache 时的数量限制。防止单次分配在整理链表上耗时过长。

## main_arena 配置

```c
/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped malloc_state, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that malloc_state
   is initialized to all zeroes (as is true of C statics).  */

static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};
```

main_arena 存在于 libc.so 的数据段，地址是固定的；而 Thread Arena 是动态 mmap 出来的，它是唯一一个在 main() 函数执行前就已经存在的分配区，且它是整个分配区循环链表的头结点。

## mp_ 配置

```c
/* There is only one instance of the malloc parameters.  */

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```

如果说 main_arena 是堆管理的“执行者”，那么 mp_ 就是“策略制定者”。它定义了分配器在全局范围内如何与操作系统交互。

**1. 堆扩展与收缩策略**
*   **`.top_pad = DEFAULT_TOP_PAD`**
    *   **默认值**：通常为 0。
    *   **作用**：当 malloc 通过 sbrk 增加堆空间时，额外申请的“填充”大小。虽然默认为 0，但在实际运行中，分配器可能会为了减少系统调用次数而申请比需求更多的空间。
*   **`.trim_threshold = DEFAULT_TRIM_THRESHOLD`**
    *   **默认值**：128 KB。
    *   **作用**：收缩阈值。当 top chunk的空闲空间超过这个值时，free 会自动调用 sbrk(-size) 将内存归还给内核。
*   **`.mmap_threshold = DEFAULT_MMAP_THRESHOLD`**
    *   **默认值**：128 KB。
    *   **作用**：**核心决策点**。如果用户申请的内存大于此值，free 将放弃从堆分配，转而使用 mmap 直接向内核申请一块独立的匿名映射区域。
    *   **动态特性**：在现代 glibc 中，如果没有手动设置此值，它会根据已释放块的大小**动态增长**，以减少频繁 mmap/munmap 带来的性能抖动。

**2. Mmap 限制**
*   **`.n_mmaps_max = DEFAULT_MMAP_MAX`**
    *   **默认值**：通常是 65536。
    *   **作用**：限制进程同时拥有的 mmap 分配块的总数。这是为了防止大量零碎的 mmap 耗尽操作系统的虚拟内存区域资源。

**3. Arena 创建逻辑**
*   **`.arena_test = NARENAS_FROM_NCORES (1)`**
*   **宏定义解析**：`#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))`
    *   **32位系统 (long=4)**：每个核心对应 2 个 Arena。
    *   **64位系统 (long=8)**：每个核心对应 8 个 Arena。
    *   **逻辑说明**：这里初始化传入参数为 1。意味着在单核配置参考下，64位系统默认“预设”了 8 个 Arena 的探测阈值。
    *   **设计目的**：这是为了在性能（减少锁竞争）和内存（ Arena 结构体本身占空间）之间取得平衡。64位系统内存大，所以允许创建更多的 Arena（最高可达 8 * 核心数 ）。

**4. Tcache (Thread Local Cache) 配置**
这是 glibc 2.26+ 性能大幅提升的关键，它在 malloc_state 之外为每个线程提供了一层极速缓存。

*   **`.tcache_count = TCACHE_FILL_COUNT`**
    *   **默认值**：**7**。
    *   **作用**：每个 Tcache bin 最多存放多少个空闲块。如果一个线程连续释放 10 个 0x20 的块，前 7 个进 Tcache，后 3 个才会进全局的 Fastbin。
*   **`.tcache_bins = TCACHE_MAX_BINS`**
    *   **默认值**：**64**。
    *   **作用**：Tcache 覆盖的大小范围数量。
*   **`.tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1)`**
    *   **默认值**：通常是 **1032 字节** (64位系统)。
    *   **作用**：Tcache 管理的最大块尺寸。在这个尺寸以下的内存申请，都会优先检查线程本地缓存，**不需要加锁**，速度极快。
*   **`.tcache_unsorted_limit = 0`**
    *   **作用**：限制从 `unsorted bin` 搬运块到 Tcache 的数量。设置为 `0` 表示**不限制**，即尽可能填满 Tcache 桶。

---

# __libc_malloc 源码分析

## __libc_malloc 源码

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");

  if (!__malloc_initialized)
    ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```

## Tcache 相关

### 调用 checked_request2size

```c
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
```

checked_request2size 负责检查 bytes 是否会导致溢出，并根据申请的 bytes 计算实际应分配的内存大小，用 tbytes 记录，这块内存大小即 chunk 的实际大小

request2size 宏中 SIZE_SZ 为 size_t 类型的大小， MALLOC_ALIGN_MASK 为 MALLOC_ALIGNMENT - 1 ，其中 MALLOC_ALIGNMENT 是内存对齐的字节数， MINSIZE 为堆分配的最小字节数

64 位下， SIZE_SZ 为 8 ， MALLOC_ALIGNMENT 为 16 ， MALLOC_ALIGN_MASK 为 0b1111 ， MINSIZE 为 32
32 位下， SIZE_SZ 为 4 ， MALLOC_ALIGNMENT 为 8 ， MALLOC_ALIGN_MASK 为 0b111 ， MINSIZE 为 16

64 位 下 request2size 满足 0x8 舍 0x9 入： 0x28 -> 0x30 , 0x29 -> 0x40 ，其结果是对齐 16 位的

```c
/* pad request bytes into a usable size -- internal version */
/* Note: This must be a macro that evaluates to a compile time constant
   if passed a literal constant.  */
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* Check if REQ overflows when padded and aligned and if the resulting value
   is less than PTRDIFF_T.  Returns TRUE and the requested size or MINSIZE in
   case the value is less than MINSIZE on SZ or false if any of the previous
   check fail.  */
static inline bool
checked_request2size (size_t req, size_t *sz) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))
    return false;

  /* When using tagged memory, we cannot share the end of the user
     block with the header for the next chunk, so ensure that we
     allocate blocks that are rounded up to the granule size.  Take
     care not to overflow from close to MAX_SIZE_T to a small
     number.  Ideally, this would be part of request2size(), but that
     must be a macro that produces a compile time constant if passed
     a constant literal.  */
  if (__glibc_unlikely (mtag_enabled))
    {
      /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
      asm ("");

      req = (req + (__MTAG_GRANULE_SIZE - 1)) &
	    ~(size_t)(__MTAG_GRANULE_SIZE - 1);
    }

  *sz = request2size (req);
  return true;
}
```

### 调用 csize2tidx

```c
  size_t tc_idx = csize2tidx (tbytes);
```

回到 __libc_malloc ，csize2tidx 负责将分配的字节数 nb 线性映射为对应 num_slots 和 entries 的下标 tc_idx，即 0x20 -> 0 , 0x30 -> 1 ... 0x410 -> 63

```c
/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
```

```c
/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
```

### 初始化 Tcache

```c
  MAYBE_INIT_TCACHE ();
```

#### tcache_init 源码

```c
# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();
```

```c
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
```

tcache_init 展示了 malloc 是如何“自举”的。为了实现无锁的 Tcache 分配，它必须先通过有锁的 _int_malloc 分配出 Tcache 结构。这意味着每个线程的第一次 malloc 总是比较慢的，因为要进 tcache_init 走加锁路径

### 分配 Tcache

```c
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
```

当 tc_idx 未超界且 tcache 中存在 free chunk 时使用 tcache_get (tc_idx) 获取一个 chunk 并将该 chunk 标记为 usable

#### mp_ 结构体
```c
/* There is only one instance of the malloc parameters.  */

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```

```c
mp_.tcache_count = TCACHE_FILL_COUNT = 7
mp_.tcache_bins = TCACHE_MAX_BINS = 64
mp_.tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1) = 0x408
```

由此可知，tc_idx 上限为 63，仅 0x20 , 0x30 ... 0x410 大小的 chunk 会被 Tcache 管辖

#### Tcache 结构体

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

/* Process-wide key to try and catch a double-free in the same thread.  */
static uintptr_t tcache_key;
```

tcache 是单向链表， LIFO

tcache_entry 结构体起始于 chunk + 0x10 字节处，这正是原本返回给用户的指针地址
next 字段 占用了原本 fd 的位置
key 字段 占用了原本 bk 的位置

counts 用于统计每个类别的 BIN 中有多少 free chunk ， entries 是属于该 BIN 的 free chunk 的链表头

tcache_perthread_struct 本身也是堆内存。如果你在 GDB 中查看一个线程，你会发现它的 tcache 指针通常指向该线程申请的第一个大块内存

tcache_key 和 tcache_entry 中的 key 针对 Double Free 进行防护，暂略

```
[ 线程 A 的 TLS 区域 ]
          |
          +-- tcache 指针 ----+
                              |
[ 堆内存 (Heap / Arena) ] <---+
      |                       |
      +--> [ tcache_perthread_struct ] (管理结构)
                |
                +-- entries[0] --> [ 空闲块 1 ] --> [ 空闲块 2 ]
                |
                +-- entries[1] --> [ 空闲块 A ] --> [ 空闲块 B ]
```

#### tcache_get 源码

```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

#### PROTECT_PTR 宏

```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

tcache_get 获取 `tcache->entries[tc_idx]` 中存放的指针，并让 `tcache->entries[tc_idx]->next` 解密后取代 `tcache->entries[tc_idx]` ，然后减少 BIN 的计数，并将取出的 tcache_entry 的 key 标记清空

可以注意到，`tcache->entries[tc_idx]` 存的指针并没有被加密，而 tcache_entry 的 next 指针均会被加密，加密方式为指针与右移 12 位的指针在堆上的地址进行异或

#### tag_new_usable 源码

```c
/* If memory tagging is enabled the layout changes to accommodate the granule
   size, this is wasteful for small allocations so not done by default.
   Both the chunk header and user data has to be granule aligned.  */
_Static_assert (__MTAG_GRANULE_SIZE <= CHUNK_HDR_SZ,
		"memory tagging is not supported with large granule.");

static __always_inline void *
tag_new_usable (void *ptr)
{
  if (__glibc_unlikely (mtag_enabled) && ptr)
    {
      mchunkptr cp = mem2chunk(ptr);
      ptr = __libc_mtag_tag_region (__libc_mtag_new_tag (ptr), memsize (cp));
    }
  return ptr;
}
```

```c
/* Convert a user mem pointer to a chunk address and extract the right tag.  */
#define mem2chunk(mem) ((mchunkptr)tag_at (((char*)(mem) - CHUNK_HDR_SZ)))
```

```c
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
```

```c
/* This is the size of the real usable data in the chunk.  Not valid for
   dumped heap chunks.  */
#define memsize(p)                                                    \
  (__MTAG_GRANULE_SIZE > SIZE_SZ && __glibc_unlikely (mtag_enabled) ? \
    chunksize (p) - CHUNK_HDR_SZ :                                    \
    chunksize (p) - CHUNK_HDR_SZ + (chunk_is_mmapped (p) ? 0 : SIZE_SZ))
```

mem2chunk 将原本指向 chunk 数据区的指针转换至 chunk header 区域

```c
ptr = __libc_mtag_tag_region (__libc_mtag_new_tag (ptr), memsize (cp));
```

主要用于对新分配的内存进行标签初始化

## 有锁分配相关

```c
  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
```

arena 相关暂略，剩下的部分交给了 _int_malloc

---

# _int_malloc 源码分析

## _int_malloc 源码

```c
/*
   ------------------------------ malloc ------------------------------
 */

static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size returns false for request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }

  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }

          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      if (return_cached)
	{
	  return tcache_get (tc_idx);
	}
#endif

      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin)
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd))
                victim = victim->fd;

              remainder_size = size - nb;
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */

      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }

          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}
```

## 前置处理

```c
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size returns false for request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }
```

nb 为实际应分配的内存大小， sysmalloc 部分暂略

## fastbin 相关

```c
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }
```

fastbin 是单向链表， LIFO

### REMOVE_FB 宏

```c
#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\
```

宏参数含义
- fb: 指向 fastbin 链表头的指针（即 `&main_arena.fastbinsY[i]` ）。
- victim: 输出参数，成功时指向被取出的内存块。
- pp: 临时变量，最初存放旧的链表头，成功后作为新链表头。

无锁原子操作 (CAS) 是该宏最核心的部分。为了避免在分配内存时频繁加锁带来的性能损耗，glibc 使用了 catomic_compare_and_exchange_val_acq：
- 语义：这是一个 CAS （ Compare-And-Swap ）操作。它会检查 *fb （当前的 fastbin 链表头）是否仍然等于 victim。
- 如果相等：说明没有其他线程修改链表头，它会将 *fb 更新为 pp（即 victim->fd ），成功弹出 victim 。
- 如果不相等：说明在执行逻辑期间，有其他线程抢先分配或插入了块， CAS 失败。此时 pp 会被更新为当前的 *fb （新的链表头），循环再次尝试，直到成功。

过程要求 pp 的地址对齐 16 位

### 获取 index

```c
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;
```

追溯得到 get_max_fast () 返回 DEFAULT_MXFAST ，为 `64 * SIZE_SZ / 4` ，即 0x80 字节

首先判断应分配内存大小 nb 是否在 fastbin 的管辖范围内，然后根据 nb 的大小计算在 fastbin 中的 index 

fb 为对应 fastbin 的头指针

```c
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

由此， 0x20 -> 0 , 0x30 -> 1 ... 0x80 -> 7

### 取出 chunk 并检验

```c
      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
```

要求 victim 的地址对齐 16 位

SINGLE_THREAD_P 宏判断当前进程是否只有一个线程，若是，则直接更新 fb 为 next ，否则用 REMOVE_FB 宏更新，并维护 fb , pp , victim 的正确性

victim_idx 为被取出 chunk 的 size 字段对应的 fastbin index

比对 victim_idx 和 idx ，要求同一个 size 字段与 fastbin 应该存放的大小相符

check_remalloced_chunk 正常情况下为空，不用管

```c
/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)
```

chunksize 会去除标志位

### 向 Tcache 中转移 fastbin

```c
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
```

过程要求 tc_victim 的地址对齐 16 位

### 分配成功

```c
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
```

## smallbin 相关

```c
  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

smallbin 是双向循环链表， FIFO

### 索引

```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);
```

```c
/*
   Indexing

    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:

    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left

    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.

    The bins top out around 1MB because we expect to service large
    requests via mmap.

    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > CHUNK_HDR_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
```

```c
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))
```

根据应分配的 chunk 大小计算 smallbin 的索引，并注意到从 smallbin_idx 到 bins 的索引还有换算

0x20 -> 2 -> 2 , 0x30 -> 3 -> 4 ... 0x400 -> 40 -> 78 

然后取出对应 bin 的链表头

### 脱链

```c
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
```

`last (bin)` 即 bin->bk

`if ((victim = last (bin)) != bin)` 判断条件：如果 `victim == bin` ，说明链表为空（只有一个头节点），代码将跳过此段

`if (__glibc_unlikely (bck->fd != victim))` 要求在双向链表中，victim 的前驱节点的后继指针``victim->bk->fd` 必须指向 victim 自己，若满足要求，则设置与它物理相邻下一个高地址的 chunk 的 prev_inuse 位为 1 并脱链

注意到，我们要取出的 victim 为 bin->bk ，事实上， bin 本身是一个哨兵，不代表任何 chunk

```c
#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)
```

该宏设置与它物理相邻下一个高地址的 chunk 的 prev_inuse 位为 1

### 向 Tcache 中转移 smallbin

```c
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
```

由于重新取出 tcache 时不会操作 prev_inuse ，所以这里会提前处理

### 分配成功

```c
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

## largebin 相关

```c
  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }
```

largebin 是双向循环且沿 fb 时 size 单调递减的链表，在同一 Size 组内部表现为 FIFO

### largebin_index 宏分析

```c
// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))
```

这个宏是 `ptmalloc` 用于将内存块的大小（size）映射到对应的 **Large Bin 索引** 的核心逻辑。

它的设计思路非常巧妙，采用的是**分段线性映射**（Piecewise Linear Mapping）。简单来说：**随着内存块越来越大，Bin 所覆盖的范围也越来越广，但分辨率（精确度）越来越低。**

以下是该映射逻辑的深度拆解：

**1. 核心设计原则：对数级增长**
Small Bins 是等差数列（每 16 字节一个 Bin），而 Large Bins 是分组的。为了平衡查找效率和空间碎片，`ptmalloc` 将 Large Bins 分成了 **6 个组（Intervals）**，每组的步长（Step）呈指数级增长。

**2. 六个组的详细映射分析**

我们将 `sz >> n` 理解为按 $2^n$ 的步长进行划分：

| 组别 | 大小范围 (64位系统) | 步长 (Step) | 索引计算公式 | 对应 Bin 数量 |
| :--- | :--- | :--- | :--- | :--- |
| **第 1 组** | 1024B ~ 3072B | **64 B** (`>>6`) | $48 + (sz >> 6)$ | 32 个 (Bin 64-95) |
| **第 2 组** | 3072B ~ 10KB | **512 B** (`>>9`) | $91 + (sz >> 9)$ | 16 个 (Bin 96-111) |
| **第 3 组** | 10KB ~ 40KB | **4KB** (`>>12`) | $110 + (sz >> 12)$ | 8 个 (Bin 112-119) |
| **第 4 组** | 40KB ~ 128KB | **32KB** (`>>15`) | $119 + (sz >> 15)$ | 4 个 (Bin 120-123) |
| **第 5 组** | 128KB ~ 512KB | **256KB** (`>>18`) | $124 + (sz >> 18)$ | 2 个 (Bin 124-125) |
| **第 6 组** | > 512KB | **无** | **固定为 126** | 1 个 (Bin 126) |

`if (atomic_load_relaxed (&av->have_fastchunks))` 检查 fastbin 中是否有空闲块，若有，则进入 malloc_consolidate

### Largebin 结构

我们可以将 Largebin 的结构总结为一种 **“双层嵌套式跳跃循环双向链表”** 。

它不仅管理着大量的堆块，还通过精妙的索引机制保证了在处理不同大小堆块时的搜索效率。以下是 Largebin 结构的完整解构：

---

#### 1. 核心分层设计 (The Dual-Layer System)

Largebin 的最独特之处在于它同时维护了两套逻辑链表，这两套链表物理上共存于同一组 Chunk 之中：

##### 第一层：主链表 (The Main `fd`/`bk` Loop)
*   **成员**：包含该 Bin 范围内**所有**被释放的 Chunk。
*   **排序**：按 **Size 从大到小** 严格排序。
*   **哨兵参与**：main_arena 中的 Bin 头部（哨兵）参与此链表。
    *   `bin->fd` 指向该 Bin 中**最大**的 Chunk。
    *   `bin->bk` 指向该 Bin 中**最小**的 Chunk。
*   **作用**：维护所有可用堆块的物理地址索引，是 unlink 操作的基础。

##### 第二层：快车道 (The `nextsize` Index Loop)
*   **成员**：仅包含每个 Size 组中的**第一个 Chunk（即“组长”）**。
*   **排序**：同样按 Size 递减排序。
*   **哨兵避让**：哨兵不具备 nextsize 指针，因此**不参与**此链表。
*   **闭环方式**：最小组长的 fd_nextsize 直接指向最大组长，形成自闭环。
*   **作用**：实现“跳表”机制，搜索时直接跳过成百上千个相同大小的堆块。

---

#### 2. “组长-跟随者”模型 (Leader-Follower Model)

这是 Largebin 维持秩序的核心逻辑：

*   **组长 (Leader)**：
    *   身份标识：`p->fd_nextsize != NULL`。
    *   物理位置：它是该 Size 组中**离哨兵最近**（在 fd 方向最靠前）的块。
    *   责任：持有 `nextsize` 指针，负责与其他尺寸的组长通信。
*   **跟随者 (Follower)**：
    *   身份标识：`p->fd_nextsize == NULL`。
    *   物理位置：紧跟在组长之后。
    *   责任：只通过 fd/bk 维持在主链表中的位置。被 unlink 时操作极快，不影响索引结构。

---

#### 3. 关键字段及其指向总结

| 字段 | 含义 | 指向特性 |
| :--- | :--- | :--- |
| **mchunk_prev_size** | 物理相邻低地址块大小 | 永远指向物理上的“前一家”，用于 free 时的向后合并。 |
| **fd** | 逻辑后继 | 指向主链表中的下一个 Chunk（Size $\le$ 当前块）。 |
| **bk** | 逻辑前驱 | 指向主链表中的上一个 Chunk（Size $\ge$ 当前块）。 |
| **fd_nextsize** | 跨组后继 | **仅组长持有**。指向下一个**更小尺寸**的组长。最小组长指回最大组长。 |
| **bk_nextsize** | 跨组前驱 | **仅组长持有**。指向上一个**更大尺寸**的组长。最大组长指回最小组长。 |

---

#### 4. 操作行为准则 (Operational Dynamics)

1.  **搜索 (Search)**：malloc 申请内存时，先看 `bin->fd` 的 fd_nextsize。如果请求 4500B，它会通过 nextsize 链表跳过整个 6000B 组和 5000B 组，直接定位到第一个可能满足条件的组。
2.  **插入 (Insertion)**：新块从 Unsorted Bin 归位时，如果发现已有同尺寸组，总是插入到**组长之后**作为跟随者。这样无需改动 nextsize 链表，效率为 $O(1)$。
3.  **脱链 (Unlink)**：
    *   如果是**跟随者**：直接修改 fd/bk 闭合。
    *   如果是**组长**：将 fd_nextsize/bk_nextsize 的所有权移交给它的 fd（二把手），然后二把手晋升为新组长。

## malloc_consolidate 源码分析

```c
/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.
*/

static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");

	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}

	check_inuse_chunk(av, p);
	nextp = REVEAL_PTR (p->fd);

	/* Slightly streamlined version of consolidation code in free() */
	size = chunksize (p);
	nextchunk = chunk_at_offset(p, size);
	nextsize = chunksize(nextchunk);

	if (!prev_inuse(p)) {
	  prevsize = prev_size (p);
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  unlink_chunk (av, p);
	}

	if (nextchunk != av->top) {
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {
	    size += nextsize;
	    unlink_chunk (av, nextchunk);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0);

	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;

	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	else {
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0);

    }
  } while (fb++ != maxfb);
}
```

malloc_consolidate 是 free() 函数的一个专门化版本，用于清理（拆解）存放在 fastbins 中的堆块。free() 函数本身不能用于此目的，主要原因之一是它可能会将堆块重新放回 fastbins 中。因此，我们需要使用一套基于相同逻辑但略有不同的变体代码。

#### 前置处理

```c
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);
```

`atomic_store_relaxed (&av->have_fastchunks, false);` 将“是否存在 Fastbin 块”的标志位重置为 false

然后获取 unsorted_bin 链表头

```c
/*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M)          (bin_at (M, 1))
```

翻译：
所有由内存块分割产生的余块（remainders），以及所有归还的内存块（被释放的 chunks），都会首先被放入“unsorted” bin。在将它们移入常规 bin（small/large bins）之前，malloc 会给予它们仅有一次被直接使用的机会。
因此，从本质上讲，unsorted_chunks 列表充当了一个队列的角色：内存块在执行 free（以及 malloc_consolidate）时被放入该队列，并在执行 malloc 时被移出该队列（移出后要么直接用于满足当前的分配请求，要么被分拣到对应的常规 bin 中）。
此外，对于 unsorted 块，NON_MAIN_ARENA 标志位永远不会被设置，因此在进行内存块大小的比较时，无需考虑该标志位的影响。

unsortedbin 在 bins 中的索引为 0

### 取出 fastbin 链表

```c
  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");

	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}

	check_inuse_chunk(av, p);
	nextp = REVEAL_PTR (p->fd);
```

`p = atomic_exchange_acq (fb, NULL);` 以原子方式，一次性拎走（提取）整条 Fastbin 链表，并同时将该 Bin 清空。

要求 p 的地址对齐 16 位

然后获取 p 中 size 的对应 index ，要求与 fastbin 索引一致

然后解码 p->fd 赋予 nextp 

### 合并操作

```c
	/* Slightly streamlined version of consolidation code in free() */
	size = chunksize (p);
	nextchunk = chunk_at_offset(p, size);
	nextsize = chunksize(nextchunk);

	if (!prev_inuse(p)) {
	  prevsize = prev_size (p);
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  unlink_chunk (av, p);
	}
```

当物理上前一个 chunk 是 free 状态时，若 chunksize(p) != prevsize 检查通过，即当前 chunk 的 prevsize 与前一个 chunk 的 size 匹配，则触发 unlink_chunk

### unlink_chunk 源码分析

```c
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
}
```

#### 校验与脱链

```c
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
```

`chunksize (p) != prev_size (next_chunk (p))` 检测要求被取出块 p 的 size 与其物理相邻的高地址块的 prevsize 匹配

`__builtin_expect (fd->bk != p || bk->fd != p, 0)` 检测要求当前块前驱的后继和后继的前驱均为自己

校验完成，脱链

#### Nextsize 链表维护

```c
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
```

`!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL` 检测要求块 p 的 size 不属于 smallbin 的管辖范围，即 p 属于 largebin 的管辖范围，且 p->fd_nextsize 不为空，即 p 是该 Size 组的组长，即距离哨兵最近的那个。这确保 p 一定在 largebin 或 unsortedbin 中

而接下来的 double-link 检测则排除了 p 位于 unsortedbin 的情况，由此 p 一定在 largebin 中

 fd_nextsize 和 bk_nextsize 参与构建了一个按 Size 排序的沿 bk 单调递增的不包含哨兵的双向循环链表，该链表是 largebin 链表的一个子链表，而这段代码正是维护了这个链表

 ### 合并策略

 ```c
 	if (nextchunk != av->top) {
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {
	    size += nextsize;
	    unlink_chunk (av, nextchunk);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0);

	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;

	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	else {
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0);

    }
  } while (fb++ != maxfb);
 ```

 set_head 和 set_foot 分别设置 size 和对应的 prev_size

 综合该段代码和前面的分析， malloc_consolidate 的作用是：

1.  **合并策略**：
    *   **向后看（低地址）**：在进入这段代码前， p 已经和低地址块合并过了。
    *   **向前看（高地址）**：这段代码检查 nextchunk 是否空闲，能合就合。
2.  **结果去向**：
    *   如果碰到了 **Top Chunk** $\rightarrow$ 合并进去，壮大荒野。
    *   如果没碰到 **Top Chunk** $\rightarrow$ 塞进 **Unsorted Bin**，等下次 malloc 时再重新分配或归类。

### 总结

malloc_consolidate 会将 fastbin 中的块合并后，放入以下两个地方之一：

1.  **Unsorted Bin**（绝大多数情况）
2.  **Top Chunk**（如果合并后的块在物理地址上紧邻 Top Chunk）

#### 详细的过程拆解

你可以把 malloc_consolidate 想象成一个“粉碎机”+“焊机”，它处理 fastbin 块的逻辑如下：

##### 第一步：取样与合并
它会遍历所有的 fastbins，把里面的每一个 chunk 拿出来。拿出来之后，它**不会**立即给这个 chunk 找新家，而是先看它的“邻居”：
*   **向后合并（低地址）**：检查物理相邻的低地址块是否空闲。如果是，利用 prev_size 找到它，把它从它所在的 bin 中 unlink 掉，和当前块合并。
*   **向前合并（高地址）**：检查物理相邻的高地址块是否空闲。如果是，把它从所在的 bin 中 unlink 掉，和当前块合并。

##### 第二步：根据位置决定去向
经过第一步，这个 chunk 可能已经从小碎片变成了大块。现在它面临两个选择：

1.  **并入 Top Chunk**：
    *   如果合并后的块，其高地址方向紧挨着 **Top Chunk**。
    *   **结果**：它不会进入任何 bin，而是直接被“吸入” Top Chunk，增加 Top Chunk 的大小，并更新 `av->top` 的指针。

2.  **放入 Unsorted Bin**：
    *   如果合并后的块，其高地址方向**不是** Top Chunk。
    *   **结果**：它会被放入 **Unsorted Bin**。
    *   **注意**：此时它**还没有**进入 Smallbin 或 Largebin。只有在接下来的 _int_malloc 循环遍历 Unsorted Bin 时，才会根据它的最终大小，把它分拣（Place）到对应的 Smallbin 或 Largebin 中。

#### 效应

在 malloc_consolidate 运行结束后：
*   **Fastbins**：变为空（Empty）。
*   **Unsorted Bin**：多了很多合并后的中大型堆块。
*   **Top Chunk**：可能变得更大。
*   **Small/Large Bins**：**此时没有任何变化**（它们的变化发生在随后的 _int_malloc 流程中）。

## unsortedbin 相关处理

### 转移准备

```c
  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif
```

翻译：
处理最近释放的（recently freed）或切分剩余的（remaindered）堆块。只有在以下两种情况时才直接取用堆块：一是大小完全匹配（exact fit）；二是对于小尺寸（small request）申请，该块是最近一次非精确匹配后切剩下的余料。
将其余遍历到的堆块放入对应的 bin 中（即 Smallbin 或 Largebin）。请注意，这一步是整个分配程序中唯一一处将堆块放入（归类到）对应 bin 的地方。
此处需要一个外层循环，是因为直到分配过程接近尾声时，我们才可能意识到应当进行内存合并（consolidation），此时必须执行合并并重试分配。这种情况最多只会发生一次，且仅当在不合并就必须扩展内存（即调用 sbrk/mmap）来满足“小尺寸”申请时才会触发。

同时准备把 unsortedbin 转移至 tcache

### 各种检查

```c
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

外层 for 循环作用如翻译所言：
> 此处需要一个外层循环，是因为直到分配过程接近尾声时，我们才可能意识到应当进行内存合并（consolidation），此时必须执行合并并重试分配。这种情况最多只会发生一次，且仅当在不合并就必须扩展内存（即调用 sbrk/mmap）来满足“小尺寸”申请时才会触发。

内层 while 对 unsorted_chunks 作遍历，直到 unsortedbin 为空

此处针对 unsorted_chunks 的检查有：
1. 当前 Chunk 尺寸合法性检查
2. 下一个 Chunk 尺寸合法性检查
3. size 与 prev_size 的一致性检查
4. double linked 检查
5. PREV_INUSE (P) 标志位一致性检查

### 切割余料

```c
          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```

#### 翻译：
如果是小尺寸请求（small request），且 Unsorted Bin 中只有一个堆块，则尝试使用‘最近一次切分剩下的余料’（last remainder）。这有助于提升连续小尺寸请求序列的局部性（locality）。这是对‘最佳适配’（best-fit）原则的唯一例外，且仅在没有找到大小完全精确匹配（exact fit）的小堆块时才会生效

#### 触发条件：
为了不让这种例外导致严重的内存碎片，它必须满足：
是 Small Request：申请的大小在 Smallbin 范围内。
Unsorted Bin 只有这一个块：如果还有别的块，说明还没分拣完，必须按规矩办事。
没有 Exact Fit：如果你申请 0x20，而 Unsorted Bin 里正好有一个 0x20 的块，那肯定优先用那个，不需要切余料。

### 脱链，以及大小匹配情形

```c
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }
```

把 chunk 从 unsortedbin 脱链

若发现该 chunk 符合申请的 size ，考虑：
1. 可以放进 tcache 则放进 tcache ，然后 continue 回去读下一个 chunk
2. 否则直接返回该 chunk

### 放进 smallbin

```c
          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
```

该 chunk 不符合申请的 size ，但符合 in_smallbin_range ，那就先放进 smallbin

### 放进 largebin

```c
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
```

否则考虑将 chunk 放入 largebin 中，并维护单调性，过程中有 double linked 审查

注意，这时候只更新了 fwd 和 bck ，还没插入 victim

### while 循环收尾

```c
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      if (return_cached)
	{
	  return tcache_get (tc_idx);
	}
#endif
```

正式插入 victim ，并在 binmap 中打上标记

如果 return_cached 满足且 tcache 对从 unsortedbin 的转移做了限制且目前已超出限制，则返回之前记录的转移至 tcache 中的 chunk

设定内层 while 循环的最大迭代次数

内层 while 循环边界在此

如果我们找到的所有小块（small chunks）最终都存入了 tcache，那么现在就返回其中一个。

#### Binmap 相关

```c
/*
   Binmap

    To help compensate for the large number of bins, a one-level index
    structure is used for bin-by-bin searching.  `binmap' is a
    bitvector recording whether bins are definitely empty so they can
    be skipped over during during traversals.  The bits are NOT always
    cleared as soon as bins are empty, but instead only
    when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))
```

Binmap 是 malloc 中的一个**极其高效的性能优化机制**。

简单来说，它的作用是：**在“箱子索引图”（binmap）中打个勾，标记第 i 号 bin 现在已经不是空的了。**

在 malloc 的分配过程中，当 Unsorted Bin 里的块被分拣完后，系统需要去 Smallbins 或 Largebins 里寻找合适的块。
*   **笨办法**：从目标的 bin 开始，一个一个往后检查每个 bin 是否为空。如果连续 50 个 bin 都是空的，这种遍历会非常浪费 CPU 时间。
*   **聪明办法（glibc 的做法）**：维护一个**位图（Bitmap）**。每个 bit 代表一个 bin：
    *   如果 bit 是 1，表示这个 bin **可能**有空闲块。
    *   如果 bit 是 0，表示这个 bin **一定**是空的。
*   **加速效果**：通过检查位图（利用 CPU 的位运算指令，如 ffs 或 bsf），malloc 可以瞬间跳过几十个空的 bin，直接定位到最近的非空 bin

## 扫描 largebin

```c
      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin)
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd))
                victim = victim->fd;

              remainder_size = size - nb;
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```

如果是大尺寸请求，按排序顺序遍历当前 bin 中的堆块，以寻找满足要求的最小堆块（即最佳适配）。为此利用跳表（skip list，指 nextsize 指针链表）来实现。

如果 bin 为空，或者最大的堆块也太小（无法满足请求尺寸），则跳过扫描。

避免移除同尺寸堆块中的第一个条目（组长），这样就不必重新调整跳表（nextsize 链表）的指针指向。

如果剩余部分的大小不足以作为一个独立堆块，则将整个堆块全部分配给用户）。

如果剩余部分足够大，可以作为一个独立的堆块存在。

我们不能假设 Unsorted 链表是空的，因此必须在后续执行完整的插入操作（将切分出的余料放入 Unsorted Bin），同时记得清空 nextsize 指针。

## 检索 binmap

```c
      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */

      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }

          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```

### 初始化

```c
      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */

      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
```

通过扫描 bins 来寻找堆块，从紧邻的下一个较大的 bin 开始。这种搜索严格遵循“最佳适配”（best-fit）原则；也就是说，会选择满足要求的最小堆块（如果大小相同，则大致选择最久未使用的那个）。

位图（bitmap）机制避免了检查大多数（为空的）bin 块的需要。在程序刚启动（预热阶段）、尚无堆块被释放回 bin 时，跳过所有 bin 的这种特定情况，其执行速度比看起来还要快。

找到对应的 binmap ，初始化相关要素

进入内层 for 循环

### 定位 bin

```c
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }
```

如果当前 block 中没有多余的标记，那么去找后边的 block，找不到就用 top_chunk

推进到对应比特位已置位的那个 bin。此时一定能找到一个。

检查该 bin。它很可能不是空的。

如果是误报（即 bin 实际上是空的），则清除该位图比特位，然后再次迭代检索 binmap。

### 取出这个 chunk

```c
          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```

使 chunk 脱链

如果剩余部分的大小不足以作为一个独立堆块，则将整个堆块全部分配给用户）。

如果剩余部分足够大，可以作为一个独立的堆块存在。

我们不能假设 Unsorted 链表是空的，因此必须在后续执行完整的插入操作（将切分出的余料放入 Unsorted Bin），同时记得清空 nextsize 指针。

然后返回这个 chunk

## 使用 top_chunk

```c
    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}
```

如果（Top Chunk）足够大，就切分出紧邻内存末尾的那个堆块（由 av->top 持有）。注意，这符合“最佳适配”（best-fit）搜索规则。实际上，av->top 被视为比任何其他可用堆块都大（因此匹配度较低），因为它可以在必要时进行扩展（直至系统限制）。

我们要求 av->top 在初始化后始终存在（即大小大于 MINSIZE），因此如果它将被当前请求耗尽，则必须对其进行补充。（确保其存在的主要原因是，在 sysmalloc 中，我们可能需要 MINSIZE 的空间来放置“栅栏桩”。）

`if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))` 如果切割后的剩余空间大于最小应分配内存，则直接切割分配

`else if (atomic_load_relaxed (&av->have_fastchunks))` 否则考虑从 fastbin 中拿出可能存在块合并，放入 unsortedbin 或 top_chunk 中，同时更新 idx ，以外层 for 为基准再迭代一轮

如果还是没有空间，那就只好用 sysmalloc 了

外层 for 循环边界在此

_int_malloc 函数边界在此，分析完成

## small_request 处理总结

在 glibc 2.35 中，处理一个 small_request（通常指 64 位系统下，不含头部大小在 1016 字节以下的请求，即最终 size <= 1024 字节）是一个多层级的搜索过程。

为了提升性能，glibc 采用了从“最快且私有”到“最慢且全局”的搜索策略。以下是 small_request 在 _int_malloc 中可能经过的一切流程：

### 1. 尺寸计算与对齐 (checked_request2size)
首先，malloc 会将你申请的 bytes 加上 CHUNK_HDR_SZ（16 字节），并向上对齐到 16 字节。
*   例如 malloc(0x20) -> 实际 size 为 0x30。
*   如果符合 smallbin 范围，进入后续逻辑。

### 2. 第一关：Tcache (Thread Local Cache) —— 最快路径
这是 glibc 2.26 之后引入的线程私有缓存，**不需要加锁**。
*   **搜索**：根据计算出的 size 找到对应的 tcache 索引。
*   **命中**：如果 `tcache->entries[idx]` 有块，直接弹出一个返回。
*   **安全检查**：2.35 版本会检查 tcache 的 key 字段（防止 double free）以及指针的对齐性。

### 3. 第二关：Fastbins —— 快速路径
如果 Tcache 没命中，且 size 属于 Fastbin 范围（通常 <= 0x80）：
*   **加锁**：获取当前 Arena 的互斥锁。
*   **搜索**：在 `av->fastbinsY` 中查找。
*   **命中**：
    1.  从栈顶取出一个块。
    2.  **Tcache 填充**：这是 2.35 的特性。如果发现了命中，它会尝试把该 fastbin 链表里剩下的块全都“挪”到当前线程的 Tcache 中，直到 Tcache 填满（默认 7 个）。
    3.  返回该块。

### 4. 第三关：Smallbins —— 确定性路径
如果不是 Fastbin 尺寸，或者 Fastbin 为空：
*   **搜索**：直接在 `av->bins` 的对应 Smallbin 索引处查看。
*   **命中**：
    1.  从链表末尾（BK 方向）取出一个块（FIFO 机制）。
    2.  **安全检查**：执行 Safe Unlink 检查（即 `victim->bk->fd == victim`）。
    3.  **标志位**：设置该块的 PREV_INUSE。
    4.  **Tcache 填充**：同样，如果对应 Smallbin 还有剩余块，会批量存入 Tcache，然后返回其中一个。

### 5. 第四关：Unsorted Bin 遍历 —— 整理与中转
如果 Smallbins 也没命中，说明目前没有大小正好合适的空闲块。此时 malloc 必须开始“干苦活”：遍历 Unsorted Bin。

在此过程中，malloc 会处理之前被 free 掉但还没归类的块：
*   **Last Remainder 优化**：如果申请的是 small request，且 Unsorted Bin 中只有一个块且它是 last_remainder，且大小足够切分，则直接切分：
    *   切出一块给用户，剩下的作为新的 last_remainder 留在 Unsorted Bin 中。
*   **分拣与精确匹配**：如果上述不成立，开始循环遍历 Unsorted Bin：
    1.  把块从 Unsorted Bin 移除（执行前面讨论过的各种安全检查）。
    2.  如果大小**完全一致**（Exact Fit）：停止分拣，直接给用户（或者放入 Tcache 备用）。
    3.  如果大小不一致：根据大小把这个块扔进对应的 **Smallbin** 或 **Largebin**，并更新 binmap。

### 6. 第五关：Binmap 搜索 —— 寻找大块切分
如果 Unsorted Bin 遍历完了还没找到正好相等的块（且 Tcache 也没填满）：
*   **搜索比目标大的 Bin**：通过 binmap 快速定位比当前 size 大的最小非空 Smallbin 或 Largebin。
*   **切分（Splitting）**：
    1.  找到一个比需求大的块。
    2.  切开它：前半部分给用户，后半部分作为 **Remainder** 放入 Unsorted Bin。

### 7. 第六关：Top Chunk —— 最后的荒野
如果连大块都没有了：
*   **检查 Top Chunk**：看 `av->top` 的剩余空间是否足够。
*   **切分**：如果够，从 Top Chunk 切出一块。Top Chunk 的起始地址增加，剩余 size 减少。

### 8. 第七关：绝望的挣扎 —— Consolidation
如果 Top Chunk 也不够大：
*   **检查 Fastbins**：看 fastbins 里是不是还有没合并的碎片。
*   **调用 malloc_consolidate**：清空 fastbins，把它们合并后扔进 Unsorted Bin。
*   **重试**：回到步骤 5（Unsorted Bin 遍历），再给一次机会。这种情况在整个分配逻辑中**只允许发生一次**。

### 9. 第八关：向操作系统要钱 —— sysmalloc
如果上述所有招数都用完了，还没内存：
*   **sbrk / mmap**：调用内核接口增加堆空间（brk 扩展）或申请新的内存映射（mmap）。
*   如果系统也没内存了，返回 NULL 并设置 errno 为 ENOMEM。

### 总结：
1.  **Tcache 优先级极高**：几乎所有的命中（Fastbin, Smallbin, Unsorted Bin Exact Fit）都会伴随一个“填满 Tcache”的动作。
2.  **安全检查增强**：2.35 引入了更严格的指针保护和双向链表校验。
3.  **局部性优先**：通过 Last Remainder 和 Tcache 填充极力保证连续申请的小块在物理地址上靠近，提升缓存命中率。

这个流程体现了从**私有缓存 -> 快速链表 -> 整理分拣 -> 物理切分 -> 系统申请**的严密逻辑

## large_request 处理总结

在 glibc 2.35 中，large_request 指的是申请的内存大小（计算对齐和头部后）超过了 Smallbin 的上限（通常在 64 位系统上 **> 1024 字节**）。

处理 Large Request 的过程比 Small Request 更加复杂，因为它涉及 **Best-fit（最佳适配）** 算法和特殊的 **Nextsize 双向跳表** 结构。以下是 large_request 在 _int_malloc 中可能经过的一切流程：

### 1. 尺寸计算与 Tcache 检查（入口点）
首先，malloc 会计算最终的 nb（request size + 16 字节对齐）。
*   **Tcache 命中（即便很大）**：
    *   注意：Tcache 默认的最大尺寸是 **1032 字节**（TCACHE_MAX_SZ）。
    *   如果你的请求正好在这个边界内（例如请求 1000 字节，nb 为 1024），它仍会先查 Tcache。如果命中，直接返回。
*   **进入主分配器**：
    *   如果超过 Tcache 范围，或者 Tcache 未命中，则获取 Arena 锁并进入 _int_malloc。

### 2. 预处理：Fastbin 合并（特殊触发）
对于 Large Request，glibc 有一个“激进合并”策略：
*   **触发条件**：如果申请的尺寸非常大（大于 FASTBIN_CONSOLIDATION_THRESHOLD，通常 64KB），或者在后续流程中发现 Bins 和 Top Chunk 都不够用。
*   **动作**：调用 malloc_consolidate。这会把 Fastbins 中的所有零碎小块合并并扔进 Unsorted Bin。
*   **目的**：大内存申请往往意味着内存压力大，提前整理碎片可以防止因碎片化导致的分配失败。

### 3. 跨过 Fastbin 和 Smallbin 路径
由于 nb 属于 Large 范围：
*   代码会直接跳过 Fastbin 查找逻辑。
*   代码会直接跳过 Smallbin 查找逻辑（`in_smallbin_range(nb)` 为假）。

### 4. 遍历 Unsorted Bin（整理与分拣）
这是 Large Request 分配中最关键的一步。malloc 并不直接去 Largebins 找，而是先清理 Unsorted Bin。

*   **遍历链表**：从 Unsorted Bin 的末尾（bk）向前遍历。
*   **Exact Fit（精确匹配）**：
    *   如果遍历到一个块，大小正好等于 nb。
    *   **动作**：将此块直接返回。
    *   *注意*：Large Request **不使用** Small Request 那种“Last Remainder”切分优化。
*   **分拣入 Bin**：
    *   如果大小不匹配，将该块从 Unsorted Bin 移除，放入它该去的 Smallbin 或 Largebin。
    *   **Largebin 特有维护**：如果要放入 Largebin，系统必须维护 fd_nextsize 链表，确保 Largebin 内部依然是**按 Size 降序排序**的。
    *   **限制**：为了防止遍历时间过长，glibc 通常限制每次遍历 Unsorted Bin 的块数（最多 10000 块，防止拒绝服务攻击）。

### 5. 扫描目标的 Largebin（寻找最佳适配）
如果在 Unsorted Bin 中没找到精确匹配，现在才开始正式搜索对应的 Largebin。

*   **确定索引**：计算 nb 属于哪一个 Largebin（Largebin 是按范围划分的，例如 1024-1088 字节是一个 bin）。
*   **利用 Nextsize 链表（跳表）搜索**：
    1.  找到该 Largebin 的第一个块（最大块 `victim = first(bin)`）。
    2.  如果最大块都比 nb 小，直接跳过此 bin。
    3.  如果够大，利用 **bk_nextsize** 从“大”往“小”跳。
    4.  **寻找最小的符合条件的块**：跳到第一个 **Size < nb** 的组，然后回退一步，找到那个 **Size >= nb 的最小组**。
*   **组内优化**：
    *   找到合适的 Size 组后，为了避免修改 fd_nextsize 链表（减少脱链成本），malloc 会优先取该组的**第二个块**（Follower），而不是组长（Leader）。
*   **切分（Splitting）**：
    *   找到 victim 后，计算 `remainder_size = size - nb`。
    *   **余料处理**：如果剩下的部分 $>=$ MINSIZE（32字节），将余料切下来，放入 **Unsorted Bin**。
    *   **耗尽处理**：如果余料太小，直接把整个块给用户。

### 6. 搜索更高级别的 Bins
如果在目标 Largebin 里没找到：
*   **Binmap 加速**：检查 binmap，寻找比当前 bin 索引更大的、非空的 bin。
*   **Best-fit 逻辑**：一旦找到一个非空的更大的 bin，逻辑同上：从该 bin 里的最小块开始切分（因为大 bin 里的任何块都一定满足申请要求）。

### 7. 切分 Top Chunk
如果所有的 Bins（Unsorted, Small, Large）都翻遍了还没找到：
*   **检查 Top Chunk**：看 `av->top` 的空间是否足够。
*   **动作**：如果足够，切出 nb，更新 Top Chunk 的位置。

### 8. 终极尝试：Sysmalloc
如果 Top Chunk 也不够了：
*   **第二次合并**：如果之前没做过 malloc_consolidate，现在会做一次，然后重试一遍搜索逻辑。
*   **系统申请**：调用 sysmalloc。
    *   **mmap 路径**：如果申请的尺寸非常巨大（超过 mmap_threshold，默认 128KB），sysmalloc 会直接调用 mmap 向内核要一块独立的匿名映射内存，不从堆里出。
    *   **brk 路径**：否则，调用 brk 扩展堆顶。

### 9. 核心防御检查（安全）
在 Large Request 流程中，glibc 2.35 强化的检查包括：
1.  **Unsorted Bin 损坏检查**：检查双向链表的 fd/bk 是否被非法篡改。
2.  **Largebin 下一跳校验**：在利用 fd_nextsize 遍历时，校验 `p->fd_nextsize->bk_nextsize == p`。
3.  **Size vs Prev_size 校验**：在切分或脱链时，验证相邻块的元数据一致性。

### 总结
对于一个 Large Request，它的旅程通常是：
1. **跳过小快灵的 Fast/Small bin 逻辑。**
2. **在 Unsorted Bin 里被迫充当“分拣工”，把路上的块都归位。**
3. **在 Largebin 里通过 nextsize 指针进行跳跃式搜索，寻找那个既能装下它、又最不浪费空间的“最佳座位”。**
4. **如果实在没位子，就去切 Top Chunk 或找操作系统“买地” (mmap)。**

---

# __libc_free 源码分析

## __libc_free 源码

```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  if (mem == 0)                              /* free(0) has no effect */
    return;

  /* Quickly check that the freed pointer matches the tag for the memory.
     This gives a useful double-free detection.  */
  if (__glibc_unlikely (mtag_enabled))
    *(volatile char *)mem;

  int err = errno;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
    }
  else
    {
      MAYBE_INIT_TCACHE ();

      /* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));

      ar_ptr = arena_for_chunk (p);
      _int_free (ar_ptr, p, 0);
    }

  __set_errno (err);
}
libc_hidden_def (__libc_free)
```

## chunk_is_mmapped 处理

### 动态阈值调整 (Dynamic Threshold Adjustment)
这是 glibc 的一种优化机制。为了提高性能，它会根据程序的分配习惯动态调整 mmap_threshold。

```c
if (!mp_.no_dyn_threshold
    && chunksize_nomask (p) > mp_.mmap_threshold
    && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
```
*   **`!mp_.no_dyn_threshold`**：检查是否启用了动态阈值调整（默认开启，除非用户通过 mallopt 禁用了它）。
*   **`chunksize_nomask (p) > mp_.mmap_threshold`**：如果当前释放的 chunk 大小比当前的 mmap_threshold 还要大。
*   **`chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX`**：当前大小没有超过硬上限（通常是 32MB 或 64MB）。

**调整逻辑：**
```c
mp_.mmap_threshold = chunksize (p);
mp_.trim_threshold = 2 * mp_.mmap_threshold;
LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2, mp_.mmap_threshold, mp_.trim_threshold);
```
*   **更新阈值**：如果程序频繁释放很大的内存块，glibc 会调高 mmap_threshold。这意味着之后申请类似大小的内存时，可能会改用 brk（堆）而不是 mmap。
*   **目的**：减少 mmap/munmap 系统调用的次数。mmap 涉及页表操作和内核交互，开销比移动堆指针（sbrk）大。
*   **联动调整**：同时调高 trim_threshold（堆收缩阈值），确保堆不会过于频繁地缩减。

### 2. 执行内存归还
```c
munmap_chunk (p);
```
这是真正的释放操作。对于 heap chunk，free 后会将其放入各种 bins（如 fastbins, smallbins）中以便复用，**不会立即还给系统**。

但对于 **mmap chunk**：
*   它直接调用 munmap 系统调用。
*   内核会将这块虚拟内存从进程的地址空间中移除。
*   **物理内存释放**：对应的物理页帧会被内核回收。
*   **特点**：
    *   **彻底释放**：内存立刻还给 OS。
    *   **无碎片**：因为它不在堆里，不会造成堆碎片。
    *   **性能开销**：由于涉及系统调用和页表刷新（TLB shootdown），在大规模频繁操作时比堆操作慢。

## munmap_chunk 源码

```c
static void
munmap_chunk (mchunkptr p)
{
  size_t pagesize = GLRO (dl_pagesize);
  INTERNAL_SIZE_T size = chunksize (p);

  assert (chunk_is_mmapped (p));

  uintptr_t mem = (uintptr_t) chunk2mem (p);
  uintptr_t block = (uintptr_t) p - prev_size (p);
  size_t total_size = prev_size (p) + size;
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
      || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
    malloc_printerr ("munmap_chunk(): invalid pointer");

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}
```

这段代码来自于 `glibc` 的 `malloc.c`，位于 `munmap_chunk` 函数中。该函数专门负责销毁那些通过 `mmap` 分配的内存块。

### 1. 注释翻译

> “不幸的是，我们在这里必须手动完成编译器应该做的工作。通常情况下，我们会分别测试 `BLOCK`（内存块地址）和 `TOTAL-SIZE`（总大小）是否符合页大小（对齐要求）。但 GCC（至少目前）还无法识别这种优化可能性，因此我们在进行位运算测试之前，先将这两个值合并为一个。”

### 2. 代码逻辑分析

这段代码的核心任务是：**在调用内核接口释放内存前，进行严格的安全检查和统计数据更新。**

#### A. 核心安全检查：对齐校验

```c
if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
    || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
  malloc_printerr ("munmap_chunk(): invalid pointer");
```

1.  **为什么需要页对齐？**
    `mmap` 和 `munmap` 是系统调用，它们操作的单位是**页**（Page，通常是 4KB）。内核要求传递给 `munmap` 的起始地址和长度必须是 `pagesize` 的整数倍。如果不对齐，内核会返回错误，甚至可能导致程序非预期行为。

2.  **注释中的优化手段 (`block | total_size`)：**
    *   `pagesize - 1` 生成一个掩码（例如页大小是 4096 (0x1000)，掩码就是 0xFFF）。
    *   按位与 `& (pagesize - 1)` 如果不等于 0，说明低位有值，即没有对齐。
    *   **手动优化点**：开发者没有写成 `(block & mask) || (total_size & mask)`，而是写成 `(block | total_size) & mask`。通过一次“按位或”运算，只要其中任何一个值没对齐，最终结果都会反映出来。这样减少了一次分支判断。

3.  **`mem & (pagesize - 1)` 检查：**
    *   mem 通常是用户可见的内存地址。
    *   这里进一步确认该指针在页内的偏移是否符合预期（通常 mmap 返回的地址页内偏移应该是固定的）。如果地址完全乱了，直接触发 malloc_printerr 报错。

#### B. 统计数据更新

```c
atomic_decrement (&mp_.n_mmaps);
atomic_add (&mp_.mmapped_mem, -total_size);
```

当一个 mmap 块被释放时，glibc 需要更新全局的内存状态：
*   **`mp_.n_mmaps`**：记录当前进程通过 mmap 分配的内存块**数量**。这里执行原子减 1。
*   **`mp_.mmapped_mem`**：记录当前进程通过 mmap 分配的内存**总字节数**。这里减去当前块的大小。
*   **atomic_ 前缀**：保证了多线程环境下这些全局变量更新的原子性，防止出现竞态条件导致统计数据错误。

## 非 mmap 处理

如果 p 不是 mmap 分配的，则通过 _int_free 处理

# _int_free 源码分析

## _int_free 源码

```c
/*
   ------------------------------ free ------------------------------
 */

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (atomic_load_relaxed (&av->have_fastchunks))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (!have_lock)
      __libc_lock_unlock (av->mutex);
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```

## 前置处理

```c
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);
```

检查 p + size 是否超过了地址空间的上限（即是否发生了整数溢出），以及地址对齐

进行尺寸堆块检查和尺寸对齐检查

## 放入 Tcache

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

有 double free 检测，若发现 `e->key == tcache_key` ，则扫描整条链表，若出现 tcache 数量过大、地址不对齐或回环，则报错，否则当作偶然处理

正常放入 Tcache

## 放入 fastbin

```c
  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }
```

### 检验

```c
    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }
```

检验相邻下一个 chunk 的 size 的合规性

### 插入 fastbin

```c
    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }
```

有简单的防 double free 逻辑，只校验 fastbin 的 top

## 放入 bin

### 前置处理

```c
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);
```

上锁，校验

禁止 free 掉 top chunk

禁止下一个 chunk 地址越界

禁止下一个 chunk 的 prev_inuse 位为 0 （防止 double free）

检验相邻下一个 chunk 的 size 的合规性

### 合并 chunk

```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
```

向后合并时要求 prevsize 与 size 匹配

放入 unsortedbin 时校验了双向链表的完整性

### 并入 top chunk

```c
    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```

### 归还空间

```c
    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (atomic_load_relaxed (&av->have_fastchunks))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }
```

如果 free 掉的空间比较大，那么在把 top chunk 的多余空间归还给操作系统前，先 malloc_consolidate 处理下 fastbin 中的碎片化内存

### 结算

```c
    if (!have_lock)
      __libc_lock_unlock (av->mutex);
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```