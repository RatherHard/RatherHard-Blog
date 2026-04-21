---
title: glibc-2.31 ret2dlresolve 分析
date: 2026-02-08 01:00:00
tags: 
    - pwn
    - ret2dlresolve
    - glibc
categories: glibc 分析
---
## 重要结构

### link_map

```c
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */

    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;

    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;

    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];

    // 后略
  };
```

- **l_addr (uint64_t)** : ELF 文件中定义的地址与内存中实际地址之间的差值
    > 这就是该模块的【基地址 (Base Address)】
    > 对于开启了 PIE 的程序或 .so 库，这里存的是随机化后的基址
    > 对于未开启 PIE (No-PIE) 的主程序，这里通常是 0
- **l_name** : 找到该对象的绝对文件名
    > 这是一个指针，指向存储库文件路径的字符串（例如 "/lib/x86_64-linux-gnu/libc.so.6"）
    > 对于主程序，这里通常是空字符串
- **l_ld (Elf64_Dyn)** : 该共享对象的动态段（.dynamic section）的地址
    > 指向内存中 .dynamic 段的指针。这个段里存着 DT_STRTAB, DT_SYMTAB 等标签
    > _dl_fixup 实际上并不直接用这个 l_ld，而是用后面定义的 l_info 数组（它是由 l_ld 解析生成的）
- **l_next, l_prev** : 已加载对象的链表
    > 双向链表指针
    > l_next 指向下一个加载的库，l_prev 指向上一个
    > 攻击时通常不需要伪造这两个指针，除非你的攻击链涉及遍历这个链表
- **l_real** : 这是一个通常指向它自己的指针
    > 只有当动态链接器（ld.so）在多个命名空间（namespace）中被使用时，这个指针才会指向不同的副本
- **l_ns (8 bytes)** : 该 link map 所属的命名空间编号
    > Linux 支持多个链接器命名空间（比如 dlmopen 可以加载一个隔离的库）
    > LM_ID_BASE (通常是 0) 表示主程序所在的默认命名空间
- **l_libname** : 指向一个链表，存储了该共享对象的名称（可能有别名，比如 libc.so.6 和 libc-2.31.so）
- **l_info (Elf64_Dyn)** : 指向动态段（dynamic section）条目的指针数组。
    > [0, DT_NUM) 范围内的元素：使用**处理器无关的标签（Tag）**直接作为下标索引。
    > [DT_NUM, ...) 范围内的元素：使用 标签值减去 DT_LOPROC 作为下标索引。
    > [...] 范围内的元素：使用 DT_VERSIONTAGIDX(tagvalue) 计算出的值作为下标索引。
    > ...（后面是关于 Extra, Val, Addr 等特殊标签的索引计算方式）。

### Elf64_Dyn

ELF 64位 动态段条目

```c
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```

- **d_tag (int64_t)** : 这是“类型标签”，用来告诉链接器后面那个 d_un 存的是什么东西
    > DT_NULL (0): 标记动态段的结束
    > DT_STRTAB (5): 字符串表（String Table）的地址
    > DT_SYMTAB (6): 符号表（Symbol Table）的地址
    > DT_JMPREL (23): 重定位表（Relocation Table，即 .rela.plt）的地址
- **d_un.d_val (uint64_t)** : 当标签表示大小或数量时使用（例如 DT_SYMENT 表示符号表每项的大小）
- **d_un.d_ptr (uint64_t)** : 当标签表示地址时使用

### Elf64_Sym

ELF 64位 符号表条目

```c
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```

- **st_name (uint32_t)** : 指向字符串表（String Table, DT_STRTAB）的相对偏移
    > 函数名地址 = DT_STRTAB 基址 + st_name
- **st_info** : 这 1 个字节包含了两个信息
    > 高 4 位 (Bind): 绑定属性（Global, Local, Weak）
    > 低 4 位 (Type): 符号类型（Object, Func, None）
    > 常见值：0x12：即 STB_GLOBAL (1) << 4 | STT_FUNC (2) ，表示这是一个全局函数
- **st_other** : 符号的可见性
    > STV_DEFAULT (0): 默认可见性（通常是公开的，可被外部链接）
    > STV_INTERNAL (1): 处理器特定的隐藏类型（很少用）
    > STV_HIDDEN (2): 符号在模块内可见，外部不可见（即使是全局符号）
    > STV_PROTECTED (3): 符号可见，但不能被抢占（Preempted）
- **st_shndx (uint16_t)** : 该符号定义在哪个节（Section）里，它是一个索引值，指向 Section Header Table
    > 几个特殊的保留索引值:
    > SHN_UNDEF (0): 未定义符号，表示该符号在本模块中被引用，但定义在其他模块（如 libc.so）中
    > SHN_ABS (0xfff1): 绝对符号，该符号的值是绝对地址，不随重定位改变
    > SHN_COMMON (0xfff2): 通用块符号（通常用于未初始化的全局变量）
- **st_value (uint64_t)** : 符号的值（通常是地址）
    > 在可重定位文件 (.o) 中：它是相对于所在节（Section）的偏移量
    > 在可执行文件或共享库 (.so) 中：
    >   如果符号已定义（st_shndx != 0）：它是符号的虚拟地址（Virtual Address）
    >   如果符号未定义（st_shndx == 0）：通常为 0 ，但如果是对齐的 Common 符号，它表示对齐约束
- **st_size (uint64_t)** : 函数或变量的大小

### Elf64_Rela

ELF 64位 重定位条目

```c
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;
```

- **r_offset** : 修正地址，即动态链接器解析出函数的真实地址后，应该把这个地址写到哪里去
    > 指向 GOT 表（Global Offset Table）中的某个条目
- **r_info** : 这是一个复合字段，高 32 位和低 32 位分别代表不同含义
    > r_info = (Symbol Index << 32) + Relocation Type
    > 高 32 位：Symbol Index (符号表索引)
    >   告诉链接器：“去符号表（Symbol Table）的第几个条目找这个函数的信息”
    > 低 32 位：Relocation Type (重定位类型)
    >   告诉链接器如何进行重定位
    >   7 即 R_X86_64_JUMP_SLOT
- **r_addend** : 加数，用于计算最终值的常数偏移
    > 最终值 = Symbol Value + Addend

## _dl_fixup 源码分析

### _dl_fixup 源码

```c
/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */

DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```

### 前置声明

```c
/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */

DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;
```

**翻译：**
这个函数是通过一个特殊的跳板（trampoline）从 PLT（过程链接表）中调用的，时机是每个 PLT 条目第一次被调用的时候。
我们必须按照给定共享对象（shared object）的 PLT 中指定的要求，执行重定位操作（relocation），并将解析出来的函数地址返回给那个跳板。
随后，跳板会重新向该地址发起原始的函数调用。
未来的调用将直接从 PLT 跳转到该函数（而不再经过这里）。

`ElfW(Word)` 为 `uint32_t` 
`PLTREL` 为 `Elf64_Rela`

```c
# define D_PTR(map, i) (map)->i->d_un.d_ptr
```

整理一下：

```c
Elf64_Sym *symtab = l->l_info[DT_SYMTAB]->d_un.d_ptr
char *strtab = l->l_info[DT_STRTAB]->d_un.d_ptr
Elf64_Rela *reloc = l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg
Elf64_Sym *sym = &symtab[(reloc->r_info) >> 32]
Elf64_Sym *refsym = sym
void *rel_addr = l->l_addr + reloc->r_offset
link_map *result
uint64_t value
```

### 版本校验

```c
  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}
```

首先要求 `reloc->r_info` 的低 4 字节为 7 ，不然报错

若 `sym->st_other` 为 0 ，则进入 if 内部

然后是一层检测，决定是否要进行**版本校验（Version Check）**，检查 `l_info[50]` 是否为 NULL ，正常情况下不为 NULL ，执行后面 if 内部代码

但是进入 if 内部后在 64 位下会报错，因为在 `vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff` 的过程中，由于我们一般伪造的 symtab 位于 bss 段，导致在 64 位下 `reloc->r_info` 较大，发生段错误

然后是锁相关操作

### 符号查找

```c
      result = _dl_lookup_symbol_x (strtab + sym->st_name,    /* 参数1: 符号名 */
                              l,                              /* 参数2: 搜索起始 link_map */
                              &sym,                           /* 参数3: 符号结构体指针 (输入/输出) */
                              l->l_scope,                     /* 参数4: 搜索范围 (Scope) */
                              version,                        /* 参数5: 版本信息 */
                              elf_machine_type_class (type),  /* 参数6: 类型分类 */
                              flags,                          /* 参数7: 标志位 */
                              NULL);


      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();
```

进入 _dl_lookup_symbol_x 

出来后是锁操作

### 收尾处理

```c
      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```

**if 分支：**
当前 result 变量包含了定义该符号的对象的基加载地址（或者 link_map 指针），现在加上符号的偏移量
即 `value = result->l_addr + sym->st_value`

**else 分支：**
我们已经找到了符号，模块（因此也包括它的加载地址）也是已知的
即 `value = l->l_addr + sym->st_value`

接下来处理 GNU Indirect Function (IFUNC)

最后把 value 写入相应的 GOT 表条目中

要求 `rel_addr = (void *)(l->l_addr + reloc->r_offset)` 可写

---

## _dl_runtime_resolve 部分分析

```asm
	# Copy args pushed by PLT in register.
	# %rdi: link_map, %rsi: reloc_index
	mov (LOCAL_STORAGE_AREA + 8)(%BASE), %RSI_LP
	mov LOCAL_STORAGE_AREA(%BASE), %RDI_LP
	call _dl_fixup		# Call resolver.
```

`LOCAL_STORAGE_AREA(%BASE)` 为进入 _dl_runtime_resolve 时 rsp 位置上的值，将传入 rdi ，作为 link_map 指针
`(LOCAL_STORAGE_AREA + 8)(%BASE)` 为进入 _dl_runtime_resolve 时 rsp + 8 位置上的值，将传入 rsi ，作为 reloc_arg (uint32_t)

---

## 64 位下利用

为了避免段错误，我们引导函数执行至以下片段

```c
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
```

这要求 `sym->st_other` 不为 0

然后通过 `value = l->l_addr + sym->st_value` 计算出我们希望写入 got 表中的那个地址

我们需要：
- 伪造 `link_map->l_addr` 为 libc 中已解析函数与想要执行的目标函数的偏移值，如 `addr_system - addr_xxx`
- 伪造 `sym->st_value` 为已经解析过的某个函数的 got 表的位置，这需要布置 sym 的位置
- 也就是相当于 `value = l_addr + st_value = addr_system - addr_xxx + real_xxx = real_system`

又
```c
Elf64_Sym *symtab = l->l_info[DT_SYMTAB]->d_un.d_ptr
Elf64_Rela *reloc = l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg
Elf64_Sym *sym = &symtab[(reloc->r_info) >> 32]
```
即
```c
sym = l->l_info[DT_SYMTAB]->d_un.d_ptr + (((l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg)->r_info) >> 32)
```

再放一遍
```c
Elf64_Sym *symtab = l->l_info[DT_SYMTAB]->d_un.d_ptr
char *strtab = l->l_info[DT_STRTAB]->d_un.d_ptr
Elf64_Rela *reloc = l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg
Elf64_Sym *sym = &symtab[(reloc->r_info) >> 32]
Elf64_Sym *refsym = sym
void *rel_addr = l->l_addr + reloc->r_offset
link_map *result
uint64_t value
```

综上，所有需要伪造的数据为：

```c
#stack:
link_map *l -> fake link_map
reloc_arg = 0

#rw:
fake link_map structure:
    l_addr = addr_system - addr_xxx
    l_info[DT_STRTAB (5)]  -> Null fake Elf64_Dyn structure
    l_info[DT_SYMTAB (6)]  -> fake Elf64_Dyn structure to fake Elf64_Sym structure (.got)
    l_info[DT_JMPREL (23)] -> fake Elf64_Dyn structure to fake Elf64_Rela structure
fake Elf64_Dyn structure -> fake Elf64_Sym:
    d_ptr -> fake Elf64_Sym (.got)
fake Elf64_Dyn structure -> fake Elf64_Rela:
    d_ptr -> fake Elf64_Rela
fake Elf64_Rela structure:
    r_offset = rwable_addr - l_addr
    r_info lower 4 bytes = 7
    r_info higher 4 bytes = 0
```

根据偏移对 link_map 进行压缩布局：

```c
0x00--0x08 l_addr = addr_system - addr_xxx
0x08--0x10 d_ptr -> fake Elf64_Sym (.got)
0x10--0x18 d_ptr -> 0x18
0x18--0x20 r_offset = rwable_addr - l_addr
0x18--0x20 r_info = 0x00000007
...
0x38--0x?? l_info
0x68--0x70 l_info[DT_STRTAB (5)]  -> 0x00
0x70--0x78 l_info[DT_SYMTAB (6)]  -> 0x00
...
0xF8--0x100 l_info[DT_JMPREL (23)] -> 0x08
```

stack 布局：

注意 _dl_runtime_resolve 有点像 srop 会还原寄存器

```
0                         高地址
fake_link_map_base_addr
ret2plt0
寄存器操作 rop 链          低地址
```