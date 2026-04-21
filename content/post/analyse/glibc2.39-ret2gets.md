---
title: glibc-2.39 ret2gets 分析
date: 2026-03-01 15:07:00
tags: 
    - pwn
    - ret2gets
    - glibc
categories: glibc 分析
---
## 重要结构

```c
typedef struct { int lock; int cnt; void *owner; } _IO_lock_t;
```

## 源码分析

### gets

```c
char *
_IO_gets (char *buf)
{
  size_t count;
  int ch;
  char *retval;

  _IO_acquire_lock (stdin);
  ch = _IO_getc_unlocked (stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
	 non-blocking mode. The error flag doesn't mean much in this
	 case. We return an error only when there is a new error. */
      int old_error = stdin->_flags & _IO_ERR_SEEN;
      stdin->_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (stdin, buf + 1, INT_MAX, '\n', 0) + 1;
      if (stdin->_flags & _IO_ERR_SEEN)
	{
	  retval = NULL;
	  goto unlock_return;
	}
      else
	stdin->_flags |= old_error;
    }
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (stdin);
  return retval;
}
```

_IO_gets 是 gets 的本体

这里重点关注 _IO_acquire_lock 和 _IO_release_lock

### _IO_acquire_lock 和 _IO_release_lock

```c
#  define _IO_acquire_lock(_fp) \
  do {									      \
    FILE *_IO_acquire_lock_file						      \
	__attribute__((cleanup (_IO_acquire_lock_fct)))			      \
	= (_fp);							      \
    _IO_flockfile (_IO_acquire_lock_file);

# define _IO_release_lock(_fp) ; } while (0)
```

注意 cleanup 属性

### _IO_flockfile 和 _IO_funlockfile

```c
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*(_fp)->_lock)
# define _IO_funlockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_unlock (*(_fp)->_lock)
```

此处 _lock 为 _IO_lock_t 的结构体指针

### _IO_lock_lock 和 _IO_lock_unlock

```c
#define _IO_lock_lock(_name) \
do {									      \
void *__self = THREAD_SELF;						      \
if (SINGLE_THREAD_P && (_name).owner == NULL)			      \
      {									      \
    (_name).lock = LLL_LOCK_INITIALIZER_LOCKED;			      \
    (_name).owner = __self;						      \
      }									      \
else if ((_name).owner != __self)					      \
      {									      \
    lll_lock ((_name).lock, LLL_PRIVATE);				      \
    (_name).owner = __self;						      \
      }									      \
else								      \
      ++(_name).cnt;							      \
  } while (0)

#define _IO_lock_unlock(_name) \
do {									      \
if (SINGLE_THREAD_P && (_name).cnt == 0)				      \
      {									      \
    (_name).owner = NULL;						      \
    (_name).lock = 0;						      \
      }									      \
else if ((_name).cnt == 0)						      \
      {									      \
    (_name).owner = NULL;						      \
    lll_unlock ((_name).lock, LLL_PRIVATE);				      \
      }									      \
else								      \
      --(_name).cnt;							      \
  } while (0)
```

### _IO_acquire_lock_fct

```c
static inline void
__attribute__ ((__always_inline__))
_IO_acquire_lock_fct (FILE **p)
{
  FILE *fp = *p;
  if ((fp->_flags & _IO_USER_LOCK) == 0)
    _IO_funlockfile (fp);
}
```

由于 cleanup 属性， gets 执行完成后会调用这个

### _IO_stdfile_0_lock

```c
static _IO_lock_t _IO_stdfile_##FD##_lock = _IO_lock_initializer;
```

```c
#define _IO_lock_initializer { LLL_LOCK_INITIALIZER, 0, NULL }
```

gets 执行完成后， rdi 为 _IO_stdfile_0_lock 的地址，指向一个 _IO_lock_t 结构体

### THREAD_SELF

```c
#  define THREAD_SELF \
  ({ struct pthread *__self;						      \
     asm ("mov %%fs:%c1,%0" : "=r" (__self)				      \
	  : "i" (offsetof (struct pthread, header.self)));	 	      \
     __self;})
```

极其高效地获取“当前线程”的线程控制块（TCB，即 struct pthread 结构体）的内存基地址

## 利用思路

目标是通过 gets 后 rdi 的残留值传入 puts 以 leak tls

在 _IO_gets 中，获取输入之前会先用 _IO_lock_lock 处理 _IO_stdfile_0_lock ，这使得 `(_name).owner = __self = THREAD_SELF`

所以只要我们能覆盖前 _IO_stdfile_0_lock 的前 8 字节就可以通过 (_name).owner 去 leak tls

但是要注意 _IO_acquire_lock_fct 即 _IO_funlockfile 即 _IO_lock_unlock 会在 gets 结束时执行，这意味着 (_name).cnt 会被减去 1 ，然后若此时 (_name).cnt 为 0 ，那么 (_name).owner 会被清空，无法 leak tls

由于 puts 的输出截断于 \x00 ，而 gets 会将末尾设置为 \x00 ，我们需要利用上面 cnt 被减去 1 的机制绕过输出截断

若构造 `'AAAA\x00\x00\x00'` 的 payload ，由于 cnt 只有不为 0 时才会被减去 1 ，而且 cnt 为 0 owner 会被清空，该构造无效

因此我们考虑分两次布置：第一次布置 `b'A' * 8 + b'\x00' * 6` ，目的是触发 `(_name).owner == NULL` ，第二次布置 `b'B' * 4` 后即可绕过截断

但是在不同 linux 版本的情况下 leak 出的地址与 libc 的偏移会不同，甚至可能 leak 出的是与 ld 相关的部分，这就导致可能需要尝试利用 ld 中的 gadget 再去 leak libc