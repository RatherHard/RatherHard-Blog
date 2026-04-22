---
title: Piggyback 输入流复用技巧
date: 2026-03-10 13:34:00
tags: 
    - Piggyback
    - pwn
categories: pwn 技巧
---
## 示例

```c
void free_trial() {
    char input_buf[32];
    char crushed[32];

    for (int i=0; i<16; i++) {
        printf("Enter a string to crush:\n");
        fgets(input_buf, sizeof(input_buf), stdin);


        printf("Enter crush rate:\n");
        int rate;
        scanf("%d", &rate);

        if (rate < 1) {
            printf("Invalid crush rate, using default of 1.\n");
            rate = 1;
        }

        printf("Enter output length:\n");
        int output_len;
        scanf("%d", &output_len);

        if (output_len > sizeof(crushed)) {
            printf("Output length too large, using max size.\n");
            output_len = sizeof(crushed);
        }

        crush_string(input_buf, crushed, rate, output_len);


        printf("Crushed string:\n");
        puts(crushed);
    }
}
```

在本地与这段代码交互时，由于 `scanf("%d", ...);` 有一个机制：遇到非数字自动截断，并将数字后面的部分保留在缓冲区中供下一次输入使用，这样如果直接使用 sendline 发送数据的话， fgets 会被跳过（scanf 不会被跳过，因为 %d 会跳过前导空白字符去读取数字）

为了避免这种情况发生，我们可以在发送 scanf 所需的数字后面直接加上要发送给 fgets 的数据，这样一来可以在依次 sendline 中通过两个读入函数

关于缓冲区的更多知识还有待学习www
