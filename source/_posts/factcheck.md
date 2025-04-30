---
layout: post
title:  "FactCheck"
pinned: True
description: "Reversing decompiled C++ code to extract a flag by tracing string manipulation logic"
date:   2025-04-23
tags: ["Medium", "Reverse Engineering", "Assembly", "Ghidra", "C++", "Python"]
category: [CTF,picoCTF2024]
---
## Challenge Info
This binary is putting together some important piece of information... Can you uncover that information?
Examine this [file](https://artifacts.picoctf.net/c_titan/188/bin). Do you understand its inner workings?

## Basic forensics & info
```
[marcial@arch ~/desktop/cyber/pico/FactCheck]$ file bin                
bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ed9d01aa375e575eb2cd16506aa83d6951841f87, for GNU/Linux 3.2.0, not stripped
```
Basic info, we see we're dealing with a non-stripped, 64-bit, linux executable.

Running `strings` and grepping for "flag" yields something interesting:

```
[marcial@arch ~/desktop/cyber/pico/FactCheck]$ strings bin | grep "pico"
picoCTF{wELF_d0N3_mate_
[marcial@arch ~/desktop/cyber/pico/FactCheck]$
```
Just like that, it looks like we have at least half our flag.

## Examining in Ghidra

After running "analyze all" in Ghidra, my go-to is to check the symbol tree, specifically for functions. I noticed a `FUN_00101020` function, which looked interesting, but didn't yield anything. After just clicking and glancing at all of them, the one that caught my eye was `main`:

```c++
/* WARNING: Removing unreachable block (ram,0x0010170c) */

undefined8 main(void)

{
  char cVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  allocator local_249;
  string local_248 [32];
  string local_228 [32];
  string local_208 [32];
  string local_1e8 [32];
  string local_1c8 [32];
  string local_1a8 [32];
  string local_188 [32];
  string local_168 [32];
  string local_148 [32];
  string local_128 [32];
  string local_108 [32];
  string local_e8 [32];
  string local_c8 [32];
  string local_a8 [32];
  string local_88 [32];
  string local_68 [32];
  string local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  std::allocator<char>::allocator();
                      /* try { // try from 001012cf to 001012d3 has its CatchHandler @ 00101975 */
  std::string::string(local_248,"picoCTF{wELF_d0N3_mate_",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 0010130a to 0010130e has its CatchHandler @ 00101996 */
  std::string::string(local_228,"7",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101345 to 00101349 has its CatchHandler @ 001019b1 */
  std::string::string(local_208,"5",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101380 to 00101384 has its CatchHandler @ 001019cc */
  std::string::string(local_1e8,"4",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 001013bb to 001013bf has its CatchHandler @ 001019e7 */
  std::string::string(local_1c8,"3",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 001013f6 to 001013fa has its CatchHandler @ 00101a02 */
  std::string::string(local_1a8,"6",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101431 to 00101435 has its CatchHandler @ 00101a1d */
  std::string::string(local_188,"9",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 0010146c to 00101470 has its CatchHandler @ 00101a38 */
  std::string::string(local_168,"a",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 001014a7 to 001014ab has its CatchHandler @ 00101a53 */
  std::string::string(local_148,"e",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 001014e2 to 001014e6 has its CatchHandler @ 00101a6e */
  std::string::string(local_128,"3",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 0010151d to 00101521 has its CatchHandler @ 00101a89 */
  std::string::string(local_108,"d",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101558 to 0010155c has its CatchHandler @ 00101aa4 */
  std::string::string(local_e8,"b",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101593 to 00101597 has its CatchHandler @ 00101abf */
  std::string::string(local_c8,"1",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 001015ce to 001015d2 has its CatchHandler @ 00101ada */
  std::string::string(local_a8,"6",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101606 to 0010160a has its CatchHandler @ 00101af5 */
  std::string::string(local_88,"e",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 0010163e to 00101642 has its CatchHandler @ 00101b0d */
  std::string::string(local_68,"c",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
  std::allocator<char>::allocator();
                      /* try { // try from 00101676 to 0010167a has its CatchHandler @ 00101b25 */
  std::string::string(local_48,"8",&local_249);
  std::allocator<char>::~allocator((allocator<char> *)&local_249);
                      /* try { // try from 00101699 to 0010185f has its CatchHandler @ 00101b3d */
  pcVar2 = (char *)std::string::operator[]((ulong)local_208);
  if (*pcVar2 < 'B') {
    std::string::operator+=(local_248,local_c8);
  }
  pcVar2 = (char *)std::string::operator[]((ulong)local_a8);
  if (*pcVar2 != 'A') {
    std::string::operator+=(local_248,local_68);
  }
  pcVar2 = (char *)std::string::operator[]((ulong)local_1c8);
  cVar1 = *pcVar2;
  pcVar2 = (char *)std::string::operator[]((ulong)local_148);
  if ((int)cVar1 - (int)*pcVar2 == 3) {
    std::string::operator+=(local_248,local_1c8);
  }
  std::string::operator+=(local_248,local_1e8);
  std::string::operator+=(local_248,local_188);
  pcVar2 = (char *)std::string::operator[]((ulong)local_168);
  if (*pcVar2 == 'G') {
    std::string::operator+=(local_248,local_168);
  }
  std::string::operator+=(local_248,local_1a8);
  std::string::operator+=(local_248,local_88);
  std::string::operator+=(local_248,local_228);
  std::string::operator+=(local_248,local_128);
  std::string::operator+=(local_248,'}');
  std::string::~string(local_48);
  std::string::~string(local_68);
  std::string::~string(local_88);
  std::string::~string(local_a8);
  std::string::~string(local_c8);
  std::string::~string(local_e8);
  std::string::~string(local_108);
  std::string::~string(local_128);
  std::string::~string(local_148);
  std::string::~string(local_168);
  std::string::~string(local_188);
  std::string::~string(local_1a8);
  std::string::~string(local_1c8);
  std::string::~string(local_1e8);
  std::string::~string(local_208);
  std::string::~string(local_228);
  std::string::~string(local_248);
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                      /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

- Starts by declaring a number of C++ string variables (`local_248`, `local_228`, etc.)
- Initializes the first string (`local_248)` with the partial flag we saw earlier: `"picoCTF{wELF_d0N3_mate_}"`)
- Additionally, there's a series of unconditionaly statements that append certain characters to the flag, but based on specific conditions, which I'll cover more in the next section


## Flag construction logic & solution
The flag's construction logic:

- If the value at index 0 of `local_208` ("5") is less than 'B', append `local_c8` ("1") - this condition is true
- If the value at index 0 of `local_a8` ("6") is not 'A', append `local_68` ("c") - this condition is true
- If the difference between the value at index 0 of `local_1c8` ("3") and `local_148` ("e") equals 3, append `local_1c8` ("3") - this needs calculation
- Unconditionally append `local_1e8` ("4")
- Unconditionally append `local_188` ("9")
- If the value at index 0 of `local_168` ("a") is 'G', append local_168 ("a") - this condition is false
- Unconditionally append local_1a8 ("6")
- Unconditionally append local_88 ("e")
- Unconditionally append local_228 ("7")
- Unconditionally append local_128 ("3")
- Unconditionally append "}" to close the flag

The solve script I used: 
```py
#!/usr/bin/env python3

def solve_picoctf():
    flag = "picoCTF{wELF_d0N3_mate_"

    # Define all the character variables as they appeared in Ghidra
    char_map = {
        'local_248': "picoCTF{wELF_d0N3_mate_",
        'local_228': "7",
        'local_208': "5",
        'local_1e8': "4",
        'local_1c8': "3",
        'local_1a8': "6",
        'local_188': "9",
        'local_168': "a",
        'local_148': "e",
        'local_128': "3",
        'local_108': "d",
        'local_e8': "b",
        'local_c8': "1",
        'local_a8': "6",
        'local_88': "e",
        'local_68': "c",
        'local_48': "8"
    }

    # Follow the logic in the decompiled code

    # If the value at index 0 of local_208 ("5") is less than 'B'
    if char_map['local_208'][0] < 'B':
        flag += char_map['local_c8']  # Append "1"

    # If the value at index 0 of local_a8 ("6") is not 'A'
    if char_map['local_a8'][0] != 'A':
        flag += char_map['local_68']  # Append "c"

    # If the difference between the value at index 0 of local_1c8 ("3") and local_148 ("e") equals 3
    # ASCII '3' is 51, ASCII 'e' is 101, difference = -50, not 3, so this condition is false
    if ord(char_map['local_1c8'][0]) - ord(char_map['local_148'][0]) == 3:
        flag += char_map['local_1c8']  # This won't execute

    # Unconditionally append these characters
    flag += char_map['local_1e8']
    flag += char_map['local_188']

    # If the value at index 0 of local_168 ("a") is 'G'
    if char_map['local_168'][0] == 'G':
        flag += char_map['local_168']  # This won't execute

    # Unconditionally append these characters
    flag += char_map['local_1a8']
    flag += char_map['local_88']
    flag += char_map['local_228']
    flag += char_map['local_128']

    flag += "}"

    return flag

if __name__ == "__main__":
    print(solve_picoctf())
```

flag: `picoCTF{wELF_d0N3_mate_1c496e73}`
