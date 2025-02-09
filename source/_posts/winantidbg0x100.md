---
layout: post
title:  "WinAntiDbg0x100 (work in progress)"
pin: True
description: Utilizing assembly calls to manipulate a Windows executable
date:   2025-02-08
tags: ["Medium", "Reverse Engineering", "Assembly", "x64dbg"]
category: [CTF,picoCTF]
---
## Challenge Info

This challenge will introduce you to 'Anti-Debugging.' Malware developers don't like it when you attempt to debug their executable files because debugging these files reveals many of their secrets! That's why, they include a lot of code logic specifically designed to interfere with your debugging process. Now that you've understood the context, go ahead and debug this Windows executable! This challenge binary file is a Windows console application and you can start with running it using `cmd` on Windows. Challenge can be downloaded [here](https://artifacts.picoctf.net/c_titan/55/WinAntiDbg0x100.zip). Unzip the archive with the password `picoctf`

---
## Poking around
First, I tried to run the executable, but had no success:

```
C:\Users\riv\Desktop\pico\WinAntiDbg0x100>WinAntiDbg0x100.exe


        _            _____ _______ ______
       (_)          / ____|__   __|  ____|
  _ __  _  ___ ___ | |       | |  | |__
 | '_ \| |/ __/ _ \| |       | |  |  __|
 | |_) | | (_| (_) | |____   | |  | |
 | .__/|_|\___\___/ \_____|  |_|  |_|
 | |
 |_|
  Welcome to the Anti-Debug challenge!
### To start the challenge, you'll need to first launch this program using a debugger!
```
When opening the program using x32dbg, it's typical to be inefficient in analyzing the executable. So, consider opening it up in Ghidra. When dealing with a challenge like this, it's encouraged to try to use Ghidra's "search" feature, which lets the user search through program text (Ctrl+Shift+E). If you search for the word "flag" you'll find the following:

![search](/images/winantidbg0x100/search.png)

Now, double click on any of the queries to jump to it. 

![ghidrafun](/images/winantidbg0x100/ghidrafun.png)

On the left, you'll notice function calls, conditional jumps, and debugger detection mechanisms.

---

## Understanding the program
Let's understand `FUN_00401580`, I've left the code below for your convenience:

```c
undefined4 FUN_00401580(void)

{
  uint uVar1;
  int iVar2;
  BOOL BVar3;
  LPWSTR lpOutputString;
  undefined in_stack_fffffff4;
  
  uVar1 = FUN_00401130();
  if ((uVar1 & 0xff) == 0) {
    FUN_00401060(PTR_s________________________(_)_/_____00405020,in_stack_fffffff4);
    FUN_00401060("### To start the challenge, you\'ll need to first launch this program using a debu gger!\n"
                 ,in_stack_fffffff4);
  }
  else {
    OutputDebugStringW(L"\n");
    OutputDebugStringW(L"\n");
    FUN_004011b0();
    iVar2 = FUN_00401200();
    if (iVar2 == 0) {
      OutputDebugStringW(L"### Error reading the \'config.bin\' file... Challenge aborted.\n");
    }
    else {
      OutputDebugStringW(
                        L"### Level 1: Why did the clever programmer become a gardener? Because they  discovered their talent for growing a \'patch\' of roses!\n"
                        );
      FUN_00401440(7);
      BVar3 = IsDebuggerPresent();
      if (BVar3 == 0) {
        FUN_00401440(0xb);
        FUN_00401530(DAT_00405404);
        lpOutputString = FUN_004013b0(DAT_00405408);
        if (lpOutputString == (LPWSTR)0x0) {
          OutputDebugStringW(L"### Something went wrong...\n");
        }
        else {
          OutputDebugStringW(L"### Good job! Here\'s your flag:\n");
          OutputDebugStringW(L"### ~~~ ");
          OutputDebugStringW(lpOutputString);
          OutputDebugStringW(L"\n");
          OutputDebugStringW(
                            L"### (Note: The flag could become corrupted if the process state is tam pered with in any way.)\n\n"
                            );
          free(lpOutputString);
        }
      }
      else {
        OutputDebugStringW(
                          L"### Oops! The debugger was detected. Try to bypass this check to get the  flag!\n"
                          );
      }
    }
    free(DAT_00405410);
  }
  OutputDebugStringW(L"\n");
  OutputDebugStringW(L"\n");
  return 0;
}

```
### Function Signature, Local Variables:
`undefined4 FUN_00401580(void)`

- `undefined4` is probably an alias used in the disassembled code, it sually corresponds to a 4-byte value (usually a `uint32_t` or `int` in C). It just means the return type is 4 bytes. 
- `FUN_00401580` is the name of the function.
- `void` the function doesn't take arguments.

So, to summarize, the function returns a 4-byte value (probably an int), and it doesn't take parameters.

### Local Variables:
```
uint uVar1;
int iVar2;
BOOL BVar3;
LPWSTR lpOutputString;
```

- `uint uVar1`: A 4-byte unsigned int (probably used to store flags or other values)
- `int iVar2`: A standard 4-byte integer, which will likely be used for status checks or results of function calls.
- `bool bVar3`: A boolean variable, used for `TRUE` or `FALSE` values. 
- `LPWSTR lpOutputString`: A pointer to a wide character string (might be used to store the flag)
- `undefined in_stack_fffffff4`: This is a variable marked as undefined, we have no way of knowing what it is. It's not referenced in any meaningful way in this snippet, maybe it's a parameter from the stack.

### 1st Bitwise AND Operation:

```
uVar1 = FUN_00401130();
if ((uVar1 & 0xff) == 0) {
    FUN_00401060(PTR_s________________________(_)_/_____00405020, in_stack_fffffff4);
    FUN_00401060("### To start the challenge, you\'ll need to first launch this program using a debu gger!\n", in_stack_fffffff4);
}
```
- `uVar1 = FUN_00401130();`: `FUN_00401130()` is called, and the program stores its return value in the variable `uVar1`. The return value is maybe our flag?
- `(uVar1 & 0xff)`: Bitwise AND operation with `0xff` (this is `11111111` in binary). 
  - The operation takes the least significant byte (the lowest 8 bits) of `uVar1`. Basically checking the value of the last byte of `uVar1`

> If you're unfamiliar with bitwise AND operations, check [this](https://stackoverflow.com/questions/3427585/understanding-the-bitwise-and-operator) out
- `(uVar1 & 0xff) == 0`: Checks if the least significant byte of uVar1 is zero. If `True`, the program continues with the code inside of the `if` block (we don't fail and continue).
  - Essentially, we need to pass this as `True` to trick the program into thinking we are running without a debugger.


# work in progress
