---
layout: post
title:  "WinAntiDbg0x200"
pinned: False
description: "Further bypassing anti-debugging checks by editing register values"
date:   2025-04-03
tags: ["Medium", "Reverse Engineering", "Assembly", "x64dbg", "C"]
category: [CTF,picoCTF2024]
---
## Challenge Info
If you have solved WinAntiDbg0x100, you'll discover something new in this one. Debug the executable and find the flag! This challenge executable is a Windows console application, and you can start by running it using Command Prompt on Windows. This executable requires admin privileges. You might want to start Command Prompt or your debugger using the 'Run as administrator' option. Challenge can be downloaded [here](https://artifacts.picoctf.net/c_titan/59/WinAntiDbg0x200.zip). Unzip the archive with the password `picoctf`

This challenge is #2 of a 3 part series

prev: [winantidbg0x100](https://rivers.sh/posts/winantidbg0x100)
next: [winantidbg0x300](https://rivers.sh/posts/winantidbg0x300)
---

## Understanding the user-code

Like WinAntiDbg0x100, I started by analyzing the program in Ghidra. And just like last time, I ran a search on the word "flag" through program text. 

We should find this user code:

```c 
undefined4 __cdecl FUN_004016e0(int param_1,int param_2)

{
  char cVar1;
  int iVar2;
  HANDLE hObject;
  DWORD DVar3;
  BOOL BVar4;
  uint uVar5;
  LPWSTR lpOutputString;
  undefined in_stack_fffffff0;
  
  iVar2 = FUN_004012f0();
  if (iVar2 == 0) {
    FUN_00401910("[ERROR] There are permission issues. This program requires debug privileges and he nce you might want to run it as an Admin.\n"
                   ,in_stack_fffffff0);
    FUN_00401910("Challenge aborted. Please run this program as an Admin. Exiting now...\n",
                   in_stack_fffffff0);
                      /* WARNING: Subroutine does not return */
    exit(0xff);
  }
  hObject = CreateMutexW((LPSECURITY_ATTRIBUTES)0x0,0,L"WinAntiDbg0x200");
  if (hObject == (HANDLE)0x0) {
    FUN_00401910("[ERROR] Failed to create the Mutex. Exiting now...\n",in_stack_fffffff0);
                      /* WARNING: Subroutine does not return */
    exit(0xff);
  }
  DVar3 = GetLastError();
  if (DVar3 == 0xb7) {
    if (param_1 != 2) {
      FUN_00401910("[ERROR] Expected an argument\n",in_stack_fffffff0);
                      /* WARNING: Subroutine does not return */
      exit(0xbeef);
    }
    DVar3 = atoi(*(char **)(param_2 + 4));
    BVar4 = DebugActiveProcess(DVar3);
    if (BVar4 != 0) {
                      /* WARNING: Subroutine does not return */
      exit(0);
    }
                      /* WARNING: Subroutine does not return */
    exit(0xbeef);
  }
  FUN_00401910(PTR_s________________________(_)_/_____00405000,in_stack_fffffff0);
  uVar5 = FUN_00401600();
  if ((uVar5 & 0xff) == 0) {
    FUN_00401910("### To start the challenge, you\'ll need to first launch this program using a debu gger!\n"
                   ,in_stack_fffffff0);
    goto LAB_004018de;
  }
  OutputDebugStringW((LPCWSTR)&lpOutputString_004036e0);
  OutputDebugStringW((LPCWSTR)&lpOutputString_004036e4);
  FUN_00401400();
  iVar2 = FUN_00401450();
  if (iVar2 == 0) {
    OutputDebugStringW(L"### Error reading the \'config.bin\' file... Challenge aborted.\n");
  }
  else {
    OutputDebugStringW(
                         L"### Level 2: Why did the parent process get a promotion at work? Because it had a \"fork-tastic\" child process that excelled in multitasking!\n"
                         );
    FUN_00401090(3);
    cVar1 = FUN_004011d0();
    if (cVar1 == '\0') {
      BVar4 = IsDebuggerPresent();
      if (BVar4 == 0) {
         FUN_00401090(1);
         FUN_00401180(DAT_0040509c);
         lpOutputString = FUN_00401000(DAT_004050a0);
         if (lpOutputString == (LPWSTR)0x0) {
           OutputDebugStringW(L"### Something went wrong...\n");
         }
         else {
           OutputDebugStringW(L"### Good job! Here\'s your flag:\n");
           OutputDebugStringW(L"### ~~~ ");
           OutputDebugStringW(lpOutputString);
           OutputDebugStringW((LPCWSTR)&lpOutputString_004039c0);
           OutputDebugStringW(
                                L"### (Note: The flag could become corrupted if the process state is tam pered with in any way.)\n\n"
                                );
           free(lpOutputString);
         }
         goto LAB_004018ce;
      }
    }
    OutputDebugStringW(
                         L"### Oops! The debugger was detected. Try to bypass this check to get the fla g!\n"
                         );
  }
LAB_004018ce:
  free(DAT_00405098);
LAB_004018de:
  CloseHandle(hObject);
  OutputDebugStringW((LPCWSTR)&lpOutputString_00403a88);
  OutputDebugStringW((LPCWSTR)&lpOutputString_00403a8c);
  return 0;
}
```
Right away, we notice more checks. I will concisely explain the user-code before moving to the assembly.

### #1. Admin privileges check
```c
iVar2 = FUN_004012f0();
if (iVar2 == 0) {
  FUN_00401910("[ERROR] There are permission issues. This program requires debug privileges and hence you might want to run it as an Admin.\n", in_stack_fffffff0);
  FUN_00401910("Challenge aborted. Please run this program as an Admin. Exiting now...\n", in_stack_fffffff0);
  exit(0xff);
}
```
- Ensures the program runs with admin privileges
- Exits with error if check fails
- For good practice, this will be the first check we bypass

### #2. Mutex check
```c
hObject = CreateMutexW((LPSECURITY_ATTRIBUTES)0x0, 0, L"WinAntiDbg0x200");
if (hObject == (HANDLE)0x0) {
  FUN_00401910("[ERROR] Failed to create the Mutex. Exiting now...\n", in_stack_fffffff0);
  exit(0xff);
}
DVar3 = GetLastError();
if (DVar3 == 0xb7) {
  if (param_1 != 2) {
    FUN_00401910("[ERROR] Expected an argument\n", in_stack_fffffff0);
    exit(0xbeef);
  }
  DVar3 = atoi(*(char **)(param_2 + 4));
  BVar4 = DebugActiveProcess(DVar3);
  if (BVar4 != 0) {
    exit(0);
  }
  exit(0xbeef);
}
```
- Creates a mutex to ensure only one instance runs
- If mutex already exists (error 0xB7), checks for command-line arguments
- If present, tries to debug the process with PID from arguments
- Don't worry about bypassing this, it's just to make sure only one instance is running

### #3. Initial debugger check
```c
uVar5 = FUN_00401600();
if ((uVar5 & 0xff) == 0) {
  FUN_00401910("### To start the challenge, you\'ll need to first launch this program using a debugger!\n", in_stack_fffffff0);
  goto LAB_004018de;
}
```
- Ironically requires a debugger to be present initially
- If no debugger is detected, displays message to run with debugger
- Don't worry about bypassing this either, since we'll have a debugger active anyways

### #4. Config file check
```c
iVar2 = FUN_00401450();
if (iVar2 == 0) {
  OutputDebugStringW(L"### Error reading the \'config.bin\' file... Challenge aborted.\n");
}
```
- Verifies if "config.bin" file can be read
- Aborts if file cannot be accessed
- Again, don't worry about bypassing this check


### #5. Custom check
```c
cVar1 = FUN_004011d0();
if (cVar1 == '\0') {
  // Proceeds to next check if passed
}
```
- Must return '\0' to continue
- This will be the second check we bypass

### #6. Standard debugger check
```c
BVar4 = IsDebuggerPresent();
if (BVar4 == 0) {
  // Proceeds to flag decryption if passed
}
```
- Standard Windows API to detect debuggers
- Must return 0 (no debugger detected) to reach the flag
- Third check we will bypass

### #7. Flag decryption

```c
FUN_00401090(1);
FUN_00401180(DAT_0040509c);
lpOutputString = FUN_00401000(DAT_004050a0);
if (lpOutputString == (LPWSTR)0x0) {
  OutputDebugStringW(L"### Something went wrong...\n");
}
else {
  OutputDebugStringW(L"### Good job! Here\'s your flag:\n");
  OutputDebugStringW(L"### ~~~ ");
  OutputDebugStringW(lpOutputString);
  OutputDebugStringW((LPCWSTR)&lpOutputString_004039c0);
  OutputDebugStringW(L"### (Note: The flag could become corrupted if the process state is tampered with in any way.)\n\n");
  free(lpOutputString);
}
```
- Only runs if all previous checks pass
- Decrypts and displays the flag
- We want to reach this


> HEAVY WORK IN PROGRESS BEYOND THIS POINT


## Understanding the assembly

Like in *WinAntiDbg0x100*, we will find the corresponding `TEST` calls for each crucial check. **KEEP IN MIND**: As discussed in my [WinAntiDbg0x100](https://rivers.sh/posts/winantidbg0x100) writeup, the memory addresses in Ghidra and x32dbg might not line up exactly, but the last 4 digits will, so we'll just use those (easier anyways). 

Unlike WinAntiDbg0x100, this challenge uses both the EAX and EDX register, as well as both the JE and JNE jump instructions. Before explaining the assembly, let's quickly refresh on the difference between **JE & JNE**:
- **JE (Jump if Equal)**: Jumps to a specified address if the comparison result is equal (zero flag is set). Also called JZ (Jump if Zero).
- **JNE (Jump if Not Equal)**: Jumps to a specified address if the comparison result is not equal (zero flag is clear). Also called JNZ (Jump if Not Zero).


### First Check (Admin Privileges Check) - 16eb
```
004016eb 85 c0       TEST     EAX,EAX
004016ed 75 25       JNZ      LAB_00401714
```
This check tests if the program has sufficient privileges:

- `TEST EAX,EAX` performs a bitwise AND on EAX with itself (common way to check if a value is zero)
- `JNZ LAB_00401714` jumps if the result is not zero (meaning privileges are present), and we continue
- `If EAX = 0` (no privileges), it continues to the error message and exits, and we lose


### Second Check (`if (cVar1 == '\0')` condition) - 1824
```
00401824 85 d2       TEST     EDX,EDX
00401826 75 0a       JNZ      LAB_00401832
```

This corresponds to the `cVar1 = FUN_004011d0();` check

- `TEST EDX,EDX` checks if EDX is zero
- `JNZ LAB_00401832` jumps if debugger is detected (EDX != 0)
- If EDX = 0 (no debugger detected by custom function), it continues to the next check


### Third Check (IsDebuggerPresent Check) - 182e
```
0040182e 85 c0       TEST     EAX,EAX
00401830 74 15       JZ       LAB_00401847
```

This corresponds to the `BVar4 = IsDebuggerPresent();` check

- `TEST EAX,EAX` checks if EAX is zero
- `JZ LAB_00401847` jumps if EAX = 0 (no debugger detected by Windows API)
- This is the opposite logic from the previous checks - it jumps if condition is met (debugger not present)

## Bypassing all 3 checks
Knowing this, all you have to do is manually set breakpoints at the corresponding instructions (16eb, 1824, 182e) and edit the EAX/EDX values accordingly. 

1. 16eb - *JNE call*, set **EAX** to 1 to take the jump (bypassing admin check)
2. 1824 - *JNE call*, set **EDX** to 0 to avoid taking jump, as taking jump will skip over the 3rd check, subsequently denying the flag!) 
3. 1830 - *JE* call, set EDX to 0 to take the jump, giving us our flag

flag: `picoCTF{0x200_debug_f0r_Win_e6b68f6e}`
