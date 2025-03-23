---
layout: post
title:  "WinAntiDbg0x200 (work in progress)"
pinned: True
description: "Bypassing anti-debugging techniques in a Windows executable through dynamic analysis"
date:   2025-03-22
tags: ["Medium", "Reverse Engineering", "Assembly", "x64dbg"]
category: [CTF,picoCTF]
---
## Challenge Info
If you have solved WinAntiDbg0x100, you'll discover something new in this one. Debug the executable and find the flag! This challenge executable is a Windows console application, and you can start by running it using Command Prompt on Windows. This executable requires admin privileges. You might want to start Command Prompt or your debugger using the 'Run as administrator' option. Challenge can be downloaded [here](https://artifacts.picoctf.net/c_titan/59/WinAntiDbg0x200.zip). Unzip the archive with the password `picoctf`

This challenge is #2 of a 3 part series

[winantidbg0x100](https://rivers.sh/posts/winantidbg0x100)

---

## Understanding the program

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
Right away, we notice more checks.

```c
  iVar2 = FUN_004012f0();
  if (iVar2 == 0) {
    FUN_00401910("[ERROR] There are permission issues. This program requires debug privileges and he nce you might want to run it as an Admin.\n"
                   ,in_stack_fffffff0);
    FUN_00401910("Challenge aborted. Please run this program as an Admin. Exiting now...\n",
                   in_stack_fffffff0);
                      /* WARNING: Subroutine does not return */
    exit(0xff);
  }
```

1. Calls a function `FUN_004012f0()` and stores the return value in `iVar2`
2. The function `FUN_004012F0()` probably attempts to check if the program has debugging privileges, and returns a value indicating success (non-zero) or failure (0)
3. If `iVar2 == 0` (meaning the privilege check failed, and we lost):
  - Calls `FUN_00401910()` twice to display error messages 
  - First message explains debug privileges are required. Second message informs us that the challenge is aborted (we lost)

So, if this check passes, we continue onto the next check (or level).

```c
hObject = CreateMutexW((LPSECURITY_ATTRIBUTES)0x0,0,L"WinAntiDbg0x200");
```
- Creates a mutex named "WinAntiDbg0x200" to prevent multiple instances of the program from running. 

```c
  DVar3 = GetLastError();
  if (DVar3 == 0xb7) {
    if (param_1 != 2) {
      FUN_00401910("[ERROR] Expected an argument\n",in_stack_fffffff0);
      exit(0xbeef);

```

- If the mutex already exists (`error 0xB7 = ERROR_ALREADY_EXISTS)`) it checks for command line arguments and tries to debug another process using the provided PID. 

```c
  uVar5 = FUN_00401600();
  if ((uVar5 & 0xff) == 0) {
    FUN_00401910("### To start the challenge, you\'ll need to first launch this program using a debu gger!\n"
                   ,in_stack_fffffff0);
    goto LAB_004018de;
  }

```

- Checks if a debugger is present, which is ironic, since it initially wants us to use a debugger to start the challenge.

### Critical anti-debugging check

```c
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
```
- Calls `FUN_004011D0()`, a custom anti-debugging function
- Then checks if a debugger is present using standard Windows API
- If both pass (meaning a debugger wasn't detected), we get our flag

## Bypassing the checks

Like WinAntiDbg0x100, we will find the corresponding `TEST` calls for each crucial `if` statement.


> WORK IN PROGRESS

![guts](/images/winantidbg0x200/guts.png)
