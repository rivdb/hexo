---
layout: post
title:  "WinAntiDbg0x300"
pinned: True
description: "Bypassing an infinite debugger-killing loop by NOP'ing an unconditional jump"
date:   2025-04-04
tags: ["Medium", "Reverse Engineering", "Assembly", "x64dbg"]
category: [CTF,picoCTF2024]
---
## Challenge Info
This challenge is a little bit invasive. It will try to fight your debugger. With that in mind, debug the binary and get the flag!
This challenge executable is a GUI application and it requires admin privileges. And remember, the flag might get corrupted if you mess up the process's state.

Challenge can be downloaded [here](https://artifacts.picoctf.net/c_titan/123/WinAntiDbg0x300.zip). Unzip the archive with the password `picoctf`

If you get "VCRUNTIME140D.dll" and "ucrtbased.dll" missing error, then that means the Universal C Runtime library and Visual C++ Debug library are not installed on your Windows machine.
The quickest way to fix this is:

- Download Visual Studio Community installer from https://visualstudio.microsoft.com/vs/community/
- After the installer starts, first select 'Desktop development with C++' and then, in the right side column, select 'MSVC v143 - VS 2022 C++ x64/x86 build tools' and 'Windows 11 SDK' packages.

This will take ~30 mins to install any missing DLLs.

This challenge is #3 of a 3 part series

[WinAntiDbg0x100](https://rivers.sh/posts/winantidbg0x100)
[WinAntiDbg0x200](https://rivers.sh/posts/winantidbg0x100)


---

## Basic forensics & info

Unlike the WinAntiDbg0x100 & 200, this challenge doesn't look normal when loaded into Ghidra. Additionally, we are given a `.pdb` (Program Database).
Even when loading this `.pdb`, I notice Ghidra isn't able to load symbols. So, I decided to run the `file` command on the `.exe`:
```
[marcial@arch ~/desktop/cyber/pico/winantidbg0x300]$ file WinAntiDbg0x300.exe
WinAntiDbg0x300.exe: PE32 executable for MS Windows 6.00 (GUI), Intel i386, UPX compressed, 3 sections
[marcial@arch ~/desktop/cyber/pico/winantidbg0x300]$
```
Right away, I notice that the `.exe` is compressed via UPX. So, I head back to my Windows 10 virtual machine, install UPX, and run `upx -d WinAntiDbg0x300.exe` to decompress the file. Now, when loading this file into Ghidra alongside the `.pdb`, I notice symbols, which significantly makes it easier to reverse engineer. 

Additionally, one of the hints states that: "if you've done everything correctly, the flag should pop-up on your screen after 5 esconds of launching the program." DebugView can be downloaded [here](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview)

## Understanding the user-code

### wWinMain

Looking at the symbol tree, I notice a folder under "Functions", `wWinMain`, when inspecting the `wWinMain` function, we should see:

```c
int __cdecl wWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,wchar_t *param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  undefined4 local_34 [2];
  int local_2c;
  undefined4 local_18;
  int local_14;
  wchar_t **local_10;
  undefined4 local_c;
  int local_8;
  
  PrintDbgBanner();
  LoadStringW(param_1,0x67,szTitle,200);
  LoadStringW(param_1,0x6d,szWindowClass,200);
  iVar2 = ReadConfig();
  if (iVar2 == 0) {
    MessageBoxW(appWindow,L"[FATAL ERROR] Error opening the \'config.bin\' file. Challenge aborted."
                ,szTitle,0x10);
    Terminate(0xff);
  }
  ComputeHash(3);
  bVar1 = DetectDebuggerAtLaunch();
  if (bVar1) {
    MessageBoxW(appWindow,L"Oops! Debugger Detected. Challenge Aborted.",szTitle,0x40);
    Terminate(0xff);
  }
  ComputeHash(2);
  EnableDebugPrivilege();
  ComputeHash(2);
  local_c = GetCommandLineW();
  local_10 = (wchar_t **)CommandLineToArgvW(local_c,&local_14);
  ManageChildProcess(local_14,local_10);
  MyRegisterClass(param_1);
  iVar2 = InitInstance(param_1,param_4);
  if (iVar2 == 0) {
    local_2c = 0;
  }
  else {
    local_18 = LoadAcceleratorsW(param_1,0x6b);
    local_8 = CreateThread(0,0,ChallengeThreadFunction,0,0,0);
    if (local_8 == 0) {
      MessageBoxW(appWindow,L"Error creating the thread. Aborting the challenge...",szTitle,0x10);
      local_2c = 0xff;
    }
    else {
      while (iVar2 = GetMessageW(local_34,0,0,0), iVar2 != 0) {
        iVar2 = TranslateAcceleratorW(local_34[0],local_18,local_34);
        if (iVar2 == 0) {
          TranslateMessage(local_34);
          DispatchMessageW(local_34);
        }
      }
      free(CONFIG_BUFFER);
      CloseHandle(local_8);
      CloseHandle(MUTEX);
    }
  }
  return local_2c;
}
```

I'll give a quick rundown for now, and then further in the writeup I'll analyze `ManageChildProcess`, `ComputeHash`, and `ChallengeThreadFunction` (most important one!) a bit more in-depth:



1. Initial Setup:
```c
PrintDbgBanner();
LoadStringW(param_1,0x67,szTitle,200);
LoadStringW(param_1,0x6d,szWindowClass,200);
iVar2 = ReadConfig();
if (iVar2 == 0) {
  MessageBoxW(appWindow,L"[FATAL ERROR] Error opening the \'config.bin\' file. Challenge aborted."
              ,szTitle,0x10);
  Terminate(0xff);
}
```
- Displays a debug banner with `PrintDbgBanner()`
- Loads string resources for window title and class name 
- Reads configuration from "config.bin" file and exits if this fails 


2. Anti-Debugging Mechanisms: 
```
ComputeHash(3);
bVar1 = DetectDebuggerAtLaunch();
if (bVar1) {
  MessageBoxW(appWindow,L"Oops! Debugger Detected. Challenge Aborted.",szTitle,0x40);
  Terminate(0xff);
}
ComputeHash(2);
EnableDebugPrivilege();
ComputeHash(2);
```

- `ComputeHash(3)` is called, which I'll explain in a moment
- `DetectDebuggerAtLaunch()` checks if the debugger is present
  - If one is detected, we get a message and it terminates with code 0xFF (255) 
- `EnableDebugPrivilege()` probably adjusts the process's debugging permissions


3. Process Management: 
```c
local_c = GetCommandLineW();
local_10 = (wchar_t **)CommandLineToArgvW(local_c,&local_14);
ManageChildProcess(local_14,local_10);
MyRegisterClass(param_1);
iVar2 = InitInstance(param_1,param_4);
if (iVar2 == 0) {
  local_2c = 0;
}
```

- Parses command line arguments
- Calls `ManageChildProcess()`
- Creates a mutex handle (MUTEX global variable) for synchronization


4. Challenge Thread:
```c
local_18 = LoadAcceleratorsW(param_1,0x6b);
local_8 = CreateThread(0,0,ChallengeThreadFunction,0,0,0);
if (local_8 == 0) {
  MessageBoxW(appWindow,L"Error creating the thread. Aborting the challenge...",szTitle,0x10);
  local_2c = 0xff;
}
```

- Creates a separate thread running `ChallengeThreadFunction()`
- If thread creation fails, the program terminates

### ComputeHash
```c
void __cdecl ComputeHash(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iStack_10;
  int iStack_c;
  
  uVar1 = FLAG_SIZE;
  for (iStack_10 = 0; iStack_10 < param_1; iStack_10 = iStack_10 + 1) {
    for (iStack_c = 0; iStack_c < (int)uVar1; iStack_c = iStack_c + 1) {
      uVar2 = (iStack_c % 0xff & 0x55U) + (iStack_c % 0xff >> 1 & 0x55U);
      uVar2 = (uVar2 & 0x33) + ((int)uVar2 >> 2 & 0x33U);
      HASH[iStack_c] =
           (char)((int)((HASH[iStack_c] - 0x61) + (uVar2 & 0xf) + ((int)uVar2 >> 4)) % 0x1a) + 'a';
    }
  }
  return;
}
```

1. Function Signatures and Variables

```c
void __cdecl ComputeHash(int param_1)
{
  uint uVar1;
  uint uVar2;
  int iStack_10;
  int iStack_
```

- Takes a single parameter (param_1) that determines how many times the hashing operation is repeated
- Modifies a global array called HASH that likely contains the flag or verification data
- Uses a bit manipulation algorithm to transform each character

2. Algorithm 

```c
  uVar1 = FLAG_SIZE;
  for (iStack_10 = 0; iStack_10 < param_1; iStack_10 = iStack_10 + 1) {
    for (iStack_c = 0; iStack_c < (int)uVar1; iStack_c = iStack_c + 1) {
      uVar2 = (iStack_c % 0xff & 0x55U) + (iStack_c % 0xff >> 1 & 0x55U);
      uVar2 = (uVar2 & 0x33) + ((int)uVar2 >> 2 & 0x33U);
      HASH[iStack_c] =
           (char)((int)((HASH[iStack_c] - 0x61) + (uVar2 & 0xf) + ((int)uVar2 >> 4)) % 0x1a) + 'a';
    }
  }
  return;
```

- Outer loop runs param_1 times (called with values 2 and 3 in the main function)
- Inner loop iterates through each character in the global HASH array up to FLAG_SIZE
- For each character, it:
  - Performs bit counting operations (population count algorithm)
  - Manipulates the character by subtracting 'a' (97), adding bit counts, then taking modulo 26
  - Adds 'a' back to keep the result in the lowercase alphabet range (a-z)

In short, this is basically a custom obfuscation technique to ensure that we can't just immediately jump to the "decrypt flag" 

### ManageChildProcess
```c

void __cdecl ManageChildProcess(int param_1,wchar_t **param_2)

{
  int iVar1;
  char *pcVar2;
  undefined4 uVar3;
  ulong uVar4;
  
  ComputeHash(1);
  MUTEX = (void *)CreateMutexW(0,0,szTitle);
  if (MUTEX == (void *)0x0) {
    MessageBoxW(0,L"[FATAL ERROR] Failed to create the Mutex. Challenge aborted.",szTitle,0x10);
    Terminate(0xff);
  }
  iVar1 = GetLastError();
  if (iVar1 == 0xb7) {
    if (param_1 != 2) {
      OutputDebugStringW(
                        L"[ERROR] Exactly two arguments expected by the Child process. Exiting...\n"
                        );
      MessageBoxW(0,L"Check if the program is already running.",szTitle,0x10);
      CloseHandle(MUTEX);
      Terminate(0xff);
    }
    pcVar2 = WCharToChar(param_2[1]);
    if (pcVar2 == (char *)0x0) {
      OutputDebugStringW(L"Error converting WChar to Char.\n");
      CloseHandle(MUTEX);
      Terminate(0xff);
    }
    uVar3 = atoi(pcVar2);
    iVar1 = DebugActiveProcess(uVar3);
    if (iVar1 == 0) {
      uVar4 = atoi(pcVar2);
      uVar4 = getParentProcessID(uVar4);
      iVar1 = OpenProcess(1,0,uVar4);
      if (iVar1 == 0) {
        CloseHandle(MUTEX);
        free(pcVar2);
        OutputDebugStringW(L"Error opening a handle to debuggerPID.\n");
        Terminate(0xff);
      }
      iVar1 = TerminateProcess(iVar1,0);
      if (iVar1 == 0) {
        OutputDebugStringW(L"Failed to terminate the debugger process.\n");
        free(pcVar2);
        CloseHandle(MUTEX);
        Terminate(0xfe);
      }
      else {
        OutputDebugStringW(L"Debugger process terminated successfully.\n");
        free(pcVar2);
        CloseHandle(MUTEX);
        Terminate(0xfd);
      }
    }
    else {
      OutputDebugStringW(L"No debugger was present. Exiting successfully.\n");
      uVar3 = atoi(pcVar2);
      DebugActiveProcessStop(uVar3);
      CloseHandle(MUTEX);
      free(pcVar2);
      Terminate(0);
    }
    Terminate(0);
  }
  ComputeHash(1);
  return;
}
```

1. Initialization 
```c
ComputeHash(1);
MUTEX = (void *)CreateMutexW(0,0,szTitle);
if (MUTEX == (void *)0x0) {
  MessageBoxW(0,L"[FATAL ERROR] Failed to create the Mutex. Challenge aborted.",szTitle,0x10);
  Terminate(0xff);
}
```
- Computes hash to verify integrity 
- Creates a mutex with `szTitle` for synchronization between processes 
- Exits if mutex creation fails with error code 0xFF (255)

2. Process Verification 
```c
iVar1 = GetLastError();
if (iVar1 == 0xb7) {
  if (param_1 != 2) {
    OutputDebugStringW(
                      L"[ERROR] Exactly two arguments expected by the Child process. Exiting...\n"
                      );
    MessageBoxW(0,L"Check if the program is already running.",szTitle,0x10);
    CloseHandle(MUTEX);
    Terminate(0xff);
  }
```
- Checks if another instance is already running by examining `GetLastError()` for ERROR_ALREADY_EXISTS (0xb7)
- Validates the number of command-line arguments (expects exactly 2 for child process)

3. Anti-Debugging Check
```c
pcVar2 = WCharToChar(param_2[1]);
if (pcVar2 == (char *)0x0) {
  OutputDebugStringW(L"Error converting WChar to Char.\n");
  CloseHandle(MUTEX);
  Terminate(0xff);
}
uVar3 = atoi(pcVar2);
iVar1 = DebugActiveProcess(uVar3);
if (iVar1 == 0) {
  uVar4 = atoi(pcVar2);
  uVar4 = getParentProcessID(uVar4);
  iVar1 = OpenProcess(1,0,uVar4);
```

- Converts and validates the second argument (process ID) from wide character to char
- Converts string PID to integer
- If running as a child process, attempts to debug the parent process using DebugActiveProcess()
- Gets the parent's parent (the debugger) using getParentProcessID()
- Attempts to open a handle to the debugger process

4. Debugger Termination
```c
iVar1 = TerminateProcess(iVar1,0);
if (iVar1 == 0) {
  OutputDebugStringW(L"Failed to terminate the debugger process.\n");
  free(pcVar2);
  CloseHandle(MUTEX);
  Terminate(0xfe);
}
else {
  OutputDebugStringW(L"Debugger process terminated successfully.\n");
  free(pcVar2);
  CloseHandle(MUTEX);
  Terminate(0xfd);
}
```
- Tries to terminate the debugger process
- Reports success (0xFD) or failure (0xFE) via exit codes

5. Normal Execution Path
```c
else {
  OutputDebugStringW(L"No debugger was present. Exiting successfully.\n");
  uVar3 = atoi(pcVar2);
  DebugActiveProcessStop(uVar3);
  CloseHandle(MUTEX);
  free(pcVar2);
  Terminate(0);
}
```
- If no debugger is detected, it detaches and exits normally with code 0 

### ChallengeThreadFunction

```c

/* WARNING: Removing unreachable block (ram,0x004038e0) */
/* WARNING: Removing unreachable block (ram,0x00403911) */
/* WARNING: Removing unreachable block (ram,0x00403929) */

ulong __cdecl ChallengeThreadFunction(void *param_1)

{
  undefined auStack_384 [520];
  char acStack_17c [272];
  undefined4 auStack_6c [18];
  int iStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  int iStack_8;
  
  _memset(auStack_6c,0,0x44);
  auStack_6c[0] = 0x44;
  uStack_1c = 0;
  uStack_18 = 0;
  uStack_14 = 0;
  uStack_10 = 0;
  iStack_8 = 0;
  uStack_20 = GetCurrentProcessId();
  GetModuleFileNameW(0,auStack_384,0x104);
  snprintf(acStack_17c,0x110,"%ws %d");
  ComputeHash(2);
  do {
    iStack_24 = CreateProcessA(0,acStack_17c,0,0,0,0,0,0,auStack_6c,&uStack_1c);
    if (iStack_24 == 0) {
      MessageBoxW(appWindow,L"[FATAL ERROR]  Unable to create the child process. Challenge aborted."
                  ,szTitle,0x10);
      Terminate(0xff);
    }
    WaitForSingleObject(uStack_1c,0xffffffff);
    GetExitCodeProcess(uStack_1c,&iStack_8);
    if (iStack_8 == 0xff) {
      MessageBoxW(appWindow,L"Something went wrong. Challenge aborted.",szTitle,0x10);
      Terminate(0xff);
    }
    else if (iStack_8 == 0xfe) {
      MessageBoxW(appWindow,
                  L"The debugger was detected but our process wasn\'t able to fight it. Challenge ab orted."
                  ,szTitle,0x10);
      Terminate(0xff);
    }
    else if (iStack_8 == 0xfd) {
      MessageBoxW(appWindow,
                  L"Our process detected the debugger and was able to fight it. Don\'t be surprised if the debugger crashed."
                  ,szTitle,0x10);
    }
    CloseHandle(uStack_1c);
    CloseHandle(uStack_18);
    Sleep(5000);
  } while( true );
}
```
1. Initialization and Setup
```c
*memset(auStack*6c,0,0x44);
auStack_6c[0] = 0x44;
uStack_1c = 0;
uStack_18 = 0;
uStack_14 = 0;
uStack_10 = 0;
iStack_8 = 0;
uStack_20 = GetCurrentProcessId();
GetModuleFileNameW(0,auStack_384,0x104);
snprintf(acStack_17c,0x110,"%ws %d");
ComputeHash(2);
```
- Initializes a STARTUPINFO structure for child process creation
- Gets the current process ID
- Gets the executable path of the current process
- Formats a command line for the child process including the process ID
- Computes a hash for integrity verification

2. Child Process Creation & Monitoring Loop
```c
do {
  iStack_24 = CreateProcessA(0,acStack_17c,0,0,0,0,0,0,auStack_6c,&uStack_1c);
  if (iStack_24 == 0) {
    MessageBoxW(appWindow,L"[FATAL ERROR]  Unable to create the child process. Challenge aborted."
                ,szTitle,0x10);
    Terminate(0xff);
  }
```
- Enters an infinite loop to continuously monitor for debuggers
- Creates a child process with the current process path and PID as arguments
- Terminates with error if child process creation fails

3. Process Status Handling
```c
WaitForSingleObject(uStack_1c,0xffffffff);
GetExitCodeProcess(uStack_1c,&iStack_8);
if (iStack_8 == 0xff) {
  MessageBoxW(appWindow,L"Something went wrong. Challenge aborted.",szTitle,0x10);
  Terminate(0xff);
}
else if (iStack_8 == 0xfe) {
  MessageBoxW(appWindow,
              L"The debugger was detected but our process wasn\'t able to fight it. Challenge ab orted."
              ,szTitle,0x10);
  Terminate(0xff);
}
else if (iStack_8 == 0xfd) {
  MessageBoxW(appWindow,
              L"Our process detected the debugger and was able to fight it. Don\'t be surprised if the debugger crashed."
              ,szTitle,0x10);
}
```
- Waits indefinitely for the child process to complete
- Retrieves the exit code from the child process
- Handles different scenarios based on exit codes:
  - 0xFF: General error occurred
  - 0xFE: Debugger detected but couldn't be terminated
  - 0xFD: Debugger detected and successfully terminated

4. Cleanup
```c
CloseHandle(uStack_1c);
CloseHandle(uStack_18);
Sleep(5000);
} while( true );
```
- Cleans up process and thread handles
- Sleeps for 5 seconds before creating another child process
- Continues this cycle indefinitely, constantly monitoring for debuggers

In summary, that `while( true );` loop is pesky, as it creates an infinite loop to repeatedly spawn child processes that check for and attempt to terminate debuggers. It's intentoinally designend to make reverse engineering this difficult (but it isn't, I promise!) by activtely fighting against us. Unlike the other challenges, we won't be able to just set breakpoints and edit registry values, as this loop is just infinite. 

## Solution

If we click on the `while( true );` we can see the corresponding assembly. The remove this loop, we can right click the JMP instruction, select "Clear Code Bytes", and then overwrite all new 5 entries to be a NOP by right clicking each one (or hitting CTRL+Shift+G) and selecting "Patch Instruction". From there, just write `NOP` for each one. 

![nop](/images/winantidbg0x300/NOP.png)

Next, we can just export the project as a single file, run it while DebugView is open, and we should have our flag. 

flag: `picoCTF{Wind0ws_antid3bg_0x300_aba8ee97}`
