---
layout: post
title:  "Binary Instrumentation II"
pinned: True
description: "work in progress"
date:   2025-05-02
tags: ["Medium", "Reverse Engineering", "Frida", "Binary Instrumentation", "JavaScript", "Windows API"]
category: [CTF,picoCTF2024]
---
## Challenge Info
I've been learning more Windows API functions to do my bidding. Hmm... I swear this program was supposed to create a file and write the flag directly to the file. Can you try and intercept the file writing function to see what went wrong?

Download the exe [here](https://challenge-files.picoctf.net/c_verbal_sleep/4aee1b9778a8e56724d015b027431fb236853a94f53e5dcf32c5ed32aed404da/bininst2.zip). Unzip the archive with the password `picoctf`

## Basic forensics & info

```
C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2>file bininst2.exe
bininst2.exe: PE32+ executable (console) x86-64, for MS Windows

FLARE-VM Sun 05/04/2025  4:11:07.21
```

`file` doesn't yield anything unexpected/unusual. Additionally, the program produces no output when ran:

```
C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2>bininst2.exe

FLARE-VM Sun 05/04/2025  4:11:48.40
```

## Frida-trace exploration
A logical attempt would be to run the same `frida-trace` command as used in the previous challenge, in which we'd target the `Sleep` call and then inspect `Sleep.js` for anything odd. However, this is not the case with this challenge, as the `Sleep.js` in both DLL folders looks normal. 

### Overkill frida-trace

```
frida-trace -f bininst2.exe -i "*"
```
- Traces *ALL* API calls from every library
- `-i "*"` means intercept everything

This `frida-trace` command may look good at a glance, as it traces everything, but this actually works against us. The reason being, is that 99% of the handlers aren't relevant to solving the challenge, and this will just lead to information overload.

### Specific frida-trace 

Knowing that this is a CTF, it's possible the flag is being written/read from a file, so we can try something like this:
```
frida-trace -i *File* -f bininst2.exe -X KERNEL32
```
- Only traces APIs that contain "File" in their name (`CreateFile`, `ReadFile`, `WriteFile`)
- `-X KERNEL32` excludes `KERNDEL32.dll` APIs

This command, unlike the previous one, is much more focused and less noisy, as it focuses our scope on only the necessary. 

## Modifying handlers

```
C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2>frida-trace -i *File* -f bininst2.exe -X KERNEL32
Instrumenting...

...

Started tracing 547 functions. Web UI available at http://localhost:51013/
           /* TID 0x18bc */
   501 ms  NtDeviceIoControlFile()
   501 ms  RtlDosApplyFileIsolationRedirection_Ustr()
   501 ms  RtlDosApplyFileIsolationRedirection_Ustr()
   501 ms  RtlDosApplyFileIsolationRedirection_Ustr()
   501 ms  NtQueryAttributesFile()
   501 ms  NtQueryAttributesFile()
   501 ms  NtOpenFile()
   501 ms  RtlDosApplyFileIsolationRedirection_Ustr()
   511 ms  GetSystemTimeAsFileTime()
   511 ms     | GetSystemTimeAsFileTime()
   511 ms  GetModuleFileNameW()
   511 ms     | GetModuleFileNameW()
   511 ms  AreFileApisANSI()
   511 ms     | AreFileApisANSI()
   511 ms  CreateFileA()
   511 ms     | CreateFileA()
Process terminated

FLARE-VM Sun 05/04/2025  4:46:25.91
```
The output shows us that the program is utilizing `CreateFileA()`. However, upon inspecting `CreateFileA()` we see a very basic configuration, before modifying it to try and get more information, it's important to understand what we *can* do:

A quick search led me to [this](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) Microsoft page, which shows the syntax for the `CreateFileA` function. I'll also leave it below for your convenience:
```
HANDLE CreateFileA(
  [in]           LPCSTR                lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```


1st `CreateFileA` modification:

```
defineHandler({
  onEnter(log, args, state) {
    // Log the filename being created
    state.filename = Memory.readUtf8String(args[0]);
    log('CreateFileA called with filename: "' + state.filename + '"');
  },
  
  onLeave(log, retval, state) {
    // Log the result
    log('CreateFileA returned: ' + retval);
  }
});
```

- We read the filename string from `args[0]` (first argument to CreateFileA) and log it
- We store the filename in `state` so we can reference it in the onLeave function
- We log the handle returned by `CreateFileA` to see if it succeeded or failed
- If the handle is `-1` (`INVALID_HANDLE_VALUE`), we know file creation failed
- This tells us whether the path is valid and if file creation is working properly


Output:
```
frida-trace -i CreateFileA -f bininst2.exe -X KERNEL32

Started tracing 4 functions. Web UI available at http://localhost:64949/
           /* TID 0x1a40 */
    19 ms  CreateFileA()
    19 ms     | CreateFileA called with filename: "<Insert path here>"
    19 ms  CreateFileA returned: 0xffffffffffffffff
Process terminated```
```
- The program is calling `CreateFileA` with an invalid filename: ``"<Insert path here>"` - this is clearly a placeholder that wasn't properly replaced with a real path.
- `CreateFileA` returned `0xffffffffffffffff`, which is `-1` or `INVALID_HANDLE_VALUE`, confirming that file creation failed.
- The process terminated right after this, suggesting that the flag is being processed but never successfully written to a file.

This lead me to further edit `CreateFileA`, but this time, let's try replacing "<Insert path here>" with a valid filename ("flag.txt")

2nd `CreateFileA` modification:

```
defineHandler({
  onEnter(log, args, state) {
    // Read original filename
    state.originalPath = Memory.readUtf8String(args[0]);
    log('CreateFileA - Original path: "' + state.originalPath + '"');
    
    // Replace the invalid path with a valid one
    const newPath = Memory.allocUtf8String('flag.txt');
    args[0] = newPath;
    
    // Save reference to prevent garbage collection
    state.newPath = newPath;
    
    log('CreateFileA - Replaced with: "flag.txt"');
  },
  
  onLeave(log, retval, state) {
    log('CreateFileA returned: ' + retval);
  }
});
```

Output:

```
frida-trace -i CreateFileA -f bininst2.exe -X KERNEL32

Started tracing 2 functions. Web UI available at http://localhost:49254/
           /* TID 0xb4c */
    20 ms  CreateFileA()
    20 ms     | CreateFileA - Original path: "<Insert path here>"
    20 ms     | CreateFileA - Replaced with: "flag.txt"
    20 ms  CreateFileA returned: 0x274
Process terminated
```

However, upon checking the newly created `flag.txt`, you'll notice it's empty... but this is okay. Since `CreateFileA` is succeeding, that means it has to be calling `WriteFile`. So, let's try modifying the `WriteFile` handler to see if we can intercept the data it's attempting to write. 


We can set up a `WriteFile` handler to try and intercept the flag:

`WriteFile` syntax:

```c++
BOOL WriteFile(
  [in]                HANDLE       hFile,
  [in]                LPCVOID      lpBuffer,
  [in]                DWORD        nNumberOfBytesToWrite,
  [out, optional]     LPDWORD      lpNumberOfBytesWritten,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

`WriteFile.js` modification:

```
{
  onEnter(log, args, state) {
    // Log basic info
    log('WriteFile called with handle: ' + args[0]);
    log('WriteFile buffer content:');
    log(hexdump(args[1]));
  },
  
  onLeave(log, retval, state) {
    // Log result
    log('WriteFile returned: ' + retval);
  }
}
```
- We're trying to examine the data that would be written to the file using `lpBuffer`
- We're logging the file handle & return value to track success/failure 

Output:

```
frida-trace -i CreateFileA -i WriteFile -f bininst2.exe -X KERNEL32

Instrumenting...
CreateFileA: Loaded handler at "C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2\__handlers__\KERNELBASE.dll\CreateFileA.js"
WriteFile: Loaded handler at "C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2\__handlers__\KERNELBASE.dll\WriteFile.js"
CreateFileA: Loaded handler at "C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2\__handlers__\KERNEL32.DLL\CreateFileA.js"
WriteFile: Loaded handler at "C:\Users\river\Desktop\ctf\pico\BinaryInstrumentation2\__handlers__\KERNEL32.DLL\WriteFile.js"
Started tracing 4 functions. Web UI available at http://localhost:49342/
           /* TID 0x1838 */
    20 ms  CreateFileA()
    20 ms     | CreateFileA - Original path: "<Insert path here>"
    20 ms     | CreateFileA - Replaced with: "flag.txt"
    20 ms  CreateFileA returned: 0x270
    20 ms  WriteFile()
    20 ms     | WriteFile called with handle: 0x270
    20 ms     | WriteFile buffer content:
    20 ms     |             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
140002270  63 47 6c 6a 62 30 4e 55 52 6e 74 6d 63 6a 46 6b  cGljb0NURntmcjFk
140002280  59 56 39 6d 4d 48 4a 66 59 6a 46 75 58 32 6c 75  YV9mMHJfYjFuX2lu
140002290  4e 58 52 79 64 57 30 7a 62 6e 51 30 64 47 6c 76  NXRydW0zbnQ0dGlv
1400022a0  62 69 46 66 59 6a 49 78 59 57 56 6d 4d 7a 6c 39  biFfYjIxYWVmMzl9
1400022b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
1400022c0  40 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  @...............
1400022d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
1400022e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
1400022f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
140002300  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
140002310  00 00 00 00 00 00 00 00 00 30 00 40 01 00 00 00  .........0.@....
140002320  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
140002330  a0 21 00 40 01 00 00 00 b0 21 00 40 01 00 00 00  .!.@.....!.@....
140002340  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
140002350  00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
140002360  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20 ms  WriteFile returned: 0x1
Process terminated
```

Looks like it could be a flag encoded via base64, let's try and decode it:

```
[marcial@arch ~/desktop/code/hexo]$ echo "cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9" | base64 -d
picoCTF{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}%
```

flag: `cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9" | base64 -d
picoCTF{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}%`
