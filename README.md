# ptrfind
A gdb extension that helps you find pointers in your program

## Why?
Imagine this: You have an arbitrary read/write in a region in your pwn-challenge and need to move forward. So you start `hexdump`ing memory, and look for pointers. Ever thought that this could be automated? Well look no further!

## Features
- Automatic memory region detection: \
Don't want to copy-paste the `libc`'s address-range every time? No problem! Keywords like "libc", "loader", "image" and even "tls" are detected automatically, and translated to the respective memory-range. Providing the file name or absolute path of a mapped object file also works!
- Leak-chains \
Can't get to your destination directly? With `--chain`, `ptrfind` will locate leak-chains for you, i.e. getting to your location in multiple leaks. Ezpz!
- Bad Bytes filtering \
You can only leak pointers without NULL-Bytes? Don't want newlines in your pointer? Give `ptrfind` a list of bad bytes, and you will only get pointers without them.
- Caching \
The results of read-only pages are automatically cached, so that future executions will be considerably faster! Use `-c` to also cache-writeable pages, or `--clear-cache` to start from scratch.
- Independent of `gef` or `pwndbg`, also works in vanilla gdb

## Examples:
- Find your libc pointers:
```
(gdb) ptrfind libc --from image
[+] Searching for pointers, this may take a few minutes
[+] Pointer(s) found from /usr/bin/bash to /usr/lib64/libc.so.6:
	0x5555556a6890 (endgrent@got[plt]) → 0x7ffff7e6b650 (endgrent)
	0x5555556a6898 (__ctype_toupper_loc@got.plt) → 0x7ffff7dc7120 (__ctype_toupper_loc)
	0x5555556a68a0 (__strcat_chk@got.plt) → 0x7ffff7eb5020 (__strcat_chk)
	0x5555556a68a8 (iswlower@got[plt]) → 0x7ffff7ea9b70 (iswlower)
	0x5555556a68b0 (sigprocmask@got[plt]) → 0x7ffff7dceb70 (sigprocmask)
	(223 pointers omitted, use -a to show all)
[+] Search done, 228 pointers found
```
- Leak-chains:
```
(gdb) ptrfind tls --from image
[+] Searching for pointers, this may take a few minutes
[-] Search done, no pointers were found
(gdb) ptrfind tls --from image --chain 1
[+] Searching for leak-chains, this may take a few minutes
[+] Leak-chain found (2 leaks):
  → /usr/bin/bash
	0x5555556a6750 (_DYNAMIC+0xd8) → 0x7ffff7ffe108 (_r_debug_extended)
  → /usr/lib64/ld-linux-x86-64.so.2
	0x7ffff7ffb740 (_dlfo_nodelete_mappings) → 0x7ffff7d8e1e0
	0x7ffff7ffe090 (_rtld_local+0x1090) → 0x7ffff7d8e0e0
	0x7ffff7ffe0b8 (_rtld_local+0x10b8) → 0x7ffff7d8da00
	0x7ffff7ffe0c0 (_rtld_local+0x10c0) → 0x7ffff7d8da00
	0x7ffff7ffe168 (alloc_last_block) → 0x7ffff7d8e1e0
	(1 pointer omitted, use -a to show all)
  → [tls] (0x7ffff7d8d000-0x7ffff7d90000)
[+] 20 more chains were found but not printed, use --chain <num_chains_printed> to show more
[+] Search done, 21 unique chains were found
```
For more examples and a detailed description of all options, check out the command's help page.

## Requirements
A recent version of gdb with Python 3 support. This extension has been tested with gdb version 14.1-2 on Fedora 39.

## Installation instructions
TL;DR: Include this python script in your `.gdbinit` with `source path/to/ptrfind.py`. Here is an example:
```sh
cd ~
git clone https://github.com/ChaChaNop-Slide/ptrfind.git
echo "source ~/ptrfind/ptrfind.py" >> .gdbinit
```
