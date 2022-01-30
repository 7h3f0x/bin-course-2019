#!/usr/bin/env python2
from pwn import *

p = process("./rellocator")
gdb.attach(p)

string = "1) Malloc"

p.sendlineafter("Size:\n", str(0x200))

def add(index, data, size = None):
	p.sendlineafter(">> ", "1")
	p.sendlineafter("Index:\n", str(index))
	if not size:
		size = len(data)
	p.sendlineafter("Size:\n", str(size))
	p.sendafter("Data:\n", data)

def edit(index, data, size = None):
	p.sendlineafter(">> ", "2")
	p.sendlineafter("Index:\n", str(index))
	if not size:
		size = len(data)
	p.sendlineafter("Size:\n", str(size))
	p.sendafter("Data:\n", data)

def view(index):
	p.sendlineafter(">> ", "3")
	p.sendlineafter("Index:\n", str(index))
	p.recvuntil("Data :")
	return p.recvuntil(string)[:(-1)*len(string)]

p.interactive()