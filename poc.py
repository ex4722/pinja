from pwn import * 
from os import pread, preadv, system
from binaryninja import BinaryViewType, LowLevelILFcmpNe, RegisterValueType, MediumLevelILOperation
from binaryninja.debugger import DebuggerController
import binaryninja
from pwnlib.elf.datatypes import elf_prpsinfo_64


binary = "a.out"



e = ELF(binary)
e.asm(e.entrypoint, "h: jmp h;nop;nop")
e.save("/tmp/" + binary)
system("chmod +x /tmp/a.out")

p = process("/tmp/" + binary)
ti = BinaryViewType.get_view_of_file("./a.out")

dbg = DebuggerController(ti)


if dbg.attach(p.pid):
    print("ATTACHED")
else:
    print("FAILED")


bv = dbg.live_view 


dbg.set_reg_value("rip", dbg.ip +2)
dbg.add_breakpoint(bv.symbols["main"][0].address)

# Breaks at main
dbg.go()
