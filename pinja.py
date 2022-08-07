from os import system
from binaryninja.debugger import DebuggerController
import binaryninja
import pwn


# class pinja(object):
#     def __init__(self, filename):
#         e = pwn.ELF(filename)
#         e.asm(e.entrypoint, "h: jmp h;nop;nop")
#         e.save("/tmp/" + filename)
#         self.filename =  "/tmp/" + filename
#         system(f"chmod +x {filename}")

#         self.p = pwn.process(filename, aslr=False)
#         ty = binaryninja.BinaryViewType.get_view_of_file(filename)
#         self.dbg = DebuggerController(ty)
#         if self.dbg.attach(self.p.pid):
#             print("ATTACHED")
#         else:
#             print("FAILED")
#         self.bv = self.dbg.live_view 
#         self.dbg.set_reg_value("rip", self.dbg.ip +2)
#         # self.dbg.go()


class pinja(pwn.process):
    def __init__(self, filename):
        self.exe = pwn.ELF(filename)
        self.exe.asm(self.exe.entrypoint, "h: jmp h;nop;nop")
        self.exe.save("/tmp/" + filename)

        self.filename =  "/tmp/" + filename
        system(f"chmod +x {filename}")

        super().__init__(self.filename)

        bv  = binaryninja.BinaryViewType.get_view_of_file(filename)
        self.dc = DebuggerController(bv)
        if self.dc.attach(self.pid):
            pwn.info(f"Sucessfully Attached to process {self.pid}")
        else:
            pwn.error(f"Error Attaching to process {self.pid}")

        self.bv = self.dc.live_view 
        self.dc.set_reg_value("rip", self.dc.ip +2)

    def close(self): 
        super().close()
        self.bv.file.close()
        self.dc.destroy()
