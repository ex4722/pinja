from os import system
from binaryninja.debugger import DebuggerController
import binaryninja
import pwn

class pinja(pwn.process):
    def __init__(self, filename):
        """
        exe is pwn ELF object 
        filename is patched binary location 
        bv is BN live view of process
        dc is BN DebuggerController
        """

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
        self.dc.set_reg_value("rip", self.bv.entry_point +4)
        self.bv.write(self.bv.entry_point, pwn.asm("endbr64"))

    def close(self): 
        super().close()
        self.bv.file.close()
        self.dc.destroy()
