from unittest.mock import Mock
from os import system
from binaryninja.debugger import DebuggerController
import binaryninja
import pwn
from pwnlib.util import packing

class ninja_process(pwn.process):
    def __init__(self, filename):
        """
        exe is pwn ELF object 
        filename is patched binary location 
        bv is BN live view of process
        dbg is BN DebuggerController
        """

        self.exe = pwn.ELF(filename)
        self.exe.asm(self.exe.entrypoint, "h: jmp h;nop;nop")
        self.exe.save("/tmp/" + filename)

        self.filename =  "/tmp/" + filename
        system(f"chmod +x {filename}")

        super().__init__(self.filename)

        bv  = binaryninja.BinaryViewType.get_view_of_file(filename)
        self.dbg = DebuggerController(bv)
        if self.dbg.attach(self.pid):
            pwn.info(f"Sucessfully Attached to process {self.pid}")
        else:
            pwn.error(f"Error Attaching to process {self.pid}")

        self.bv = self.dbg.live_view 
        self.dbg.set_reg_value("rip", self.bv.entry_point +4)
        self.bv.write(self.bv.entry_point, pwn.asm("endbr64"))

        # Clones the BN debugger object, hopefully no name collisions
        for attr in [method_name for method_name in dir(self.dbg) if not method_name.startswith("_") ]:
            setattr(self,attr,  (getattr(self.dbg, attr)))

    # def sendline(self, line=b''):
    #     # Screw \n, If you want a newline put it in urself
    #     line = packing._need_bytes(line)
    #     self.send(line)

    def close(self): 
        super().close()
        self.bv.file.close()
        self.dbg.destroy()


# Mock everything
def fake_debug(filename):
    d = pwn.gdb.debug(filename)
    d.dbg = Mock()
    return d 

